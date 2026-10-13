"""Offline browser cleanup ownership tests; no live browser or credentials."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('credential_browser_close_tests',
    ROOT / 'local/sync_adspower_cookies.py')
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


class CredentialBrowserCloseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.enterContext(patch.object(sync, 'ROOT', self.root))
        self.audit = self.enterContext(patch.object(sync, '_audit'))
        self.path = self.root / 'local/account.json'
        self.config = sync.validate_config(dict(profile_id='one', token_id=7,
            expected_email='owner@example.test', adspower_base='http://127.0.0.1:50325',
            flow_base='http://127.0.0.1:38000', allow_saved_cookies=True))
        sync.save_private(self.path, self.config)
        sync.save_private(self.path.with_name('account.state.json'),
            dict(token_id=7, proxy_hash=sync.digest(sync.proxy_identity(''))))
        self.cookies = [{'name': 'SID', 'value': 'SYNTHETIC_COOKIE', 'domain': '.google.com',
            'path': '/', 'expires': 4102444800, 'secure': True},
            {'name': 'SIDCC', 'value': 'SYNTHETIC_RENEWING', 'domain': '.google.com',
             'path': '/', 'expires': 4102444800, 'secure': True}]
        self.profile = dict(source='cdp', ws='ws://127.0.0.1:9222/devtools/browser/synthetic', proxy='')
        self.token = dict(id=7, email='owner@example.test', login_account='owner@example.test',
            remark='adspower-sync:one', proxy_url='', captcha_proxy_url='',
            google_cookies=json.dumps(self.cookies), at='SYNTHETIC_AT', at_expires='2099-01-01T00:00:00Z')
        self.proof = dict(status='ok', reason='login_verified', token_id=7,
            opened_browser_hash=sync.digest(self.profile['ws']),
            verified_cookie_hash=sync.auth_hash(self.cookies),
            verified_session_hash=sync.auth_session_hash(self.cookies),
            verified_proxy_hash=sync.validation_proxy_hash(''))
        sync.save_private(sync.recovery_browser_owner_path(self.path),
            sync.recovery_browser_owner(self.config, self.proof['opened_browser_hash']))
        self.admission = sync._account_admission(self.config)
        self.owner = self.admission.maintenance(7)
        self.addCleanup(self.owner.close)
        client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _: self.fail('Cleanup attempted an unexpected network call')))
        self.addAsyncCleanup(client.aclose)
        self.gateway = sync.Gateway(self.config, client, {})
        self.gateway.maintenance_capability = self.owner.capability
        self.gateway.profile = AsyncMock(return_value=self.profile)
        self.gateway.tokens = AsyncMock(return_value=[self.token])
        self.gateway.cookies = AsyncMock(return_value=self.cookies)
        self.gateway.busy = AsyncMock(return_value=(False, False))
        self.calls = []
        self.stopped = False

        async def request(path, *, params):
            self.calls.append((path, params))
            with self.assertRaises(self.admission.busy_error):
                self.admission.generation(7)
            with self.assertRaises(self.admission.busy_error):
                self.admission.worker(7, self.owner.capability)
            if path.endswith('/stop'):
                self.stopped = True
                return {'code': 0}
            return {'code': 0, 'data': {'status': 'inactive' if self.stopped else 'active',
                'ws': {'puppeteer': self.profile['ws']}}}

        self.gateway._profile_request = AsyncMock(side_effect=request)

    async def close(self):
        return await self.gateway.close_recovered_browser(self.proof, self.path)

    def assert_no_stop(self):
        self.assertFalse(any(path.endswith('/stop') for path, _ in self.calls))

    async def test_committed_session_closes_only_owned_profile_with_a_and_b_still_held(self):
        self.assertTrue(await self.close())
        self.assertEqual(self.calls, [('/api/v1/browser/active', {'user_id': 'one'}),
            ('/api/v1/browser/stop', {'user_id': 'one'}),
            ('/api/v1/browser/active', {'user_id': 'one'})])
        self.assertFalse(sync.recovery_browser_owner_path(self.path).exists())
        with self.admission.worker(7, self.owner.capability):
            pass
        self.owner.close()
        with self.admission.generation(7):
            pass

    async def test_preexisting_browser_without_ownership_is_never_inspected_or_closed(self):
        self.proof.pop('opened_browser_hash')
        self.assertFalse(await self.close())
        self.gateway.profile.assert_not_awaited()
        self.assert_no_stop()

    async def test_later_ordinary_sync_closes_the_same_owned_instance_after_a_failed_login(self):
        self.assertTrue(await self.gateway.close_synced_browser(self.path))
        self.assertFalse(sync.recovery_browser_owner_path(self.path).exists())
        self.assertEqual(self.calls[1], ('/api/v1/browser/stop', {'user_id': 'one'}))

    async def test_owned_browser_already_inactive_is_finished_without_another_stop(self):
        self.gateway._profile_request.side_effect = [{'code': 0, 'data': {'status': 'Inactive'}}]
        self.assertTrue(await self.close())
        self.gateway.profile.assert_not_awaited()
        self.assertFalse(sync.recovery_browser_owner_path(self.path).exists())
        self.assert_no_stop()

    async def test_shutdown_between_activity_and_live_profile_is_confirmed_without_stop(self):
        self.gateway._profile_request.side_effect = [
            {'code': 0, 'data': {'status': 'Active'}}, {'code': 0, 'data': {'status': 'Inactive'}}]
        self.gateway.profile.side_effect = sync.SyncError('profile_inactive')
        self.assertTrue(await self.close())
        self.assertFalse(sync.recovery_browser_owner_path(self.path).exists())
        self.assert_no_stop()

    async def test_real_saved_profile_return_after_shutdown_is_confirmed_without_stop(self):
        # Exercise Gateway.profile itself: allow_saved_cookies=True returns a
        # saved source for Inactive, rather than raising profile_inactive.
        self.gateway.profile = sync.Gateway.profile.__get__(self.gateway, sync.Gateway)
        responses = iter([
            {'code': 0, 'data': {'status': 'Active'}},
            {'code': 0, 'data': {'status': 'Inactive'}},
            {'code': 0, 'data': {'list': [{'user_id': 'one', 'user_proxy_config': {'proxy_type': 'no_proxy'}}]}},
            {'code': 0, 'data': {'status': 'Inactive'}},
        ])

        async def request(path, *, params):
            self.calls.append((path, params))
            with self.assertRaises(self.admission.busy_error):
                self.admission.generation(7)
            return next(responses)

        self.gateway._profile_request.side_effect = request
        self.assertTrue(await self.close())
        self.assertEqual([path for path, _ in self.calls], [
            '/api/v1/browser/active', '/api/v1/browser/active', '/api/v1/user/list', '/api/v1/browser/active'])
        self.assertFalse(sync.recovery_browser_owner_path(self.path).exists())
        self.gateway.cookies.assert_not_awaited()
        self.assert_no_stop()

    async def test_real_saved_profile_return_cannot_clear_owner_when_fresh_activity_is_active_or_unknown(self):
        self.gateway.profile = sync.Gateway.profile.__get__(self.gateway, sync.Gateway)
        confirmations = [
            {'code': 0, 'data': {'status': 'Active', 'ws': {'puppeteer': self.profile['ws']}}},
            {'code': 0, 'data': {'status': 'Unknown'}},
            {'code': 0, 'data': {}},
            {'code': True, 'data': {'status': 'Inactive'}},
        ]
        for confirmation in confirmations:
            with self.subTest(confirmation=confirmation):
                self.calls.clear()
                responses = iter([
                    {'code': 0, 'data': {'status': 'Active'}},
                    {'code': 0, 'data': {'status': 'Inactive'}},
                    {'code': 0, 'data': {'list': [{'user_id': 'one', 'user_proxy_config': {'proxy_type': 'no_proxy'}}]}},
                    confirmation,
                ])

                async def request(path, *, params):
                    self.calls.append((path, params))
                    return next(responses)

                self.gateway._profile_request.side_effect = request
                self.assertFalse(await self.close())
                self.assertTrue(sync.recovery_browser_owner_path(self.path).exists())
                self.assertEqual(len(self.calls), 4)
                self.assert_no_stop()

    async def test_ordinary_sync_live_only_gateway_can_finish_an_already_closed_instance(self):
        self.config['allow_saved_cookies'] = False
        sync.save_private(self.path, self.config)
        sync.save_private(sync.recovery_browser_owner_path(self.path),
            sync.recovery_browser_owner(self.config, self.proof['opened_browser_hash']))
        self.gateway.profile.side_effect = sync.SyncError('profile_inactive')
        self.gateway._profile_request.side_effect = [{'code': 0, 'data': {'status': 'Inactive'}}]
        self.assertTrue(await self.gateway.close_synced_browser(self.path))
        self.assertFalse(sync.recovery_browser_owner_path(self.path).exists())
        self.assert_no_stop()

    async def test_a_missing_expired_or_replaced_owner_prevents_browser_access(self):
        self.owner.close()
        with self.admission.maintenance(7):
            self.assertFalse(await self.close())
        self.gateway.profile.assert_not_awaited()
        self.assert_no_stop()

    async def test_old_worker_still_running_prevents_browser_access(self):
        with self.admission.worker(7, self.owner.capability):
            self.assertFalse(await self.close())
        self.gateway.profile.assert_not_awaited()
        self.assert_no_stop()

    async def test_missing_stale_or_invalid_private_ownership_prevents_browser_access(self):
        path = sync.recovery_browser_owner_path(self.path)
        path.unlink()
        self.assertFalse(await self.close())
        record = sync.recovery_browser_owner(self.config, 'f' * 64)
        sync.save_private(path, record)
        self.assertFalse(await self.close())
        sync.save_private(path, sync.recovery_browser_owner(self.config, self.proof['opened_browser_hash']))
        path.chmod(0o644)
        self.assertFalse(await self.close())
        self.gateway.profile.assert_not_awaited()
        self.assert_no_stop()

    async def test_new_generation_or_unknown_busy_state_keeps_browser_open(self):
        for busy in ((True, False), (False, True)):
            with self.subTest(busy=busy):
                self.gateway.busy.return_value = busy
                self.assertFalse(await self.close())
                self.assert_no_stop()
        self.gateway.busy.side_effect = sync.SyncError('spark_inventory_incomplete')
        self.assertFalse(await self.close())
        self.assert_no_stop()

    async def test_uncommitted_changed_expired_or_wrong_account_credentials_prevent_stop(self):
        for changes in ({'at': None}, {'at_expires': '2000-01-01T00:00:00Z'},
                        {'id': 8}, {'google_cookies': '[]'},
                        {'google_cookies': json.dumps([dict(self.cookies[0], value='OTHER_SESSION')])}):
            with self.subTest(changes=changes):
                self.gateway.tokens.return_value = [dict(self.token, **changes)]
                self.assertFalse(await self.close())
                self.assert_no_stop()

    async def test_observed_reopened_browser_is_preserved_before_and_after_cookie_read(self):
        other = dict(self.profile, ws='ws://127.0.0.1:9222/devtools/browser/reopened')
        for profiles in ([other], [self.profile, other]):
            with self.subTest(profiles=profiles):
                self.gateway.profile.side_effect = profiles
                self.assertFalse(await self.close())
                self.assert_no_stop()

    async def test_config_source_proxy_and_live_session_changes_prevent_stop(self):
        self.gateway.cookies.return_value = [dict(self.cookies[0], value='OTHER_LIVE_SESSION')]
        self.assertFalse(await self.close())
        self.gateway.cookies.return_value = self.cookies
        self.gateway.profile.return_value = dict(self.profile, proxy='http://other.example.test:8080')
        self.assertFalse(await self.close())
        self.gateway.profile.return_value = self.profile
        sync.save_private(self.path, dict(self.config, token_id=8))
        self.assertFalse(await self.close())
        self.assert_no_stop()

    async def test_session_renewal_does_not_prevent_cleanup_of_the_same_verified_instance(self):
        renewed = copy.deepcopy(self.cookies)
        renewed[1].update(value='SYNTHETIC_RENEWED', expires=4102444830)
        self.gateway.cookies.return_value = renewed
        self.assertTrue(await self.close())

    async def test_stop_ack_is_not_reported_as_closed_without_inactive_confirmation(self):
        async def active(path, **_kwargs):
            self.calls.append((path, _kwargs['params']))
            return {'code': 0} if path.endswith('/stop') else {'code': 0, 'data': {
                'status': 'active', 'ws': {'puppeteer': self.profile['ws']}}}
        self.gateway._profile_request.side_effect = active
        with patch.object(sync.asyncio, 'sleep', AsyncMock()):
            self.assertFalse(await self.close())
        self.assertEqual(sum(path.endswith('/stop') for path, _ in self.calls), 1)
        self.assertEqual(sum(path.endswith('/active') for path, _ in self.calls), 21)
        self.assertTrue(sync.recovery_browser_owner_path(self.path).exists())
        self.assertEqual(self.audit.call_args.kwargs['details'],
                         {'retry_reason': 'browser_shutdown_pending'})
        from src.core.account_audit import sanitize_details
        self.assertEqual(sanitize_details({'retry_reason': 'browser_shutdown_pending'}),
                         {'retry_reason': 'browser_shutdown_pending'})

    async def test_shutdown_after_the_original_five_polls_is_confirmed_with_one_stop(self):
        polls_after_stop = 0

        async def delayed(path, *, params):
            nonlocal polls_after_stop
            self.calls.append((path, params))
            with self.assertRaises(self.admission.busy_error):
                self.admission.generation(7)
            with self.assertRaises(self.admission.busy_error):
                self.admission.worker(7, self.owner.capability)
            if path.endswith('/stop'):
                self.stopped = True
                return {'code': 0}
            if self.stopped:
                polls_after_stop += 1
            return {'code': 0, 'data': {
                'status': 'inactive' if polls_after_stop == 8 else 'active',
                'ws': {'puppeteer': self.profile['ws']}}}

        self.gateway._profile_request.side_effect = delayed
        with patch.object(sync.asyncio, 'sleep', AsyncMock()):
            self.assertTrue(await self.close())
        self.assertEqual(polls_after_stop, 8)
        self.assertEqual(sum(path.endswith('/stop') for path, _ in self.calls), 1)
        self.assertFalse(sync.recovery_browser_owner_path(self.path).exists())

    async def test_reopened_endpoint_during_shutdown_is_preserved_without_repeating_stop(self):
        self.gateway._profile_request.side_effect = [
            {'code': 0, 'data': {'status': 'active', 'ws': {'puppeteer': self.profile['ws']}}},
            {'code': 0},
            {'code': 0, 'data': {'status': 'active',
                'ws': {'puppeteer': 'ws://127.0.0.1:9222/devtools/browser/reopened'}}},
        ]
        self.assertFalse(await self.close())
        self.assertEqual(self.gateway._profile_request.await_count, 3)
        self.assertEqual(sum(call.args[0].endswith('/stop')
            for call in self.gateway._profile_request.await_args_list), 1)
        self.assertTrue(sync.recovery_browser_owner_path(self.path).exists())
        self.assertEqual(self.audit.call_args.kwargs['details'],
                         {'retry_reason': 'profile_changed_during_sync'})

    async def test_delayed_shutdown_is_confirmed_without_repeating_stop(self):
        responses = [{'code': 0, 'data': {'status': 'active'}}, {'code': 0}, {'code': 0, 'data': {'status': 'active',
            'ws': {'puppeteer': self.profile['ws']}}}, {'code': 0, 'data': {'status': 'inactive'}}]
        self.gateway._profile_request.side_effect = responses
        with patch.object(sync.asyncio, 'sleep', AsyncMock()):
            self.assertTrue(await self.close())
        self.assertEqual(self.gateway._profile_request.await_count, 4)

    async def test_adspower_capitalized_activity_status_confirms_shutdown(self):
        self.gateway._profile_request.side_effect = [{'code': 0, 'data': {'status': 'Active'}}, {'code': 0},
            {'code': 0, 'data': {'status': 'Inactive'}}]
        self.assertTrue(await self.close())

    async def test_transport_failure_defers_cleanup_and_keeps_the_commit_and_owner(self):
        self.gateway._profile_request.side_effect = RuntimeError('PRIVATE_UPSTREAM_DETAIL')
        self.assertFalse(await self.close())
        self.assertEqual(self.token['at'], 'SYNTHETIC_AT')
        with self.admission.worker(7, self.owner.capability):
            pass
        self.assertNotIn('PRIVATE', repr(self.audit.call_args_list))
