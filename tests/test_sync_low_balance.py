"""Balance policy regressions with fake services and private temporary files."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sync_low_balance', ROOT / 'local/sync_adspower_cookies.py')
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)
SPEC = importlib.util.spec_from_file_location('pool_low_balance', ROOT / 'local/sync_adspower_cookie_pool.py')
pool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pool)
PROXY = 'http://test-user:test-password@proxy.example.test:3128'
COOKIES = [{'name': 'SID', 'value': 'TEST_SOURCE_SESSION', 'domain': '.google.com',
            'path': '/', 'secure': True}]


def config(**values):
    fields = dict(profile_id='fixed-profile', expected_email='fixed@example.test', token_id=7,
                  adspower_base='http://127.0.0.1:50325', flow_base='http://127.0.0.1:38000',
                  enable_on_create=False, disable_below_credits=10)
    fields.update(values)
    return sync.validate_config(fields)


def account(**values):
    row = dict(id=7, email='fixed@example.test', login_account='fixed@example.test',
               remark='adspower-sync:fixed-profile', google_cookies=json.dumps(COOKIES),
               proxy_url=PROXY, captcha_proxy_url=PROXY, st='frontend-original',
               at='flow-frontend-cookie', at_expires='2099-01-01T00:00:00Z', credits=100,
               is_active=True, image_enabled=True, video_enabled=False,
               auto_refresh_enabled=False, protocol_mode='protocol',
               image_concurrency=1, video_concurrency=2, ban_reason=None, banned_at=None)
    row.update(values)
    return row


class FakeGateway:
    def __init__(self, row=None):
        self.row = copy.deepcopy(row or account())
        self.source = dict(source='cdp', ws='ws://127.0.0.1:1234/devtools/browser/test', proxy=PROXY)
        self.profile = AsyncMock(side_effect=lambda: copy.deepcopy(self.source))
        self.tokens = AsyncMock(side_effect=lambda: [copy.deepcopy(self.row)] if self.row else [])
        self.cookies = AsyncMock(return_value=copy.deepcopy(COOKIES))
        self.busy = AsyncMock(return_value=(False, False))
        self.write = AsyncMock(side_effect=self.save)
        self.disable = AsyncMock(side_effect=self.stop_selection)

    async def save(self, token_id, payload):
        self.row.update(payload)
        self.row['at_expires'] = '2099-01-02T00:00:00Z'

    async def stop_selection(self, token_id):
        if token_id != self.row['id']:
            raise AssertionError('wrong account')
        self.row['is_active'] = False


class LowBalanceTests(unittest.IsolatedAsyncioTestCase):
    def validator(self, credits=9):
        return AsyncMock(return_value={'email': 'fixed@example.test', 'credits': credits})

    async def run_sync(self, credits=9, row=None, state=None, **options):
        gateway, check = FakeGateway(row), self.validator(credits)
        result = await sync.synchronize(config(**options), state if state is not None else {},
                                        gateway, validator=check, now=1000)
        return result, gateway, check

    async def test_threshold_boundary_and_real_zero(self):
        for credits in (0, 9, 9.999, 10, 10.001, 100):
            with self.subTest(credits=credits):
                result, gateway, check = await self.run_sync(credits)
                check.assert_awaited_once()
                if credits < 10:
                    self.assertEqual(result, {'status': 'disabled', 'reason': 'low_balance_disabled',
                                             'token_id': 7, 'credits': credits})
                    gateway.disable.assert_awaited_once_with(7)
                    gateway.write.assert_not_awaited()
                else:
                    self.assertEqual(result['status'], 'unchanged')
                    gateway.disable.assert_not_awaited()

    async def test_invalid_threshold_is_rejected_before_external_reads(self):
        for value in (True, False, -1, '10', float('nan'), float('inf'), -float('inf'), [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(sync.SyncError, 'invalid_disable_credit_threshold'):
                    config(disable_below_credits=value)
                conf, gateway = config(), FakeGateway()
                conf['disable_below_credits'] = value
                with self.assertRaisesRegex(sync.SyncError, 'invalid_disable_credit_threshold'):
                    await sync.synchronize(conf, {}, gateway, validator=self.validator())
                gateway.profile.assert_not_awaited()
        self.assertEqual(config(disable_below_credits=0)['disable_below_credits'], 0)

    async def test_bad_credit_or_identity_result_never_disables_or_writes(self):
        for result in ({}, None, {'email': 'other@example.test', 'credits': 0},
                       *({'email': 'fixed@example.test', 'credits': value}
                         for value in (True, False, None, '0', -1, float('nan'), float('inf'), 10**12))):
            with self.subTest(result=result):
                gateway, check = FakeGateway(), self.validator()
                check.return_value = result
                with self.assertRaises(sync.SyncError):
                    await sync.synchronize(config(), {}, gateway, validator=check, now=1000)
                gateway.disable.assert_not_awaited()
                gateway.write.assert_not_awaited()
        for exception in (RuntimeError('TEST_SECRET_RESPONSE'), sync.SyncError('google_session_requires_attention', 'auth')):
            gateway, check = FakeGateway(), self.validator()
            check.side_effect = exception
            with self.assertRaises(sync.SyncError) as error:
                await sync.synchronize(config(), {}, gateway, validator=check, now=1000)
            self.assertNotIn('TEST_SECRET', str(error.exception))
            gateway.disable.assert_not_awaited()

    async def test_low_balance_ignores_busy_work_and_unavailable_busy_inventory(self):
        for busy in ((True, True), RuntimeError('busy inventory unavailable')):
            gateway, check = FakeGateway(), self.validator(9)
            if isinstance(busy, Exception):
                gateway.busy.side_effect = busy
            else:
                gateway.busy.return_value = busy
            self.assertEqual((await sync.synchronize(config(), {}, gateway,
                             validator=check, now=1000))['status'], 'disabled')
            gateway.busy.assert_not_awaited()
            gateway.disable.assert_awaited_once_with(7)
            gateway.write.assert_not_awaited()

    async def test_disable_preserves_credentials_proxy_flags_and_sync_receipts(self):
        original, state = account(), {'synced_at': 500, 'synced_cookie_hash': 'previous-source-hash'}
        result, gateway, _ = await self.run_sync(9, row=original, state=state)
        self.assertEqual(result['status'], 'disabled')
        self.assertEqual(gateway.row, dict(original, is_active=False))
        self.assertEqual(state['synced_at'], 500)
        self.assertEqual(state['synced_cookie_hash'], 'previous-source-hash')

    async def test_already_disabled_never_posts_or_reenables_even_when_balance_recovers(self):
        for credits in (9, 10, 100):
            result, gateway, check = await self.run_sync(credits, row=account(is_active=False))
            check.assert_awaited_once()
            gateway.disable.assert_not_awaited()
            gateway.write.assert_not_awaited()
            self.assertFalse(gateway.row['is_active'])
            if credits < 10:
                self.assertEqual(result['reason'], 'low_balance_already_disabled')

    async def test_configured_policy_bypasses_identity_cache_and_db_balance(self):
        for fresh, stored in ((9, 1000), (10, 0)):
            state = dict(validated_hash=sync.auth_hash(COOKIES), validated_at=999,
                         validated_proxy_hash=sync.validation_proxy_hash(PROXY), cached_credits=stored)
            result, gateway, check = await self.run_sync(fresh, row=account(credits=stored), state=state)
            check.assert_awaited_once()
            self.assertEqual(result['status'] == 'disabled', fresh < 10)
        gateway, check, state = FakeGateway(), self.validator(100), {}
        await sync.synchronize(config(), state, gateway, validator=check, now=1000)
        check.return_value['credits'] = 9
        self.assertEqual((await sync.synchronize(config(), state, gateway,
                         validator=check, now=1001))['status'], 'disabled')
        self.assertEqual(check.await_count, 2)

    async def test_old_configs_keep_cache_busy_protection_and_no_auto_disable(self):
        conf = config(disable_below_credits=None)
        self.assertIsNone(conf['disable_below_credits'])
        gateway, check, state = FakeGateway(account(credits=0)), self.validator(0), {}
        await sync.synchronize(conf, state, gateway, validator=check, now=1000)
        await sync.synchronize(conf, state, gateway, validator=check, now=1001)
        self.assertEqual(check.await_count, 1)
        gateway.disable.assert_not_awaited()
        gateway = FakeGateway()
        gateway.busy.return_value = (True, True)
        self.assertEqual((await sync.synchronize(conf, {}, gateway,
                         validator=self.validator(0), now=1000))['reason'], 'generation_busy')
        gateway.disable.assert_not_awaited()

    async def test_saved_source_rollback_protection_checks_only_current_db_balance(self):
        for credits in (0, 10):
            with self.subTest(credits=credits):
                current = account(google_cookies=json.dumps([dict(COOKIES[0], value='TEST_DB_ROTATED')]))
                gateway, check = FakeGateway(current), self.validator(credits)
                gateway.source['source'] = 'saved'
                state = {'synced_cookie_hash': sync.auth_hash(COOKIES), 'validated_at': 1}
                result = await sync.synchronize(config(), state, gateway, validator=check, now=1000)
                check.assert_awaited_once_with(current['google_cookies'], 'fixed@example.test', PROXY)
                self.assertEqual(result['status'], 'disabled' if credits < 10 else 'unchanged')
                if credits >= 10:
                    self.assertEqual(result['reason'], 'saved_source_unchanged')
                gateway.write.assert_not_awaited()
                gateway.busy.assert_not_awaited()
                self.assertEqual(gateway.row['google_cookies'], current['google_cookies'])
                self.assertEqual(state['synced_cookie_hash'], sync.auth_hash(COOKIES))
                self.assertNotIn('validated_hash', state)

    async def test_saved_db_validation_failure_does_not_bind_backoff_to_saved_hash(self):
        current = account(google_cookies=json.dumps([dict(COOKIES[0], value='TEST_DB_ROTATED')]))
        gateway, check = FakeGateway(current), self.validator()
        gateway.source['source'] = 'saved'
        check.side_effect = sync.SyncError('google_session_requires_attention', 'auth')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conf_path = root / 'local/config.json'
            state_path = root / 'local/config.state.json'
            sync.save_private(conf_path, config())
            sync.save_private(root / 'local/credentials.json', {'username': 'TEST_USER', 'password': 'TEST_PASSWORD'})
            sync.save_private(state_path, {'synced_cookie_hash': sync.auth_hash(COOKIES)})
            with patch.object(sync, 'ROOT', root):
                result = await sync.run_once(conf_path, gateway_factory=lambda *_: gateway, validator=check)
            self.assertEqual(result['status'], 'error')
            saved_state = sync.private_json(state_path)
            self.assertNotIn('auth_failed_hash', saved_state)
            self.assertNotIn('auth_retry_after', saved_state)
            self.assertNotIn('network_retry_after', saved_state)
            self.assertNotIn('TEST_DB_ROTATED', json.dumps(saved_state))
        gateway.disable.assert_not_awaited()
        gateway.write.assert_not_awaited()

    async def test_unavailable_or_invalid_source_checks_db_balance_without_copying_it(self):
        current = account(google_cookies=json.dumps([dict(COOKIES[0], value='TEST_DB_CURRENT')]))
        for source in (sync.SyncError('cookies_unavailable', 'auth'),
                       sync.SyncError('cookie_structure_invalid'), [], [{'name': 'SID', 'value': True}]):
            for credits in (0, 10):
                with self.subTest(source=source, credits=credits):
                    gateway, check = FakeGateway(current), self.validator(credits)
                    if isinstance(source, Exception):
                        gateway.cookies.side_effect = source
                    else:
                        gateway.cookies.return_value = source
                    state = {'observed_hash': 'previous-source', 'synced_at': 500}
                    if credits < 10:
                        result = await sync.synchronize(config(), state, gateway, validator=check, now=1000)
                        self.assertEqual(result['status'], 'disabled')
                        gateway.disable.assert_awaited_once_with(7)
                    else:
                        with self.assertRaises(sync.SyncError) as error:
                            await sync.synchronize(config(), state, gateway, validator=check, now=1000)
                        self.assertEqual(error.exception.category, 'balance')
                        self.assertIn(error.exception.reason, {'cookies_unavailable', 'cookie_structure_invalid'})
                        gateway.disable.assert_not_awaited()
                    check.assert_awaited_once_with(current['google_cookies'], 'fixed@example.test', PROXY)
                    gateway.write.assert_not_awaited()
                    gateway.busy.assert_not_awaited()
                    self.assertEqual(gateway.row['google_cookies'], current['google_cookies'])
                    self.assertEqual(state['observed_hash'], 'previous-source')
                    self.assertNotIn('auth_failed_hash', state)

    async def test_unavailable_source_and_failed_db_session_never_disable_or_poison_retry(self):
        for result in ({'email': 'fixed@example.test', 'credits': None},
                       sync.SyncError('google_session_requires_attention', 'auth')):
            gateway, check = FakeGateway(), self.validator()
            gateway.cookies.side_effect = sync.SyncError('cookies_unavailable', 'auth')
            if isinstance(result, Exception):
                check.side_effect = result
            else:
                check.return_value = result
            state = {'observed_hash': 'previous-source'}
            with self.assertRaises(sync.SyncError) as error:
                await sync.synchronize(config(), state, gateway, validator=check, now=1000)
            self.assertEqual(error.exception.category, 'balance')
            gateway.disable.assert_not_awaited()
            gateway.write.assert_not_awaited()
            self.assertNotIn('auth_failed_hash', state)
            self.assertNotIn('auth_retry_after', state)

    async def test_pre_disable_binding_credentials_and_status_races_abort(self):
        for field, changed in (('id', 8), ('email', 'other@example.test'), ('remark', 'different-profile'),
                               ('google_cookies', 'changed'), ('st', 'changed'), ('at', 'changed'),
                               ('at_expires', '2000-01-01T00:00:00Z'), ('proxy_url', 'http://other.test:80'),
                               ('captcha_proxy_url', 'http://other.test:80'), ('credits', 1000),
                               ('is_active', False), ('image_enabled', False), ('video_enabled', True)):
            with self.subTest(field=field):
                gateway, check = FakeGateway(), self.validator()
                async def change(*_):
                    gateway.row[field] = changed
                    return {'email': 'fixed@example.test', 'credits': 9}
                check.side_effect = change
                with self.assertRaises(sync.SyncError):
                    await sync.synchronize(config(), {}, gateway, validator=check, now=1000)
                gateway.disable.assert_not_awaited()
                gateway.write.assert_not_awaited()

    async def test_source_ws_endpoint_and_auth_races_abort(self):
        for field, changed in (('ws', 'ws://127.0.0.1:1234/different'),
                               ('proxy', PROXY.replace('proxy.example.test', 'other.example.test')),
                               ('proxy', PROXY.replace('test-password', 'different'))):
            gateway, check = FakeGateway(), self.validator()
            async def change(*_):
                gateway.source[field] = changed
                return {'email': 'fixed@example.test', 'credits': 9}
            check.side_effect = change
            with self.assertRaisesRegex(sync.SyncError, 'profile_changed_during_sync'):
                await sync.synchronize(config(), {}, gateway, validator=check, now=1000)
            gateway.disable.assert_not_awaited()

    async def test_disable_failure_or_unexpected_saved_fields_is_not_retried(self):
        for mode in ('exception', 'still-active', 'changed-cookie'):
            gateway = FakeGateway()
            async def disable(token_id):
                if mode == 'exception':
                    raise sync.SyncError('local_transport_failed', 'network')
                if mode == 'changed-cookie':
                    gateway.row.update(is_active=False, google_cookies='unexpected')
            gateway.disable.side_effect = disable
            with self.assertRaises(sync.SyncError):
                await sync.synchronize(config(), {}, gateway, validator=self.validator(), now=1000)
            gateway.disable.assert_awaited_once_with(7)
            gateway.write.assert_not_awaited()

    async def test_source_change_during_disable_is_not_reported_successful(self):
        for field, changed in (('ws', 'ws://127.0.0.1:1234/different'),
                               ('proxy', PROXY.replace('test-password', 'different'))):
            gateway = FakeGateway()
            async def disable(token_id):
                await gateway.stop_selection(token_id)
                gateway.source[field] = changed
            gateway.disable.side_effect = disable
            with self.assertRaisesRegex(sync.SyncError, 'profile_changed_during_sync'):
                await sync.synchronize(config(), {}, gateway, validator=self.validator(), now=1000)
            gateway.disable.assert_awaited_once_with(7)
            gateway.write.assert_not_awaited()
            self.assertFalse(gateway.row['is_active'])

    async def test_missing_or_non_bool_account_state_is_not_treated_as_disabled(self):
        for active in (None, 0, 1, 'false'):
            gateway = FakeGateway(account(is_active=active))
            with self.assertRaisesRegex(sync.SyncError, 'account_flags_changed'):
                await sync.synchronize(config(), {}, gateway, validator=self.validator(), now=1000)
            gateway.disable.assert_not_awaited()
            gateway.write.assert_not_awaited()

    async def test_failure_backoffs_make_no_balance_judgment(self):
        for state in ({'network_retry_after': 1500},
                      {'auth_failed_hash': sync.auth_hash(COOKIES), 'auth_retry_after': 1500,
                       'auth_failed_proxy_hash': sync.validation_proxy_hash(PROXY)}):
            gateway, check = FakeGateway(account(credits=0)), self.validator(0)
            result = await sync.synchronize(config(), state, gateway, validator=check, now=1000)
            self.assertEqual(result['status'], 'deferred')
            gateway.disable.assert_not_awaited()
            gateway.write.assert_not_awaited()
            check.assert_not_awaited()

    async def test_low_unbound_account_cannot_be_created_enabled(self):
        gateway = FakeGateway()
        gateway.row = None
        result = await sync.synchronize(config(token_id=None, enable_on_create=True), {}, gateway,
                                        validator=self.validator(0), now=1000)
        self.assertEqual(result['reason'], 'low_balance_unbound')
        gateway.write.assert_not_awaited()
        gateway.disable.assert_not_awaited()

    async def test_gateway_disable_only_calls_original_disable_route(self):
        gateway = sync.Gateway(config(), None, {})
        gateway.authorization = {'Authorization': 'TEST_BEARER'}
        gateway.request = AsyncMock(return_value={'success': True})
        await gateway.disable(7)
        gateway.request.assert_awaited_once_with('POST', 'http://127.0.0.1:38000',
            '/api/tokens/7/disable', headers={'Authorization': 'TEST_BEARER'})
        gateway.request.return_value = {'success': False}
        with self.assertRaisesRegex(sync.SyncError, 'account_write_unconfirmed'):
            await gateway.disable(7)

    async def test_pool_counts_disabling_as_success_and_exposes_only_finite_balance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            local = root / 'local'
            local.mkdir()
            for name in ('one.json', 'two.json'):
                sync.save_private(local / name, {})
            sync.save_private(local / 'pool.json', {'config_paths': ['one.json', 'two.json']})
            async def runner(path):
                return dict(status='disabled' if path.name == 'one.json' else 'unchanged',
                            reason='low_balance_disabled' if path.name == 'one.json' else 'low_balance_already_disabled',
                            token_id=7, credits=0, cookie='TEST_SECRET', proxy_url=PROXY)
            with patch.object(pool, 'ROOT', root), patch.object(pool, 'LOCAL', local):
                result = await pool.run_pool('local/pool.json', run_once=runner)
            self.assertEqual(result['status'], 'ok')
            self.assertEqual(result['counts']['disabled'], 1)
            self.assertEqual(result['counts']['error'], 0)
            self.assertEqual(result['results'][0]['credits'], 0)
            self.assertNotIn('TEST_SECRET', json.dumps(result))
            self.assertNotIn('test-password', json.dumps(result))
        for value in (True, False, -1, float('nan'), float('inf'), None, '0', 10**12):
            self.assertNotIn('credits', pool._safe_result(dict(status='disabled',
                             reason='low_balance_disabled', token_id=7, credits=value)))


if __name__ == '__main__':
    unittest.main()
