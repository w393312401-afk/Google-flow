"""Offline recovery integration tests; all files and transports are synthetic."""
import asyncio
import builtins
import contextlib
import copy
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx


_SPEC = importlib.util.spec_from_file_location(
    "sync_adspower_cookies_recovery_tests",
    Path(__file__).resolve().parents[1] / "local/sync_adspower_cookies.py")
sync = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sync)
_ASYNC_CLIENT = httpx.AsyncClient
_EMAIL = "owner@example.test"
_COOKIE_HASH = "a" * 64
_PROXY_HASH = "b" * 64


def config(**updates):
    value = dict(profile_id="one", expected_email=_EMAIL, token_id=7,
                 adspower_base="http://127.0.0.1:50325",
                 flow_base="http://127.0.0.1:38000",
                 spark_base="http://127.0.0.1:8085")
    value.update(updates)
    return value


def proof(**updates):
    value = dict(status="ok", reason="login_verified", token_id=7,
                 verified_cookie_hash=_COOKIE_HASH,
                 verified_proxy_hash=_PROXY_HASH)
    value.update(updates)
    return value


def backoff(**updates):
    value = dict(auth_failed_hash=_COOKIE_HASH, observed_hash=_COOKIE_HASH,
                 auth_failed_proxy_hash=_PROXY_HASH, auth_retry_after=5000)
    value.update(updates)
    return value


def policy_token(**updates):
    value = dict(id=7, email=_EMAIL, login_account=_EMAIL,
                 remark="adspower-sync:one", auto_refresh_enabled=True,
                 refresh_interval_minutes=30, at=None, at_expires=None)
    value.update(updates)
    return value


def at_expiry(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


class RecoveryRunTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "account.json"
        self.state_path = self.root / "account.state.json"
        (self.root / "local").mkdir()
        sync.save_private(self.root / "local/credentials.json",
                          {"username": "SYNTHETIC_ADMIN", "password": "SYNTHETIC_PASSWORD"})
        self.write_config()
        self.recovery = AsyncMock(return_value=proof())
        self.gateway = type("SyntheticGateway", (), {})()
        self.gateway.recover_login = self.recovery
        self.policy_row = policy_token()
        self.gateway.tokens = AsyncMock(side_effect=lambda: [copy.deepcopy(self.policy_row)])
        self.factory_calls = []

        def factory(conf, client, credentials):
            self.factory_calls.append((copy.deepcopy(conf), copy.deepcopy(credentials)))
            return self.gateway

        self.factory = factory
        self.validator = AsyncMock()
        self.addCleanup(patch.stopall)
        patch.object(sync, "ROOT", self.root).start()
        patch.object(sync.time, "time", return_value=1000).start()

        def reject_network(request):
            raise AssertionError("An integration test attempted an unexpected HTTP call")

        def offline_client(**kwargs):
            return _ASYNC_CLIENT(transport=httpx.MockTransport(reject_network), **kwargs)

        patch.object(sync.httpx, "AsyncClient", side_effect=offline_client).start()

    def write_config(self, **updates):
        sync.save_private(self.path, config(**updates))

    async def run_with(self, first, second=None, *, state=None, side_effect=None):
        sync.save_private(self.state_path, state or {})
        replies = [first] if second is None else [first, second]
        synchronize = AsyncMock(side_effect=side_effect or replies)
        with patch.object(sync, "synchronize", synchronize):
            result = await sync.run_once(self.path, gateway_factory=self.factory,
                                         validator=self.validator)
        return result, synchronize

    async def assert_policy_deferred(self, row, reason, *, source_reason="cookies_unavailable", state=None):
        self.write_config(allow_pool_login=True)
        self.policy_row = copy.deepcopy(row)
        self.recovery.reset_mock()
        self.gateway.tokens.reset_mock()
        self.factory_calls.clear()
        before = ({"login_attempted_at": 100, "login_retry_after": 200,
                   "login_last_reason": "login_captcha_required"} if state is None else state)
        with patch.object(sync, '_audit') as audit:
            result, operation = await self.run_with(
                {"status": "error", "reason": source_reason, "detail": "SOURCE_PRIVATE_DETAIL"}, state=before)
        expected = {"status": "deferred", "reason": reason, "token_id": 7,
                    "prior_reason": source_reason}
        self.assertEqual(result, expected)
        saved = sync.private_json(self.state_path)
        self.assertEqual(saved['last_result'], expected)
        for field in ('login_attempted_at', 'login_retry_after', 'login_last_reason'):
            self.assertEqual((field in saved, saved.get(field)), (field in before, before.get(field)))
        operation.assert_awaited_once()
        self.gateway.tokens.assert_awaited_once()
        self.recovery.assert_not_awaited()
        self.assertEqual(len(self.factory_calls), 2)
        self.assertEqual(self.factory_calls[1][1],
                         {"username": "SYNTHETIC_ADMIN", "password": "SYNTHETIC_PASSWORD"})
        deferred = [call for call in audit.call_args_list if call.kwargs.get('reason') == reason]
        self.assertEqual(len(deferred), 1)
        self.assertEqual(deferred[0].args[1:3], ('auto_login', 'deferred'))
        self.assertEqual(deferred[0].kwargs['details'], {'retry_reason': source_reason})
        self.assertNotIn('SOURCE_PRIVATE_DETAIL', json.dumps(result) + self.state_path.read_text()
                         + repr(audit.call_args_list))
        self.assertNotIn('SYNTHETIC_POLICY_AT', json.dumps(result) + self.state_path.read_text()
                         + repr(audit.call_args_list))
        from src.core.account_audit import normalize_event
        event = normalize_event(7, operation='auto_login', status='deferred', reason=reason,
                                stage='login', source='cookie_sync', details={'retry_reason': source_reason})
        self.assertEqual(event['reason'], reason)
        self.assertEqual(json.loads(event['details']), {'retry_reason': source_reason})

    def test_admission_loader_uses_only_the_stdlib_file_and_caches_its_error_class(self):
        original_import = builtins.__import__
        def without_flow_package(name, *_args, **_kwargs):
            if name == 'src' or name.startswith('src.'):
                raise ModuleNotFoundError('Flow package dependencies are unavailable')
            return original_import(name, *_args, **_kwargs)

        conf = sync.validate_config(sync.private_json(self.path))
        with patch('builtins.__import__', side_effect=without_flow_package):
            admission = sync._account_admission(conf)
            again = sync._account_admission(conf)
            self.assertIs(type(admission), type(again))
            with admission.maintenance(7) as owner, admission.worker(7, owner.capability):
                with self.assertRaises(admission.busy_error):
                    admission.generation(7)

    async def test_account_admission_covers_initial_sync_login_and_final_sync(self):
        self.write_config(allow_pool_login=True)
        admission = sync._account_admission(sync.validate_config(sync.private_json(self.path)))
        capabilities, stages = [], []
        calls = 0

        def assert_generation_blocked():
            with self.assertRaises(admission.busy_error) as raised:
                admission.generation(7)
            self.assertEqual(raised.exception.reason, 'generation_busy')

        async def synchronize(conf, state, gateway, **_kwargs):
            nonlocal calls
            calls += 1
            stages.append('initial_sync' if calls == 1 else 'final_sync')
            capabilities.append(gateway.maintenance_capability)
            assert_generation_blocked()
            return ({'status': 'error', 'reason': 'cookies_unavailable'} if calls == 1 else
                    {'status': 'updated', 'reason': 'sync_complete', 'token_id': 7})

        async def login():
            stages.append('login')
            capabilities.append(self.gateway.maintenance_capability)
            assert_generation_blocked()
            with admission.worker(7, self.gateway.maintenance_capability):
                assert_generation_blocked()
            return proof()

        async def policy():
            stages.append('policy')
            capabilities.append(self.gateway.maintenance_capability)
            assert_generation_blocked()
            fd = os.open(self.root / 'account.lock', os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            return [self.policy_row]

        self.recovery.side_effect = login
        self.gateway.tokens.side_effect = policy
        result, _ = await self.run_with(None, side_effect=synchronize)
        self.assertEqual(stages, ['initial_sync', 'policy', 'login', 'final_sync'])
        self.assertEqual(result['status'], 'updated')
        self.assertEqual(len(set(capabilities)), 1)
        self.assertRegex(capabilities[0], r'^[0-9a-f]{64}$')
        self.assertNotIn(capabilities[0], self.state_path.read_text() + json.dumps(result))
        with admission.generation(7):
            pass

    async def test_opened_recovery_browser_closes_after_final_sync_with_owner_and_worker_fencing(self):
        self.write_config(allow_pool_login=True)
        verified = proof(opened_browser_hash='d' * 64)
        self.recovery.return_value = verified
        admission = sync._account_admission(sync.validate_config(sync.private_json(self.path)))
        stages, capabilities = [], []

        async def synchronize(conf, state, gateway, **kwargs):
            stages.append('initial_sync' if not stages else 'final_sync_committed')
            capabilities.append(gateway.maintenance_capability)
            return ({'status': 'error', 'reason': 'cookies_unavailable'} if len(stages) == 1 else
                    {'status': 'updated', 'reason': 'sync_complete', 'token_id': 7})

        async def close(received, config_path):
            self.assertEqual(stages, ['initial_sync', 'final_sync_committed'])
            self.assertEqual(received, verified)
            self.assertEqual(config_path, self.path)
            self.assertEqual(sync.private_json(self.state_path)['last_result']['status'], 'updated')
            self.assertEqual(self.gateway.maintenance_capability, capabilities[0])
            with self.assertRaises(admission.busy_error) as raised:
                admission.generation(7)
            self.assertEqual(raised.exception.reason, 'generation_busy')
            # The real close helper will acquire this worker B under the still
            # held maintenance A; use its real lock contract without a browser.
            with admission.worker(7, self.gateway.maintenance_capability):
                with self.assertRaises(admission.busy_error):
                    admission.generation(7)
            stages.append('browser_closed')
            return True

        self.gateway.close_recovered_browser = AsyncMock(side_effect=close)
        result, operation = await self.run_with(None, side_effect=synchronize)
        self.assertEqual(stages, ['initial_sync', 'final_sync_committed', 'browser_closed'])
        self.assertEqual(operation.await_count, 2)
        self.gateway.close_recovered_browser.assert_awaited_once_with(verified, self.path)
        self.assertEqual(result, {'status': 'updated', 'reason': 'sync_complete', 'token_id': 7, 'browser_closed': True})
        self.assertEqual(len(set(capabilities)), 1)
        self.assertNotIn(verified['opened_browser_hash'], json.dumps(result))
        with admission.generation(7):
            pass

    async def test_old_recovery_proof_without_opened_browser_keeps_expected_sync_result(self):
        self.write_config(allow_pool_login=True)
        self.gateway.close_recovered_browser = AsyncMock()
        expected = {'status': 'updated', 'reason': 'sync_complete', 'token_id': 7}
        result, operation = await self.run_with({'status': 'error', 'reason': 'cookies_unavailable'}, expected)
        self.assertEqual(result, expected)
        self.assertEqual(operation.await_count, 2)
        self.gateway.close_recovered_browser.assert_not_awaited()

    async def test_successful_first_sync_finishes_owned_browser_without_another_login_and_under_owner_lock(self):
        self.write_config(allow_pool_login=True)
        conf = sync.validate_config(sync.private_json(self.path))
        owner_path = sync.recovery_browser_owner_path(self.path)
        sync.save_private(owner_path, sync.recovery_browser_owner(conf, 'd' * 64))
        admission = sync._account_admission(conf)
        stages = []

        async def synchronized(*args, **kwargs):
            stages.append('initial_sync_committed')
            return {'status': 'updated', 'reason': 'sync_complete', 'token_id': 7}

        async def close(config_path):
            self.assertEqual(config_path, self.path)
            self.assertEqual(stages, ['initial_sync_committed'])
            self.assertEqual(sync.private_json(self.state_path)['last_result']['status'], 'updated')
            with self.assertRaises(admission.busy_error) as raised:
                admission.generation(7)
            self.assertEqual(raised.exception.reason, 'generation_busy')
            stages.append('owned_browser_closed')
            return True

        self.gateway.close_synced_browser = AsyncMock(side_effect=close)
        self.gateway.close_recovered_browser = AsyncMock()
        result, operation = await self.run_with(None, side_effect=synchronized)
        self.assertEqual(result, {'status': 'updated', 'reason': 'sync_complete', 'token_id': 7, 'browser_closed': True})
        self.assertEqual(stages, ['initial_sync_committed', 'owned_browser_closed'])
        operation.assert_awaited_once()
        self.gateway.close_synced_browser.assert_awaited_once_with(self.path)
        self.gateway.close_recovered_browser.assert_not_awaited()
        self.recovery.assert_not_awaited()
        with admission.generation(7):
            pass

    async def test_failed_first_sync_keeps_browser_ownership_for_a_later_success_and_never_closes(self):
        self.write_config(allow_pool_login=True)
        conf = sync.validate_config(sync.private_json(self.path))
        owner_path = sync.recovery_browser_owner_path(self.path)
        ownership = sync.recovery_browser_owner(conf, 'd' * 64)
        sync.save_private(owner_path, ownership)
        self.gateway.close_synced_browser = AsyncMock()
        self.gateway.close_recovered_browser = AsyncMock()
        failure = {'status': 'error', 'reason': 'account_write_unconfirmed', 'token_id': 7}
        result, operation = await self.run_with(failure)
        self.assertEqual(result, failure)
        self.assertEqual(sync.private_json(owner_path), ownership)
        operation.assert_awaited_once()
        self.gateway.close_synced_browser.assert_not_awaited()
        self.gateway.close_recovered_browser.assert_not_awaited()
        self.recovery.assert_not_awaited()

    async def test_failed_final_sync_or_commit_never_closes_opened_recovery_browser(self):
        self.write_config(allow_pool_login=True)
        self.recovery.return_value = proof(opened_browser_hash='d' * 64)
        self.gateway.close_recovered_browser = AsyncMock()
        failures = [
            {'status': 'deferred', 'reason': 'generation_busy', 'token_id': 7},
            {'status': 'error', 'reason': 'account_write_unconfirmed'},
            sync.SyncError('account_write_unconfirmed'),
        ]
        for final in failures:
            with self.subTest(final=final):
                self.gateway.close_recovered_browser.reset_mock()
                result, operation = await self.run_with({'status': 'error', 'reason': 'cookies_unavailable'}, final)
                self.assertIn(result['status'], {'error', 'deferred'})
                self.assertNotIn('browser_closed', result)
                self.assertEqual(operation.await_count, 2)
                self.gateway.close_recovered_browser.assert_not_awaited()

    async def test_cleanup_false_does_not_turn_successful_final_sync_into_failure(self):
        self.write_config(allow_pool_login=True)
        verified = proof(opened_browser_hash='d' * 64)
        self.recovery.return_value = verified
        self.gateway.close_recovered_browser = AsyncMock(return_value=False)
        result, _ = await self.run_with({'status': 'error', 'reason': 'cookies_unavailable'},
                                      {'status': 'updated', 'reason': 'sync_complete', 'token_id': 7})
        self.gateway.close_recovered_browser.assert_awaited_once_with(verified, self.path)
        self.assertEqual(result, {'status': 'updated', 'reason': 'sync_complete', 'token_id': 7, 'browser_closed': False})

    async def test_live_generation_or_another_maintainer_defers_before_any_sync(self):
        admission = sync._account_admission(sync.validate_config(sync.private_json(self.path)))
        for operation, reason in ((admission.generation, 'generation_busy'),
                                  (admission.maintenance, 'already_running')):
            with self.subTest(reason=reason), operation(7), patch.object(sync, 'synchronize', AsyncMock()) as synchronize:
                result = await sync.run_once(self.path, gateway_factory=self.factory, validator=self.validator)
                self.assertEqual(result, {'status': 'deferred', 'reason': reason, 'token_id': 7})
                synchronize.assert_not_awaited()
                self.recovery.assert_not_awaited()
                self.assertEqual(self.factory_calls, [])
        with admission.generation(7):
            pass

    async def test_cancelled_scheduled_run_releases_admission_after_cleanup(self):
        admission = sync._account_admission(sync.validate_config(sync.private_json(self.path)))
        entered = asyncio.Event()

        async def synchronize(*_args, **_kwargs):
            entered.set()
            await asyncio.Event().wait()

        with patch.object(sync, 'synchronize', AsyncMock(side_effect=synchronize)):
            running = asyncio.create_task(sync.run_once(self.path, gateway_factory=self.factory, validator=self.validator))
            await asyncio.wait_for(entered.wait(), 2)
            with self.assertRaises(admission.busy_error):
                admission.generation(7)
            running.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await running
        with admission.generation(7):
            pass

    async def test_unbound_account_keeps_existing_global_checks_without_an_admission_lease(self):
        self.write_config(token_id=None)
        with patch.object(sync, '_account_admission', side_effect=AssertionError('No bound token')):
            result, synchronize = await self.run_with({'status': 'deferred', 'reason': 'generation_busy'})
        self.assertEqual(result, {'status': 'deferred', 'reason': 'generation_busy'})
        synchronize.assert_awaited_once()

    async def test_binding_or_database_change_cannot_sync_inside_the_previous_account_admission(self):
        for updates in ({'token_id': 8}, {'flow_db_path': str(self.root / 'different/flow.db')}):
            with self.subTest(updates=updates):
                self.write_config()
                admission = sync._account_admission(sync.validate_config(sync.private_json(self.path)))
                original = admission.maintenance

                @contextlib.contextmanager
                def changed_binding(token_id):
                    with original(token_id) as lease:
                        self.write_config(**updates)
                        yield lease

                with patch.object(sync, '_account_admission', return_value=admission), \
                     patch.object(admission, 'maintenance', side_effect=changed_binding), \
                     patch.object(sync, 'synchronize', AsyncMock()) as synchronize:
                    result = await sync.run_once(self.path, gateway_factory=self.factory, validator=self.validator)
                self.assertEqual(result, {'status': 'error', 'reason': 'config_binding_changed'})
                synchronize.assert_not_awaited()
                self.recovery.assert_not_awaited()
                self.assertEqual(self.factory_calls, [])
                with admission.generation(7):
                    pass

    async def test_default_and_explicit_false_never_attempt_login(self):
        for option in ({}, {"allow_pool_login": False}):
            for reason in sync.LOGIN_TRIGGERS:
                with self.subTest(option=option, reason=reason):
                    self.write_config(**option)
                    self.recovery.reset_mock()
                    first = {"status": "error", "reason": reason}
                    result, operation = await self.run_with(first)
                    self.assertEqual(result, first)
                    self.recovery.assert_not_awaited()
                    operation.assert_awaited_once()

    async def test_wrong_identity_and_invalid_credits_do_not_attempt_login(self):
        self.write_config(allow_pool_login=True)
        for reason in ("google_identity_mismatch", "google_credit_validation_failed",
                       "generation_busy", "identity_validation_unavailable"):
            with self.subTest(reason=reason):
                self.recovery.reset_mock()
                result, operation = await self.run_with({"status": "error", "reason": reason})
                self.assertEqual(result["reason"], reason)
                self.recovery.assert_not_awaited()
                operation.assert_awaited_once()

    async def test_unbound_account_never_attempts_login(self):
        self.write_config(allow_pool_login=True, token_id=None)
        result, operation = await self.run_with(
            {"status": "error", "reason": "cookies_unavailable"})
        self.assertEqual(result["reason"], "cookies_unavailable")
        self.recovery.assert_not_awaited()
        operation.assert_awaited_once()

    async def test_legacy_auth_backoff_allows_one_login_then_one_sync(self):
        self.write_config(allow_pool_login=True)
        expected = {"status": "unchanged", "reason": "identity_validated", "token_id": 7}
        result, operation = await self.run_with(
            {"status": "deferred", "reason": "authentication_backoff"}, expected,
            state=backoff())
        self.assertEqual(result, expected)
        self.recovery.assert_awaited_once_with()
        self.assertEqual(operation.await_count, 2)
        self.assertEqual(self.factory_calls[1][1],
                         {"username": "SYNTHETIC_ADMIN", "password": "SYNTHETIC_PASSWORD"})
        self.assertEqual(self.factory_calls[2][1], {}, "Host recovery must not receive admin credentials")

    async def test_known_identity_or_credit_auth_backoff_never_attempts_login(self):
        self.write_config(allow_pool_login=True)
        for reason in ("google_identity_mismatch", "google_credit_validation_failed"):
            with self.subTest(reason=reason):
                self.recovery.reset_mock()
                first = {"status": "deferred", "reason": "authentication_backoff"}
                result, operation = await self.run_with(first,
                    state=backoff(auth_failed_reason=reason))
                self.assertEqual(result, first)
                self.recovery.assert_not_awaited()
                operation.assert_awaited_once()

    async def test_reserved_login_backoff_prevents_another_host_call(self):
        self.write_config(allow_pool_login=True)
        result, operation = await self.run_with(
            {"status": "error", "reason": "cookies_unavailable"},
            state={"login_retry_after": 1001})
        self.assertEqual(result, {"status": "deferred", "reason": "login_backoff", "token_id": 7,
                                  "retry_after": 1001})
        self.assertEqual(sync.private_json(self.state_path)["last_result"], result)
        self.recovery.assert_not_awaited()
        operation.assert_awaited_once()

    async def test_disabled_automatic_refresh_keeps_sync_and_source_reason_without_reserving_login(self):
        for source_reason in ('profile_inactive', 'cookies_unavailable', 'authentication_backoff'):
            with self.subTest(source_reason=source_reason):
                # Explicit disable remains decisive even if unrelated policy
                # fields are absent or malformed and a host backoff is active.
                row = policy_token(auto_refresh_enabled=False, at='SYNTHETIC_POLICY_AT', at_expires='invalid')
                row.pop('refresh_interval_minutes')
                await self.assert_policy_deferred(row, 'automatic_login_disabled', source_reason=source_reason,
                    state={'login_attempted_at': 900, 'login_retry_after': 2800,
                           'login_last_reason': 'login_captcha_required'})

    async def test_fresh_at_does_not_open_browser_to_repair_a_cookie_source(self):
        await self.assert_policy_deferred(
            policy_token(at='SYNTHETIC_POLICY_AT', at_expires=at_expiry(1001)),
            'automatic_login_at_unexpired', source_reason='profile_inactive')

    async def test_unknown_automatic_refresh_policy_is_fail_closed_for_each_schema(self):
        missing = object()
        cases = [
            ('auto_refresh_enabled', value) for value in (missing, None, 1, 'true')
        ] + [
            ('refresh_interval_minutes', value) for value in (missing, None, False, 0, -1, 30.0, '120')
        ] + [
            ('at', value) for value in (False, 12, [])
        ] + [
            ('at_expires', value) for value in (missing, None, 'invalid', 1001)
        ]
        for field, value in cases:
            with self.subTest(field=field, value='missing' if value is missing else value):
                row = policy_token(at='SYNTHETIC_POLICY_AT', at_expires=at_expiry(999))
                if value is missing:
                    row.pop(field)
                else:
                    row[field] = value
                await self.assert_policy_deferred(row, 'automatic_login_policy_unknown')

    async def test_interval_120_and_existing_host_backoff_both_limit_the_next_attempt(self):
        self.write_config(allow_pool_login=True)
        self.policy_row = policy_token(refresh_interval_minutes=120)
        for existing_retry, expected_retry in ((2800, 8100), (8500, 8500)):
            with self.subTest(existing_retry=existing_retry):
                before = dict(login_attempted_at=900, login_retry_after=existing_retry,
                              login_last_reason='login_captcha_required')
                result, operation = await self.run_with(
                    {'status': 'error', 'reason': 'cookies_unavailable'}, state=before)
                self.assertEqual(result, {'status': 'deferred', 'reason': 'login_backoff', 'token_id': 7,
                                          'prior_reason': 'login_captcha_required', 'retry_after': expected_retry})
                saved = sync.private_json(self.state_path)
                for field, value in before.items():
                    self.assertEqual(saved[field], value)
                self.assertEqual(saved['last_result'], result)
                operation.assert_awaited_once()
                self.recovery.assert_not_awaited()

    async def test_eligible_expired_or_absent_at_reserves_the_configured_interval(self):
        self.write_config(allow_pool_login=True)
        for access_token, expiry in ((None, None), ('', 'invalid'),
                                     ('SYNTHETIC_POLICY_AT', at_expiry(999)),
                                     ('SYNTHETIC_POLICY_AT', at_expiry(1000))):
            with self.subTest(access_token=access_token, expiry=expiry):
                self.policy_row = policy_token(refresh_interval_minutes=120, at=access_token, at_expires=expiry)
                self.recovery.reset_mock()

                async def host():
                    saved = sync.private_json(self.state_path)
                    self.assertEqual(saved['login_attempted_at'], 1000)
                    self.assertEqual(saved['login_retry_after'], 8200)
                    return proof()

                self.recovery.side_effect = host
                expected = {'status': 'unchanged', 'reason': 'identity_validated', 'token_id': 7}
                result, operation = await self.run_with(
                    {'status': 'error', 'reason': 'cookies_unavailable'}, expected)
                self.assertEqual(result, expected)
                self.assertEqual(operation.await_count, 2)
                self.recovery.assert_awaited_once()
                self.assertEqual(sync.private_json(self.state_path)['login_retry_after'], 8200)

    async def test_policy_query_failure_defers_without_reservation_or_private_error_text(self):
        self.write_config(allow_pool_login=True)
        before = {'login_attempted_at': 100, 'login_retry_after': 200}
        for failure in (RuntimeError('PRIVATE_POLICY_TRANSPORT'), sync.SyncError('local_transport_failed')):
            with self.subTest(failure=type(failure).__name__):
                self.gateway.tokens.side_effect = failure
                with patch.object(sync, '_audit') as audit:
                    result, operation = await self.run_with(
                        {'status': 'error', 'reason': 'profile_inactive'}, state=before)
                self.assertEqual(result, {'status': 'deferred', 'reason': 'automatic_login_policy_unknown',
                                          'token_id': 7, 'prior_reason': 'profile_inactive'})
                saved = sync.private_json(self.state_path)
                self.assertEqual(saved['login_attempted_at'], before['login_attempted_at'])
                self.assertEqual(saved['login_retry_after'], before['login_retry_after'])
                operation.assert_awaited_once()
                self.recovery.assert_not_awaited()
                self.assertNotIn('PRIVATE_POLICY_TRANSPORT', json.dumps(result)
                                 + self.state_path.read_text() + repr(audit.call_args_list))

    async def test_policy_read_binding_mismatch_cannot_reserve_or_reach_host(self):
        self.write_config(allow_pool_login=True)
        for updates in ({'id': 8}, {'remark': 'adspower-sync:other'}, {'login_account': 'other@example.test'}):
            with self.subTest(updates=updates):
                self.policy_row = policy_token(**updates)
                with self.assertRaises(sync.SyncError) as raised:
                    await self.run_with({'status': 'error', 'reason': 'cookies_unavailable'})
                self.assertEqual(raised.exception.reason, 'account_binding_mismatch')
                saved = sync.private_json(self.state_path)
                self.assertNotIn('login_attempted_at', saved)
                self.assertNotIn('login_retry_after', saved)
                self.recovery.assert_not_awaited()

    async def test_configuration_changed_during_policy_read_prevents_login(self):
        self.write_config(allow_pool_login=True)

        async def changed():
            self.write_config(allow_pool_login=True, expected_email='replacement@example.test')
            return [self.policy_row]

        self.gateway.tokens.side_effect = changed
        with self.assertRaises(sync.SyncError) as raised:
            await self.run_with({'status': 'error', 'reason': 'cookies_unavailable'})
        self.assertEqual(raised.exception.reason, 'config_binding_changed')
        self.assertNotIn('login_attempted_at', sync.private_json(self.state_path))
        self.recovery.assert_not_awaited()

    async def test_real_policy_tokens_uses_private_admin_credentials_and_current_time_under_locks(self):
        self.write_config(allow_pool_login=True)
        conf = sync.validate_config(sync.private_json(self.path))
        admission = sync._account_admission(conf)
        requests, stages, capabilities = [], [], []
        policy_gateway = None
        clock = 1000

        def locked():
            with self.assertRaises(admission.busy_error):
                admission.generation(7)
            fd = os.open(self.root / 'account.lock', os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

        def transport(request):
            nonlocal clock
            locked()
            requests.append(request)
            capabilities.append(policy_gateway.maintenance_capability)
            self.assertNotIn('cookie', request.headers)
            self.assertEqual((request.url.host, request.url.port), ('127.0.0.1', 38000))
            if request.url.path == '/api/admin/login':
                self.assertEqual(request.method, 'POST')
                self.assertEqual(json.loads(request.content),
                                 {'username': 'SYNTHETIC_ADMIN', 'password': 'SYNTHETIC_PASSWORD'})
                return httpx.Response(200, json={'success': True, 'token': 'SYNTHETIC_ADMIN_SESSION'})
            if request.url.path == '/api/admin/logout':
                self.assertEqual(request.method, 'POST')
                self.assertEqual(json.loads(request.content), {})
                self.assertEqual(request.headers['authorization'], 'Bearer SYNTHETIC_ADMIN_SESSION')
                stages.append('policy_logout')
                return httpx.Response(200, json={'success': True})
            self.assertEqual(request.url.path, '/api/tokens')
            self.assertEqual(request.method, 'GET')
            self.assertEqual(request.headers['authorization'], 'Bearer SYNTHETIC_ADMIN_SESSION')
            # The AT expires while the read is in flight. Admission must use
            # the current time after the latest policy snapshot is received.
            clock = 2000
            stages.append('policy_tokens')
            return httpx.Response(200, json=[policy_token(refresh_interval_minutes=120,
                at='SYNTHETIC_POLICY_AT', at_expires=at_expiry(1500))])

        def factory(conf, client, credentials):
            nonlocal policy_gateway
            self.factory_calls.append((copy.deepcopy(conf), copy.deepcopy(credentials)))
            if len(self.factory_calls) == 2:
                policy_gateway = sync.Gateway(conf, client, credentials)
                return policy_gateway
            return self.gateway

        async def synchronize(conf, state, gateway, **kwargs):
            locked()
            capabilities.append(gateway.maintenance_capability)
            stages.append('initial_sync' if not stages else 'final_sync')
            return ({'status': 'error', 'reason': 'cookies_unavailable'} if len(stages) == 1 else
                    {'status': 'unchanged', 'reason': 'identity_validated', 'token_id': 7})

        async def host():
            stages.append('host')
            capabilities.append(self.gateway.maintenance_capability)
            self.assertEqual(self.factory_calls[2][1], {})
            state = sync.private_json(self.state_path)
            self.assertEqual(state['login_attempted_at'], 2000)
            self.assertEqual(state['login_retry_after'], 9200)
            with self.assertRaises(admission.busy_error):
                admission.generation(7)
            with sync.process_lock(self.root / 'account.lock'):
                pass
            return proof()

        def client(**kwargs):
            return _ASYNC_CLIENT(transport=httpx.MockTransport(transport), **kwargs)

        self.recovery.side_effect = host
        with patch.object(sync.time, 'time', side_effect=lambda: clock), \
             patch.object(sync.httpx, 'AsyncClient', side_effect=client), \
             patch.object(sync, 'synchronize', AsyncMock(side_effect=synchronize)), \
             patch.object(sync, '_audit') as audit:
            result = await sync.run_once(self.path, gateway_factory=factory, validator=self.validator)
        self.assertEqual(result, {'status': 'unchanged', 'reason': 'identity_validated', 'token_id': 7})
        self.assertEqual(stages, ['initial_sync', 'policy_tokens', 'policy_logout', 'host', 'final_sync'])
        self.assertEqual(len(requests), 3)
        self.assertEqual(self.factory_calls[1][1],
                         {'username': 'SYNTHETIC_ADMIN', 'password': 'SYNTHETIC_PASSWORD'})
        self.assertEqual(len(set(capabilities)), 1)
        self.assertNotIn(capabilities[0], json.dumps(result) + self.state_path.read_text())
        self.assertNotIn('SYNTHETIC_ADMIN', repr(audit.call_args_list))
        self.assertNotIn('SYNTHETIC_POLICY_AT', repr(audit.call_args_list))
        with admission.generation(7):
            pass

    async def test_policy_logout_failure_preserves_disabled_or_fresh_at_decision_without_login(self):
        self.write_config(allow_pool_login=True)
        before = {'login_attempted_at': 100, 'login_retry_after': 200}
        decisions = [
            (policy_token(auto_refresh_enabled=False), 'automatic_login_disabled'),
            (policy_token(at='SYNTHETIC_POLICY_AT', at_expires=at_expiry(1001)), 'automatic_login_at_unexpired'),
        ]
        for row, reason in decisions:
            for failure in ('http', 'transport'):
                with self.subTest(reason=reason, logout_failure=failure):
                    requests = []
                    self.factory_calls.clear()
                    self.recovery.reset_mock()

                    def transport(request):
                        requests.append(request)
                        self.assertEqual((request.url.host, request.url.port), ('127.0.0.1', 38000))
                        self.assertNotIn('cookie', request.headers)
                        if request.url.path == '/api/admin/login':
                            return httpx.Response(200, json={'success': True, 'token': 'SYNTHETIC_ADMIN_SESSION'})
                        self.assertEqual(request.headers['authorization'], 'Bearer SYNTHETIC_ADMIN_SESSION')
                        if request.url.path == '/api/tokens':
                            return httpx.Response(200, json=[row])
                        self.assertEqual(request.url.path, '/api/admin/logout')
                        self.assertEqual(request.method, 'POST')
                        self.assertEqual(json.loads(request.content), {})
                        if failure == 'transport':
                            raise httpx.ConnectError('PRIVATE_LOGOUT_TRANSPORT_PASSWORD', request=request)
                        return httpx.Response(500, json={'message': 'PRIVATE_LOGOUT_RESPONSE_COOKIE'})

                    def client(**kwargs):
                        return _ASYNC_CLIENT(transport=httpx.MockTransport(transport), **kwargs)

                    def factory(conf, client, credentials):
                        self.factory_calls.append((copy.deepcopy(conf), copy.deepcopy(credentials)))
                        return sync.Gateway(conf, client, credentials) if len(self.factory_calls) == 2 else self.gateway

                    with patch.object(sync.httpx, 'AsyncClient', side_effect=client), \
                         patch.object(self, 'factory', factory), patch.object(sync, '_audit') as audit:
                        result, operation = await self.run_with(
                            {'status': 'error', 'reason': 'profile_inactive'}, state=before)
                    self.assertEqual(result, {'status': 'deferred', 'reason': reason, 'token_id': 7,
                                              'prior_reason': 'profile_inactive'})
                    self.assertEqual([request.url.path for request in requests],
                                     ['/api/admin/login', '/api/tokens', '/api/admin/logout'])
                    saved = sync.private_json(self.state_path)
                    self.assertEqual(saved['login_attempted_at'], before['login_attempted_at'])
                    self.assertEqual(saved['login_retry_after'], before['login_retry_after'])
                    self.assertEqual(saved['last_result'], result)
                    operation.assert_awaited_once()
                    self.recovery.assert_not_awaited()
                    self.assertEqual(len(self.factory_calls), 2)
                    self.assertNotIn('PRIVATE_LOGOUT', repr(audit.call_args_list)
                                     + json.dumps(result) + self.state_path.read_text())

    async def test_host_call_runs_after_account_lock_is_released_and_attempt_reserved(self):
        self.write_config(allow_pool_login=True)

        async def host():
            fd = os.open(self.root / "account.lock", os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                state = sync.private_json(self.state_path)
                self.assertEqual(state["login_attempted_at"], 1000)
                self.assertEqual(state["login_retry_after"], 2800)
            finally:
                os.close(fd)
            return proof()

        self.recovery.side_effect = host
        await self.run_with({"status": "error", "reason": "cookies_unavailable"},
                            {"status": "unchanged", "reason": "identity_validated"})
        self.recovery.assert_awaited_once()

    async def test_failed_second_sync_does_not_recursively_attempt_login(self):
        self.write_config(allow_pool_login=True)
        first = {"status": "error", "reason": "google_session_requires_attention"}
        result, operation = await self.run_with(first, first)
        self.assertEqual(result, first)
        self.assertEqual(operation.await_count, 2)
        self.recovery.assert_awaited_once()

    async def test_busy_manual_and_host_failures_return_only_fixed_safe_fields(self):
        self.write_config(allow_pool_login=True)
        for reason in sorted(sync.LOGIN_DEFERRED | sync.LOGIN_ERRORS | {"RAW_COOKIE_SECRET"}):
            with self.subTest(reason=reason):
                self.recovery.reset_mock()
                self.recovery.return_value = {"status": "error", "reason": reason,
                                              "message": "COOKIE_SECRET PASSWORD_SECRET"}
                result, operation = await self.run_with(
                    {"status": "error", "reason": "cookies_unavailable"})
                expected = reason if reason in sync.LOGIN_DEFERRED | sync.LOGIN_ERRORS else "login_internal_error"
                self.assertEqual(result, {"status": "deferred" if reason in sync.LOGIN_DEFERRED else "error",
                                          "reason": expected, "token_id": 7})
                self.assertEqual(set(result), {"status", "reason", "token_id"})
                saved = sync.private_json(self.state_path)
                self.assertEqual(saved["last_result"], result)
                self.assertEqual(saved["login_last_reason"], expected)
                operation.assert_awaited_once()
                self.recovery.assert_awaited_once()

    async def test_host_exception_is_sanitized(self):
        self.write_config(allow_pool_login=True)
        self.recovery.side_effect = RuntimeError("COOKIE_SECRET PASSWORD_SECRET")
        result, _ = await self.run_with({"status": "error", "reason": "cookies_unavailable"})
        self.assertEqual(result, {"status": "deferred", "reason": "login_host_unavailable", "token_id": 7})

    def configure_full_sync_gateway(self):
        cookies = [{"name": "SID", "value": "SYNTHETIC_SESSION", "domain": ".google.com",
                    "path": "/", "secure": True}]
        row = {"id": 7, "email": _EMAIL, "login_account": _EMAIL,
               "remark": "adspower-sync:one", "google_cookies": json.dumps(cookies),
               "proxy_url": "", "captcha_proxy_url": "", "is_active": False,
               "image_enabled": False, "video_enabled": False,
               "at_expires": "2099-01-01T00:00:00Z",
               "auto_refresh_enabled": True, "refresh_interval_minutes": 30}
        self.gateway.profile = AsyncMock(return_value={"ws": "ws://127.0.0.1:9222/fake", "proxy": ""})
        self.gateway.tokens = AsyncMock(return_value=[row])
        self.gateway.cookies = AsyncMock(return_value=cookies)
        self.gateway.busy = AsyncMock(return_value=(False, False))
        self.gateway.write = AsyncMock()
        self.gateway.disable = AsyncMock()
        self.recovery.return_value = proof(verified_cookie_hash=sync.auth_hash(cookies),
                                          verified_proxy_hash=sync.validation_proxy_hash(""))

    async def test_full_sync_revalidates_identity_after_exact_host_proof(self):
        self.write_config(allow_pool_login=True)
        self.configure_full_sync_gateway()
        error = type("SyntheticAuthError", (Exception,), {"category": "authentication_required"})("COOKIE_SECRET")
        self.validator.side_effect = [error, {"email": _EMAIL, "credits": 925}]
        result = await sync.run_once(self.path, gateway_factory=self.factory,
                                     validator=self.validator)
        self.assertEqual(result, {"status": "unchanged", "reason": "identity_validated", "token_id": 7})
        self.assertEqual(self.validator.await_count, 2, "Host proof must not replace ordinary sync identity validation")
        self.recovery.assert_awaited_once()
        self.gateway.write.assert_not_awaited()
        self.gateway.disable.assert_not_awaited()
        state = sync.private_json(self.state_path)
        self.assertNotIn("auth_retry_after", state)
        self.assertNotIn("COOKIE_SECRET", json.dumps(state))

    async def test_full_sync_identity_or_credit_mismatch_never_calls_host(self):
        self.write_config(allow_pool_login=True)
        self.configure_full_sync_gateway()
        for value, reason in (({"email": "other@example.test", "credits": 840}, "google_identity_mismatch"),
                              ({"email": _EMAIL, "credits": None}, "google_credit_validation_failed")):
            with self.subTest(reason=reason):
                sync.save_private(self.state_path, {})
                self.validator.side_effect = None
                self.validator.return_value = value
                result = await sync.run_once(self.path, gateway_factory=self.factory,
                                             validator=self.validator)
                self.assertEqual(result, {"status": "error", "reason": reason})
                self.recovery.assert_not_awaited()
                self.gateway.write.assert_not_awaited()
                self.gateway.disable.assert_not_awaited()

    async def test_authentication_backoff_preserves_known_manual_action_reason(self):
        self.write_config(allow_pool_login=True)
        self.configure_full_sync_gateway()
        for value, reason in (({"email": "other@example.test", "credits": 840}, "google_identity_mismatch"),
                              ({"email": _EMAIL, "credits": None}, "google_credit_validation_failed")):
            with self.subTest(reason=reason):
                sync.save_private(self.state_path, {})
                self.validator.return_value = value
                await sync.run_once(self.path, gateway_factory=self.factory, validator=self.validator)
                result = await sync.run_once(self.path, gateway_factory=self.factory, validator=self.validator)
                self.assertEqual(result["reason"], "authentication_backoff")
                self.assertEqual(result.get("prior_reason"), reason)
                self.assertEqual(result.get("retry_after"), 4600)
                self.assertEqual(sync.private_json(self.state_path)["last_result"], result)
                self.recovery.assert_not_awaited()

    async def test_only_exact_session_proxy_and_binding_proof_clear_old_backoff(self):
        scenarios = [(True, {}, {}, True),
                     (True, {"verified_cookie_hash": "c" * 64}, {}, False),
                     (True, {"verified_proxy_hash": "c" * 64}, {}, False),
                     (True, {"token_id": 8}, {}, False),
                     (True, {"verified_proxy_hash": None}, {}, False),
                     (True, {"verified_proxy_hash": None}, {"auth_failed_proxy_hash": None}, False),
                     (True, {"status": "error"}, {}, False),
                     (True, {"reason": "logged_in"}, {}, False),
                     (True, {}, {"observed_hash": "c" * 64}, False),
                     (False, {}, {}, False)]
        for enabled, proof_updates, state_updates, cleared in scenarios:
            with self.subTest(enabled=enabled, proof=proof_updates, state=state_updates):
                self.write_config(allow_pool_login=enabled)
                sync.save_private(self.state_path, backoff(auth_failed_reason="google_session_requires_attention",
                                                           **state_updates))
                snapshots = []

                async def inspect_state(conf, state, gateway, **kwargs):
                    snapshots.append(copy.deepcopy(state))
                    return {"status": "deferred", "reason": "generation_busy"}

                with patch.object(sync, "synchronize", AsyncMock(side_effect=inspect_state)):
                    await sync._run_once_locked(self.path, gateway_factory=self.factory,
                                                validator=self.validator,
                                                login_proof=proof(**proof_updates))
                fields = ("auth_failed_hash", "auth_failed_proxy_hash", "auth_retry_after", "auth_failed_reason")
                for field in fields:
                    self.assertEqual(field not in snapshots[0], cleared)


class GatewayRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def recover(self, status=200, value=None, *, content=None, exception=None, capability=None):
        received = []

        def transport(request):
            received.append(request)
            if exception:
                raise exception
            kwargs = {"content": json.dumps(value).encode()} if content is None else {"content": content}
            return httpx.Response(status, headers={"set-cookie": "HOST_COOKIE_SECRET=x; Path=/"}, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spark.json"
            sync.save_private(path, {"accessCode": "SYNTHETIC_SPARK_ACCESS"})
            async with _ASYNC_CLIENT(transport=httpx.MockTransport(transport)) as client:
                client.cookies.set("ADMIN_COOKIE_SECRET", "secret", domain="127.0.0.1")
                gateway = sync.Gateway(config(spark_config_path=str(path)), client,
                                       {"username": "ADMIN_USER_SECRET", "password": "ADMIN_PASSWORD_SECRET"})
                gateway.authorization = {"Authorization": "Bearer ADMIN_TOKEN_SECRET"}
                gateway.maintenance_capability = capability
                result = await gateway.recover_login()
                self.assertEqual(list(client.cookies.items()), [])
        self.assertEqual(len(received), 1)
        request = received[0]
        self.assertEqual(str(request.url), "http://127.0.0.1:8085/api/account-pool/login-sync")
        expected = {"profile_id": "one", "expected_email": _EMAIL, "token_id": 7}
        if capability is not None:
            expected['maintenance_capability'] = capability
        self.assertEqual(json.loads(request.content), expected)
        self.assertNotIn("cookie", request.headers)
        self.assertNotIn("authorization", request.headers)
        self.assertEqual(request.headers["x-access-code"], "SYNTHETIC_SPARK_ACCESS")
        self.assertNotIn("ADMIN_", request.content.decode())
        return result

    async def test_maintenance_capability_is_delegated_without_admin_credentials_or_response_echo(self):
        capability = 'c' * 64
        result = await self.recover(value=dict(status='ok', code='login_verified', token_id=7,
            credits=40, verified_cookie_hash=_COOKIE_HASH, verified_proxy_hash=_PROXY_HASH), capability=capability)
        self.assertEqual(result, proof())
        self.assertNotIn(capability, json.dumps(result))

    async def test_success_response_has_only_whitelisted_fields(self):
        result = await self.recover(value=dict(status="ok", code="login_verified", token_id=7,
            credits=840, verified_cookie_hash=_COOKIE_HASH, verified_proxy_hash=_PROXY_HASH,
            cookie="COOKIE_SECRET", password="PASSWORD_SECRET", message="PRIVATE_PAGE_SECRET"))
        self.assertEqual(result, proof())

    async def test_opened_browser_hash_is_the_only_new_forwarded_success_field(self):
        opened_hash = 'd' * 64
        result = await self.recover(value=dict(status='ok', code='login_verified', token_id=7,
            credits=840, verified_cookie_hash=_COOKIE_HASH, verified_proxy_hash=_PROXY_HASH,
            opened_browser_hash=opened_hash, browser_ws='PRIVATE_BROWSER_WS_SECRET',
            browser_profile={'cookie': 'PRIVATE_COOKIE_SECRET'},
            cookie='PRIVATE_COOKIE_SECRET', password='PRIVATE_PASSWORD_SECRET',
            maintenance_capability='e' * 64, message='PRIVATE_PAGE_SECRET'))
        self.assertEqual(result, proof(opened_browser_hash=opened_hash))
        self.assertNotIn('PRIVATE_', json.dumps(result))
        self.assertEqual(set(result), {'status', 'reason', 'token_id', 'verified_cookie_hash',
                                     'verified_proxy_hash', 'opened_browser_hash'})

    async def test_malformed_optional_opened_browser_hash_rejects_host_success(self):
        response = dict(status='ok', code='login_verified', token_id=7, credits=840,
                        verified_cookie_hash=_COOKIE_HASH, verified_proxy_hash=_PROXY_HASH)
        for value in (None, 1, [], '', 'PRIVATE_BROWSER_WS_SECRET', 'D' * 64, 'd' * 63):
            with self.subTest(value=value):
                result = await self.recover(value=dict(response, opened_browser_hash=value))
                self.assertEqual(result, {'status': 'error', 'reason': 'login_internal_error'})

    async def test_invalid_optional_hashes_are_dropped(self):
        result = await self.recover(value=dict(status="ok", code="login_verified", token_id=7,
            credits=0, verified_cookie_hash="COOKIE_SECRET", verified_proxy_hash="B" * 64))
        self.assertEqual(result, {"status": "ok", "reason": "login_verified", "token_id": 7})

    async def test_session_hash_proof_is_preserved_and_malformed_field_is_rejected(self):
        response = dict(status="ok", code="login_verified", token_id=7, credits=40,
                        verified_cookie_hash=_COOKIE_HASH, verified_proxy_hash=_PROXY_HASH,
                        verified_session_hash="c" * 64)
        result = await self.recover(value=response)
        self.assertEqual(result["verified_session_hash"], "c" * 64)
        for malformed in (None, 1, [], "COOKIE_SECRET", "C" * 64):
            with self.subTest(field=malformed):
                result = await self.recover(value=dict(response, verified_session_hash=malformed))
                self.assertEqual(result, {"status": "error", "reason": "login_internal_error"})

    async def test_busy_and_manual_codes_require_expected_http_status(self):
        for codes, status, result_status in ((sync.LOGIN_DEFERRED, 409, "deferred"),
                                             (sync.LOGIN_ERRORS, 422, "error")):
            for code in sorted(codes):
                with self.subTest(code=code):
                    result = await self.recover(status, {"code": code, "message": "COOKIE_SECRET"})
                    self.assertEqual(result, {"status": result_status, "reason": code})
        for status, code in ((200, "generation_busy"), (422, "generation_busy"),
                             (409, "login_wrong_password"), (200, "UNKNOWN_COOKIE_SECRET")):
            with self.subTest(status=status, code=code):
                self.assertEqual(await self.recover(status, {"code": code}),
                                 {"status": "error", "reason": "login_internal_error"})

    async def test_unknown_status_malformed_oversized_and_transport_errors_are_safe(self):
        for status in (201, 302, 401, 403, 500):
            with self.subTest(status=status):
                result = await self.recover(status, {"code": "COOKIE_SECRET"})
                self.assertEqual(result, {"status": "deferred", "reason": "login_host_unavailable"})
        for content, expected in ((b"COOKIE_SECRET", "login_internal_error"),
                                  (b"x" * 4097, "login_host_unavailable"),
                                  (b"[]", "login_internal_error")):
            with self.subTest(content_size=len(content)):
                self.assertEqual((await self.recover(content=content))["reason"], expected)
        result = await self.recover(exception=httpx.ConnectError("PASSWORD_SECRET"))
        self.assertEqual(result, {"status": "deferred", "reason": "login_host_unavailable"})

    async def test_success_requires_matching_integer_token_and_finite_valid_credits(self):
        for updates in ({"token_id": True}, {"token_id": 8}, {"token_id": "7"},
                        {"credits": None}, {"credits": True}, {"credits": -1},
                        {"credits": math.nan}, {"credits": math.inf}, {"credits": 10**12},
                        {"status": "error"}, {"code": "logged_in"}):
            with self.subTest(updates=updates):
                value = dict(status="ok", code="login_verified", token_id=7, credits=840)
                value.update(updates)
                self.assertEqual(await self.recover(value=value),
                                 {"status": "error", "reason": "login_internal_error"})


class VerifiedSessionRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_valid_identity_with_real_zero_is_accepted(self):
        check = AsyncMock(return_value={"email": "OWNER@EXAMPLE.TEST", "credits": 0})
        self.assertEqual(await sync.verified_session(check, "SYNTHETIC_COOKIE", _EMAIL, ""), 0)

    async def test_invalid_identity_and_credits_have_distinct_non_login_failures(self):
        for value, reason in (({}, "google_identity_mismatch"),
                             ({"email": "other@example.test", "credits": 840}, "google_identity_mismatch"),
                             ({"email": _EMAIL}, "google_credit_validation_failed"),
                             *[({"email": _EMAIL, "credits": credits}, "google_credit_validation_failed")
                               for credits in (None, True, "840", -1, math.nan, math.inf, 10**12)]):
            with self.subTest(value=value):
                with self.assertRaises(sync.SyncError) as raised:
                    await sync.verified_session(AsyncMock(return_value=value), "COOKIE_SECRET", _EMAIL, "")
                self.assertEqual(raised.exception.reason, reason)
                self.assertNotIn(reason, sync.LOGIN_TRIGGERS)

    async def test_validator_categories_map_without_exception_secret_leak(self):
        for category, reason in (("identity_mismatch", "google_identity_mismatch"),
                                 ("credits_unverifiable", "google_credit_validation_failed"),
                                 ("authentication_required", "google_session_requires_attention"),
                                 ("identity_unverifiable", "google_session_requires_attention"),
                                 ("network", "identity_validation_unavailable")):
            with self.subTest(category=category):
                error = type("SyntheticValidationError", (Exception,), {"category": category})("COOKIE_SECRET")
                with self.assertRaises(sync.SyncError) as raised:
                    await sync.verified_session(AsyncMock(side_effect=error), "COOKIE_SECRET", _EMAIL, "")
                self.assertEqual(str(raised.exception), reason)


class RecoverySummaryTests(unittest.TestCase):
    def test_pool_summary_preserves_only_actionable_auth_and_login_backoff_details(self):
        spec = importlib.util.spec_from_file_location("synthetic_pool_sanitizer_tests",
            Path(__file__).resolve().parents[1] / "local/sync_adspower_cookie_pool.py")
        pool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pool)
        for outer, prior in (("authentication_backoff", "google_identity_mismatch"),
                             ("authentication_backoff", "google_credit_validation_failed"),
                             ("login_backoff", "login_captcha_required"),
                             ("login_backoff", "login_host_unavailable")):
            with self.subTest(outer=outer, prior=prior):
                expected = {"status": "deferred", "reason": outer, "token_id": 7,
                            "prior_reason": prior, "retry_after": 4600}
                self.assertEqual(pool._safe_result(dict(expected, detail="COOKIE_SECRET")), expected)
                redacted = pool._safe_result(dict(expected, prior_reason="PASSWORD_SECRET",
                                                   retry_after=float("nan")))
                self.assertEqual(redacted, {"status": "deferred", "reason": outer, "token_id": 7})


if __name__ == "__main__":
    unittest.main()
