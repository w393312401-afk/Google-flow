"""Admin one-click refresh: active accounts only, sequential, isolated failures."""

import asyncio
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from src.api import admin
from src.core.account_admission import AccountAdmissionBusy
from src.core.account_operation_context import account_error_reason
from src.services.token_manager import TokenManager


def account(token_id, *, active=True, expires=None):
    return SimpleNamespace(id=token_id, email=f'a{token_id}@example.test',
                           is_active=active, at_expires=expires)


class FakeManager:
    def __init__(self, accounts, outcomes=None):
        self.accounts = {a.id: a for a in accounts}
        self.outcomes = outcomes or {}
        self._last_at_refresh_error = {}
        self.order = []
        self.gate = None
        self.classifier = TokenManager(SimpleNamespace(), SimpleNamespace())
        self.account_admission = None
        self.exit_rotation = None
        self.refresh_inside_maintenance = []

    def _safe_health_error(self, stage, error):
        return self.classifier._safe_health_error(stage, error)

    async def get_all_tokens(self):
        return list(self.accounts.values())

    async def get_token(self, token_id):
        return self.accounts.get(token_id)

    async def _refresh_at(self, token_id):
        self.order.append(token_id)
        self.refresh_inside_maintenance.append(bool(
            self.account_admission and self.account_admission.active
        ))
        if self.gate is not None:
            await self.gate.wait()
        outcome = self.outcomes.get(token_id, True)
        if isinstance(outcome, list):
            outcome = outcome.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if outcome == 'transient':
            self._last_at_refresh_error[token_id] = 'AT_REFRESH: network or proxy unavailable'
            return False
        if isinstance(outcome, str) and outcome.startswith(('AT_REFRESH:', 'AT_VERIFY:', 'ST_REFRESH:')):
            self._last_at_refresh_error[token_id] = outcome
            return False
        if outcome is False:
            self._last_at_refresh_error[token_id] = 'AT_REFRESH: credentials rejected'
            self.accounts[token_id].is_active = False
        return outcome


class FakeAdmission:
    def __init__(self, *, busy=False):
        self.busy = busy
        self.active = False
        self.calls = []

    def maintenance(self, token_id):
        self.calls.append(token_id)
        if self.busy:
            raise AccountAdmissionBusy('generation_busy')
        return self

    def __enter__(self):
        if self.active:
            raise AssertionError('maintenance lease entered twice')
        self.active = True
        return self

    def __exit__(self, *_args):
        self.active = False


class FakeExitRotation:
    def __init__(self, admission, *, registered=True):
        self.admission = admission
        self.registered = registered
        self.enabled_calls = []
        self.mark_calls = []
        self.prepare_calls = []

    def enabled_for(self, token_id):
        self.enabled_calls.append(token_id)
        return self.registered

    async def mark_health_error(self, token_id, reason):
        if not self.admission.active:
            raise AssertionError('mark must run under maintenance')
        self.mark_calls.append((token_id, reason))
        return True

    async def prepare_token(self, latest):
        if not self.admission.active:
            raise AssertionError('prepare must run under maintenance')
        self.prepare_calls.append(latest.id)
        return latest


def add_rotation(manager, *, registered=True, busy=False):
    admission = FakeAdmission(busy=busy)
    rotation = FakeExitRotation(admission, registered=registered)
    manager.account_admission = admission
    manager.exit_rotation = rotation
    return admission, rotation


class RefreshAllTests(unittest.IsolatedAsyncioTestCase):
    def use(self, manager):
        self.enterContext(patch.object(admin, 'token_manager', manager))
        self.enterContext(patch.object(admin, 'refresh_all_retry_delays', (0, 0)))
        self.addCleanup(setattr, admin, 'refresh_all_running', False)

    async def test_refreshes_only_active_accounts_in_order(self):
        expires = datetime(2026, 10, 6, tzinfo=timezone.utc)
        manager = FakeManager([account(1, expires=expires), account(2, active=False),
                               account(3, expires=expires)])
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1, 3])
        self.assertEqual((result['total'], result['succeeded'], result['failed']), (2, 2, 0))
        self.assertEqual(result['results'][0]['at_expires'], expires.isoformat())
        self.assertFalse(admin.refresh_all_running)

    async def test_failure_is_reported_and_does_not_stop_the_rest(self):
        manager = FakeManager([account(1), account(2), account(3)],
                              outcomes={1: RuntimeError('boom'), 2: False})
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1, 2, 3])
        self.assertEqual((result['succeeded'], result['failed']), (1, 2))
        first, second, third = result['results']
        self.assertEqual(first['error'], 'AT_REFRESH: upstream validation unavailable (unclassified error)')
        self.assertEqual(second['error'], 'AT_REFRESH: credentials rejected')
        self.assertTrue(second['disabled'])
        self.assertTrue(third['success'])

    async def test_transient_network_failure_is_retried_until_it_succeeds(self):
        manager = FakeManager([account(1), account(2)],
                              outcomes={1: ['transient', 'transient', True]})
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1, 1, 1, 2])
        self.assertEqual((result['succeeded'], result['failed']), (2, 0))
        first = result['results'][0]
        self.assertEqual(first['attempts'], 3)
        self.assertNotIn('error', first)

    async def test_registered_network_failure_rotates_once_and_retries_outside_maintenance(self):
        manager = FakeManager([account(1)], outcomes={1: ['transient', 'transient', True]})
        admission, rotation = add_rotation(manager)
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertTrue(result['results'][0]['success'])
        self.assertEqual(result['results'][0]['attempts'], 3)
        self.assertEqual(admission.calls, [1])
        self.assertEqual(rotation.mark_calls, [(1, 'network or proxy unavailable')])
        self.assertEqual(rotation.prepare_calls, [1])
        self.assertEqual(manager.refresh_inside_maintenance, [False, False, False])

    async def test_registered_gateway_failure_passes_only_safe_status_to_rotation(self):
        reason = 'ST_REFRESH: upstream unavailable (HTTP 503)'
        manager = FakeManager([account(1)], outcomes={1: [reason, True]})
        _admission, rotation = add_rotation(manager)
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertTrue(result['results'][0]['success'])
        self.assertEqual(rotation.mark_calls, [(1, 'upstream unavailable (HTTP 503)')])
        self.assertEqual(rotation.prepare_calls, [1])
        self.assertEqual(manager.refresh_inside_maintenance, [False, False])

    async def test_maintenance_busy_stops_without_rotation_or_blind_retry(self):
        manager = FakeManager([account(1)], outcomes={1: ['transient', True]})
        admission, rotation = add_rotation(manager, busy=True)
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertFalse(result['results'][0]['success'])
        self.assertEqual(result['results'][0]['attempts'], 1)
        self.assertEqual(manager.order, [1])
        self.assertEqual(admission.calls, [1])
        self.assertEqual(rotation.mark_calls, [])
        self.assertEqual(rotation.prepare_calls, [])

    async def test_unregistered_account_keeps_existing_bounded_retries(self):
        manager = FakeManager([account(1)], outcomes={1: ['transient'] * 10})
        admission, rotation = add_rotation(manager, registered=False)
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(result['results'][0]['attempts'], 3)
        self.assertEqual(manager.order, [1, 1, 1])
        self.assertEqual(admission.calls, [])
        self.assertEqual(rotation.mark_calls, [])
        self.assertEqual(rotation.prepare_calls, [])

    async def test_persistent_network_failure_stops_after_bounded_retries(self):
        manager = FakeManager([account(1), account(2)], outcomes={1: ['transient'] * 10})
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1, 1, 1, 2])
        first = result['results'][0]
        self.assertEqual(first['attempts'], 3)
        self.assertEqual(first['error'], 'AT_REFRESH: network or proxy unavailable')
        self.assertFalse(first['disabled'])
        self.assertTrue(result['results'][1]['success'])

    async def test_credential_rejection_is_not_retried(self):
        manager = FakeManager([account(1)], outcomes={1: False})
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1])
        self.assertEqual(result['results'][0]['attempts'], 1)

    async def test_temporary_gateway_failures_retry_and_then_continue_to_next_account(self):
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                reason = f'AT_REFRESH: upstream unavailable (HTTP {status})'
                manager = FakeManager([account(1), account(2)], outcomes={1: [reason, True]})
                self.use(manager)

                result = await admin.refresh_all_tokens(token='admin')

                self.assertEqual(manager.order, [1, 1, 2])
                self.assertEqual((result['succeeded'], result['failed']), (2, 0))
                self.assertEqual(result['results'][0]['attempts'], 2)
                self.assertTrue(manager.accounts[1].is_active)

    async def test_persistent_gateway_failure_has_bounded_retries_and_keeps_account_enabled(self):
        reason = 'AT_VERIFY: upstream unavailable (HTTP 503)'
        manager = FakeManager([account(1), account(2)], outcomes={1: [reason] * 10})
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1, 1, 1, 2])
        self.assertEqual((result['succeeded'], result['failed']), (1, 1))
        self.assertEqual(result['results'][0]['attempts'], 3)
        self.assertEqual(result['results'][0]['error'], reason)
        self.assertFalse(result['results'][0]['disabled'])
        self.assertTrue(manager.accounts[1].is_active)

    async def test_other_http_failures_do_not_retry_or_disable_account(self):
        for status in (400, 403, 404, 429, 501):
            with self.subTest(status=status):
                reason = f'AT_REFRESH: upstream unavailable (HTTP {status})'
                manager = FakeManager([account(1)], outcomes={1: [reason, True]})
                self.use(manager)

                result = await admin.refresh_all_tokens(token='admin')

                self.assertEqual(manager.order, [1])
                self.assertEqual(result['results'][0]['attempts'], 1)
                self.assertFalse(result['results'][0]['disabled'])
                self.assertTrue(manager.accounts[1].is_active)

    async def test_invalid_validation_response_retries_but_stops_after_three_attempts(self):
        reason = 'AT_REFRESH: upstream validation response invalid'
        manager = FakeManager([account(1), account(2), account(3)],
                              outcomes={1: [reason, True], 2: [reason] * 10})
        self.use(manager)
        result = await admin.refresh_all_tokens(token='admin')
        self.assertEqual(manager.order, [1, 1, 2, 2, 2, 3])
        self.assertEqual((result['succeeded'], result['failed']), (2, 1))
        self.assertEqual(result['results'][1]['attempts'], 3)
        self.assertEqual(result['results'][1]['error'], reason)
        self.assertFalse(result['results'][1]['disabled'])

    async def test_raised_network_exception_is_safely_classified_and_retried(self):
        manager = FakeManager([account(1)], outcomes={1: [TimeoutError(), True]})
        self.use(manager)
        self.assertTrue((await admin.refresh_all_tokens(token='admin'))['results'][0]['success'])
        self.assertEqual(manager.order, [1, 1])

    async def test_rotation_never_receives_or_logs_raw_network_exception(self):
        manager = FakeManager(
            [account(1)],
            outcomes={1: [TimeoutError('http://user:secret@proxy.invalid:8080'), True]},
        )
        _admission, rotation = add_rotation(manager)
        self.use(manager)
        with patch('src.core.logger.debug_logger.log_error') as log:
            result = await admin.refresh_all_tokens(token='admin')
        observed = str(rotation.mark_calls) + str(log.call_args_list) + str(result)
        self.assertTrue(result['results'][0]['success'])
        self.assertEqual(rotation.mark_calls, [(1, 'network or proxy unavailable')])
        self.assertNotIn('secret', observed)
        self.assertNotIn('proxy.invalid', observed)

    async def test_batch_never_returns_or_logs_raw_exception_details(self):
        manager = FakeManager([account(1)], outcomes={1: RuntimeError('SECRET_COOKIE private upstream body')})
        self.use(manager)
        with patch('src.core.logger.debug_logger.log_error') as log:
            result = await admin.refresh_all_tokens(token='admin')
        self.assertNotIn('SECRET', str(result) + str(log.call_args_list))
        self.assertNotIn('private upstream', str(result) + str(log.call_args_list))
        self.assertEqual(manager.order, [1])

    async def test_overlapping_request_is_rejected_and_flag_is_released(self):
        manager = FakeManager([account(1)])
        manager.gate = asyncio.Event()
        self.use(manager)

        running = asyncio.create_task(admin.refresh_all_tokens(token='admin'))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_all_tokens(token='admin')
        self.assertEqual(caught.exception.status_code, 409)

        manager.gate.set()
        result = await running
        self.assertEqual(result['succeeded'], 1)
        self.assertFalse(admin.refresh_all_running)

    async def test_no_active_accounts_is_a_successful_noop(self):
        manager = FakeManager([account(1, active=False)])
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual((result['total'], result['results']), (0, []))
        self.assertEqual(manager.order, [])


class RefreshSingleTests(unittest.IsolatedAsyncioTestCase):
    def use(self, manager):
        self.enterContext(patch.object(admin, 'token_manager', manager))
        self.enterContext(patch.object(admin, 'refresh_all_retry_delays', (0, 0)))

    async def test_success_returns_new_expiry(self):
        expires = datetime(2026, 10, 6, tzinfo=timezone.utc)
        self.use(FakeManager([account(1, expires=expires)]))

        result = await admin.refresh_at(1, token='admin')

        self.assertEqual(result['token'], {'id': 1, 'email': 'a1@example.test',
                                           'at_expires': expires.isoformat()})

    async def test_rejected_credentials_explain_the_real_cause(self):
        self.use(FakeManager([account(1)], outcomes={1: False}))

        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_at(1, token='admin')

        self.assertEqual(caught.exception.status_code, 500)
        self.assertIn('登录态已失效', caught.exception.detail)
        self.assertIn('已被自动禁用', caught.exception.detail)
        self.assertNotIn('personal', caught.exception.detail)

    async def test_transient_failure_is_retried_then_reported_as_network_problem(self):
        manager = FakeManager([account(1), account(2)],
                              outcomes={1: ['transient', True], 2: ['transient'] * 10})
        self.use(manager)

        self.assertEqual((await admin.refresh_at(1, token='admin'))['success'], True)
        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_at(2, token='admin')

        self.assertEqual(manager.order, [1, 1, 2, 2, 2])
        self.assertIn('网络或代理暂时不可用', caught.exception.detail)
        self.assertEqual(account_error_reason(caught.exception), 'network_or_proxy_unavailable')

    async def test_single_gateway_failure_is_retried_and_exhaustion_shows_safe_status(self):
        reason = 'ST_REFRESH: upstream unavailable (HTTP 503)'
        manager = FakeManager([account(1), account(2)],
                              outcomes={1: [reason, True], 2: [reason] * 10})
        self.use(manager)

        self.assertTrue((await admin.refresh_at(1, token='admin'))['success'])
        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_at(2, token='admin')

        self.assertEqual(manager.order, [1, 1, 2, 2, 2])
        self.assertEqual(caught.exception.status_code, 500)
        self.assertEqual(caught.exception.detail,
                         'AT刷新失败: 上游服务暂时不可用（HTTP 503），请稍后再试')
        self.assertTrue(manager.accounts[2].is_active)
        self.assertEqual(account_error_reason(caught.exception), 'upstream_unavailable')

    async def test_traffic_restriction_is_not_retried_and_keeps_audit_category(self):
        reason = 'AT_REFRESH: upstream traffic restriction (PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC)'
        manager = FakeManager([account(1)], outcomes={1: [reason, True]})
        self.use(manager)

        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_at(1, token='admin')

        self.assertEqual(manager.order, [1])
        self.assertTrue(manager.accounts[1].is_active)
        self.assertEqual(account_error_reason(caught.exception), 'traffic_restriction')

    async def test_credential_recovery_required_shows_action_without_network_retry(self):
        reason = 'AT_REFRESH: credential recovery required'
        manager = FakeManager([account(1)], outcomes={1: [reason, True]})
        self.use(manager)

        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_at(1, token='admin')

        self.assertEqual(manager.order, [1])
        self.assertIn('登录凭证需要恢复', caught.exception.detail)
        self.assertIn('刷新凭证', caught.exception.detail)
        self.assertIn('AdsPower', caught.exception.detail)
        self.assertNotIn('网络', caught.exception.detail)
        self.assertNotIn('自动重试', caught.exception.detail)
        self.assertEqual(account_error_reason(caught.exception), 'credential_recovery_required')

    async def test_unknown_account_is_404(self):
        self.use(FakeManager([]))

        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_at(9, token='admin')

        self.assertEqual(caught.exception.status_code, 404)


class RefreshFailureReasonTests(unittest.TestCase):
    def test_only_fixed_route_failures_are_eligible_for_proxy_repair(self):
        self.assertEqual(
            admin._safe_proxy_repair_reason('AT_REFRESH: network or proxy unavailable'),
            'network or proxy unavailable',
        )
        self.assertEqual(
            admin._safe_proxy_repair_reason('AT_REFRESH: upstream transport unavailable'),
            'upstream transport unavailable',
        )
        self.assertTrue(admin._is_retryable_refresh_failure(
            'AT_REFRESH: upstream transport unavailable'))
        for status in (502, 503, 504):
            with self.subTest(status=status):
                self.assertEqual(
                    admin._safe_proxy_repair_reason(
                        f'AT_VERIFY: upstream unavailable (HTTP {status})'),
                    f'upstream unavailable (HTTP {status})',
                )
        excluded = (
            'AT_REFRESH: credentials rejected',
            'AT_REFRESH: credential recovery required',
            'AT_REFRESH: upstream traffic restriction',
            'AT_REFRESH: upstream validation response invalid',
            'AT_REFRESH: upstream unavailable (HTTP 401)',
            'AT_REFRESH: upstream unavailable (HTTP 403)',
            'AT_REFRESH: upstream unavailable (HTTP 429)',
            'AT_REFRESH: upstream unavailable (HTTP 500)',
            'AT_REFRESH: network or proxy unavailable http://user:secret@proxy.invalid:8080',
            'AT_REFRESH: upstream transport unavailable http://user:secret@proxy.invalid:8080',
        )
        for reason in excluded:
            with self.subTest(reason=reason):
                self.assertIsNone(admin._safe_proxy_repair_reason(reason))
        self.assertFalse(admin._is_retryable_refresh_failure(
            'AT_REFRESH: upstream transport unavailable private upstream body'))

    def test_credential_recovery_required_is_actionable_and_not_transport_retryable(self):
        reason = 'AT_REFRESH: credential recovery required'
        self.assertFalse(admin._is_retryable_refresh_failure(reason))
        self.assertEqual(account_error_reason(reason), 'credential_recovery_required')

    def test_sanitized_upstream_http_failures_keep_fixed_audit_category(self):
        for status in (403, 429, 502, 503, 504):
            with self.subTest(status=status):
                self.assertEqual(account_error_reason(
                    f'AT_VERIFY: upstream unavailable (HTTP {status})'), 'upstream_unavailable')

    def test_upstream_translation_never_includes_free_text_after_status(self):
        message = admin._translate_health_reason(
            'AT_REFRESH: upstream unavailable (HTTP 503) SECRET_COOKIE upstream body')
        self.assertEqual(message, '上游服务暂时不可用（HTTP 503），请稍后再试')
        self.assertNotIn('SECRET', message)

    def test_invalid_response_translation_and_retry_are_fixed_categories(self):
        reason = 'AT_REFRESH: upstream validation response invalid'
        self.assertTrue(admin._is_retryable_refresh_failure(reason))
        self.assertFalse(admin._is_retryable_refresh_failure(reason + ' private upstream body'))
        self.assertFalse(admin._is_retryable_refresh_failure(
            'AT_REFRESH: upstream validation unavailable (unclassified error)'))
        message = admin._translate_health_reason(reason + ' SECRET_COOKIE upstream body')
        self.assertEqual(message, '上游余额校验响应异常，请稍后重试或检查该账号的代理')
        self.assertNotIn('SECRET', message)

    def test_invalid_response_keeps_upstream_audit_category_only_for_fixed_reason(self):
        stages = (None, 'AT_CHECK', 'AT_VERIFY', 'AT_REFRESH', 'ST_REFRESH', 'PROTOCOL_REFRESH')
        for stage in stages:
            with self.subTest(stage=stage):
                reason = 'upstream validation response invalid'
                if stage:
                    reason = f'{stage}: {reason}'
                self.assertEqual(account_error_reason(reason), 'upstream_unavailable')
        self.assertEqual(
            account_error_reason('AT_REFRESH: upstream validation response invalid private body'),
            'operation_failed',
        )
        self.assertEqual(
            account_error_reason('AT_REFRESH: upstream validation unavailable (unclassified error)'),
            'operation_failed',
        )


if __name__ == '__main__':
    unittest.main()
