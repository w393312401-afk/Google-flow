"""Offline identity verification tests; all transport operations are mocked."""
import asyncio
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, call, patch

from curl_cffi.requests.exceptions import ProxyError, RequestException

_SPEC = importlib.util.spec_from_file_location(
    "sync_adspower_identity", Path(__file__).resolve().parents[1] / "local/sync_adspower_identity.py"
)
module = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(module)


class IdentityTests(unittest.TestCase):
    def test_only_signed_in_identity_is_used(self):
        html = 'other@example.com<script>window.WIZ_global_data = {"oPEP7c":"Account@example.com"};</script>'
        self.assertEqual(module.extract_signed_in_email(html), "account@example.com")

    def test_arbitrary_email_does_not_authorize(self):
        for html in ('account@example.com', '{"oPEP7c":"account@example.com"}',
                     'WIZ_global_data = {"other":"account@example.com"};'):
            with self.subTest(html=html), self.assertRaises(module.SessionValidationError):
                module.extract_signed_in_email(html)

    def test_ambiguous_identity_fails_closed(self):
        html = 'WIZ_global_data={"oPEP7c":"a@example.com"}; WIZ_global_data={"oPEP7c":"b@example.com"};'
        with self.assertRaises(module.SessionValidationError):
            module.extract_signed_in_email(html)


class ValidationTests(unittest.IsolatedAsyncioTestCase):
    def client(self):
        client = AsyncMock(spec=['_load_flow_frontend_bootstrap', 'get_credits'])
        client._load_flow_frontend_bootstrap = AsyncMock(
            return_value='WIZ_global_data={"oPEP7c":"wanted@example.com"};')
        client.get_credits = AsyncMock(return_value={'credits': 12})
        return client

    def receive_failure(self, status=404):
        return ProxyError(f'Failed to perform, curl: (56) CONNECT tunnel failed, response {status}. PRIVATE', code=56)

    def wrapped_failure(self, original):
        try:
            raise original
        except Exception:
            try:
                raise Exception('Flow API text request failed: PRIVATE')
            except Exception as wrapped:
                return wrapped

    async def test_actual_credit_parser_cannot_turn_invalid_rpc_payload_into_valid_identity(self):
        for payload in ([], [None], [True], [float('nan')], [float('inf')], [-0.5], [-1],
                        ['synthetic-private-value']):
            with self.subTest(payload=payload):
                client = module.FlowClient(None)
                client._load_flow_frontend_bootstrap = AsyncMock(
                    return_value='WIZ_global_data={"oPEP7c":"wanted@example.com"};')
                client._current_rpc = AsyncMock(return_value=payload)
                with patch.object(module, 'FlowClient', return_value=client):
                    with self.assertRaises(module.SessionValidationError) as caught:
                        await module.validate_identity('SID=test', 'wanted@example.com', '')
                self.assertEqual(str(caught.exception), 'validation_unavailable')

    async def test_actual_zero_credit_balance_still_validates_identity(self):
        client = module.FlowClient(None)
        client._load_flow_frontend_bootstrap = AsyncMock(
            return_value='WIZ_global_data={"oPEP7c":"wanted@example.com"};')
        client._current_rpc = AsyncMock(return_value=[0])
        with patch.object(module, 'FlowClient', return_value=client):
            self.assertEqual(await module.validate_identity('SID=test', 'wanted@example.com', ''),
                             {'email': 'wanted@example.com', 'credits': 0})

    async def test_identity_mismatch_never_calls_credits(self):
        client = AsyncMock()
        client._load_flow_frontend_bootstrap.return_value = 'WIZ_global_data={"oPEP7c":"other@example.com"};'
        with patch.object(module, "FlowClient", return_value=client):
            with self.assertRaisesRegex(module.SessionValidationError, "identity_mismatch"):
                await module.validate_identity("SID=test", "wanted@example.com", "http://proxy.invalid:80")
        client.get_credits.assert_not_awaited()

    async def test_real_credit_check_and_explicit_proxy(self):
        client = AsyncMock()
        client._load_flow_frontend_bootstrap.return_value = 'WIZ_global_data={"oPEP7c":"wanted@example.com"};'
        client.get_credits.return_value = {"credits": 12}
        with patch.object(module, "FlowClient", return_value=client) as factory:
            result = await module.validate_identity("SID=test", "wanted@example.com", "http://proxy.invalid:80")
        self.assertEqual(await factory.call_args.args[0].get_request_proxy_url(), "http://proxy.invalid:80")
        self.assertEqual(result, {"email": "wanted@example.com", "credits": 12})
        client.get_credits.assert_awaited_once_with(google_cookies="SID=test")

    async def test_failure_is_redacted_and_403_is_not_expiry(self):
        for message, category in (("rpc code=401 secret=do-not-log", "authentication_required"),
                                  ("HTTP 403 secret=do-not-log", "validation_unavailable")):
            client = AsyncMock()
            client._load_flow_frontend_bootstrap.side_effect = RuntimeError(message)
            with patch.object(module, "FlowClient", return_value=client):
                with self.assertRaises(module.SessionValidationError) as caught:
                    await module.validate_identity("SID=test", "wanted@example.com", "")
            self.assertEqual(str(caught.exception), category)

    async def test_receive_failure_recovers_on_third_attempt_with_fixed_proxy(self):
        client = self.client()
        client._load_flow_frontend_bootstrap.side_effect = [
            self.receive_failure(), self.receive_failure(),
            'WIZ_global_data={"oPEP7c":"wanted@example.com"};']
        delay = AsyncMock()
        with patch.object(module, 'FlowClient', return_value=client) as factory, \
                patch.object(module.asyncio, 'sleep', delay):
            result = await module.validate_identity('SID=test', 'wanted@example.com', 'http://proxy.invalid:80')
        self.assertEqual(result, {'email': 'wanted@example.com', 'credits': 12})
        self.assertEqual(factory.call_count, 3)
        pinned = factory.call_args_list[0].args[0]
        self.assertTrue(all(entry.args[0] is pinned for entry in factory.call_args_list))
        self.assertEqual(await pinned.get_request_proxy_url(), 'http://proxy.invalid:80')
        self.assertEqual(delay.await_args_list, [call(1), call(2)])
        client.get_credits.assert_awaited_once_with(google_cookies='SID=test')
        self.assertEqual(set(entry[0] for entry in client.mock_calls),
                         {'_load_flow_frontend_bootstrap', 'get_credits'})

    async def test_wrapped_credit_failure_rechecks_identity_without_rereading_cookies(self):
        client = self.client()
        candidate = [{'name': 'SID', 'value': 'FIRST', 'domain': '.google.com', 'path': '/'}]
        original_raw = json.dumps(candidate)
        client.get_credits.side_effect = [self.wrapped_failure(self.receive_failure()), {'credits': 51}]
        async def delay(_):
            candidate[0]['value'] = 'CHANGED'
        with patch.object(module, 'FlowClient', return_value=client), \
                patch.object(module.asyncio, 'sleep', side_effect=delay):
            result = await module.validate_identity(candidate, 'wanted@example.com', 'http://proxy.invalid:80')
        self.assertEqual(result, {'email': 'wanted@example.com', 'credits': 51})
        self.assertEqual(client._load_flow_frontend_bootstrap.await_count, 2)
        self.assertEqual(client.get_credits.await_args_list,
                         [call(google_cookies=original_raw), call(google_cookies=original_raw)])
        self.assertTrue(all(entry.args[1] == 'SID=FIRST'
                            for entry in client._load_flow_frontend_bootstrap.await_args_list))

    async def test_repeated_receive_failure_stops_after_three_attempts_and_redacts(self):
        client = self.client()
        client._load_flow_frontend_bootstrap.side_effect = self.receive_failure()
        delay = AsyncMock()
        with patch.object(module, 'FlowClient', return_value=client) as factory, \
                patch.object(module.asyncio, 'sleep', delay):
            with self.assertRaises(module.SessionValidationError) as caught:
                await module.validate_identity('SID=test', 'wanted@example.com', '')
        self.assertEqual(str(caught.exception), 'validation_unavailable')
        self.assertEqual(factory.call_count, 3)
        self.assertEqual(client._load_flow_frontend_bootstrap.await_count, 3)
        self.assertEqual(delay.await_args_list, [call(1), call(2)])
        client.get_credits.assert_not_awaited()

    async def test_only_exact_bootstrap_server_errors_are_recovered(self):
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                client = self.client()
                client._load_flow_frontend_bootstrap.side_effect = [
                    RuntimeError(f'Flow frontend bootstrap failed: HTTP {status}'),
                    'WIZ_global_data={"oPEP7c":"wanted@example.com"};']
                delay = AsyncMock()
                with patch.object(module, 'FlowClient', return_value=client), \
                        patch.object(module.asyncio, 'sleep', delay):
                    result = await module.validate_identity('SID=test', 'wanted@example.com', '')
                self.assertEqual(result['credits'], 12)
                self.assertEqual(client._load_flow_frontend_bootstrap.await_count, 2)
                delay.assert_awaited_once_with(1)

    async def test_authentication_connect_and_program_errors_are_never_retried(self):
        failures = [
            (self.receive_failure(status), 'validation_unavailable') for status in (401, 403, 407)
        ] + [
            (self.wrapped_failure(self.receive_failure(status)), 'validation_unavailable')
            for status in (401, 403, 407)
        ] + [
            (RuntimeError('rpc code=401 PRIVATE'), 'authentication_required'),
            (RuntimeError('UNAUTHENTICATED PRIVATE'), 'authentication_required'),
            (RuntimeError('Flow frontend bootstrap failed: HTTP 404'), 'validation_unavailable'),
            (RuntimeError('Flow frontend bootstrap failed: HTTP 501'), 'validation_unavailable'),
            (RuntimeError('Flow frontend bootstrap failed: HTTP 502 PRIVATE'), 'validation_unavailable'),
            (RuntimeError('Flow credits RPC response invalid'), 'validation_unavailable'),
            (RuntimeError('Flow frontend RPC returned no payload: rpc=nzlxg'), 'validation_unavailable'),
            (TypeError('PRIVATE'), 'validation_unavailable'),
            (ModuleNotFoundError('PRIVATE'), 'validation_unavailable'),
            (Exception('Flow API text request failed: curl: (56) PRIVATE'), 'validation_unavailable'),
            (RequestException('PRIVATE', code=60), 'validation_unavailable'),
            (RequestException('PRIVATE', code=3), 'validation_unavailable'),
            (RequestException('PRIVATE', code=28), 'validation_unavailable'),
        ]
        program_error = ValueError('PRIVATE')
        program_error.__cause__ = self.receive_failure()
        failures.append((program_error, 'validation_unavailable'))
        for error, category in failures:
            with self.subTest(error_type=type(error).__name__, category=category):
                client = self.client()
                client._load_flow_frontend_bootstrap.side_effect = error
                delay = AsyncMock()
                with patch.object(module, 'FlowClient', return_value=client), \
                        patch.object(module.asyncio, 'sleep', delay):
                    with self.assertRaises(module.SessionValidationError) as caught:
                        await module.validate_identity('SID=test', 'wanted@example.com', '')
                self.assertEqual(str(caught.exception), category)
                client._load_flow_frontend_bootstrap.assert_awaited_once()
                client.get_credits.assert_not_awaited()
                delay.assert_not_awaited()

    async def test_identity_and_unknown_credits_end_recovery_immediately(self):
        for credits in (None, True, -1, 'PRIVATE', float('inf'), 1.5):
            with self.subTest(credits_type=type(credits).__name__):
                client = self.client()
                client.get_credits.return_value = {'credits': credits}
                delay = AsyncMock()
                with patch.object(module, 'FlowClient', return_value=client), \
                        patch.object(module.asyncio, 'sleep', delay):
                    with self.assertRaisesRegex(module.SessionValidationError, 'credits_unverifiable'):
                        await module.validate_identity('SID=test', 'wanted@example.com', '')
                client._load_flow_frontend_bootstrap.assert_awaited_once()
                client.get_credits.assert_awaited_once()
                delay.assert_not_awaited()
        client = self.client()
        client._load_flow_frontend_bootstrap.side_effect = [
            'WIZ_global_data={"oPEP7c":"wanted@example.com"};',
            'WIZ_global_data={"oPEP7c":"other@example.com"};']
        client.get_credits.side_effect = self.receive_failure()
        delay = AsyncMock()
        with patch.object(module, 'FlowClient', return_value=client), \
                patch.object(module.asyncio, 'sleep', delay):
            with self.assertRaisesRegex(module.SessionValidationError, 'identity_mismatch'):
                await module.validate_identity('SID=test', 'wanted@example.com', '')
        self.assertEqual(client._load_flow_frontend_bootstrap.await_count, 2)
        client.get_credits.assert_awaited_once()
        delay.assert_awaited_once_with(1)

    async def test_total_budget_interrupts_an_inflight_attempt(self):
        client = self.client()
        async def blocked(*_):
            await asyncio.Event().wait()
        client._load_flow_frontend_bootstrap.side_effect = blocked
        delay = AsyncMock()
        with patch.object(module, 'VALIDATION_TIMEOUT', 0.01), \
                patch.object(module, 'FlowClient', return_value=client), \
                patch.object(module.asyncio, 'sleep', delay):
            with self.assertRaisesRegex(module.SessionValidationError, 'validation_unavailable'):
                await module.validate_identity('SID=test', 'wanted@example.com', '')
        client._load_flow_frontend_bootstrap.assert_awaited_once()
        client.get_credits.assert_not_awaited()
        delay.assert_not_awaited()

    async def test_total_budget_includes_retry_delay(self):
        client = self.client()
        client._load_flow_frontend_bootstrap.side_effect = self.receive_failure()
        async def blocked(_):
            await asyncio.Event().wait()
        with patch.object(module, 'VALIDATION_TIMEOUT', 0.01), \
                patch.object(module, 'FlowClient', return_value=client), \
                patch.object(module.asyncio, 'sleep', side_effect=blocked) as delay:
            with self.assertRaisesRegex(module.SessionValidationError, 'validation_unavailable'):
                await module.validate_identity('SID=test', 'wanted@example.com', '')
        client._load_flow_frontend_bootstrap.assert_awaited_once()
        delay.assert_awaited_once_with(1)

    async def test_external_cancellation_propagates_without_retry(self):
        client = self.client()
        entered = asyncio.Event()
        async def blocked(*_):
            entered.set()
            await asyncio.Event().wait()
        client._load_flow_frontend_bootstrap.side_effect = blocked
        delay = AsyncMock()
        with patch.object(module, 'FlowClient', return_value=client), \
                patch.object(module.asyncio, 'sleep', delay):
            task = asyncio.create_task(module.validate_identity('SID=test', 'wanted@example.com', ''))
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        client._load_flow_frontend_bootstrap.assert_awaited_once()
        delay.assert_not_awaited()

    async def test_cancellation_during_retry_delay_propagates(self):
        client = self.client()
        client._load_flow_frontend_bootstrap.side_effect = self.receive_failure()
        delay = AsyncMock(side_effect=asyncio.CancelledError())
        with patch.object(module, 'FlowClient', return_value=client), \
                patch.object(module.asyncio, 'sleep', delay):
            with self.assertRaises(asyncio.CancelledError):
                await module.validate_identity('SID=test', 'wanted@example.com', '')
        client._load_flow_frontend_bootstrap.assert_awaited_once()
        delay.assert_awaited_once_with(1)


if __name__ == "__main__":
    unittest.main()
