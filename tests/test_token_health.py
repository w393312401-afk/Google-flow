import asyncio
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

from src.core.config import config
from src.core.account_operation_context import account_error_reason
from src.core.database import Database
from src.core.models import Token
from src.services.captcha_errors import BrowserCaptchaError
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager


TRAFFIC_ERROR = (
    "Flow frontend RPC rejected: rpc=nzlxg, "
    "error=PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC"
)
AUTH_ERROR = "Flow 登录认证失败 (rpc=nzlxg, code=401)"


class TokenHealthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db = Database(db_path=f"{self.temp_dir.name}/flow.db")
        await self.db.init_db()
        self.token_id = await self.db.add_token(
            Token(
                st="frontend-test-session",
                at=FlowClient.FRONTEND_ACCESS_TOKEN,
                at_expires=datetime.now(timezone.utc) + timedelta(minutes=55),
                email="health@example.com",
                google_cookies="OSID=secret-osid; SID=secret-sid",
                protocol_mode="protocol",
                auto_refresh_enabled=False,
                credits=77,
                last_st_refresh_result="previous ST result",
            )
        )
        proxy = Mock()
        proxy.get_request_proxy_url = AsyncMock(return_value=None)
        self.flow = FlowClient(proxy_manager=proxy, db=self.db)
        # Exercise the real current Flow get_credits / st_to_at methods while
        # replacing their network boundary. No browser or paid request is made.
        self.flow._current_rpc = AsyncMock(return_value=[123])
        self.flow.st_to_at = AsyncMock(wraps=self.flow.st_to_at)
        self.manager = TokenManager(self.db, self.flow)
        self.monotonic = Mock(return_value=1000.0)
        self.enterContext(patch(
            "src.services.token_manager.time", SimpleNamespace(monotonic=self.monotonic),
        ))
        self.protocol_login = self.enterContext(
            patch(
                "src.services.protocol_login.protocol_loginer.login",
                new_callable=AsyncMock,
                return_value={
                    "success": True, "google_cookies": "OSID=new-osid; SID=new-sid",
                    "email": "health@example.com",
                },
            )
        )

    async def token(self):
        return await self.db.get_token(self.token_id)

    async def assert_unavailable_and_active(self):
        self.assertTrue((await self.token()).is_active)
        self.assertFalse(self.manager._has_recent_at_validation(self.token_id))
        self.assertIsNotNone(self.manager.get_last_validation_error(self.token_id))

    async def test_cold_start_non_auth_failure_never_refreshes_or_marks_valid(self):
        failures = (
            (TRAFFIC_ERROR, "PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC"),
            ("Flow 登录认证失败：Google Cookie 已失效 (code=403)", "HTTP 403"),
            ("Flow frontend bootstrap metadata is unavailable", "metadata"),
            ("connection timed out", "network or proxy"),
            ("unexpected response", "unclassified error"),
        )
        original = (await self.token()).model_dump()
        for message, expected in failures:
            with self.subTest(message=message):
                self.monotonic.return_value += 3600
                calls_before = self.flow._current_rpc.await_count
                self.flow._current_rpc.side_effect = RuntimeError(
                    message + " Cookie: OSID=secret-osid; Authorization: Bearer secret-at"
                )
                for _ in range(2):
                    self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
                await self.assert_unavailable_and_active()
                reason = self.manager.get_last_validation_error(self.token_id)
                self.assertIn("AT_CHECK:", reason)
                self.assertIn(expected, reason)
                self.assertNotIn("secret", reason)
                self.assertEqual((await self.token()).model_dump(), original)
                self.assertEqual(self.flow._current_rpc.await_count, calls_before + 1)
                self.flow.st_to_at.assert_not_awaited()
                self.protocol_login.assert_not_awaited()

    async def test_expiring_frontend_token_non_auth_failure_keeps_account(self):
        await self.db.update_token(
            self.token_id, at_expires=datetime.now(timezone.utc) + timedelta(minutes=2)
        )
        self.manager._mark_at_valid(self.token_id)
        self.flow._current_rpc.side_effect = RuntimeError(TRAFFIC_ERROR)
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        await self.assert_unavailable_and_active()
        self.assertIn("AT_REFRESH:", self.manager.get_last_validation_error(self.token_id))
        self.flow.st_to_at.assert_awaited_once()
        self.protocol_login.assert_not_awaited()

    async def test_candidate_at_is_not_committed_or_accepted_when_verification_fails(self):
        self.manager._mark_at_valid(self.token_id)
        self.flow.st_to_at = AsyncMock(
            return_value={
                "access_token": "unverified-candidate",
                "expires": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
            }
        )
        self.flow._current_rpc.side_effect = RuntimeError("HTTP 503: secret response")
        original = (await self.token()).model_dump()
        with patch("src.services.token_manager.record_token_refresh") as metric:
            self.assertFalse(await self.manager._refresh_at(self.token_id))
        await self.assert_unavailable_and_active()
        self.assertEqual((await self.token()).model_dump(), original)
        self.assertIn("AT_VERIFY:", self.manager.get_last_validation_error(self.token_id))
        self.protocol_login.assert_not_awaited()
        metric.assert_called_once_with("at", "failure")

    def test_structured_http_status_overrides_untrusted_exception_text(self):
        for field in ("status_code", "response"):
            for status in (401, 403, 500, 503):
                with self.subTest(field=field, status=status):
                    failure = RuntimeError("UNAUTHENTICATED HTTP 401 secret-cookie private upstream body")
                    setattr(failure, field, status if field == "status_code" else SimpleNamespace(status_code=status))
                    reason = self.manager._safe_health_error("AT_REFRESH", failure)
                    if status == 401:
                        self.assertEqual(reason, "AT_REFRESH: credentials rejected (UNAUTHENTICATED)")
                    else:
                        self.assertEqual(reason, f"AT_REFRESH: upstream unavailable (HTTP {status})")
                    self.assertEqual(self.manager._is_authentication_failure(failure), status == 401)
                    self.assertNotIn("secret", reason)
                    self.assertNotIn("private", reason)

    def test_fixed_transport_and_browser_recovery_failures_are_never_unclassified(self):
        fixed_transport = self.manager._safe_health_error(
            "AT_REFRESH", RuntimeError("Flow API text request failed: request failed")
        )
        self.assertEqual(fixed_transport, "AT_REFRESH: upstream transport unavailable")
        self.assertEqual(account_error_reason(fixed_transport), "upstream_unavailable")

        cases = (
            (BrowserCaptchaError("navigation", "proxy_connection_failed"),
             "ST_REFRESH: network or proxy unavailable"),
            (BrowserCaptchaError("cookie_binding", "login_credentials_missing"),
             "ST_REFRESH: credential recovery required"),
            (BrowserCaptchaError("browser_acquisition", "browser_closed"),
             "ST_REFRESH: credential recovery unavailable"),
            (RuntimeError("账号浏览器标签页不可用"),
             "ST_REFRESH: credential recovery unavailable"),
            (RuntimeError("Flow 页面未返回已登录账号，请重新同步 Google Cookies"),
             "ST_REFRESH: credential recovery required"),
        )
        for failure, expected in cases:
            with self.subTest(failure=type(failure).__name__, expected=expected):
                reason = self.manager._safe_health_error("ST_REFRESH", failure)
                self.assertEqual(reason, expected)
                self.assertNotIn("unclassified", reason)

    async def test_auth_root_survives_network_failure_during_recovery(self):
        self.flow._current_rpc.side_effect = RuntimeError(AUTH_ERROR)
        self.protocol_login.return_value = {
            "success": False,
            "error": "Flow API text request failed: connection unavailable",
        }

        self.assertFalse(await self.manager._refresh_at(self.token_id))

        final_reason = self.manager.get_last_validation_error(self.token_id)
        self.assertEqual(final_reason, "AT_REFRESH: credential recovery required")
        self.assertEqual(self.manager._last_at_refresh_error[self.token_id], final_reason)
        self.assertEqual(
            self.manager._last_st_refresh_error[self.token_id],
            "ST_REFRESH: network or proxy unavailable",
        )
        self.assertEqual(account_error_reason(final_reason), "credential_recovery_required")
        self.assertNotIn("network or proxy", final_reason)
        self.assertTrue((await self.token()).is_active)
        self.assertEqual(self.manager.get_validation_cooldown_reason(await self.token()), final_reason)

    async def test_google_login_redirect_reaches_recovery_without_unclassified_error(self):
        # Exercise the real frontend transport, current RPC and TokenManager;
        # only the HTTP session and protocol login boundary are replaced.
        del self.flow._current_rpc
        session = AsyncMock()
        session.__aenter__.return_value = session
        session.get.return_value = SimpleNamespace(
            status_code=200,
            url="https://accounts.google.com/v3/signin/identifier?continue=test-secret-url",
            text="test-secret-login-page",
        )
        self.protocol_login.return_value = {"success": False, "error": "HTTP 503 test-secret"}
        with patch("src.services.flow_frontend.AsyncSession", return_value=session):
            self.assertFalse(await self.manager._refresh_at(self.token_id))
        self.assertEqual(self.manager.get_last_validation_error(self.token_id),
                         "AT_REFRESH: credential recovery required")
        self.protocol_login.assert_awaited_once()
        session.get.assert_awaited_once()
        await self.assert_unavailable_and_active()
        audit = await self.db.get_account_operation_logs(token_id=self.token_id, page_size=100)
        self.assertNotIn("test-secret", str(audit))
        self.assertTrue(any(row["details"].get("auth_evidence") == "login_redirect"
                            for row in audit["items"]))

    async def test_at_check_auth_root_survives_refresh_transport_failure_and_cools_down(self):
        for failure in (TimeoutError(), RuntimeError("HTTP 503 private-response"), RuntimeError(TRAFFIC_ERROR)):
            with self.subTest(failure=type(failure).__name__, message=str(failure)):
                self.monotonic.return_value += 3600
                self.flow._current_rpc.reset_mock()
                self.flow._current_rpc.side_effect = [RuntimeError(AUTH_ERROR), failure]
                self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
                final_reason = "AT_REFRESH: credential recovery required"
                self.assertEqual(self.manager.get_last_validation_error(self.token_id), final_reason)
                self.assertEqual(self.manager.get_validation_cooldown_reason(await self.token()), final_reason)
                # Queued requests must not retry the broken recovery transport.
                self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
                self.assertEqual(self.flow._current_rpc.await_count, 2)
                self.protocol_login.assert_not_awaited()
                await self.assert_unavailable_and_active()
                audit = await self.db.get_account_operation_logs(
                    token_id=self.token_id, operation="health_check", page_size=100,
                )
                failures = {row["reason"] for row in audit["items"] if row["status"] == "failed"}
                self.assertIn("credentials_rejected", failures)
                self.assertIn("credential_recovery_required", failures)
                self.assertNotIn("private-response", str(audit))

    async def test_replaced_credentials_do_not_inherit_previous_at_check_auth_root(self):
        calls = 0

        async def refresh_with_replaced_cookie(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError(AUTH_ERROR)
            await self.db.update_token(self.token_id, google_cookies="OSID=new-session; SID=new-account")
            raise TimeoutError()

        self.flow._current_rpc.side_effect = refresh_with_replaced_cookie
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        outcome = self.manager.consume_validation_outcome(self.token_id)
        self.assertEqual(outcome.reason, "AT_REFRESH: network or proxy unavailable")
        self.assertNotEqual(outcome.identity, self.manager.health_identity(await self.token()))
        self.assertIsNone(self.manager.get_validation_cooldown_reason(await self.token()))
        self.assertTrue((await self.token()).is_active)

    async def test_prior_attempt_auth_error_does_not_taint_new_transport_failure(self):
        await self.db.update_token(self.token_id, at_expires=datetime.now(timezone.utc))
        self.manager._last_at_refresh_error[self.token_id] = "AT_CHECK: credentials rejected (UNAUTHENTICATED)"
        self.flow._current_rpc.side_effect = TimeoutError()
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertEqual(self.manager.get_last_validation_error(self.token_id),
                         "AT_REFRESH: network or proxy unavailable")
        self.assertTrue((await self.token()).is_active)

    async def test_periodic_protocol_auth_root_survives_browser_transport_failure(self):
        await self.db.update_token(self.token_id, auto_refresh_enabled=True)
        self.protocol_login.return_value = {"success": False, "error": AUTH_ERROR}
        browser = SimpleNamespace(refresh_google_cookies=AsyncMock(
            side_effect=BrowserCaptchaError("navigation", "proxy_connection_failed"),
        ))
        browser_module = SimpleNamespace(BrowserCaptchaService=SimpleNamespace(
            get_instance=AsyncMock(return_value=browser),
        ))
        with patch.object(type(config), "captcha_method", new_callable=PropertyMock, return_value="browser"), \
             patch.dict("sys.modules", {"src.services.browser_captcha": browser_module}):
            await self.manager._refresh_protocol_token(await self.token(), datetime.now(timezone.utc))
        reason = "ST_REFRESH: credential recovery required"
        # The rejected page/browser renewal keeps its own root cause, while a
        # separately successful current RPC proves this AT remains usable.
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
        self.assertEqual(self.manager._last_st_refresh_error[self.token_id], reason)
        self.assertEqual((await self.token()).last_st_refresh_result, reason)
        self.protocol_login.assert_awaited_once()
        browser.refresh_google_cookies.assert_awaited_once()
        self.flow._current_rpc.assert_awaited_once()
        self.assertIsNotNone(await self.manager.ensure_valid_token(await self.token()))
        audit = await self.db.get_account_operation_logs(
            token_id=self.token_id, operation="refresh_st", page_size=100,
        )
        failed = {(row["stage"], row["reason"]) for row in audit["items"] if row["status"] == "failed"}
        self.assertIn(("page_probe", "credentials_rejected"), failed)
        self.assertIn(("ST_REFRESH", "network_or_proxy_unavailable"), failed)

    async def test_periodic_protocol_403_with_browser_timeout_does_not_claim_auth_rejection(self):
        await self.db.update_token(self.token_id, auto_refresh_enabled=True)
        self.protocol_login.return_value = {"success": False, "error": "HTTP 403"}
        browser = SimpleNamespace(refresh_google_cookies=AsyncMock(side_effect=TimeoutError()))
        browser_module = SimpleNamespace(BrowserCaptchaService=SimpleNamespace(
            get_instance=AsyncMock(return_value=browser),
        ))
        with patch.object(type(config), "captcha_method", new_callable=PropertyMock, return_value="browser"), \
             patch.dict("sys.modules", {"src.services.browser_captcha": browser_module}):
            await self.manager._refresh_protocol_token(await self.token(), datetime.now(timezone.utc))
        self.assertEqual((await self.token()).last_st_refresh_result,
                         "ST_REFRESH: network or proxy unavailable")
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
        self.flow._current_rpc.assert_awaited_once()
        self.assertIsNotNone(await self.manager.ensure_valid_token(await self.token()))

    async def test_empty_network_exceptions_keep_account_active_without_committing_credentials(self):
        original = (await self.token()).model_dump()
        for failure in (TimeoutError(), ConnectionError()):
            with self.subTest(error_type=type(failure).__name__):
                self.flow._current_rpc.side_effect = failure
                self.assertFalse(await self.manager._refresh_at(self.token_id))
                self.assertEqual(self.manager.get_last_validation_error(self.token_id),
                                 "AT_REFRESH: network or proxy unavailable")
                await self.assert_unavailable_and_active()
                self.assertEqual((await self.token()).model_dump(), original)
        self.protocol_login.assert_not_awaited()

    async def test_exact_invalid_balance_responses_keep_fixed_safe_reason_and_backoff(self):
        original = (await self.token()).model_dump()
        for message in ("Flow frontend RPC returned no payload: rpc=nzlxg", "Flow credits RPC response invalid"):
            with self.subTest(message=message):
                self.monotonic.return_value += 3600
                self.flow._current_rpc.side_effect = RuntimeError(message)
                calls_before = self.flow._current_rpc.await_count
                for _ in range(2):
                    self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
                self.assertEqual(self.manager.get_last_validation_error(self.token_id),
                                 "AT_CHECK: upstream validation response invalid")
                self.assertEqual(self.flow._current_rpc.await_count, calls_before + 1)
                self.assertEqual((await self.token()).model_dump(), original)
                await self.assert_unavailable_and_active()
                audit = await self.db.get_account_operation_logs(
                    token_id=self.token_id, operation="health_check", page_size=100,
                )
                latest = audit["items"][:2]
                self.assertEqual(
                    {(row["status"], row["reason"]) for row in latest},
                    {("failed", "upstream_unavailable"), ("cooldown", "validation_backoff")},
                )
                cooldown = next(row for row in latest if row["status"] == "cooldown")
                self.assertEqual(cooldown["details"]["retry_reason"], "upstream_unavailable")
        self.protocol_login.assert_not_awaited()
        other_rpc = self.manager._safe_health_error("AT_REFRESH", RuntimeError(
            "Flow frontend RPC returned no payload: rpc=jHPbke"))
        self.assertIn("unclassified error", other_rpc)

    async def test_frontend_refresh_reuses_one_real_balance_validation_including_zero(self):
        for balance in (0, 123):
            with self.subTest(balance=balance):
                self.flow._current_rpc.return_value = [balance]
                self.flow._current_rpc.reset_mock()
                self.assertTrue(await self.manager._refresh_at(self.token_id))
                self.flow._current_rpc.assert_awaited_once()
                token = await self.token()
                self.assertEqual(token.at, FlowClient.FRONTEND_ACCESS_TOKEN)
                self.assertEqual(token.credits, balance)
                self.assertEqual(token.user_paygate_tier,
                                 "PAYGATE_TIER_ONE" if balance else "PAYGATE_TIER_NOT_PAID")
                self.assertTrue(self.manager._has_recent_at_validation(self.token_id))

    async def test_missing_or_invalid_frontend_balance_and_legacy_at_still_require_verification(self):
        cases = [
            {"access_token": FlowClient.FRONTEND_ACCESS_TOKEN},
            *({"access_token": FlowClient.FRONTEND_ACCESS_TOKEN, "credits": balance}
              for balance in (None, True, -1, "123", float("nan"), float("inf"))),
            {"access_token": "legacy-candidate", "credits": 999},
        ]
        for result in cases:
            with self.subTest(result=result):
                self.flow.st_to_at = AsyncMock(return_value=result)
                self.flow._current_rpc.reset_mock()
                self.assertTrue(await self.manager._refresh_at(self.token_id))
                self.flow._current_rpc.assert_awaited_once()
                self.assertEqual((await self.token()).credits, 123)

    async def test_invalid_frontend_credit_response_cannot_update_expiry_or_balance(self):
        original = (await self.token()).model_dump()
        self.flow._current_rpc.return_value = []
        self.assertFalse(await self.manager._refresh_at(self.token_id))
        self.assertEqual(self.manager.get_last_validation_error(self.token_id),
                         "AT_REFRESH: upstream validation response invalid")
        self.assertEqual((await self.token()).model_dump(), original)
        await self.assert_unavailable_and_active()
        self.flow._current_rpc.assert_awaited_once()

    async def test_cold_start_auth_failure_recovers_and_caches_success(self):
        self.flow._current_rpc.side_effect = [
            RuntimeError(AUTH_ERROR),
            RuntimeError(AUTH_ERROR),
            [123],
            [123],
        ]
        result = await self.manager.ensure_valid_token(await self.token())
        self.assertIsNotNone(result)
        self.assertTrue(result.is_active)
        self.assertTrue(result.st.startswith("frontend-"))
        self.assertEqual(result.google_cookies, "OSID=new-osid; SID=new-sid")
        self.assertEqual(result.credits, 123)
        self.protocol_login.assert_awaited_once()
        self.assertTrue(self.manager._has_recent_at_validation(self.token_id))
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
        self.assertIsNotNone(await self.manager.ensure_valid_token(result))
        self.assertEqual(self.flow._current_rpc.await_count, 3)

    async def test_explicit_auth_rejection_after_recovery_disables(self):
        self.flow._current_rpc.side_effect = RuntimeError(AUTH_ERROR)
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.protocol_login.assert_awaited_once()
        self.assertFalse((await self.token()).is_active)
        self.assertFalse(self.manager._has_recent_at_validation(self.token_id))
        self.assertIn("UNAUTHENTICATED", self.manager.get_last_validation_error(self.token_id))

    async def test_debug_disabled_still_logs_auth_evidence_and_final_decision_safely(self):
        cases = (
            ("HTTP 401", "http_401"),
            ("UNAUTHENTICATED", "unauthenticated"),
            ("Google Cookies 不完整，缺少", "missing_cookie"),
            ("页面已跳转到 Google 登录", "login_redirect"),
        )
        for error, evidence in cases:
            with self.subTest(evidence=evidence):
                await self.db.update_token(self.token_id, is_active=True)
                self.flow._current_rpc.side_effect = RuntimeError(
                    error + "; health@example.com https://private.example OSID=secret-osid"
                )
                with patch("src.core.logger.config", SimpleNamespace(debug_enabled=False)):
                    with self.assertLogs("debug_logger", level="WARNING") as logs:
                        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
                output = "\n".join(logs.output)
                self.assertIn(f"stage=AT_CHECK auth_evidence={evidence}", output)
                self.assertIn(f"stage=AT_REFRESH auth_evidence={evidence}", output)
                self.assertIn("decision=recover", output)
                self.assertIn("decision=disabled", output)
                self.assertFalse((await self.token()).is_active)
                for private in ("health@example.com", "private.example", "secret-osid", "Token "):
                    self.assertNotIn(private, output)

    async def test_debug_disabled_nonauth_failure_logs_unavailable_without_auth_claim(self):
        self.flow._current_rpc.side_effect = RuntimeError("HTTP 403 secret-upstream-body")
        with patch("src.core.logger.config", SimpleNamespace(debug_enabled=False)):
            with self.assertLogs("debug_logger", level="WARNING") as logs:
                self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertEqual(len(logs.output), 1)
        self.assertIn("stage=AT_CHECK auth_evidence=none", logs.output[0])
        self.assertIn("reason=upstream unavailable (HTTP 403) decision=unavailable", logs.output[0])
        self.assertNotIn("secret", logs.output[0])
        await self.assert_unavailable_and_active()
        self.flow.st_to_at.assert_not_awaited()
        self.protocol_login.assert_not_awaited()

    async def test_auth_recovery_then_traffic_failure_keeps_account(self):
        self.flow._current_rpc.side_effect = [
            RuntimeError(AUTH_ERROR), RuntimeError(AUTH_ERROR), RuntimeError(TRAFFIC_ERROR)
        ]
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.protocol_login.assert_awaited_once()
        await self.assert_unavailable_and_active()
        self.assertEqual(
            self.manager.get_last_validation_error(self.token_id),
            "AT_REFRESH: credential recovery required",
        )
        self.assertIn("traffic restriction", self.manager._last_st_refresh_error[self.token_id])

    async def test_temporary_protocol_failure_cools_down_same_cookie(self):
        self.flow._current_rpc.side_effect = RuntimeError(AUTH_ERROR)
        self.protocol_login.return_value = {
            "success": False, "error": "HTTP 503: OSID=secret-osid"
        }
        for _ in range(2):
            self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.protocol_login.assert_awaited_once()
        await self.assert_unavailable_and_active()
        self.assertEqual(
            self.manager.get_last_validation_error(self.token_id),
            "AT_REFRESH: credential recovery required",
        )
        self.assertEqual(
            self.manager._last_st_refresh_error[self.token_id],
            "ST_REFRESH: upstream unavailable (HTTP 503)",
        )
        self.assertNotIn("secret", (await self.token()).last_st_refresh_result)
        await self.db.update_token(self.token_id, google_cookies="OSID=new-osid; SID=new-sid")
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertEqual(self.protocol_login.await_count, 2)

    async def test_successful_cold_check_clears_failure_and_preserves_st_history(self):
        self.flow._current_rpc.side_effect = RuntimeError(TRAFFIC_ERROR)
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.flow._current_rpc.side_effect = None
        self.monotonic.return_value += 301
        result = await self.manager.ensure_valid_token(await self.token())
        self.assertEqual(result.credits, 123)
        self.assertEqual(result.last_st_refresh_result, "previous ST result")
        self.assertTrue(self.manager._has_recent_at_validation(self.token_id))
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
        self.assertIsNotNone(await self.manager.ensure_valid_token(result))
        self.assertEqual(self.flow._current_rpc.await_count, 2)
        self.flow.st_to_at.assert_not_awaited()
        self.protocol_login.assert_not_awaited()

    async def test_validation_backoff_serializes_concurrent_failed_cold_checks(self):
        self.flow._current_rpc.side_effect = RuntimeError(TRAFFIC_ERROR)
        original = (await self.token()).model_dump()
        results = await asyncio.gather(*[
            self.manager.ensure_valid_token(await self.token()) for _ in range(12)
        ])
        self.assertEqual(results, [None] * 12)
        self.flow._current_rpc.assert_awaited_once()
        self.assertEqual((await self.token()).model_dump(), original)
        self.assertIn("traffic restriction", self.manager.get_validation_cooldown_reason(await self.token()))
        self.flow._current_rpc.side_effect = None
        self.monotonic.return_value += 299
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.flow._current_rpc.assert_awaited_once()
        self.monotonic.return_value += 1
        result = await self.manager.ensure_valid_token(await self.token())
        self.assertEqual(result.credits, 123)
        self.assertEqual(self.flow._current_rpc.await_count, 2)
        self.assertIsNone(self.manager.get_validation_cooldown_reason(result))

    async def test_changed_cookie_or_proxy_can_retry_without_waiting_for_old_backoff(self):
        self.flow._current_rpc.side_effect = RuntimeError("HTTP 503")
        for field, value in (
            ("google_cookies", "OSID=repaired-osid; SID=repaired-sid"),
            ("proxy_url", "http://repaired-proxy:8080"),
        ):
            with self.subTest(field=field):
                self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
                calls_before = self.flow._current_rpc.await_count
                self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
                self.assertEqual(self.flow._current_rpc.await_count, calls_before)
                await self.db.update_token(self.token_id, **{field: value})
                self.assertIsNone(self.manager.get_validation_cooldown_reason(await self.token()))
                self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
                self.assertEqual(self.flow._current_rpc.await_count, calls_before + 1)
                self.assertTrue((await self.token()).is_active)

    async def test_explicit_enable_rechecks_temporary_validation_failure(self):
        self.flow._current_rpc.side_effect = RuntimeError("HTTP 503")
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.flow._current_rpc.side_effect = None
        await self.manager.enable_token(self.token_id)
        self.assertIsNotNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertEqual(self.flow._current_rpc.await_count, 2)

    async def test_generic_unusual_activity_has_same_non_auth_backoff(self):
        self.flow._current_rpc.side_effect = RuntimeError("PUBLIC_ERROR_UNUSUAL_ACTIVITY")
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertIn("PUBLIC_ERROR_UNUSUAL_ACTIVITY", self.manager.get_validation_cooldown_reason(await self.token()))
        self.monotonic.return_value += 60
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.flow._current_rpc.assert_awaited_once()
        self.assertTrue((await self.token()).is_active)
        self.protocol_login.assert_not_awaited()

    async def test_late_failed_check_cannot_cool_down_repaired_credentials(self):
        async def fail_old_cookie(**kwargs):
            await self.db.update_token(self.token_id, google_cookies="SID=repaired-during-check")
            raise RuntimeError("HTTP 503 private old response")

        self.flow._current_rpc.side_effect = fail_old_cookie
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertIsNone(self.manager.get_validation_cooldown_reason(await self.token()))
        self.flow._current_rpc.side_effect = None
        self.assertIsNotNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertEqual(self.flow._current_rpc.await_count, 2)

    async def test_late_successful_check_does_not_validate_unchecked_new_cookie(self):
        async def validate_old_cookie(**kwargs):
            await self.db.update_token(self.token_id, google_cookies="SID=repaired-during-check")
            return [123]

        self.flow._current_rpc.side_effect = validate_old_cookie
        returned = await self.manager.ensure_valid_token(await self.token())
        self.assertIsNone(returned)
        current = await self.token()
        self.assertFalse(self.manager._has_recent_at_validation(
            self.token_id, proxy_url=current.proxy_url, token=current,
        ))
        self.flow._current_rpc.side_effect = None
        self.assertIsNotNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertEqual(self.flow._current_rpc.await_count, 2)

    async def test_concurrent_auth_failures_recover_once_then_stop_using_disabled_account(self):
        self.flow._current_rpc.side_effect = RuntimeError(AUTH_ERROR)
        results = await asyncio.gather(*[
            self.manager.ensure_valid_token(await self.token()) for _ in range(12)
        ])
        self.assertEqual(results, [None] * 12)
        self.protocol_login.assert_awaited_once()
        self.assertEqual(self.flow._current_rpc.await_count, 3)
        self.assertFalse((await self.token()).is_active)
        calls_before = self.flow._current_rpc.await_count
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertEqual(self.flow._current_rpc.await_count, calls_before)

    async def test_periodic_refresh_does_not_preserve_valid_cache_on_failed_verification(self):
        await self.db.update_token(self.token_id, auto_refresh_enabled=True)
        original = await self.token()
        self.manager._mark_at_valid(self.token_id)
        self.flow._current_rpc.side_effect = RuntimeError("HTTP 503")
        await self.manager._refresh_protocol_token(original, datetime.now(timezone.utc))
        await self.assert_unavailable_and_active()
        self.assertEqual((await self.token()).at_expires, original.at_expires)
        self.assertIn("HTTP 503", self.manager.get_last_validation_error(self.token_id))

    def test_auth_classifier_requires_specific_evidence(self):
        for message in (AUTH_ERROR, "HTTP Error 401", "UNAUTHENTICATED", "unauthenticated"):
            with self.subTest(message=message):
                self.assertTrue(self.manager._is_authentication_failure(message))
        for message in (
            "request 40123 failed", "HTTP 403", "Flow 登录认证失败 (code=403)",
            "unknown", "UNAUTHENTICATED_EXTRA", TRAFFIC_ERROR,
        ):
            with self.subTest(message=message):
                self.assertFalse(self.manager._is_authentication_failure(message))


if __name__ == "__main__":
    unittest.main()
