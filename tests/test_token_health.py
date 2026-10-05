import asyncio
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from src.core.database import Database
from src.core.models import Token
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
                return_value={"success": True, "session_token": "recovered-session"},
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
        self.assertEqual(result.st, "recovered-session")
        self.assertEqual(result.credits, 123)
        self.protocol_login.assert_awaited_once()
        self.assertTrue(self.manager._has_recent_at_validation(self.token_id))
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
        self.assertIsNotNone(await self.manager.ensure_valid_token(result))
        self.assertEqual(self.flow._current_rpc.await_count, 4)

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
        self.assertIn("traffic restriction", self.manager.get_last_validation_error(self.token_id))

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
        self.assertFalse(self.manager._has_recent_at_validation(
            self.token_id, proxy_url=returned.proxy_url, token=returned,
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
        self.flow._current_rpc.side_effect = [[123], RuntimeError("HTTP 503")]
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
