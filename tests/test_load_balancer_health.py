import ast
import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from src.core.database import Database
from src.core.models import Token
from src.services.flow_client import FlowClient
from src.services.captcha_errors import BrowserCaptchaError
from src.services.flow_frontend import FlowRPCRejected
from src.services.generation_handler import GenerationHandler, MODEL_CONFIG
from src.services.load_balancer import LoadBalancer
from src.services.token_manager import TokenManager


TRAFFIC_ERROR = "PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC"


def unsubmitted_browser_error(stage, reason):
    """Mirror the native runner's explicit pre-arming submission annotation."""
    failure = BrowserCaptchaError(stage, reason)
    failure.submission_pending = False
    return failure


def runtime_browser_failure_methods():
    """Run the real error producers without importing/installing a browser."""
    source = Path(__file__).parents[1] / "src/services/browser_captcha.py"
    browser = next(node for node in ast.parse(source.read_text()).body
                   if isinstance(node, ast.ClassDef) and node.name == "TokenBrowser")
    browser.body = [method for method in browser.body if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and method.name in {"_wait_for_flow_editor", "_captcha_failure", "_classify_captcha_error"}]
    namespace = {"asyncio": asyncio, "BrowserCaptchaError": BrowserCaptchaError}
    exec(compile(ast.Module(body=[browser], type_ignores=[]), str(source), "exec"), namespace)
    return namespace["TokenBrowser"]()


class LoadBalancerHealthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db = Database(db_path=f"{self.temp_dir.name}/flow.db")
        await self.db.init_db()
        self.account_count = 0
        self.failures = {}
        self.flow = FlowClient(proxy_manager=Mock(), db=self.db)
        self.flow._current_rpc = AsyncMock(side_effect=self.rpc)
        self.manager = TokenManager(self.db, self.flow)
        self.balancer = LoadBalancer(self.manager)
        self.monotonic = Mock(return_value=1000.0)
        for module in ("load_balancer", "token_manager"):
            self.enterContext(patch(
                f"src.services.{module}.time", SimpleNamespace(monotonic=self.monotonic),
            ))
        self.enterContext(
            patch(
                "src.services.load_balancer.config",
                SimpleNamespace(captcha_method="browser", call_logic_mode="polling"),
            )
        )

    async def rpc(self, **kwargs):
        failure = self.failures.get(kwargs["token_id"])
        if failure:
            raise RuntimeError(failure + "; Cookie: OSID=private-cookie")
        return [123]

    async def add_token(self, **overrides):
        self.account_count += 1
        values = {
            "st": f"private-session-{self.account_count}",
            "at": FlowClient.FRONTEND_ACCESS_TOKEN,
            "at_expires": datetime.now(timezone.utc) + timedelta(minutes=55),
            "email": f"private-account-{self.account_count}@example.com",
            "google_cookies": "OSID=private-cookie; SID=private-sid",
            "user_paygate_tier": "PAYGATE_TIER_ONE",
            "auto_refresh_enabled": False,
        }
        values.update(overrides)
        return await self.db.add_token(Token(**values))

    async def test_selection_failure_exposes_deduplicated_safe_health_reason(self):
        first = await self.add_token()
        second = await self.add_token()
        self.failures = {first: TRAFFIC_ERROR, second: TRAFFIC_ERROR}
        self.assertIsNone(await self.balancer.select_token(for_image_generation=True))
        reason = await self.balancer.get_unavailable_reason(for_image_generation=True)
        self.assertIn("均未通过上游校验", reason)
        self.assertEqual(reason.count(TRAFFIC_ERROR), 1)
        self.assertNotIn("private", reason)
        self.assertNotIn("@", reason)
        self.assertEqual(self.flow._current_rpc.await_count, 2)

    async def test_different_failures_are_preserved_in_aggregate(self):
        first = await self.add_token()
        second = await self.add_token()
        self.failures = {first: TRAFFIC_ERROR, second: "HTTP 403"}
        self.assertIsNone(await self.balancer.select_token(for_video_generation=True))
        reason = await self.balancer.get_unavailable_reason(for_video_generation=True)
        self.assertIn(TRAFFIC_ERROR, reason)
        self.assertIn("HTTP 403", reason)

    async def test_last_candidate_disabled_retains_only_this_selection_reason(self):
        token_id = await self.add_token()
        self.failures[token_id] = "HTTP 401"
        self.manager._try_refresh_st = AsyncMock(return_value="recovered-session")
        self.assertIsNone(await self.balancer.select_token(for_video_generation=True, model="test-2k"))
        self.assertFalse((await self.db.get_token(token_id)).is_active)
        reason = await self.balancer.get_unavailable_reason(for_video_generation=True, model="test-2k")
        self.assertIn("UNAUTHENTICATED", reason)
        self.assertNotIn("private", reason)
        self.assertIsNone(await self.balancer.get_unavailable_reason(for_video_generation=True, model="test-2k"))

    async def test_disabled_last_candidate_reason_reaches_generation_503_and_request_log(self):
        token_id = await self.add_token()
        self.failures[token_id] = "HTTP 401"
        self.manager._try_refresh_st = AsyncMock(return_value="recovered-session")
        handler = GenerationHandler.__new__(GenerationHandler)
        handler.flow_client = self.flow
        handler.token_manager = self.manager
        handler.load_balancer = self.balancer
        handler._log_request = AsyncMock()
        handler._update_request_log_progress = AsyncMock()
        model = next(
            name for name, cfg in MODEL_CONFIG.items()
            if cfg["type"] == "image" and not cfg.get("upsample")
        )
        responses = [response async for response in handler.handle_generation(model, "test")]
        self.assertFalse((await self.db.get_token(token_id)).is_active)
        error = json.loads(responses[0])["error"]
        self.assertIn("UNAUTHENTICATED", error["message"])
        self.assertNotIn("private", error["message"])
        self.assertEqual(handler._log_request.await_args.kwargs["status_code"], 503)
        self.assertEqual(handler._log_request.await_args.kwargs["response_data"]["error"], error["message"])
        self.assertIsNone(await self.balancer.select_token(for_video_generation=True, model="test-2k"))
        self.assertIsNone(await self.balancer.get_unavailable_reason(for_video_generation=True, model="test-2k"))

    async def test_failure_snapshot_cannot_cross_capability_model_or_child_task(self):
        token_id = await self.add_token()
        self.failures[token_id] = TRAFFIC_ERROR
        for query in ({"for_video_generation": True}, {"for_image_generation": True, "model": "test-2k"}):
            self.assertIsNone(await self.balancer.select_token(for_image_generation=True))
            self.assertIsNone(await self.balancer.get_unavailable_reason(**query))
            self.assertIsNone(await self.balancer.get_unavailable_reason(for_image_generation=True))
        self.assertIsNone(await self.balancer.select_token(for_image_generation=True))
        child_reason = await asyncio.create_task(
            self.balancer.get_unavailable_reason(for_image_generation=True)
        )
        self.assertIsNone(child_reason)
        self.assertIn(TRAFFIC_ERROR, await self.balancer.get_unavailable_reason(for_image_generation=True))

    async def test_concurrent_selections_keep_their_own_failure_reason(self):
        image_id = await self.add_token(video_enabled=False)
        video_id = await self.add_token(image_enabled=False)
        self.failures = {image_id: TRAFFIC_ERROR, video_id: "HTTP 403"}
        barrier = asyncio.Barrier(2)

        async def select_and_explain(**flags):
            self.assertIsNone(await self.balancer.select_token(**flags))
            await barrier.wait()
            return await self.balancer.get_unavailable_reason(**flags)

        image_reason, video_reason = await asyncio.gather(
            select_and_explain(for_image_generation=True),
            select_and_explain(for_video_generation=True),
        )
        self.assertIn(TRAFFIC_ERROR, image_reason)
        self.assertNotIn("HTTP 403", image_reason)
        self.assertIn("HTTP 403", video_reason)
        self.assertNotIn(TRAFFIC_ERROR, video_reason)

    async def test_capacity_exclusions_and_failed_reservations_do_not_report_stale_health(self):
        token_id = await self.add_token()
        self.failures[token_id] = TRAFFIC_ERROR
        self.assertIsNone(await self.balancer.select_token(for_image_generation=True))
        concurrency = SimpleNamespace(
            can_use_image=AsyncMock(return_value=False),
            get_image_inflight=AsyncMock(return_value=0),
            get_image_remaining=AsyncMock(return_value=1),
            acquire_image=AsyncMock(return_value=False),
        )
        self.balancer.concurrency_manager = concurrency
        self.assertIsNone(await self.balancer.select_token(for_image_generation=True))
        self.assertIsNone(await self.balancer.get_unavailable_reason(for_image_generation=True))

        # Another capable account being busy also prevents an all-health-failed claim.
        busy_id = await self.add_token()
        concurrency.can_use_image.side_effect = lambda candidate: candidate != busy_id
        self.assertIsNone(await self.balancer.select_token(for_image_generation=True))
        self.assertIsNone(await self.balancer.get_unavailable_reason(for_image_generation=True))

        self.failures.clear()
        concurrency.can_use_image.side_effect = None
        concurrency.can_use_image.return_value = True
        self.assertIsNone(await self.balancer.select_token(for_image_generation=True, reserve=True))
        self.assertIsNone(await self.balancer.get_unavailable_reason(for_image_generation=True))

    async def test_healthy_candidate_does_not_report_all_accounts_failed(self):
        failed = await self.add_token()
        healthy = await self.add_token()
        self.failures[failed] = TRAFFIC_ERROR
        result = await self.balancer.select_token(for_image_generation=True)
        self.assertEqual(result.id, healthy)
        self.assertIsNotNone(self.manager.get_last_validation_error(failed))
        self.assertIsNone(await self.balancer.get_unavailable_reason(for_image_generation=True))

    async def test_unchecked_candidate_does_not_report_all_accounts_failed(self):
        failed = await self.add_token()
        await self.add_token()
        self.failures[failed] = TRAFFIC_ERROR
        self.assertIsNone(await self.manager.ensure_valid_token(await self.db.get_token(failed)))
        self.assertIsNone(await self.balancer.get_unavailable_reason(for_image_generation=True))
        self.assertEqual(self.flow._current_rpc.await_count, 1)

    async def test_tier_and_capability_excluded_accounts_do_not_mask_failure(self):
        failed = await self.add_token()
        await self.add_token(user_paygate_tier="PAYGATE_TIER_NOT_PAID")
        await self.add_token(image_enabled=False)
        self.failures[failed] = "Flow frontend bootstrap metadata is unavailable"
        self.assertIsNone(
            await self.balancer.select_token(for_image_generation=True, model="test-2k")
        )
        reason = await self.balancer.get_unavailable_reason(
            for_image_generation=True, model="test-2k"
        )
        self.assertIn("metadata", reason)
        self.assertEqual(self.flow._current_rpc.await_count, 1)

    async def test_existing_tier_and_capability_messages_take_precedence(self):
        await self.add_token(image_enabled=False, video_enabled=False)
        self.assertIn(
            "需要 Ult 账号",
            await self.balancer.get_unavailable_reason(model="test-4k"),
        )
        for flag, expected in (
            ("for_image_generation", "图片生成功能已全部禁用"),
            ("for_video_generation", "视频生成功能已全部禁用"),
        ):
            self.assertIn(expected, await self.balancer.get_unavailable_reason(**{flag: True}))
        self.flow._current_rpc.assert_not_awaited()

    async def test_manager_without_health_getter_retains_existing_behavior(self):
        token_id = await self.add_token()
        manager = SimpleNamespace(
            get_active_tokens=AsyncMock(return_value=[await self.db.get_token(token_id)])
        )
        self.assertIsNone(
            await LoadBalancer(manager).get_unavailable_reason(for_image_generation=True)
        )

    async def test_mode_failure_routes_video_to_other_account_and_keeps_images_usable(self):
        failed = await self.add_token()
        healthy = await self.add_token()
        first = await self.balancer.select_token(for_video_generation=True)
        self.assertEqual(first.id, failed)
        self.assertTrue(await self.balancer.record_generation_failure(
            failed, unsubmitted_browser_error("native_generation_setup", "mode_failed"),
            for_video_generation=True, token=first,
        ))
        for _ in range(12):
            selected = await self.balancer.select_token(
                for_video_generation=True, track_pending=True,
            )
            self.assertEqual(selected.id, healthy)
            await self.balancer.release_pending(selected.id, for_video_generation=True)
        self.assertEqual(self.balancer._video_pending, {})
        self.assertEqual((await self.balancer.select_token(for_image_generation=True)).id, failed)
        self.assertTrue((await self.db.get_token(failed)).is_active)
        self.assertEqual((await self.db.get_token_stats(failed)).consecutive_error_count, 0)
        self.assertEqual(self.flow._current_rpc.await_count, 2)

    async def test_single_failed_account_reports_cooldown_without_repeated_validation(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        await self.balancer.record_generation_failure(
            token_id, unsubmitted_browser_error("page_loaded", "flow_editor_unavailable"),
            for_video_generation=True, token=token,
        )
        for _ in range(50):
            self.assertIsNone(await self.balancer.select_token(
                for_video_generation=True, model="test-2k", track_pending=True,
            ))
            reason = await self.balancer.get_unavailable_reason(
                for_video_generation=True, model="test-2k",
            )
            self.assertIn("flow_editor_unavailable", reason)
            self.assertIn("临时冷却", reason)
            self.assertNotIn("private", reason)
            self.assertNotIn("上游校验", reason)
        self.assertEqual(self.balancer._video_pending, {})
        self.flow._current_rpc.assert_not_awaited()
        self.assertTrue((await self.db.get_token(token_id)).is_active)

    async def test_cooldown_expires_and_repeat_failures_back_off_with_bound(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        failure = unsubmitted_browser_error("native_generation_setup", "mode_failed")
        expected_delays = (60, 120, 240, 480, 600, 600, 600)
        for delay in expected_delays:
            await self.balancer.record_generation_failure(
                token_id, failure, for_video_generation=True, token=token,
            )
            self.assertIn(f"{delay} 秒", self.balancer.get_generation_cooldown_reason(
                token, for_video_generation=True,
            ))
            self.assertIsNone(await self.balancer.select_token(for_video_generation=True))
            self.monotonic.return_value += delay
            self.assertEqual((await self.balancer.select_token(for_video_generation=True)).id, token_id)
        self.balancer.record_generation_success(token_id, for_image_generation=True, token=token)
        await self.balancer.record_generation_failure(token_id, failure, for_video_generation=True, token=token)
        self.assertIn("600 秒", self.balancer.get_generation_cooldown_reason(token, for_video_generation=True))
        self.balancer.record_generation_success(token_id, for_video_generation=True, token=token)
        self.assertIsNone(self.balancer.get_generation_cooldown_reason(token, for_video_generation=True))
        await self.balancer.record_generation_failure(token_id, failure, for_video_generation=True, token=token)
        self.assertIn("60 秒", self.balancer.get_generation_cooldown_reason(token, for_video_generation=True))

    async def test_changed_identity_retries_and_old_success_cannot_clear_new_route_failure(self):
        token_id = await self.add_token()
        old = await self.db.get_token(token_id)
        failure = unsubmitted_browser_error("native_generation_setup", "mode_failed")
        await self.balancer.record_generation_failure(token_id, failure, for_video_generation=True, token=old)
        await self.db.update_token(token_id, google_cookies="SID=repaired-cookie")
        new = await self.balancer.select_token(for_video_generation=True)
        self.assertEqual(new.id, token_id)
        await self.balancer.record_generation_failure(token_id, failure, for_video_generation=True, token=new)
        self.balancer.record_generation_success(token_id, for_video_generation=True, token=old)
        self.assertIsNotNone(self.balancer.get_generation_cooldown_reason(new, for_video_generation=True))
        self.balancer.record_generation_success(token_id, for_video_generation=True, token=new)
        self.assertIsNone(self.balancer.get_generation_cooldown_reason(new, for_video_generation=True))

    async def test_model_control_failure_is_scoped_to_requested_model(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        await self.balancer.record_generation_failure(
            token_id, unsubmitted_browser_error("native_generation_setup", "model_failed"),
            for_video_generation=True, model="test-2k", token=token,
        )
        self.assertIsNone(await self.balancer.select_token(for_video_generation=True, model="test-2k"))
        self.assertEqual((await self.balancer.select_token(for_video_generation=True, model="another-2k")).id, token_id)

    async def test_confirmed_traffic_rejection_cools_account_for_both_capabilities_safely(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        failure = FlowRPCRejected("private body Cookie: OSID=private-cookie", "eb1hJf", TRAFFIC_ERROR)
        with self.assertLogs("debug_logger", level="WARNING") as logs:
            await self.balancer.record_generation_failure(
                token_id, failure, for_video_generation=True, token=token,
            )
        self.assertNotIn("private", "\n".join(logs.output))
        for flag in ("for_image_generation", "for_video_generation"):
            self.assertIsNone(await self.balancer.select_token(**{flag: True}))
            self.assertIn(TRAFFIC_ERROR, await self.balancer.get_unavailable_reason(**{flag: True}))
        self.assertTrue((await self.db.get_token(token_id)).is_active)
        self.monotonic.return_value += 300
        self.assertEqual((await self.balancer.select_token(for_video_generation=True)).id, token_id)

    async def test_unknown_submission_or_request_errors_do_not_open_generation_circuit(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        pending = BrowserCaptchaError("native_submit", "browser_operation_failed")
        pending.submission_pending = True
        for failure in (
            pending, BrowserCaptchaError("native_submit", "browser_operation_failed"),
            BrowserCaptchaError("native_generation_setup", "mode_failed"),
            unsubmitted_browser_error("native_generation_setup", "invalid_spec"),
            BrowserCaptchaError("native_response", "response_missing"),
            BrowserCaptchaError("private-stage", "private-cookie"),
            unsubmitted_browser_error("native_generation_setup", "private_cookie_failed"),
            RuntimeError(TRAFFIC_ERROR),
            FlowRPCRejected("private", "ogiZ0b", "PERMISSION_DENIED"),
        ):
            with self.subTest(failure=type(failure).__name__):
                self.assertFalse(await self.balancer.record_generation_failure(
                    token_id, failure, for_video_generation=True, token=token,
                ))
        self.assertEqual(self.balancer._generation_cooldowns, {})

    async def test_mixed_browser_cooldown_and_validation_failure_preserve_distinct_reasons(self):
        browser_id = await self.add_token()
        auth_check_id = await self.add_token()
        await self.balancer.record_generation_failure(
            browser_id, unsubmitted_browser_error("native_generation_setup", "mode_failed"),
            for_video_generation=True, token=await self.db.get_token(browser_id),
        )
        self.failures[auth_check_id] = "HTTP 503"
        self.assertIsNone(await self.balancer.select_token(for_video_generation=True))
        reason = await self.balancer.get_unavailable_reason(for_video_generation=True)
        self.assertIn("mode_failed", reason)
        self.assertIn("AT_CHECK", reason)
        self.assertIn("HTTP 503", reason)

    async def test_circuit_opened_during_health_check_releases_pending_candidate(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        started, release = asyncio.Event(), asyncio.Event()

        async def validate(candidate):
            started.set()
            await release.wait()
            return candidate

        self.manager.ensure_valid_token = AsyncMock(side_effect=validate)

        async def select_and_explain():
            selected = await self.balancer.select_token(for_video_generation=True, track_pending=True)
            reason = await self.balancer.get_unavailable_reason(for_video_generation=True)
            return selected, reason

        task = asyncio.create_task(select_and_explain())
        await started.wait()
        self.assertEqual(self.balancer._video_pending, {token_id: 1})
        await self.balancer.record_generation_failure(
            token_id, unsubmitted_browser_error("native_generation_setup", "mode_failed"),
            for_video_generation=True, token=token,
        )
        release.set()
        selected, reason = await task
        self.assertIsNone(selected)
        self.assertIn("mode_failed", reason)
        self.assertEqual(self.balancer._video_pending, {})

    async def test_busy_alternative_prevents_claim_that_all_accounts_are_cooling_down(self):
        failed = await self.add_token()
        busy = await self.add_token()
        await self.balancer.record_generation_failure(
            failed, unsubmitted_browser_error("native_generation_setup", "mode_failed"),
            for_video_generation=True, token=await self.db.get_token(failed),
        )
        self.balancer.concurrency_manager = SimpleNamespace(
            can_use_video=AsyncMock(side_effect=lambda token_id: token_id != busy),
        )
        self.assertIsNone(await self.balancer.select_token(for_video_generation=True))
        self.assertIsNone(await self.balancer.get_unavailable_reason(for_video_generation=True))

    async def test_editor_and_submit_preparation_failures_open_reversible_ui_circuit(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        for stage, reason in (
            ("native_submit_prepare", "submit_control_missing"),
            ("native_submit_prepare", "submit_control_not_ready"),
            ("navigation", "network_empty_response"),
            ("navigation", "network_connection_failed"),
            ("navigation", "navigation_interrupted"),
            ("editor_readiness", "editor_missing"),
            ("editor_readiness", "flow_editor_unavailable"),
            ("recaptcha_readiness", "flow_editor_unavailable"),
        ):
            with self.subTest(stage=stage, reason=reason):
                failure = BrowserCaptchaError(stage, reason)
                failure.submission_pending = False
                self.assertTrue(await self.balancer.record_generation_failure(
                    token_id, failure, for_video_generation=True, token=token,
                ))
                self.assertIsNone(await self.balancer.select_token(for_video_generation=True))
                self.assertIn(reason, await self.balancer.get_unavailable_reason(for_video_generation=True))
                self.assertTrue((await self.db.get_token(token_id)).is_active)
                self.balancer.record_generation_success(token_id, for_video_generation=True, token=token)

    async def test_errors_emitted_by_actual_editor_readiness_open_routing_circuit(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        browser = runtime_browser_failure_methods()

        def record_stage(stage, reason=None, **fields):
            browser._captcha_stage = stage

        browser._record_captcha_stage = Mock(side_effect=record_stage)
        for state, error, expected in (
            ({"location": "flow_project"}, TimeoutError("private timeout"), "editor_missing"),
            ({"location": "flow_landing"}, TimeoutError("private timeout"), "flow_editor_unavailable"),
            ({"location": "flow_project"}, RuntimeError("net::ERR_CONNECTION_CLOSED private URL"), "network_connection_failed"),
        ):
            with self.subTest(reason=expected):
                editor = SimpleNamespace(wait_for=AsyncMock(side_effect=error))
                page = SimpleNamespace(locator=Mock(return_value=SimpleNamespace(first=editor)))
                browser._capture_captcha_page_state = AsyncMock(return_value=state)
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await browser._wait_for_flow_editor(page)
                self.assertEqual((raised.exception.stage, raised.exception.reason), ("editor_readiness", expected))
                self.assertIsNone(raised.exception.submission_pending)
                # The readiness helper cannot know whether the runner armed
                # submission; its outer pre-submit guard provides this evidence.
                raised.exception.submission_pending = False
                self.assertTrue(await self.balancer.record_generation_failure(
                    token_id, raised.exception, for_video_generation=True, token=token,
                ))
                self.assertIsNone(await self.balancer.select_token(for_video_generation=True))
                reason = await self.balancer.get_unavailable_reason(for_video_generation=True)
                self.assertIn(expected, reason)
                self.assertNotIn("private", reason)
                self.assertTrue((await self.db.get_token(token_id)).is_active)
                self.balancer.record_generation_success(token_id, for_video_generation=True, token=token)

    async def test_late_old_identity_failure_cannot_overwrite_current_route_circuit(self):
        token_id = await self.add_token()
        old = await self.db.get_token(token_id)
        await self.db.update_token(token_id, google_cookies="SID=current-repaired-cookie")
        current = await self.db.get_token(token_id)
        failure = unsubmitted_browser_error("native_generation_setup", "mode_failed")
        await self.balancer.record_generation_failure(token_id, failure, for_video_generation=True, token=current)
        self.monotonic.return_value += 1
        await self.balancer.record_generation_failure(token_id, failure, for_video_generation=True, token=old)
        self.assertEqual(len(self.balancer._generation_cooldowns), 2)
        self.assertIn("59 秒", self.balancer.get_generation_cooldown_reason(current, for_video_generation=True))
        self.assertIsNone(await self.balancer.select_token(for_video_generation=True))
        self.balancer.record_generation_success(token_id, for_video_generation=True, token=old)
        self.assertIsNotNone(self.balancer.get_generation_cooldown_reason(current, for_video_generation=True))
        self.monotonic.return_value += 59
        self.assertEqual((await self.balancer.select_token(for_video_generation=True)).id, token_id)

    async def test_unknown_native_submit_errors_never_open_ui_circuit_without_prearm_evidence(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        for pending in (None, True):
            for stage, reason in (
                ("native_submit", "browser_operation_failed"),
                ("native_submit", "timeout"),
                ("native_generation_setup", "mode_failed"),
                ("editor_readiness", "editor_missing"),
            ):
                with self.subTest(stage=stage, pending=pending):
                    failure = BrowserCaptchaError(stage, reason)
                    failure.submission_pending = pending
                    self.assertFalse(await self.balancer.record_generation_failure(
                        token_id, failure, for_video_generation=True, token=token,
                    ))
        self.assertEqual(self.balancer._generation_cooldowns, {})
        self.assertEqual((await self.balancer.select_token(for_video_generation=True)).id, token_id)

    async def test_real_image_rpc_unusual_rejection_cools_route_without_changing_submission_evidence(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        for error_code in ("PUBLIC_ERROR_UNUSUAL_ACTIVITY", TRAFFIC_ERROR):
            with self.subTest(error_code=error_code):
                frames = [[["wrb.fr", "ogiZ0b", None, None, None, [error_code]]]]
                with self.assertRaises(FlowRPCRejected) as raised:
                    self.flow._raise_batchexecute_error(frames, "ogiZ0b")
                failure = raised.exception
                self.assertFalse(failure.submission_rejected)
                self.assertTrue(await self.balancer.record_generation_failure(
                    token_id, failure, for_image_generation=True, token=token,
                ))
                self.assertFalse(failure.submission_rejected)
                for flag in ("for_image_generation", "for_video_generation"):
                    self.assertIsNone(await self.balancer.select_token(**{flag: True}))
                    self.assertIn(error_code, await self.balancer.get_unavailable_reason(**{flag: True}))
                self.balancer.record_generation_success(token_id, for_image_generation=True, token=token)

    async def test_old_same_identity_success_cannot_clear_newer_failure(self):
        token_id = await self.add_token()
        token = await self.db.get_token(token_id)
        for failure, model in (
            (unsubmitted_browser_error("native_generation_setup", "mode_failed"), None),
            (unsubmitted_browser_error("native_generation_setup", "model_failed"), "test-2k"),
            (FlowRPCRejected("fixed rejection", "ogiZ0b", TRAFFIC_ERROR), None),
        ):
            with self.subTest(category=type(failure).__name__, model=model):
                old_started_at = self.monotonic.return_value
                self.monotonic.return_value += 10
                await self.balancer.record_generation_failure(
                    token_id, failure, for_video_generation=True, model=model, token=token,
                )
                self.monotonic.return_value += 5
                self.balancer.record_generation_success(
                    token_id, for_video_generation=True, model=model, token=token,
                    started_at=old_started_at,
                )
                self.assertIsNotNone(self.balancer.get_generation_cooldown_reason(
                    token, for_video_generation=True, model=model,
                ))
                self.assertIsNone(await self.balancer.select_token(for_video_generation=True, model=model))
                self.balancer.record_generation_success(
                    token_id, for_video_generation=True, model=model, token=token,
                    started_at=self.monotonic.return_value,
                )
                self.assertIsNone(self.balancer.get_generation_cooldown_reason(
                    token, for_video_generation=True, model=model,
                ))

    def set_min_video_credits(self, value):
        self.enterContext(patch(
            "src.services.load_balancer.config",
            SimpleNamespace(captcha_method="browser", call_logic_mode="polling", flow_min_video_credits=value),
        ))

    async def selected_ids(self, count=4, **flags):
        # The harness RPC rewrites a validated account's credits, but routing is
        # under test here, so selection skips account validation.
        self.manager.ensure_valid_token = AsyncMock(side_effect=lambda token: token)
        return {(await self.balancer.select_token(**flags)).id for _ in range(count)}

    async def test_underfunded_video_account_is_skipped_while_a_funded_account_exists(self):
        poor = await self.add_token(credits=2)
        rich = await self.add_token(credits=500)
        self.assertEqual(await self.selected_ids(for_video_generation=True), {rich})
        # Credits only gate video; the same accounts stay usable for images.
        self.assertEqual(await self.selected_ids(for_image_generation=True), {poor, rich})

    async def test_underfunded_accounts_stay_selectable_when_none_is_funded(self):
        first = await self.add_token(credits=2)
        second = await self.add_token(credits=0)
        self.assertEqual(await self.selected_ids(for_video_generation=True), {first, second})

    async def test_video_credit_floor_is_configurable_and_zero_disables_it(self):
        modest = await self.add_token(credits=50)
        rich = await self.add_token(credits=500)
        for floor, expected in ((10, {modest, rich}), (100, {rich}), (0, {modest, rich})):
            with self.subTest(floor=floor):
                self.set_min_video_credits(floor)
                self.assertEqual(await self.selected_ids(for_video_generation=True), expected)

    async def rotated(self, token_id, index):
        """The route exit rotation writes before a later lease."""
        route = f"http://route-{index}.example:8022"
        await self.db.update_token(token_id, proxy_url=route, captcha_proxy_url=route)
        return await self.db.get_token(token_id)

    async def test_failure_streak_continues_across_exit_rotation_route_changes(self):
        token_id = await self.add_token()
        failure = unsubmitted_browser_error("editor_readiness", "editor_missing")
        for index, delay in enumerate((60, 120, 240, 480, 600, 600)):
            token = await self.rotated(token_id, index)
            await self.balancer.record_generation_failure(
                token_id, failure, for_video_generation=True, token=token,
            )
            self.assertIn(f"{delay} 秒", self.balancer.get_generation_cooldown_reason(
                token, for_video_generation=True,
            ))
            self.monotonic.return_value += delay
        # Each repeat supersedes the previous route's record instead of piling up.
        self.assertEqual(len(self.balancer._generation_cooldowns), 1)

    async def test_upstream_rejection_streak_also_backs_off_across_route_changes(self):
        token_id = await self.add_token()
        rejection = FlowRPCRejected("fixed rejection", "ogiZ0b", TRAFFIC_ERROR)
        for index, delay in enumerate((300, 600, 1200, 1800, 1800)):
            token = await self.rotated(token_id, index)
            await self.balancer.record_generation_failure(
                token_id, rejection, for_video_generation=True, token=token,
            )
            self.assertIn(f"{delay} 秒", self.balancer.get_generation_cooldown_reason(
                token, for_video_generation=True,
            ))
            self.monotonic.return_value += delay

    async def test_success_on_a_rotated_route_resets_the_streak(self):
        token_id = await self.add_token()
        failure = unsubmitted_browser_error("editor_readiness", "editor_missing")
        for index in range(3):
            await self.balancer.record_generation_failure(
                token_id, failure, for_video_generation=True, token=await self.rotated(token_id, index),
            )
            self.monotonic.return_value += 600
        self.balancer.record_generation_success(
            token_id, for_video_generation=True, token=await self.rotated(token_id, 3),
        )
        self.assertEqual(self.balancer._generation_cooldowns, {})
        token = await self.rotated(token_id, 4)
        await self.balancer.record_generation_failure(token_id, failure, for_video_generation=True, token=token)
        self.assertIn("60 秒", self.balancer.get_generation_cooldown_reason(token, for_video_generation=True))

    async def test_changed_credentials_start_the_streak_over_after_route_changes(self):
        token_id = await self.add_token()
        failure = unsubmitted_browser_error("editor_readiness", "editor_missing")
        for index, delay in enumerate((60, 120)):
            token = await self.rotated(token_id, index)
            await self.balancer.record_generation_failure(
                token_id, failure, for_video_generation=True, token=token,
            )
            self.assertIn(f"{delay} 秒", self.balancer.get_generation_cooldown_reason(
                token, for_video_generation=True,
            ))
        await self.db.update_token(token_id, google_cookies="SID=repaired-cookie")
        repaired = await self.db.get_token(token_id)
        self.assertIsNone(self.balancer.get_generation_cooldown_reason(repaired, for_video_generation=True))
        await self.balancer.record_generation_failure(
            token_id, failure, for_video_generation=True, token=repaired,
        )
        self.assertIn("60 秒", self.balancer.get_generation_cooldown_reason(repaired, for_video_generation=True))


if __name__ == "__main__":
    unittest.main()
