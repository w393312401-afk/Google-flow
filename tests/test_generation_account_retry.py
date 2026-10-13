"""A video attempt that provably never started upstream runs again on another account."""
import json
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

from src.core.database import Database
from src.core.models import Token
from src.services.captcha_errors import BrowserCaptchaError
from src.services.flow_client import FlowClient
from src.services.flow_frontend import FlowRPCRejected
from src.services.generation_handler import GenerationHandler, MODEL_CONFIG
from src.services.load_balancer import LoadBalancer
from src.services.submission_ledger import SubmissionLedger
from src.services.token_manager import TokenManager

VIDEO_MODEL = "omni-1.1-flash-frames-10s-portrait-360p"
IMAGE_MODEL = next(
    name for name, cfg in MODEL_CONFIG.items() if cfg["type"] == "image" and not cfg.get("upsample")
)


def unsubmitted(stage="editor_readiness", reason="editor_missing"):
    """The native runner's explicit guarded cleanup evidence that nothing was sent."""
    failure = BrowserCaptchaError(stage, reason)
    failure.submission_pending = False
    return failure


class GenerationAccountRetryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db = Database(db_path=f"{self.temp_dir.name}/flow.db")
        await self.db.init_db()
        self.flow = FlowClient(proxy_manager=Mock(), db=self.db)
        self.flow._current_rpc = AsyncMock(return_value=[123])
        self.manager = TokenManager(self.db, self.flow)
        self.balancer = LoadBalancer(self.manager)
        self.enterContext(patch(
            "src.services.load_balancer.config",
            SimpleNamespace(captcha_method="browser", call_logic_mode="polling"),
        ))
        self.account_count = 0
        self.attempts = []
        self.outcomes = []

    async def add_token(self):
        self.account_count += 1
        return await self.db.add_token(Token(
            st=f"private-session-{self.account_count}",
            at=FlowClient.FRONTEND_ACCESS_TOKEN,
            at_expires=datetime.now(timezone.utc) + timedelta(minutes=55),
            email=f"private-account-{self.account_count}@example.com",
            google_cookies="OSID=private-cookie; SID=private-sid",
            user_paygate_tier="PAYGATE_TIER_ONE",
            auto_refresh_enabled=False,
            credits=500,
        ))

    def make_handler(self, chunks=1):
        """Real routing with a fake pipeline: each run takes the next scripted outcome."""
        handler = GenerationHandler.__new__(GenerationHandler)
        handler.db = self.db
        handler.flow_client = SimpleNamespace(clear_request_fingerprint=Mock(), prefill_remote_browser_pool=AsyncMock())
        handler.token_manager = SimpleNamespace(
            ensure_valid_token=AsyncMock(side_effect=lambda token: token),
            ensure_project_exists=AsyncMock(return_value="project"),
            record_error=AsyncMock(), record_usage=AsyncMock(), record_success=AsyncMock(),
        )
        handler.load_balancer = self.balancer
        handler._update_request_log_progress = AsyncMock()
        handler._log_request = AsyncMock()

        async def pipeline(token, *args, generation_result, **kwargs):
            self.attempts.append(token.id)
            outcome = self.outcomes.pop(0) if self.outcomes else None
            if outcome is not None:
                raise outcome
            generation_result["success"] = True
            for index in range(chunks):
                yield f"video-from-{token.id}" if chunks == 1 else f"video-part-{index + 1}"

        handler._handle_video_generation = pipeline
        handler._handle_image_generation = pipeline
        return handler

    @staticmethod
    async def collect(handler, model=VIDEO_MODEL, **kwargs):
        return [chunk async for chunk in handler.handle_generation(model, "prompt", **kwargs)]

    @staticmethod
    def logged_statuses(handler):
        # The "started" row is written with keywords, every final row positionally.
        return [call.kwargs["status_code"] if "status_code" in call.kwargs else call.args[4]
                for call in handler._log_request.await_args_list]

    async def test_unsubmitted_failure_runs_on_another_account_and_only_the_result_is_returned(self):
        first, second = await self.add_token(), await self.add_token()
        self.outcomes = [unsubmitted()]
        handler = self.make_handler()
        responses = await self.collect(handler)
        self.assertEqual(sorted(self.attempts), sorted([first, second]))
        self.assertEqual(responses, [f"video-from-{self.attempts[1]}"])
        # Every attempt stays visible in the request log, but only the last one reaches the caller.
        self.assertEqual(self.logged_statuses(handler), [500, 200])
        failed = handler._log_request.await_args_list[0].args[3]
        self.assertEqual((failed["code"], failed["upstream_accepted"]), ("submission_not_started", False))
        failed_account = await self.db.get_token(self.attempts[0])
        self.assertIsNotNone(self.balancer.get_generation_cooldown_reason(
            failed_account, for_video_generation=True, model=VIDEO_MODEL,
        ))
        self.assertEqual(self.balancer._video_pending, {})

    async def test_new_native_actionability_failures_automatically_use_one_other_account(self):
        await self.add_token(), await self.add_token()
        for reason in ("browser_closed", "element_detached", "click_intercepted", "submit_disabled"):
            with self.subTest(reason=reason):
                self.attempts = []
                self.outcomes = [unsubmitted("native_submit", reason)]
                handler = self.make_handler()
                responses = await self.collect(handler)
                self.assertEqual(len(self.attempts), 2)
                self.assertNotEqual(self.attempts[0], self.attempts[1])
                self.assertEqual(responses, [f"video-from-{self.attempts[1]}"])
                self.assertEqual(self.logged_statuses(handler), [500, 200])
                handler.token_manager.record_error.assert_not_awaited()
                failed_account = await self.db.get_token(self.attempts[0])
                self.assertTrue(failed_account.is_active)
                self.assertIsNotNone(self.balancer.get_generation_cooldown_reason(
                    failed_account, for_video_generation=True, model=VIDEO_MODEL,
                ))
                self.balancer.record_generation_success(
                    failed_account.id, for_video_generation=True, model=VIDEO_MODEL, token=failed_account,
                )
                self.assertEqual(self.balancer._video_pending, {})

    async def test_stream_announces_the_retry_without_showing_the_first_error(self):
        await self.add_token(), await self.add_token()
        self.outcomes = [unsubmitted()]
        handler = self.make_handler()
        text = "".join(await self.collect(handler, stream=True))
        self.assertNotIn("错误", text)
        self.assertEqual(text.count("生成任务已启动"), 1)
        self.assertEqual(text.count("换用其他账号重试"), 1)
        self.assertIn(f"video-from-{self.attempts[1]}", text)
        # The retry logs once it has an account, so no row is left at "started".
        self.assertEqual(self.logged_statuses(handler), [102, 500, 200])

    async def test_upstream_rejection_is_retried_too(self):
        await self.add_token(), await self.add_token()
        rejection = FlowRPCRejected("fixed rejection", "nprQif", "PUBLIC_ERROR_UNUSUAL_ACTIVITY")
        self.assertTrue(rejection.submission_rejected)
        self.outcomes = [rejection]
        handler = self.make_handler()
        responses = await self.collect(handler)
        self.assertEqual(responses, [f"video-from-{self.attempts[1]}"])
        self.assertNotEqual(*self.attempts)
        failed = handler._log_request.await_args_list[0].args[3]
        self.assertEqual(failed["code"], "submission_rejected")

    async def test_original_error_is_returned_when_no_other_account_exists(self):
        only = await self.add_token()
        self.outcomes = [unsubmitted(), unsubmitted()]
        handler = self.make_handler()
        responses = await self.collect(handler)
        self.assertEqual(self.attempts, [only])
        self.assertEqual(len(responses), 1)
        error = json.loads(responses[0])["error"]
        self.assertEqual(error["code"], "submission_not_started")
        self.assertIn("editor_missing", error["message"])
        self.assertIs(error["upstream_accepted"], False)
        # No second row: the failed retry search is not a new outcome.
        self.assertEqual(self.logged_statuses(handler), [500])
        self.assertEqual(self.balancer._video_pending, {})

    async def test_stream_without_another_account_ends_with_the_original_error(self):
        await self.add_token()
        self.outcomes = [unsubmitted()]
        handler = self.make_handler()
        chunks = await self.collect(handler, stream=True)
        text = "".join(chunks)
        self.assertEqual(text.count("生成任务已启动"), 1)
        self.assertIn("错误:", text)
        self.assertIn("editor_missing", chunks[-1])
        self.assertEqual(json.loads(chunks[-1])["error"]["code"], "submission_not_started")
        self.assertEqual(self.logged_statuses(handler), [102, 500])

    async def test_only_one_retry_even_when_more_accounts_exist(self):
        for _ in range(3):
            await self.add_token()
        self.outcomes = [unsubmitted(), unsubmitted(), unsubmitted()]
        handler = self.make_handler()
        responses = await self.collect(handler)
        self.assertEqual(len(self.attempts), 2)
        self.assertEqual(len(set(self.attempts)), 2)
        self.assertEqual(len(responses), 1)
        self.assertEqual(json.loads(responses[0])["error"]["code"], "submission_not_started")
        self.assertEqual(self.logged_statuses(handler), [500, 500])

    async def test_retry_count_is_configurable_and_zero_disables_it(self):
        for _ in range(3):
            await self.add_token()
        for retries, expected_attempts in ((0, 1), (2, 3)):
            with self.subTest(retries=retries):
                self.attempts, self.outcomes = [], [unsubmitted(), unsubmitted(), unsubmitted()]
                self.balancer._generation_cooldowns.clear()
                handler = self.make_handler()
                with patch("src.core.config.Config.flow_account_retries",
                           new_callable=PropertyMock, return_value=retries):
                    responses = await self.collect(handler)
                self.assertEqual(len(self.attempts), expected_attempts)
                self.assertEqual(json.loads(responses[-1])["error"]["code"], "submission_not_started")

    async def test_failures_that_are_not_proven_account_or_route_problems_are_not_retried(self):
        await self.add_token(), await self.add_token()
        unproven, still_pending = unsubmitted(), unsubmitted()
        unproven.submission_pending, still_pending.submission_pending = None, True
        for name, failure in (
            ("request-caused", unsubmitted("native_frame_prepare", "frame_image_invalid")),
            ("no evidence", unproven),
            ("submission pending", still_pending),
            ("generic", RuntimeError("generation failed")),
        ):
            with self.subTest(name):
                self.attempts, self.outcomes = [], [failure]
                self.balancer._generation_cooldowns.clear()
                handler = self.make_handler()
                responses = await self.collect(handler)
                self.assertEqual(len(self.attempts), 1)
                self.assertEqual(len(responses), 1)
                self.assertIn("error", json.loads(responses[0]))
                self.assertEqual(self.logged_statuses(handler), [500])

    async def test_image_generation_is_not_retried(self):
        await self.add_token(), await self.add_token()
        self.outcomes = [unsubmitted()]
        handler = self.make_handler()
        responses = await self.collect(handler, model=IMAGE_MODEL)
        self.assertEqual(len(self.attempts), 1)
        self.assertEqual(json.loads(responses[0])["error"]["code"], "submission_not_started")

    async def test_ledger_records_the_account_that_produced_the_result(self):
        await self.add_token(), await self.add_token()
        self.outcomes = [unsubmitted()]
        submission_id = str(uuid.uuid4())
        ledger = SubmissionLedger(self.db)
        await ledger.reserve(submission_id, "fingerprint", VIDEO_MODEL)
        handler = self.make_handler()
        await self.collect(handler, client_submission_id=submission_id)
        row = await ledger.get(submission_id)
        self.assertEqual(row["account_id"], self.attempts[1])
        # Only the route layer settles a receipt, from the final result it delivers.
        self.assertEqual(row["state"], "pending")

    async def test_closing_the_stream_releases_the_running_attempt(self):
        await self.add_token()
        handler = self.make_handler(chunks=2)
        stream = handler.handle_generation(VIDEO_MODEL, "prompt")
        self.assertEqual(await anext(stream), "video-part-1")
        self.assertEqual(self.balancer._video_pending, {self.attempts[0]: 1})
        await stream.aclose()
        self.assertEqual(self.balancer._video_pending, {})


if __name__ == "__main__":
    unittest.main()
