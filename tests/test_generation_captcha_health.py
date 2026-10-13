import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from src.core.models import Token
from src.services.captcha_errors import BrowserCaptchaError
from src.services.generation_handler import GenerationHandler, MODEL_CONFIG


class GenerationCaptchaHealthTests(unittest.IsolatedAsyncioTestCase):
    async def run_failure(self, failure, *, stream=False, routing_failure=None, success=False):
        token = Token(id=1, st="session", at="access", email="test@example.com")
        handler = GenerationHandler.__new__(GenerationHandler)
        handler.flow_client = SimpleNamespace(
            clear_request_fingerprint=Mock(),
            prefill_remote_browser_pool=AsyncMock(),
            generate_image=AsyncMock(side_effect=failure),
        )
        handler.token_manager = SimpleNamespace(
            ensure_valid_token=AsyncMock(return_value=token),
            ensure_project_exists=AsyncMock(return_value="project"),
            record_error=AsyncMock(),
            record_usage=AsyncMock(),
            record_success=AsyncMock(),
        )
        handler.load_balancer = SimpleNamespace(
            select_token=AsyncMock(return_value=token), release_pending=AsyncMock(),
            record_generation_failure=AsyncMock(side_effect=routing_failure), record_generation_success=Mock(),
        )
        handler._update_request_log_progress = AsyncMock()
        handler._log_request = AsyncMock()
        model = next(
            name for name, cfg in MODEL_CONFIG.items()
            if cfg["type"] == "image" and not cfg.get("upsample")
        )
        if success:
            async def successful_pipeline(*args, **kwargs):
                kwargs['generation_result']['success'] = True
                yield 'confirmed-result'
            handler._handle_image_generation = successful_pipeline

        responses = [response async for response in handler.handle_generation(model, "test", stream=stream)]
        return handler, responses

    async def test_native_captcha_failure_is_reported_without_penalizing_account(self):
        failure = BrowserCaptchaError("request_interception", "streamchat_missing")
        handler, responses = await self.run_failure(failure)

        handler.flow_client.generate_image.assert_awaited_once()
        handler.token_manager.record_error.assert_not_awaited()
        handler.load_balancer.record_generation_failure.assert_awaited_once()
        self.assertIs(handler.load_balancer.record_generation_failure.await_args.args[1], failure)
        self.assertTrue(handler.load_balancer.record_generation_failure.await_args.kwargs['for_image_generation'])
        handler.load_balancer.record_generation_success.assert_not_called()
        handler.load_balancer.release_pending.assert_awaited_once()
        self.assertEqual(len(responses), 1)
        self.assertIn(str(failure), responses[0])
        self.assertEqual(json.loads(responses[0])["error"]["code"], "generation_failed")
        self.assertEqual(handler._log_request.await_args.args[4], 500)
        self.assertEqual(handler._log_request.await_args.kwargs["status_text"], "failed")
        self.assertTrue(handler._should_count_token_error(RuntimeError("UNAUTHENTICATED")))

    async def test_proven_pre_submit_failure_is_returned_and_logged_as_unsubmitted(self):
        for stream in (False, True):
            with self.subTest(stream=stream):
                failure = BrowserCaptchaError("native_editor_input", "prompt_input_mismatch")
                failure.submission_pending = False
                handler, responses = await self.run_failure(failure, stream=stream)
                error = json.loads(responses[-1])["error"]
                self.assertEqual(error["code"], "submission_not_started")
                self.assertIs(error["submission_pending"], False)
                self.assertIn(str(failure), error["message"])
                logged = handler._log_request.await_args.args[3]
                self.assertEqual(logged["code"], "submission_not_started")
                self.assertIs(logged["submission_pending"], False)
                handler.token_manager.record_error.assert_not_awaited()

    async def test_native_submission_evidence_is_logged_and_returned_without_raw_browser_data(self):
        failure = BrowserCaptchaError("native_submit", "timeout")
        failure.submission_pending = False
        failure.native_submission_diagnostic = {
            "stage": "native_submit", "reason": "timeout", "error_kind": "timeout",
            "armed": True, "request_admitted": False, "forwarding_started": False,
            "request_forwarded": False, "page_closed": True, "submit_attempts": 2,
            "elapsed_ms": 17000, "raw_error": "private-url?cookie=secret",
            "cookie": "secret", "token_id": "secret",
        }
        handler, responses = await self.run_failure(failure)
        error = json.loads(responses[-1])["error"]
        diagnostic = error["native_submission_diagnostic"]
        self.assertEqual(error["code"], "submission_not_started")
        self.assertEqual(error["reason"], "timeout")
        self.assertEqual(diagnostic["submit_attempts"], 2)
        self.assertIs(diagnostic["forwarding_started"], False)
        self.assertNotIn("secret", json.dumps(diagnostic))
        self.assertEqual(handler._log_request.await_args.args[3]["native_submission_diagnostic"], diagnostic)

    async def test_routing_bookkeeping_failure_preserves_original_submission_evidence(self):
        failure = BrowserCaptchaError('native_generation_setup', 'mode_failed')
        failure.submission_pending = False
        async def broken_hook(*a, **kw):
            raise RuntimeError('local bookkeeping failed')
        handler, responses = await self.run_failure(failure, routing_failure=broken_hook)
        self.assertEqual(json.loads(responses[-1])['error']['code'], 'submission_not_started')
        handler.load_balancer.record_generation_failure.assert_awaited_once()
        handler.token_manager.record_error.assert_not_awaited()

    async def test_confirmed_success_clears_only_the_routing_capability_it_used(self):
        handler, responses = await self.run_failure(None, success=True)
        handler.load_balancer.record_generation_success.assert_called_once()
        call = handler.load_balancer.record_generation_success.call_args
        self.assertEqual(call.args, (1,))
        self.assertIs(call.kwargs['for_image_generation'], True)
        self.assertIs(call.kwargs['for_video_generation'], False)
        handler.load_balancer.record_generation_failure.assert_not_awaited()
        handler.token_manager.record_success.assert_awaited_once_with(1)

    async def test_stage_or_string_without_runner_evidence_cannot_clear_pending(self):
        for failure in (
            BrowserCaptchaError("native_editor_input", "prompt_input_mismatch"),
            BrowserCaptchaError("native_response", "upstream_http_500"),
            RuntimeError("native_editor_input/prompt_input_mismatch"),
        ):
            with self.subTest(error_type=type(failure).__name__):
                handler, responses = await self.run_failure(failure)
                error = json.loads(responses[-1])["error"]
                self.assertEqual(error["code"], "generation_failed")
                self.assertNotIn("submission_pending", error)
                self.assertNotIn("submission_pending", handler._log_request.await_args.args[3])


if __name__ == "__main__":
    unittest.main()
