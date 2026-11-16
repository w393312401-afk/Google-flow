import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from src.core.models import Token
from src.services.captcha_errors import BrowserCaptchaError
from src.services.flow_client import FlowClient
from src.services.generation_handler import GenerationHandler, MODEL_CONFIG
from src.services.load_balancer import LoadBalancer
from src.services.token_manager import TokenManager


class RotationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def make_handler(self):
        selected = Token(id=2, st="session", at="access", email="test@example.com", proxy_url="http://old:80")
        fresh = selected.model_copy(update={"proxy_url": "http://new:80", "captcha_proxy_url": "http://new:80"})
        handler = GenerationHandler.__new__(GenerationHandler)
        handler.flow_client = FlowClient(Mock(), Mock())
        handler.flow_client.prefill_remote_browser_pool = AsyncMock()
        handler.token_manager = SimpleNamespace(
            ensure_valid_token=AsyncMock(return_value=fresh),
            ensure_project_exists=AsyncMock(return_value="project"),
            record_error=AsyncMock(), record_usage=AsyncMock(), record_success=AsyncMock(),
        )
        handler.load_balancer = SimpleNamespace(
            select_token=AsyncMock(return_value=selected), release_pending=AsyncMock(),
        )
        handler.exit_rotation = SimpleNamespace(
            acquire=AsyncMock(return_value=fresh), note_sent=AsyncMock(),
            note_error=AsyncMock(), release=AsyncMock(),
        )
        handler._update_request_log_progress = AsyncMock()
        handler._log_request = AsyncMock()
        self.model = next(name for name, cfg in MODEL_CONFIG.items() if cfg["type"] == "image" and not cfg.get("upsample"))
        return handler, selected, fresh

    async def test_success_uses_fresh_pinned_route_and_counts_only_submission(self):
        handler, selected, fresh = self.make_handler()

        async def generate(token, *args, generation_result, **kwargs):
            self.assertIs(token, fresh)
            self.assertEqual(handler.flow_client.get_request_fingerprint()["proxy_url"], fresh.proxy_url)
            await handler.flow_client._notify_generation_sent()
            generation_result["success"] = True
            yield "done"

        handler._handle_image_generation = generate
        self.assertEqual([part async for part in handler.handle_generation(self.model, "test")], ["done"])
        handler.token_manager.ensure_valid_token.assert_awaited_once_with(fresh)
        handler.exit_rotation.acquire.assert_awaited_once()
        handler.exit_rotation.note_sent.assert_awaited_once()
        handler.exit_rotation.note_error.assert_not_awaited()
        handler.exit_rotation.release.assert_awaited_once_with(selected.id, handler.exit_rotation.acquire.await_args.args[1])
        self.assertIsNone(handler.flow_client.get_generation_sent_callback())
        self.assertIsNone(handler.flow_client.get_request_fingerprint())

    async def test_local_preparation_error_keeps_exit_without_counting_send(self):
        handler, _, _ = self.make_handler()

        async def generate(*args, **kwargs):
            failure = BrowserCaptchaError("native_editor_input", "prompt_input_mismatch")
            failure.submission_pending = False
            raise failure
            yield  # async generator

        handler._handle_image_generation = generate
        responses = [part async for part in handler.handle_generation(self.model, "test")]
        self.assertIs(json.loads(responses[-1])["error"]["submission_pending"], False)
        handler.exit_rotation.note_sent.assert_not_awaited()
        handler.exit_rotation.note_error.assert_not_awaited()
        handler.exit_rotation.release.assert_awaited_once()

    async def test_network_error_still_rotates_but_project_and_balance_errors_do_not(self):
        for reason, should_rotate in (
            ("proxy_connection_failed", True),
            ("project_not_found", False),
            ("insufficient_credits", False),
            ("submit_control_missing", False),
        ):
            with self.subTest(reason=reason):
                handler, _, _ = self.make_handler()

                async def generate(*args, **kwargs):
                    failure = BrowserCaptchaError("native_submit_prepare", reason)
                    failure.submission_pending = False
                    raise failure
                    yield

                handler._handle_image_generation = generate
                responses = [part async for part in handler.handle_generation(self.model, "test")]
                self.assertIs(json.loads(responses[-1])["error"]["submission_pending"], False)
                self.assertEqual(handler.exit_rotation.note_error.await_count, int(should_rotate))
                handler.exit_rotation.note_sent.assert_not_awaited()
                handler.exit_rotation.release.assert_awaited_once()

    async def test_failed_health_releases_original_account_when_token_becomes_none(self):
        handler, selected, _ = self.make_handler()
        handler.token_manager.ensure_valid_token.return_value = None
        responses = [part async for part in handler.handle_generation(self.model, "test")]
        self.assertEqual(json.loads(responses[-1])["error"]["code"], "no_available_token")
        handler.exit_rotation.note_error.assert_awaited_once()
        handler.load_balancer.release_pending.assert_awaited_once_with(selected.id, for_image_generation=True, for_video_generation=False)
        handler.exit_rotation.release.assert_awaited_once()

    async def test_closing_on_unknown_status_keeps_receipt_and_does_not_replay(self):
        handler, _, _ = self.make_handler()
        calls = []

        async def generate(*args, generation_result, **kwargs):
            calls.append("submit")
            await handler.flow_client._notify_generation_sent()
            generation_result.update(submission_pending=True, operation="original-operation", error_message="status unknown")
            yield handler._create_error_response("status unknown", code="video_status_unknown", submission_pending=True, upstream_accepted=True)

        handler._handle_image_generation = generate
        iterator = handler.handle_generation(self.model, "test")
        event = json.loads(await anext(iterator))["error"]
        self.assertTrue(event["submission_pending"])
        await iterator.aclose()
        self.assertEqual(calls, ["submit"])
        handler.exit_rotation.note_sent.assert_awaited_once()
        handler.exit_rotation.note_error.assert_awaited_once()
        handler.exit_rotation.release.assert_awaited_once()

    async def test_load_balancer_prepares_route_before_health_and_marks_failure(self):
        token = Token(id=2, st="session", at="access", email="test@example.com")
        events = []

        async def prepare(value):
            events.append("prepare")
            return value

        async def health(value):
            events.append("health")
            return None

        manager = SimpleNamespace(get_active_tokens=AsyncMock(return_value=[token]), needs_at_refresh=Mock(return_value=False), ensure_valid_token=health, get_last_validation_error=Mock(return_value="AT_CHECK: network or proxy unavailable"))
        balancer = LoadBalancer(manager)
        balancer.exit_rotation = SimpleNamespace(prepare_token=prepare, mark_health_error=AsyncMock())
        with patch("src.services.load_balancer.config", SimpleNamespace(captcha_method="browser", call_logic_mode="polling")):
            self.assertIsNone(await balancer.select_token(for_image_generation=True))
        self.assertEqual(events, ["prepare", "health"])
        balancer.exit_rotation.mark_health_error.assert_awaited_once_with(token.id)

    async def test_late_health_result_from_old_exit_cannot_validate_new_exit(self):
        manager = TokenManager(Mock(), Mock())
        manager._mark_at_valid(2, proxy_url="http://old:80")
        manager._clear_at_validation_cache(2)
        # A slow validation that began before rotation finishes afterwards.
        manager._mark_at_valid(2, proxy_url="http://old:80")
        self.assertTrue(manager._has_recent_at_validation(2, proxy_url="http://old:80"))
        self.assertFalse(manager._has_recent_at_validation(2, proxy_url="http://new:80"))

    async def test_load_balancer_does_not_rotate_without_this_call_failure_evidence(self):
        token = Token(id=2, st="session", at="access", email="test@example.com")
        manager = SimpleNamespace(
            get_active_tokens=AsyncMock(return_value=[token]), needs_at_refresh=Mock(return_value=False),
            ensure_valid_token=AsyncMock(return_value=None),
            get_last_validation_error=Mock(return_value="AT_CHECK: network or proxy unavailable"),
            consume_validation_outcome=Mock(side_effect=[None, None]),
        )
        balancer = LoadBalancer(manager)
        balancer.exit_rotation = SimpleNamespace(
            prepare_token=AsyncMock(return_value=token), mark_health_error=AsyncMock(),
            accepts_health_error_reason=True, accepts_health_error_identity=True,
        )
        with patch("src.services.load_balancer.config", SimpleNamespace(captcha_method="browser", call_logic_mode="polling")):
            self.assertIsNone(await balancer.select_token(for_image_generation=True))
        self.assertEqual(manager.consume_validation_outcome.call_count, 2)
        balancer.exit_rotation.mark_health_error.assert_not_awaited()

    async def test_load_balancer_marks_exact_caller_failure_identity_and_reason(self):
        token = Token(id=2, st="session", at="access", email="test@example.com")
        failure = SimpleNamespace(
            token_id=2, success=False, reason="AT_CHECK: upstream unavailable (HTTP 502)",
            identity="identity-of-actually-validated-route",
        )
        manager = SimpleNamespace(
            get_active_tokens=AsyncMock(return_value=[token]), needs_at_refresh=Mock(return_value=False),
            ensure_valid_token=AsyncMock(return_value=None),
            get_last_validation_error=Mock(return_value="another caller's unrelated error"),
            consume_validation_outcome=Mock(side_effect=[None, failure]),
        )
        balancer = LoadBalancer(manager)
        balancer.exit_rotation = SimpleNamespace(
            prepare_token=AsyncMock(return_value=token), mark_health_error=AsyncMock(),
            accepts_health_error_reason=True, accepts_health_error_identity=True,
        )
        with patch("src.services.load_balancer.config", SimpleNamespace(captcha_method="browser", call_logic_mode="polling")):
            self.assertIsNone(await balancer.select_token(for_image_generation=True))
        balancer.exit_rotation.mark_health_error.assert_awaited_once_with(
            2, error=failure.reason, failed_identity=failure.identity,
        )
        manager.get_last_validation_error.assert_not_called()

    async def test_rotation_state_failure_cannot_reclassify_unknown_submission(self):
        handler, _, _ = self.make_handler()
        handler.exit_rotation.note_error.side_effect = OSError("state write failed")

        async def generate(*args, generation_result, **kwargs):
            await handler.flow_client._notify_generation_sent()
            generation_result.update(submission_pending=True, error_message="status unknown")
            yield handler._create_error_response("status unknown", code="video_status_unknown", submission_pending=True, upstream_accepted=True)

        handler._handle_image_generation = generate
        events = [part async for part in handler.handle_generation(self.model, "test")]
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0])["error"]["code"], "video_status_unknown")
        handler._log_request.assert_not_awaited()
        handler.exit_rotation.release.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
