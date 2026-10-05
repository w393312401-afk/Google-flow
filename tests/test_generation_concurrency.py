"""Offline concurrency regressions: no browsers or upstream requests."""

import asyncio
import json
import unittest
from collections import Counter
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from src.core.models import Token
from src.services.captcha_errors import BrowserCaptchaError
from src.services.concurrency_manager import ConcurrencyManager
from src.services.generation_handler import GenerationHandler, MODEL_CONFIG
from src.services.load_balancer import LoadBalancer


class PendingSelectionTests(unittest.IsolatedAsyncioTestCase):
    async def make_balancer(self, count=5):
        tokens = [Token(id=index, st="synthetic", email="synthetic@example.com", image_concurrency=1,
                        video_concurrency=1) for index in range(1, count + 1)]
        concurrency = ConcurrencyManager()
        await concurrency.initialize(tokens)
        manager = SimpleNamespace(
            get_active_tokens=AsyncMock(return_value=tokens),
            needs_at_refresh=Mock(return_value=False),
            ensure_valid_token=AsyncMock(side_effect=lambda token: token),
        )
        return LoadBalancer(manager, concurrency), manager

    async def test_burst_reserves_different_accounts_before_health_checks_finish(self):
        for mode in ("default", "polling"):
            with self.subTest(mode=mode), patch(
                "src.services.load_balancer.config",
                SimpleNamespace(captcha_method="browser", call_logic_mode=mode),
            ), patch("src.services.load_balancer.random.random", return_value=0):
                balancer, manager = await self.make_balancer()
                barrier = asyncio.Barrier(10)

                async def health(token):
                    await barrier.wait()
                    return token

                manager.ensure_valid_token.side_effect = health
                chosen = await asyncio.wait_for(asyncio.gather(*[
                    balancer.select_token(for_video_generation=True,
                                          enforce_concurrency_filter=False,
                                          track_pending=True)
                    for _ in range(10)
                ]), timeout=2)
                self.assertEqual(Counter(token.id for token in chosen),
                                 Counter({index: 2 for index in range(1, 6)}))
                for token in chosen:
                    await balancer.release_pending(token.id, for_video_generation=True)
                self.assertEqual(balancer._video_pending, {})

    async def test_health_failure_and_cancellation_release_temporary_reservations(self):
        with patch("src.services.load_balancer.config", SimpleNamespace(
            captcha_method="browser", call_logic_mode="default"
        )):
            balancer, manager = await self.make_balancer(count=1)
            manager.ensure_valid_token.return_value = None
            manager.ensure_valid_token.side_effect = None
            self.assertIsNone(await balancer.select_token(
                for_video_generation=True, track_pending=True,
                enforce_concurrency_filter=False,
            ))
            self.assertEqual(balancer._video_pending, {})
            started = asyncio.Event()

            async def wait_forever(token):
                started.set()
                await asyncio.Event().wait()

            manager.ensure_valid_token.side_effect = wait_forever
            task = asyncio.create_task(balancer.select_token(
                for_video_generation=True, track_pending=True,
                enforce_concurrency_filter=False,
            ))
            await started.wait()
            self.assertEqual(balancer._video_pending, {1: 1})
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(balancer._video_pending, {})

    async def test_idle_account_is_used_before_busy_account_without_refresh(self):
        with patch("src.services.load_balancer.config", SimpleNamespace(
            captcha_method="browser", call_logic_mode="default"
        )):
            balancer, manager = await self.make_balancer(count=2)
            await balancer.concurrency_manager.acquire_video(1)
            manager.needs_at_refresh.side_effect = lambda token: token.id == 2
            token = await balancer.select_token(for_video_generation=True,
                                               track_pending=True,
                                               enforce_concurrency_filter=False)
            self.assertEqual(token.id, 2)


class GenerationSlotTests(unittest.IsolatedAsyncioTestCase):
    async def make_handler(self, media_type="video"):
        token = Token(id=1, st="synthetic", at="synthetic", email="synthetic@example.com", image_concurrency=1,
                      video_concurrency=1, user_paygate_tier="PAYGATE_TIER_ONE")
        handler = GenerationHandler.__new__(GenerationHandler)
        handler.concurrency_manager = ConcurrencyManager()
        await handler.concurrency_manager.initialize([token])
        handler.flow_client = SimpleNamespace(clear_request_fingerprint=Mock(),
                                             prefill_remote_browser_pool=AsyncMock())
        handler.load_balancer = SimpleNamespace(select_token=AsyncMock(return_value=token),
                                               release_pending=AsyncMock())
        handler.token_manager = SimpleNamespace(
            ensure_valid_token=AsyncMock(return_value=token),
            ensure_project_exists=AsyncMock(return_value="synthetic-project"),
            record_error=AsyncMock(), record_usage=AsyncMock(), record_success=AsyncMock(),
        )
        handler._log_request = AsyncMock()
        handler._update_request_log_progress = AsyncMock()
        model = next(name for name, spec in MODEL_CONFIG.items()
                     if spec["type"] == media_type and not spec.get("upsample"))
        return handler, model

    async def collect(self, handler, model):
        return [part async for part in handler.handle_generation(model, "synthetic prompt")]

    async def test_same_account_waits_until_first_generation_and_polling_finish(self):
        for media_type in ("image", "video"):
            with self.subTest(media_type=media_type):
                handler, model = await self.make_handler(media_type)
                entered = asyncio.Event()
                release = asyncio.Event()
                calls = []

                async def pipeline(*args, generation_result, **kwargs):
                    calls.append("enter")
                    entered.set()
                    await release.wait()
                    generation_result["success"] = True
                    yield "complete"

                setattr(handler, f"_handle_{media_type}_generation", pipeline)
                first = asyncio.create_task(self.collect(handler, model))
                await entered.wait()
                second = asyncio.create_task(self.collect(handler, model))
                await asyncio.sleep(0.07)
                self.assertEqual(calls, ["enter"])
                get_inflight = getattr(handler.concurrency_manager, f"get_{media_type}_inflight")
                self.assertEqual(await get_inflight(1), 1)
                release.set()
                self.assertEqual(await asyncio.gather(first, second), [["complete"], ["complete"]])
                self.assertEqual(calls, ["enter", "enter"])
                self.assertEqual(await get_inflight(1), 0)
                self.assertEqual(handler.load_balancer.release_pending.await_count, 2)

    async def test_failure_cancellation_and_generator_close_release_account_slot(self):
        for outcome in ("failure", "cancel", "close"):
            with self.subTest(outcome=outcome):
                handler, model = await self.make_handler()
                entered = asyncio.Event()

                async def pipeline(*args, generation_result, **kwargs):
                    entered.set()
                    if outcome == "failure":
                        raise BrowserCaptchaError("native_editor_input", "synthetic_failure")
                    if outcome == "cancel":
                        await asyncio.Event().wait()
                    yield "status_unknown"

                handler._handle_video_generation = pipeline
                if outcome == "cancel":
                    task = asyncio.create_task(self.collect(handler, model))
                    await entered.wait()
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                elif outcome == "close":
                    iterator = handler.handle_generation(model, "synthetic prompt")
                    self.assertEqual(await anext(iterator), "status_unknown")
                    await iterator.aclose()
                else:
                    await self.collect(handler, model)
                self.assertEqual(await handler.concurrency_manager.get_video_inflight(1), 0)
                handler.load_balancer.release_pending.assert_awaited_once()

    async def test_queue_timeout_is_explicitly_unsubmitted(self):
        handler, model = await self.make_handler()
        handler.concurrency_manager.wait_acquire_video = AsyncMock(return_value=(False, 1000))
        handler._handle_video_generation = Mock()
        result = await self.collect(handler, model)
        error = json.loads(result[-1])["error"]
        self.assertEqual(error["code"], "submission_not_started")
        self.assertIs(error["submission_pending"], False)
        self.assertIs(error["upstream_accepted"], False)
        handler._handle_video_generation.assert_not_called()
        handler.load_balancer.release_pending.assert_awaited_once()
        self.assertEqual(await handler.concurrency_manager.get_video_inflight(1), 0)


if __name__ == "__main__":
    unittest.main()
