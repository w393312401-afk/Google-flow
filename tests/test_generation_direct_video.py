"""A confirmed direct video must not fail during success bookkeeping."""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from src.core.models import Token
from src.services.generation_handler import GenerationHandler


class DirectVideoGenerationTests(unittest.IsolatedAsyncioTestCase):
    async def make_handler(self):
        token = Token(id=1, st='fixture', at='fixture', email='fixture@example.test')
        handler = GenerationHandler.__new__(GenerationHandler)
        handler.proxy_manager = None
        handler.flow_client = SimpleNamespace(
            clear_request_fingerprint=Mock(), prefill_remote_browser_pool=AsyncMock(),
            generate_video_text=AsyncMock(return_value={
                'direct_media':True, 'video_url':'https://media.example.test/result.mp4',
            }),
        )
        handler.token_manager = SimpleNamespace(
            ensure_valid_token=AsyncMock(return_value=token), ensure_project_exists=AsyncMock(return_value='project'),
            record_usage=AsyncMock(), record_success=AsyncMock(), record_error=AsyncMock(),
        )
        handler.load_balancer = SimpleNamespace(
            select_token=AsyncMock(return_value=token), release_pending=AsyncMock(),
            record_generation_success=Mock(), record_generation_failure=AsyncMock(),
        )
        handler._update_request_log_progress = AsyncMock()
        handler._log_request = AsyncMock()
        return handler

    async def test_direct_media_returns_success_and_records_usage_once(self):
        handler = await self.make_handler()
        model = 'omni-1.1-flash-10s-portrait-360p'
        chunks = [chunk async for chunk in handler.handle_generation(model,'fixture prompt')]
        self.assertIn('https://media.example.test/result.mp4',chunks[-1])
        handler.flow_client.generate_video_text.assert_awaited_once()
        handler.token_manager.record_usage.assert_awaited_once_with(1,is_video=True)
        handler.token_manager.record_success.assert_awaited_once_with(1)
        handler.token_manager.record_error.assert_not_awaited()
        handler.load_balancer.record_generation_failure.assert_not_awaited()
        self.assertEqual(handler._log_request.await_args.args[4],200)
        for call in handler.load_balancer.record_generation_success.call_args_list:
            self.assertEqual(call.kwargs['model'],model)
            self.assertIs(call.kwargs['for_video_generation'],True)

    async def test_client_closing_after_direct_result_keeps_confirmed_success(self):
        handler = await self.make_handler()
        generation = handler.handle_generation('omni-1.1-flash-10s-portrait-360p','fixture prompt')
        result = await anext(generation)
        self.assertIn('https://media.example.test/result.mp4',result)
        await generation.aclose()
        handler.token_manager.record_usage.assert_awaited_once_with(1,is_video=True)
        handler.token_manager.record_success.assert_awaited_once_with(1)
        handler.load_balancer.record_generation_success.assert_called_once()
        handler.load_balancer.record_generation_failure.assert_not_awaited()
        self.assertEqual(handler._log_request.await_args.args[4],200)
