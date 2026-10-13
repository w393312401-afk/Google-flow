import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from src.services.generation_handler import GenerationHandler


class VideoStatusUnknownTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.handler = GenerationHandler.__new__(GenerationHandler)
        self.handler.db = SimpleNamespace(update_task=AsyncMock(), update_request_log=AsyncMock())
        self.handler.flow_client = SimpleNamespace(check_video_status=AsyncMock())
        self.handler._fail_video_task = AsyncMock()
        self.token = SimpleNamespace(id=1, at="access", google_cookies="fixture", user_paygate_tier="PAYGATE_TIER_ONE")
        self.operations = [{"operation": {"name": "submitted-operation"}, "status": "MEDIA_GENERATION_STATUS_ACTIVE"}]
        self.state = {"id": 40, "progress": 45}
        self.result = self.handler._create_generation_result()

    async def poll(self, attempts=4):
        with patch("src.services.generation_handler.config", SimpleNamespace(video_timeout=attempts * 0.1 - 0.05, poll_interval=0.1)), patch("src.services.generation_handler.asyncio.sleep", new=AsyncMock()):
            return [chunk async for chunk in self.handler._poll_video_result(
                self.token, "project", self.operations, False,
                generation_result=self.result, request_log_state=self.state,
            )]

    async def test_poll_auth_failure_preserves_submitted_operation_before_error(self):
        self.handler.flow_client.check_video_status.side_effect = RuntimeError("rpc=jwpduf code=401")
        chunks = await self.poll()
        error = json.loads(chunks[-1])["error"]
        self.assertEqual(error["code"], "video_status_unknown")
        self.assertEqual(error["reason"], "poll_auth_failed")
        self.assertTrue(error["submission_pending"])
        self.assertTrue(error["upstream_accepted"])
        self.assertEqual(error["task_id"], "submitted-operation")
        self.assertTrue(self.result["submission_pending"])
        self.handler._fail_video_task.assert_not_awaited()
        task = self.handler.db.update_task.await_args
        self.assertEqual(task.kwargs["status"], "status_unknown")
        self.assertIsNone(task.kwargs["completed_at"])
        log = self.handler.db.update_request_log.await_args.kwargs
        self.assertEqual(log["status_text"], "video_status_unknown")
        self.assertTrue(json.loads(log["response_body"])["error"]["submission_pending"])
        self.assertEqual(self.handler.flow_client.check_video_status.await_count, 3)

    async def test_local_poll_deadline_does_not_claim_upstream_cancelled(self):
        self.handler.flow_client.check_video_status.return_value = {"operations": self.operations}
        error = json.loads((await self.poll(attempts=2))[-1])["error"]
        self.assertEqual(error["reason"], "poll_deadline")
        self.assertTrue(error["submission_pending"])
        self.assertNotIn("取消", error["message"])
        self.handler._fail_video_task.assert_not_awaited()

    async def test_explicit_upstream_failure_remains_a_confirmed_failure(self):
        self.handler.flow_client.check_video_status.return_value = {"operations": [{
            "status": "MEDIA_GENERATION_STATUS_FAILED", "operation": {
                "name": "submitted-operation", "error": {"code": 9, "message": "fixture rejection"},
            },
        }]}
        error = json.loads((await self.poll())[-1])["error"]
        self.assertEqual(error["code"], "video_generation_failed")
        self.assertFalse(error['submission_pending'])
        self.assertTrue(error['upstream_accepted'])
        self.assertFalse(self.result.get("submission_pending", False))
        self.handler._fail_video_task.assert_awaited_once()
        self.handler.db.update_task.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
