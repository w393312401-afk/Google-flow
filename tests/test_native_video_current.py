import json
import unittest
from unittest.mock import AsyncMock, patch

from src.services.flow_client import FlowClient


PROJECT = "01234567-89ab-cdef-0123-456789abcdef"
OPERATION = "11234567-89ab-cdef-0123-456789abcdef"
MEDIA = "21234567-89ab-cdef-0123-456789abcdef"


class NativeVideoCurrentTests(unittest.IsolatedAsyncioTestCase):
    async def test_omni_native_submission_returns_pollable_operation_without_solver(self):
        client = FlowClient(proxy_manager=None)
        client._frontend_cookie = AsyncMock(return_value="SID=fixture")
        client._get_recaptcha_token = AsyncMock()
        client._current_rpc = AsyncMock()
        payload = [[[OPERATION, PROJECT, MEDIA]]]
        client._submit_browser_native_video = AsyncMock(return_value={
            "rpc": "YhhmEf",
            "response_text": json.dumps([["wrb.fr", "YhhmEf", json.dumps(payload)]]),
        })
        with patch("src.services.flow_current.config") as cfg:
            cfg.captcha_method = "browser"
            result = await client.generate_video_text(
                "at", PROJECT, "a blue teapot rotates slowly", "abra_t2v_4s",
                "VIDEO_ASPECT_RATIO_LANDSCAPE", token_id=1,
            )
        client._get_recaptcha_token.assert_not_awaited()
        client._current_rpc.assert_not_awaited()
        args = client._submit_browser_native_video.await_args.kwargs
        self.assertEqual(args["model_key"], "abra_t2v_4s")
        self.assertEqual(args["token_id"], 1)
        operation = result["operations"][0]
        self.assertEqual(operation["name"], OPERATION)
        self.assertEqual(operation["mediaName"], MEDIA)
        self.assertEqual(operation["projectId"], PROJECT)
        self.assertEqual(operation["status"], "MEDIA_GENERATION_STATUS_ACTIVE")

    async def test_native_rejection_is_not_reported_as_a_successful_submission(self):
        client = FlowClient(proxy_manager=None)
        client._frontend_cookie = AsyncMock(return_value="SID=fixture")
        client._submit_browser_native_video = AsyncMock(return_value={
            "rpc": "YhhmEf",
            "response_text": json.dumps([["wrb.fr", "YhhmEf", None, None, None,
                                           ["PUBLIC_ERROR_UNUSUAL_ACTIVITY"]]]),
        })
        with patch("src.services.flow_current.config") as cfg:
            cfg.captcha_method = "browser"
            with self.assertRaisesRegex(RuntimeError, "PUBLIC_ERROR_UNUSUAL_ACTIVITY"):
                await client.generate_video_text(
                    "at", PROJECT, "a teapot", "abra_t2v_4s",
                    "VIDEO_ASPECT_RATIO_LANDSCAPE", token_id=1,
                )


if __name__ == "__main__":
    unittest.main()
