import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from src.core.models import Token
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager


PROJECT_ID = "01234567-89ab-cdef-0123-456789abcdef"
MEDIA_ID = "11234567-89ab-cdef-0123-456789abcdef"


class FlowClientImageGenerationArgumentTests(unittest.TestCase):
    def setUp(self):
        self.client = FlowClient(proxy_manager=None)

    def test_reference_images_use_media_envelope(self):
        argument = self.client._build_frontend_image_generation_argument(
            project_id=PROJECT_ID,
            prompt="换成针织开衫",
            model_name="BELUGA",
            aspect_ratio="IMAGE_ASPECT_RATIO_LANDSCAPE",
            recaptcha_token="recaptcha-token",
            session_id="session-id",
            image_inputs=[{"name": MEDIA_ID}],
        )

        request = argument[1][0]
        # the reference slot is a 5-field envelope, not [1, mediaId]
        self.assertEqual(request[2], [[MEDIA_ID, None, None, None, 1]])
        # slot 9 stays null; a serialized settings blob here is rejected
        self.assertIsNone(request[9])
        self.assertEqual(request[8], [[["换成针织开衫"]]])
        self.assertEqual(len(request), 14)
        self.assertEqual(request[12], "session-id")

    def test_text_only_generation_omits_reference_slot(self):
        argument = self.client._build_frontend_image_generation_argument(
            project_id=PROJECT_ID,
            prompt="一只红苹果",
            model_name="BELUGA",
            aspect_ratio="IMAGE_ASPECT_RATIO_LANDSCAPE",
            recaptcha_token="recaptcha-token",
            session_id="session-id",
        )

        request = argument[1][0]
        self.assertIsNone(request[2])
        self.assertIsNone(request[9])

    def test_image_requests_follow_fourteen_slot_layout(self):
        for model_name in ("BELUGA", "HARBOR_SEAL", "GEM_PIX_2"):
            for image_inputs in (None, [{"name": MEDIA_ID}]):
                with self.subTest(model=model_name, references=bool(image_inputs)):
                    argument = self.client._build_frontend_image_generation_argument(
                        project_id=PROJECT_ID,
                        prompt="an apple",
                        model_name=model_name,
                        aspect_ratio="IMAGE_ASPECT_RATIO_LANDSCAPE",
                        recaptcha_token="recaptcha-token",
                        session_id="session-id",
                        image_inputs=image_inputs,
                    )
                    request = argument[1][0]
                    self.assertEqual(len(request), 14)
                    self.assertEqual(request[5], model_name)
                    self.assertEqual(request[9:12], [None, None, None])
                    self.assertEqual(request[12], "session-id")
                    self.assertRegex(request[13], r"^[0-9A-F-]{36}$")
                    self.assertEqual(argument[4], ["session-id"])


class FrontendCookieTokenRefreshTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 3, 5, 0, tzinfo=timezone.utc)
        self.client = FlowClient(proxy_manager=None)
        self.manager = TokenManager(db=AsyncMock(), flow_client=self.client)
        self.clock = patch("src.services.token_manager.datetime", wraps=datetime)
        self.mock_clock = self.clock.start()
        self.mock_clock.now.return_value = self.now
        self.addCleanup(self.clock.stop)

    def make_token(self, remaining_seconds, *, at=None, cookies="SID=fixture"):
        return Token(
            id=1, st="frontend-fixture", email="fixture@example.com",
            at=self.client.FRONTEND_ACCESS_TOKEN if at is None else at,
            at_expires=self.now + timedelta(seconds=remaining_seconds),
            google_cookies=cookies,
        )

    async def test_new_frontend_session_does_not_immediately_refresh_or_disable(self):
        # Use the real frontend st_to_at contract, with only its remote credits
        # call mocked. A new 55-minute placeholder must survive both selection
        # and the subsequent generation validation without another ST refresh.
        self.client.get_credits = AsyncMock(return_value={"credits": 42})
        with patch("src.services.flow_current.datetime", wraps=datetime) as clock:
            clock.now.return_value = self.now
            session = await self.client.st_to_at(google_cookies="OSID=fixture; SID=fixture")
        token = Token(
            id=1, st="frontend-fixture", email="fixture@example.com",
            at=session["access_token"],
            at_expires=datetime.fromisoformat(session["expires"].replace("Z", "+00:00")),
            google_cookies="OSID=fixture; SID=fixture",
        )
        self.assertEqual(token.at_expires - self.now, timedelta(minutes=55))
        self.assertFalse(self.manager.needs_at_refresh(token))
        self.manager._get_credits_for_token = AsyncMock(return_value={"credits": 42})
        self.manager._refresh_at = AsyncMock(return_value=False)
        self.manager.db.get_token.return_value = token
        self.manager.db.commit_token_health_result.return_value = True

        self.assertIs(await self.manager.ensure_valid_token(token), token)
        self.assertIs(await self.manager.ensure_valid_token(token), token)

        self.manager._get_credits_for_token.assert_awaited_once_with(token, token.at)
        self.manager._refresh_at.assert_not_awaited()
        self.manager.db.commit_token_health_result.assert_awaited_once_with(
            token, reason=None, updates={"credits": 42, "user_paygate_tier": None},
        )
        self.manager.db.update_token.assert_not_awaited()

    def test_frontend_refresh_window_boundaries_and_expiration(self):
        for seconds, expected in [(301, False), (300, False), (299, True),
                                  (240, True), (0, True), (-1, True)]:
            with self.subTest(remaining_seconds=seconds):
                self.assertEqual(self.manager.needs_at_refresh(self.make_token(seconds)), expected)

    def test_normal_at_retains_legacy_one_hour_window(self):
        for seconds, expected in [(3601, False), (3600, False), (3599, True),
                                  (3300, True), (0, True)]:
            with self.subTest(remaining_seconds=seconds):
                self.assertEqual(
                    self.manager.needs_at_refresh(self.make_token(seconds, at="ordinary-at")),
                    expected,
                )

    def test_frontend_marker_requires_nonempty_google_cookies(self):
        for cookies in ("", "   "):
            with self.subTest(cookies=cookies):
                self.assertTrue(self.manager.needs_at_refresh(self.make_token(3300, cookies=cookies)))

    def test_frontend_unknown_expiration_still_refreshes(self):
        token = self.make_token(3300)
        token.at_expires = None
        self.assertTrue(self.manager.needs_at_refresh(token))

    def test_frontend_naive_utc_expiration_uses_the_same_window(self):
        token = self.make_token(3300)
        token.at_expires = token.at_expires.replace(tzinfo=None)
        self.assertFalse(self.manager.needs_at_refresh(token))
        token.at_expires = (self.now + timedelta(minutes=4)).replace(tzinfo=None)
        self.assertTrue(self.manager.needs_at_refresh(token))


class NativeImageTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_browser_returns_media_without_captcha_or_http_replay(self):
        client = FlowClient(proxy_manager=None)
        client._frontend_cookie = AsyncMock(return_value="SID=fixture")
        client._resolve_flow_frontend_cookie_storage = AsyncMock(return_value="SID=fixture")
        client._get_recaptcha_token = AsyncMock()
        client._current_rpc = AsyncMock()
        payload = [[[MEDIA_ID, "https://flow-content.example/image/" + MEDIA_ID]]]
        client._submit_browser_native_image = AsyncMock(return_value={
            "rpc": "ogiZ0b", "session_id": "native-session",
            "response_text": json.dumps([["wrb.fr", "ogiZ0b", json.dumps(payload)]]),
        })
        with patch("src.services.flow_current.config") as cfg:
            cfg.captcha_method = "browser"
            result, session, trace = await client.generate_image(
                "at", PROJECT_ID, "requested prompt", "NARWHAL",
                "IMAGE_ASPECT_RATIO_LANDSCAPE", image_inputs=[{"name": MEDIA_ID}],
            )
        client._get_recaptcha_token.assert_not_awaited()
        client._current_rpc.assert_not_awaited()
        args = client._submit_browser_native_image.await_args.kwargs
        self.assertEqual(args["model_name"], "BELUGA")  # retired key is updated before submission
        self.assertEqual(args["prompt"], "requested prompt")
        self.assertEqual(args["image_inputs"], [{"name": MEDIA_ID}])
        self.assertEqual(session, "native-session")
        self.assertEqual(result["media"][0]["name"], MEDIA_ID)
        self.assertEqual(trace["generation_attempts"][0]["transport"], "browser-native-ogiZ0b")


if __name__ == "__main__":
    unittest.main()
