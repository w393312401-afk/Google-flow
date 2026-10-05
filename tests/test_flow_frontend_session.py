import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs

from curl_cffi.requests.headers import Headers

from src.services.flow_frontend import FlowFrontendMixin


BOOTSTRAP = (
    'boq_labs-ai-sandbox-frontend_test '
    '"FdrFJe":"123" "SNlM0e":"initial:token+value"'
)
RPC_RESPONSE = json.dumps([["wrb.fr", "ogiZ0b", "[1]", None, None, None]])
RPC_URL = "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute"


class _Client(FlowFrontendMixin):
    proxy_manager = None

    def __init__(self):
        self._make_text_request = AsyncMock(return_value=RPC_RESPONSE)

    def get_request_fingerprint(self):
        return None

    def _get_effective_request_user_agent(self):
        return "test-browser"

    def _resolve_runtime_impersonate(self):
        return "chrome"

    def _get_primary_accept_language(self, fallback):
        return fallback

    def _compact_json_dumps(self, value):
        return json.dumps(value, separators=(",", ":"))


def _response(*cookies):
    return SimpleNamespace(
        url="https://flow.google.com/project/test-project",
        status_code=200,
        text=BOOTSTRAP,
        headers=Headers([("Set-Cookie", value) for value in cookies]),
    )


class _Session:
    def __init__(self, response):
        self.get = AsyncMock(return_value=response)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FlowFrontendSessionTests(unittest.IsolatedAsyncioTestCase):
    async def _rpc(self, client, cookie_storage=None):
        return await client._call_flow_frontend_rpc(
            rpc_id="ogiZ0b",
            argument=["test"],
            cookie_header="OSID=saved-session; SID=saved-account",
            cookie_storage=cookie_storage,
            timeout=30,
            project_id="test-project",
        )

    async def test_first_rpc_includes_bootstrap_xsrf_token(self):
        client = _Client()
        client._load_flow_frontend_bootstrap = AsyncMock(return_value=BOOTSTRAP)

        self.assertEqual(await self._rpc(client), [1])

        client._make_text_request.assert_awaited_once()
        fields = parse_qs(client._make_text_request.await_args.kwargs["raw_body"])
        self.assertEqual(fields["at"], ["initial:token+value"])
        self.assertEqual(len(fields["f.req"]), 1)

    async def test_xsrf_retry_replaces_token_without_duplicating_form_field(self):
        client = _Client()
        client._load_flow_frontend_bootstrap = AsyncMock(return_value=BOOTSTRAP)
        client._make_text_request.side_effect = [
            '[["xsrf","refreshed:token+value"]]', RPC_RESPONSE
        ]

        await self._rpc(client)

        first, retry = [
            parse_qs(call.kwargs["raw_body"])
            for call in client._make_text_request.await_args_list
        ]
        self.assertEqual(first["at"], ["initial:token+value"])
        self.assertEqual(retry["at"], ["refreshed:token+value"])
        self.assertEqual(first["f.req"], retry["f.req"])

    async def test_missing_bootstrap_xsrf_keeps_challenge_fallback(self):
        client = _Client()
        client._load_flow_frontend_bootstrap = AsyncMock(
            return_value=BOOTSTRAP.split(' "SNlM0e"')[0]
        )
        client._make_text_request.side_effect = [
            '[["xsrf","challenge-token"]]', RPC_RESPONSE
        ]

        await self._rpc(client)

        first, retry = [
            parse_qs(call.kwargs["raw_body"])
            for call in client._make_text_request.await_args_list
        ]
        self.assertNotIn("at", first)
        self.assertEqual(retry["at"], ["challenge-token"])

    async def test_bootstrap_cookies_reach_rpc_with_original_scope_preserved(self):
        client = _Client()
        saved = json.dumps([
            {"name": "OSID", "value": "saved-session", "domain": "flow.google.com",
             "hostOnly": True, "path": "/", "secure": True},
            {"name": "SID", "value": "saved-account", "domain": ".google.com", "path": "/"},
            {"name": "SID", "value": "flow-specific", "domain": "flow.google.com",
             "hostOnly": True, "path": "/"},
            {"name": "SID", "value": "other-host", "domain": "www.google.com",
             "hostOnly": True, "path": "/"},
            {"name": "deleted", "value": "old-value", "domain": "flow.google.com", "path": "/"},
        ])
        response = _response(
            "OSID=renewed-session; Path=/; Secure; HttpOnly",
            "SID=renewed-account; Domain=.google.com; Path=/; Secure",
            "project_only=hidden; Path=/project; Secure",
            "default_path=hidden; Secure",
            "foreign=hidden; Domain=example.com; Path=/",
            "__Secure-invalid=hidden; Path=/",
            "__Host-invalid=hidden; Domain=google.com; Path=/; Secure",
            "deleted=; Path=/; Max-Age=0",
        )
        with patch("src.services.flow_frontend.AsyncSession", return_value=_Session(response)):
            await self._rpc(client, saved)

        header = client._make_text_request.await_args.kwargs["headers"]["Cookie"]
        self.assertEqual(
            header,
            "OSID=renewed-session; SID=renewed-account; SID=flow-specific",
        )
        self.assertIn("saved-session", saved)
        self.assertNotIn("renewed-session", saved)
        self.assertIsNone(client.get_request_fingerprint())

    async def test_bootstrap_cookie_updates_do_not_survive_next_call(self):
        client = _Client()
        responses = [_response("OSID=renewed; Path=/; Secure"), _response()]
        with patch("src.services.flow_frontend.AsyncSession", side_effect=lambda **kw: _Session(responses.pop(0))):
            await self._rpc(client)
            await self._rpc(client)

        first, second = [call.kwargs["headers"]["Cookie"]
                         for call in client._make_text_request.await_args_list]
        self.assertIn("OSID=renewed", first)
        self.assertIn("OSID=saved-session", second)
        self.assertNotIn("renewed", second)

    async def test_stream_chat_also_uses_bootstrap_cookie_updates(self):
        client = _Client()
        client._make_text_request.return_value = "[]"
        client._extract_stream_chat_media_ids = lambda frames: ["test-media"]
        response = _response("OSID=renewed-session; Path=/; Secure")
        with patch("src.services.flow_frontend.AsyncSession", return_value=_Session(response)):
            await client._call_flow_stream_chat(
                project_id="test-project", prompt="test", recaptcha_token="test-token",
                session_id="test-session", cookie_header="OSID=saved-session; SID=account",
                timeout=30,
            )

        call = client._make_text_request.await_args.kwargs
        self.assertEqual(call["headers"]["Cookie"], "OSID=renewed-session; SID=account")
        self.assertEqual(parse_qs(call["raw_body"])["at"], ["initial:token+value"])

    def test_cookie_updates_are_never_forwarded_to_another_host(self):
        updates = FlowFrontendMixin._frontend_bootstrap_cookie_updates(
            _response("SID=renewed; Domain=.google.com; Path=/; Secure")
        )
        header = FlowFrontendMixin._frontend_cookie_header_with_updates(
            json.dumps([{"name": "existing", "value": "other", "url": "https://example.com/"}]),
            "", "https://example.com/", updates,
        )
        self.assertEqual(header, "existing=other")

    def test_epoch_expiry_deletes_saved_cookie_instead_of_becoming_session_cookie(self):
        updates = FlowFrontendMixin._frontend_bootstrap_cookie_updates(
            _response("OSID=expired; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
        )
        header = FlowFrontendMixin._frontend_cookie_header_with_updates(
            None, "OSID=saved-session; SID=account", RPC_URL, updates,
        )
        self.assertEqual(header, "SID=account")

    async def test_redirected_bootstrap_does_not_export_cookies(self):
        response = _response("OSID=untrusted; Path=/; Secure")
        response.url = "https://accounts.google.com/signin"
        updates = []
        with patch("src.services.flow_frontend.AsyncSession", return_value=_Session(response)):
            with self.assertRaisesRegex(RuntimeError, "登录认证失败"):
                await _Client()._load_flow_frontend_bootstrap(
                    "https://flow.google.com/project/test", "OSID=old", 30,
                    cookie_updates=updates,
                )
        self.assertEqual(updates, [])


if __name__ == "__main__":
    unittest.main()
