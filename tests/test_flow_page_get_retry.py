"""Only safe Flow page GETs may recover one lost response with HTTP/1.1."""

import asyncio
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from curl_cffi import CurlInfo
from curl_cffi.const import CurlHttpVersion
from curl_cffi.requests.cookies import CurlMorsel
from curl_cffi.requests.exceptions import ConnectionError, HTTPError, Timeout
from curl_cffi.requests.headers import Headers

from src.services.protocol_login import ProtocolLogin, _cookie_jar
from src.services.token_manager import TokenManager
from tests.test_cookie_refresh import COOKIES, NEW_COOKIES, EMAIL, PAGE
from tests.test_flow_frontend_session import _Client


URL = "https://flow.google.com/projects"
PROXY = "http://offline-user:offline-password@proxy.example.test:8022"
COOKIE_HEADER = "OSID=offline-session; SID=offline-account"


def response(*, status=200, url=URL, page=PAGE):
    jar = _cookie_jar(NEW_COOKIES)
    jar.clear("flow.google.com", "/project", "deleted")
    return SimpleNamespace(
        status_code=status, url=url, text=page,
        headers=Headers([("Set-Cookie", "OSID=session-new; Path=/; Secure; HttpOnly")]),
        infos={CurlInfo.COOKIELIST: [
            CurlMorsel.from_cookiejar_cookie(cookie).to_curl_format().encode()
            for cookie in jar
        ]},
    )


class _Session:
    def __init__(self, outcome, *, kwargs, mutate_cookies=False):
        self.kwargs = kwargs
        self.closed = False
        self.initial_cookies = self.cookie_values()

        async def get(*args, **request_kwargs):
            if mutate_cookies and kwargs.get("cookies") is not None:
                for cookie in kwargs["cookies"]:
                    cookie.value = "failed-attempt-cookie"
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        self.get = AsyncMock(side_effect=get)

    def cookie_values(self):
        return [(c.name, c.value, c.domain, c.path, c.secure)
                for c in self.kwargs.get("cookies", ())]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.closed = True


class FlowPageGetRetryTests(unittest.IsolatedAsyncioTestCase):
    def make_call(self, kind, outcomes, *, mutate_cookies=False, url=URL):
        sessions = []
        outcomes = iter(outcomes)

        def factory(**kwargs):
            session = _Session(next(outcomes), kwargs=kwargs,
                               mutate_cookies=mutate_cookies and not sessions)
            if sessions:
                self.assertTrue(sessions[-1].closed, "failed session must close before fallback")
            sessions.append(session)
            return session

        module = "flow_frontend" if kind == "bootstrap" else "protocol_login"
        self.enterContext(patch(f"src.services.{module}.AsyncSession", side_effect=factory))
        warning = self.enterContext(patch(f"src.services.{module}.debug_logger.log_warning"))
        errors = self.enterContext(patch(f"src.services.{module}.debug_logger.log_error"))
        client = _Client()
        client.proxy_manager = SimpleNamespace(
            get_request_proxy_url=AsyncMock(side_effect=[PROXY, "http://changed.example.test:8022"]),
        )
        updates = []

        async def call():
            if kind == "bootstrap":
                return await client._load_flow_frontend_bootstrap(url, COOKIE_HEADER, 12, updates)
            return await ProtocolLogin().login(COOKIES, proxy=PROXY, email=EMAIL)

        return SimpleNamespace(call=call, sessions=sessions, client=client,
                               updates=updates, warning=warning, errors=errors)

    async def assert_failure(self, kind, call):
        if kind == "bootstrap":
            with self.assertRaises(Exception) as caught:
                await call()
            return caught.exception
        result = await call()
        self.assertFalse(result["success"])
        self.assertNotIn("google_cookies", result)
        return result["error"]

    async def test_bootstrap_receive_failures_recover_once_with_fixed_inputs(self):
        for code in (52, 56):
            with self.subTest(code=code):
                case = self.make_call("bootstrap", [ConnectionError("connection lost", code=code), response()])
                self.assertEqual(await case.call(), PAGE)
                self.assertEqual(len(case.sessions), 2)
                first, retry = [s.get.await_args for s in case.sessions]
                self.assertEqual(first.args, retry.args)
                self.assertEqual(retry.kwargs["http_version"], CurlHttpVersion.V1_1)
                self.assertEqual(first.kwargs, {k: v for k, v in retry.kwargs.items() if k != "http_version"})
                self.assertEqual(first.kwargs["proxy"], PROXY)
                self.assertEqual(first.kwargs["headers"]["Cookie"], COOKIE_HEADER)
                case.client.proxy_manager.get_request_proxy_url.assert_awaited_once()
                case.warning.assert_called_once()
                self.assertEqual(len(case.updates), 1)

    async def test_protocol_receive_failures_recover_with_original_cookie_jar(self):
        for code in (52, 56):
            with self.subTest(code=code):
                case = self.make_call("protocol", [ConnectionError("connection lost", code=code), response()],
                                      mutate_cookies=True)
                result = await case.call()
                self.assertTrue(result["success"])
                self.assertEqual(len(case.sessions), 2)
                first, retry = case.sessions
                self.assertEqual(first.initial_cookies, retry.initial_cookies)
                self.assertIsNot(first.kwargs["cookies"], retry.kwargs["cookies"])
                self.assertEqual(
                    {k: v for k, v in first.kwargs.items() if k != "cookies"},
                    {k: v for k, v in retry.kwargs.items() if k != "cookies"},
                )
                initial_call, retry_call = first.get.await_args, retry.get.await_args
                self.assertEqual(initial_call.args, retry_call.args)
                self.assertEqual(retry_call.kwargs["http_version"], CurlHttpVersion.V1_1)
                self.assertEqual(initial_call.kwargs,
                                 {k: v for k, v in retry_call.kwargs.items() if k != "http_version"})
                self.assertEqual(retry.kwargs["proxy"], PROXY)
                self.assertNotIn("failed-attempt-cookie", result["google_cookies"])
                cookies = {c["name"]: c for c in json.loads(result["google_cookies"])}
                self.assertEqual(cookies["OSID"]["value"], "session-new")
                self.assertTrue(cookies["OSID"]["hostOnly"])
                self.assertTrue(cookies["OSID"]["httpOnly"])
                self.assertNotIn("deleted", cookies)
                case.warning.assert_called_once()

    async def test_fallback_is_limited_to_two_attempts(self):
        for kind in ("bootstrap", "protocol"):
            with self.subTest(kind=kind):
                case = self.make_call(kind, [ConnectionError("connection lost", code=56)] * 2 + [response()])
                await self.assert_failure(kind, case.call)
                self.assertEqual(len(case.sessions), 2)
                self.assertTrue(all(s.closed for s in case.sessions))
                self.assertEqual(case.updates, [])
                case.warning.assert_called_once()

    async def test_only_numeric_52_56_may_retry(self):
        for kind in ("bootstrap", "protocol"):
            for code in (7, 16, 28, 35, 92, 0, "56"):
                with self.subTest(kind=kind, code=code):
                    case = self.make_call(kind, [ConnectionError("curl: (56) connection lost", code=code), response()])
                    await self.assert_failure(kind, case.call)
                    self.assertEqual(len(case.sessions), 1)
                    case.warning.assert_not_called()

    async def test_timeout_class_or_text_cannot_retry_even_with_receive_code(self):
        for kind in ("bootstrap", "protocol"):
            for error in (Timeout("private-timeout", code=56), TimeoutError(),
                          ConnectionError("request timed out", code=56)):
                with self.subTest(kind=kind, type=type(error).__name__):
                    case = self.make_call(kind, [error, response()])
                    await self.assert_failure(kind, case.call)
                    self.assertEqual(len(case.sessions), 1)

    async def test_cancel_is_not_retried_or_converted(self):
        for kind in ("bootstrap", "protocol"):
            for during_retry in (False, True):
                with self.subTest(kind=kind, during_retry=during_retry):
                    outcomes = [asyncio.CancelledError(), response()]
                    if during_retry:
                        outcomes.insert(0, ConnectionError("connection lost", code=56))
                    case = self.make_call(kind, outcomes)
                    with self.assertRaises(asyncio.CancelledError):
                        await case.call()
                    self.assertEqual(len(case.sessions), 2 if during_retry else 1)
                    self.assertTrue(all(session.closed for session in case.sessions))

    async def test_completed_http_errors_are_never_retried(self):
        manager = TokenManager(SimpleNamespace(), SimpleNamespace())
        for kind in ("bootstrap", "protocol"):
            for status in (401, 403, 429, 500, 502, 503, 504):
                with self.subTest(kind=kind, status=status):
                    case = self.make_call(kind, [response(status=status, page="UNAUTHENTICATED private-page"), response()])
                    error = await self.assert_failure(kind, case.call)
                    self.assertEqual(len(case.sessions), 1)
                    self.assertEqual(manager._is_authentication_failure(error), status == 401)
                    self.assertNotIn("private-page", str(error))
                    self.assertEqual(case.updates, [])

    async def test_structured_http_failure_overrides_receive_code_and_private_text(self):
        manager = TokenManager(SimpleNamespace(), SimpleNamespace())
        for kind in ("bootstrap", "protocol"):
            for status in (401, 403, 503):
                with self.subTest(kind=kind, status=status):
                    case = self.make_call(kind, [HTTPError("UNAUTHENTICATED private-page", code=56,
                        response=response(status=status)), response()])
                    error = await self.assert_failure(kind, case.call)
                    self.assertEqual(len(case.sessions), 1)
                    self.assertEqual(manager._is_authentication_failure(error), status == 401)
                    if kind == "protocol":
                        self.assertNotIn("private-page", str(error) + str(case.errors.call_args_list))

    async def test_protocol_http_status_survives_missing_cookie_snapshot_or_direct_attribute(self):
        for source in ("response", "exception"):
            with self.subTest(source=source):
                failure = SimpleNamespace(status_code=503, text="private-page", url=URL)
                if source == "exception":
                    failure = ConnectionError("UNAUTHENTICATED private-page", code=56)
                    failure.status_code = 503
                case = self.make_call("protocol", [failure, response()])
                error = await self.assert_failure("protocol", case.call)
                self.assertEqual(len(case.sessions), 1)
                self.assertEqual(error, "Flow Cookie 验证失败: HTTP 503")

    async def test_authentication_text_and_partial_foreign_redirect_do_not_retry(self):
        for kind in ("bootstrap", "protocol"):
            for error in (
                ConnectionError("UNAUTHENTICATED", code=56),
                ConnectionError("HTTP 401", code=56),
                ConnectionError("HTTP 503", code=56),
                ConnectionError("connection lost", code=56,
                    response=response(url="https://accounts.google.com/v3/signin/identifier")),
                ConnectionError("connection lost", code=56,
                    response=response(url="https://unknown.example.test/login")),
            ):
                with self.subTest(kind=kind, error=str(error)):
                    case = self.make_call(kind, [error, response()])
                    await self.assert_failure(kind, case.call)
                    self.assertEqual(len(case.sessions), 1)

    async def test_fallback_does_not_bypass_login_redirect_or_status_checks(self):
        for kind in ("bootstrap", "protocol"):
            for final in (
                response(url="https://accounts.google.com/v3/signin/identifier"),
                response(url="https://foreign.example.test/"),
                response(status=503, url="https://accounts.google.com/signin", page="UNAUTHENTICATED"),
            ):
                with self.subTest(kind=kind, status=final.status_code, url=final.url):
                    case = self.make_call(kind, [ConnectionError("connection lost", code=56), final])
                    await self.assert_failure(kind, case.call)
                    self.assertEqual(len(case.sessions), 2)
                    self.assertEqual(case.updates, [])

    async def test_protocol_fallback_still_requires_frontend_and_matching_account(self):
        for page in ("anonymous", "boq_labs-ai-sandbox-frontend_", PAGE.replace(EMAIL, "other@example.test")):
            with self.subTest(page=page):
                case = self.make_call("protocol", [ConnectionError("connection lost", code=56), response(page=page)])
                await self.assert_failure("protocol", case.call)
                self.assertEqual(len(case.sessions), 2)

    async def test_foreign_or_non_https_bootstrap_url_is_never_retried(self):
        for url in ("https://foreign.example.test/projects", "http://flow.google.com/projects",
                    "https://user@flow.google.com/projects"):
            with self.subTest(url=url):
                case = self.make_call("bootstrap", [ConnectionError("connection lost", code=56), response()], url=url)
                await self.assert_failure("bootstrap", case.call)
                self.assertEqual(len(case.sessions), 1)


if __name__ == "__main__":
    unittest.main()
