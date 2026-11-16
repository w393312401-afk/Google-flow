import builtins
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs

from curl_cffi.const import CurlHttpVersion
from curl_cffi.requests.exceptions import ConnectionError, HTTPError, ProxyError, Timeout

from src.services.flow_client import FlowClient
from src.services.flow_frontend import FlowFrontendBootstrapError, FlowRPCRejected
from src.services.token_manager import TokenManager


BOOTSTRAP = (
    'boq_labs-ai-sandbox-frontend_test '
    '"FdrFJe":"123" "SNlM0e":"test-xsrf"'
)
RPC_URL = "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute"
PROXY = "http://test-user:test-password@proxy.example:8022"


def rpc_response(rpc_id="nzlxg", payload=None):
    return SimpleNamespace(
        status_code=200,
        text=json.dumps([["wrb.fr", rpc_id, json.dumps(payload or [100]), None, None, None]]),
    )


class _Session:
    def __init__(self, outcomes):
        self.post = AsyncMock(side_effect=outcomes)
        self.get = AsyncMock(side_effect=outcomes)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FlowCreditsTransportTests(unittest.IsolatedAsyncioTestCase):
    def client(self):
        # A changed global configuration must not move the fallback to a new route.
        proxy_manager = SimpleNamespace(
            get_request_proxy_url=AsyncMock(side_effect=[PROXY, "http://other.example:8022"]),
        )
        client = FlowClient(proxy_manager)
        client._load_flow_frontend_bootstrap = AsyncMock(return_value=BOOTSTRAP)
        return client

    async def call_rpc(self, client, rpc_id="nzlxg"):
        return await client._call_flow_frontend_rpc(
            rpc_id=rpc_id,
            argument=[],
            cookie_header="OSID=test-session; SID=test-account",
            timeout=10,
        )

    async def test_successful_google_login_redirect_has_structured_auth_evidence(self):
        for path in ("/v3/signin/identifier", "/signin/v2/identifier", "/ServiceLogin", "/AccountChooser"):
            with self.subTest(path=path):
                client = FlowClient(SimpleNamespace(get_request_proxy_url=AsyncMock(return_value=None)))
                session = _Session([SimpleNamespace(
                    status_code=200, url="https://accounts.google.com" + path + "?private=test-secret",
                    text="test-secret-page-body",
                )])
                with patch("src.services.flow_frontend.AsyncSession", return_value=session):
                    with self.assertRaises(FlowFrontendBootstrapError) as caught:
                        await client._load_flow_frontend_bootstrap(
                            "https://flow.google.com/projects", "OSID=test-secret", 10,
                        )
                manager = TokenManager(SimpleNamespace(), client)
                self.assertEqual(manager._authentication_evidence(caught.exception), "login_redirect")
                self.assertEqual(manager._safe_health_error("AT_REFRESH", caught.exception),
                                 "AT_REFRESH: credentials rejected (UNAUTHENTICATED)")
                self.assertNotIn("test-secret", str(caught.exception))
                session.get.assert_awaited_once()

    async def test_bootstrap_http_status_overrides_login_target_and_private_body(self):
        for status in (401, 403, 429, 502, 503, 504):
            with self.subTest(status=status):
                client = FlowClient(SimpleNamespace(get_request_proxy_url=AsyncMock(return_value=None)))
                session = _Session([SimpleNamespace(
                    status_code=status, url="https://accounts.google.com/v3/signin/identifier",
                    text="UNAUTHENTICATED HTTP 401 test-secret-body",
                )])
                with patch("src.services.flow_frontend.AsyncSession", return_value=session):
                    with self.assertRaises(FlowFrontendBootstrapError) as caught:
                        await client._load_flow_frontend_bootstrap(
                            "https://flow.google.com/projects", "OSID=test-secret", 10,
                        )
                manager = TokenManager(SimpleNamespace(), client)
                self.assertEqual(manager._is_authentication_failure(caught.exception), status == 401)
                self.assertEqual(manager._safe_health_error("AT_REFRESH", caught.exception), (
                    "AT_REFRESH: credentials rejected (UNAUTHENTICATED)" if status == 401
                    else f"AT_REFRESH: upstream unavailable (HTTP {status})"
                ))
                self.assertNotIn("test-secret", str(caught.exception))

    async def test_unexpected_bootstrap_redirect_is_not_evidence_of_expired_credentials(self):
        for target in (
            "https://accounts.google.com.evil.test/v3/signin/identifier",
            "https://proxy.example/login?next=https://accounts.google.com/v3/signin/identifier",
            "http://accounts.google.com/v3/signin/identifier",
            "https://accounts.google.com/unknown",
            "https://accounts.google.com/ServiceLoginNotActually",
        ):
            with self.subTest(target=target):
                client = FlowClient(SimpleNamespace(get_request_proxy_url=AsyncMock(return_value=None)))
                session = _Session([SimpleNamespace(status_code=200, url=target, text="UNAUTHENTICATED")])
                with patch("src.services.flow_frontend.AsyncSession", return_value=session):
                    with self.assertRaises(FlowFrontendBootstrapError) as caught:
                        await client._load_flow_frontend_bootstrap(
                            "https://flow.google.com/projects", "OSID=test-secret", 10,
                        )
                manager = TokenManager(SimpleNamespace(), client)
                self.assertFalse(manager._is_authentication_failure(caught.exception))
                self.assertEqual(manager._safe_health_error("AT_REFRESH", caught.exception),
                                 "AT_REFRESH: upstream validation response invalid")
                self.assertNotIn(target, str(caught.exception))

    async def test_receive_failures_retry_once_with_http1_and_identical_request(self):
        for code in (52, 56):
            with self.subTest(code=code):
                client = self.client()
                session = _Session([
                    ConnectionError("test connection lost", code=code), rpc_response(),
                ])
                with patch("src.services.flow_client.AsyncSession", return_value=session):
                    self.assertEqual(await self.call_rpc(client), [100])

                first, retry = session.post.await_args_list
                self.assertEqual(first.args, retry.args)
                self.assertEqual(retry.kwargs["http_version"], CurlHttpVersion.V1_1)
                self.assertNotIn("http_version", first.kwargs)
                self.assertEqual(
                    first.kwargs,
                    {key: value for key, value in retry.kwargs.items() if key != "http_version"},
                )
                self.assertEqual(first.kwargs["proxy"], PROXY)
                self.assertEqual(first.kwargs["headers"]["Cookie"], "OSID=test-session; SID=test-account")
                self.assertEqual(parse_qs(first.kwargs["data"])["at"], ["test-xsrf"])
                client.proxy_manager.get_request_proxy_url.assert_awaited_once()
                client._load_flow_frontend_bootstrap.assert_awaited_once()

    async def test_account_proxy_override_is_preserved(self):
        client = self.client()
        account_proxy = "http://account-user:account-password@account-proxy.example:8022"
        client._set_request_fingerprint({"proxy_url": account_proxy})
        session = _Session([ConnectionError("connection lost", code=56), rpc_response()])
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            await self.call_rpc(client)
        self.assertEqual([call.kwargs["proxy"] for call in session.post.await_args_list],
                         [account_proxy, account_proxy])
        self.assertEqual(client.get_request_fingerprint()["proxy_url"], account_proxy)

    async def test_other_rpcs_are_never_replayed(self):
        for rpc_id in ("ogiZ0b", "YhhmEf", "jHPbke"):
            with self.subTest(rpc_id=rpc_id):
                client = self.client()
                session = _Session([ConnectionError("connection lost", code=56)])
                with patch("src.services.flow_client.AsyncSession", return_value=session):
                    with self.assertRaisesRegex(Exception, "text request failed"):
                        await self.call_rpc(client, rpc_id)
                session.post.assert_awaited_once()

    async def test_persistent_failure_stops_after_two_attempts_and_logs_no_private_exception(self):
        client = self.client()
        private_error = "curl: (56) test-secret-cookie test-secret-proxy-password"
        session = _Session([ConnectionError(private_error, code=56)] * 2)
        with patch("src.services.flow_client.AsyncSession", return_value=session), \
             patch("src.services.flow_client.debug_logger.log_warning") as warning, \
             patch("src.services.flow_client.debug_logger.log_error") as error:
            with self.assertRaisesRegex(Exception, "text request failed"):
                await self.call_rpc(client)
        self.assertEqual(session.post.await_count, 2)
        warning.assert_called_once()
        self.assertNotIn("test-secret", str(warning.call_args_list) + str(error.call_args_list))

    async def test_authentication_rejection_is_not_retried(self):
        client = self.client()
        response = SimpleNamespace(
            status_code=200,
            text=json.dumps([["er", "nzlxg", None, None, None, 401]]),
        )
        session = _Session([response])
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            with self.assertRaises(FlowRPCRejected):
                await self.call_rpc(client)
        session.post.assert_awaited_once()

    async def test_http_authentication_error_overrides_transport_error_code(self):
        client = self.client()
        session = _Session([HTTPError(
            "HTTP Error 401", code=56, response=SimpleNamespace(status_code=401),
        )])
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            with self.assertRaisesRegex(Exception, "HTTP 401"):
                await self.call_rpc(client)
        session.post.assert_awaited_once()

    async def test_credits_http_status_survives_without_private_body_or_transport_retry(self):
        for status in (401, 403, 429, 500, 502, 503, 504):
            with self.subTest(status=status):
                client = self.client()
                # Both a valid-looking RPC payload and an XSRF challenge in an
                # error body must remain an HTTP failure, never success/replay.
                response = SimpleNamespace(status_code=status, text=(
                    '<html>test-secret-cookie test-secret-password</html>'
                    + rpc_response().text + ' [["xsrf","test-secret-xsrf"]]'))
                session = _Session([response])
                with patch("src.services.flow_client.AsyncSession", return_value=session), \
                     patch("src.services.flow_client.debug_logger.log_error") as log_error:
                    with self.assertRaisesRegex(Exception, f"HTTP {status}") as caught:
                        await self.call_rpc(client)
                session.post.assert_awaited_once()
                self.assertEqual(caught.exception.status_code, status)
                self.assertNotIn("test-secret", str(caught.exception) + str(log_error.call_args_list))
                manager = TokenManager(SimpleNamespace(), client)
                self.assertEqual(manager._is_authentication_failure(caught.exception), status == 401)
                reason = manager._safe_health_error("AT_REFRESH", caught.exception)
                self.assertIn("credentials rejected" if status == 401 else f"HTTP {status}", reason)
                self.assertNotIn("unclassified", reason)

    async def test_structured_transport_http_status_reaches_classifier_without_private_text(self):
        for status in (401, 403, 500, 503):
            with self.subTest(status=status):
                client = self.client()
                session = _Session([HTTPError(
                    "UNAUTHENTICATED HTTP 401 test-secret-private-response", code=56,
                    response=SimpleNamespace(status_code=status),
                )])
                with patch("src.services.flow_client.AsyncSession", return_value=session):
                    with self.assertRaises(Exception) as caught:
                        await self.call_rpc(client)
                session.post.assert_awaited_once()
                failure = caught.exception
                self.assertEqual(failure.status_code, status)
                self.assertNotIn("test-secret", str(failure))
                manager = TokenManager(SimpleNamespace(), client)
                self.assertEqual(manager._is_authentication_failure(failure), status == 401)
                self.assertEqual(manager._safe_health_error("AT_REFRESH", failure), (
                    "AT_REFRESH: credentials rejected (UNAUTHENTICATED)" if status == 401
                    else f"AT_REFRESH: upstream unavailable (HTTP {status})"
                ))

    async def test_empty_transport_network_types_survive_real_rpc_boundary(self):
        for failure in (builtins.TimeoutError(), builtins.ConnectionError(), ConnectionError(""), Timeout(""), ProxyError("")):
            with self.subTest(error_type=type(failure).__name__):
                client = self.client()
                session = _Session([failure])
                with patch("src.services.flow_client.AsyncSession", return_value=session):
                    with self.assertRaises((builtins.TimeoutError, builtins.ConnectionError)) as caught:
                        await self.call_rpc(client)
                session.post.assert_awaited_once()
                manager = TokenManager(SimpleNamespace(), client)
                self.assertFalse(manager._is_authentication_failure(caught.exception))
                self.assertEqual(manager._safe_health_error("AT_REFRESH", caught.exception),
                                 "AT_REFRESH: network or proxy unavailable")

    async def test_debug_redaction_covers_proxy_headers_url_body_and_exception(self):
        for response in (
            SimpleNamespace(status_code=200, text="test-secret-response"),
            SimpleNamespace(status_code=503, text="test-secret-response"),
            ConnectionError("test-secret-exception", code=56),
        ):
            with self.subTest(outcome_type=type(response).__name__, status=getattr(response, "status_code", None)):
                client = self.client()
                client._set_request_fingerprint({"proxy_url": PROXY, "user_agent": "test-secret-user-agent"})
                session = _Session([response])
                with patch("src.services.flow_client.AsyncSession", return_value=session), \
                     patch("src.services.flow_client.config", SimpleNamespace(debug_enabled=True)), \
                     patch("src.services.flow_client.debug_logger") as logger:
                    try:
                        await client._make_text_request(
                            method="POST", url=RPC_URL + "?rpcids=nzlxg&private=test-secret-query",
                            headers={"Cookie": "test-secret-cookie"}, raw_body="test-secret-request-body",
                            redact_sensitive_logs=True,
                        )
                    except Exception as failure:
                        self.assertNotIn("test-secret", str(failure))
                    logs = str(logger.mock_calls)
                    for private in ("test-secret", "test-password", "test-user", "proxy.example", PROXY):
                        self.assertNotIn(private, logs)
                    logger.log_request.assert_called_once()
                    self.assertEqual(logger.log_request.call_args.kwargs["url"], "<redacted>")
                    self.assertIsNone(logger.log_request.call_args.kwargs["proxy"])
                # Redaction affects observation only, preserving the actual route
                # and authenticated request that the transport receives.
                session.post.assert_awaited_once()
                self.assertEqual(session.post.await_args.kwargs["proxy"], PROXY)
                self.assertEqual(session.post.await_args.kwargs["headers"]["Cookie"], "test-secret-cookie")
                self.assertEqual(session.post.await_args.kwargs["data"], "test-secret-request-body")

    async def test_sanitized_generation_failure_keeps_sent_guard_and_never_replays(self):
        client = self.client()
        observer = AsyncMock()
        client.set_generation_sent_callback(observer)
        failure = ConnectionError("test-secret-private-transport-error", code=56)
        failure.submission_uncertain = True
        session = _Session([failure])
        try:
            with patch("src.services.flow_client.AsyncSession", return_value=session):
                with self.assertRaises(builtins.ConnectionError) as caught:
                    await self.call_rpc(client, "YhhmEf")
                self.assertTrue(caught.exception.submission_uncertain)
                self.assertNotIn("test-secret", str(caught.exception))
                self.assertTrue(client._generation_request_was_sent())
                with self.assertRaisesRegex(RuntimeError, "already sent; replay disabled"):
                    await self.call_rpc(client, "YhhmEf")
            session.post.assert_awaited_once()
            observer.assert_awaited_once()
        finally:
            client.clear_generation_sent_callback()

    async def test_credits_successful_xsrf_challenge_retries_once_with_replaced_token(self):
        client = self.client()
        session = _Session([
            SimpleNamespace(status_code=200, text='[["xsrf","refreshed-xsrf"]]'),
            rpc_response(),
        ])
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            self.assertEqual(await self.call_rpc(client), [100])
        self.assertEqual(session.post.await_count, 2)
        first, retry = [parse_qs(call.kwargs["data"]) for call in session.post.await_args_list]
        self.assertEqual(first["at"], ["test-xsrf"])
        self.assertEqual(retry["at"], ["refreshed-xsrf"])
        self.assertEqual(first["f.req"], retry["f.req"])
        client._load_flow_frontend_bootstrap.assert_awaited_once()

    async def test_credits_http_failure_after_xsrf_retry_retains_status_and_stops(self):
        client = self.client()
        session = _Session([
            SimpleNamespace(status_code=200, text='[["xsrf","refreshed-xsrf"]]'),
            SimpleNamespace(status_code=503, text='<html>test-secret-response</html>'),
        ])
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            with self.assertRaisesRegex(Exception, "HTTP 503") as caught:
                await self.call_rpc(client)
        self.assertEqual(session.post.await_count, 2)
        self.assertNotIn("test-secret", str(caught.exception))

    async def test_repeated_credits_xsrf_challenge_does_not_send_a_third_post(self):
        client = self.client()
        session = _Session([
            SimpleNamespace(status_code=200, text='[["xsrf","refreshed-xsrf"]]'),
        ] * 2)
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            with self.assertRaisesRegex(RuntimeError, "no payload"):
                await self.call_rpc(client)
        self.assertEqual(session.post.await_count, 2)

    async def test_timeout_is_not_retried_by_http1_fallback(self):
        client = self.client()
        session = _Session([ConnectionError("timed out", code=28)])
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            with self.assertRaisesRegex(Exception, "timed out"):
                await self.call_rpc(client)
        session.post.assert_awaited_once()

    async def test_opt_in_cannot_replay_generation_mixed_or_foreign_requests(self):
        for url in (
            RPC_URL + "?rpcids=ogiZ0b",
            RPC_URL + "?rpcids=nzlxg,ogiZ0b",
            RPC_URL + "?rpcids=nzlxg&rpcids=ogiZ0b",
            "https://other.example/batchexecute?rpcids=nzlxg",
        ):
            with self.subTest(url=url):
                client = self.client()
                session = _Session([ConnectionError("connection lost", code=56)])
                with patch("src.services.flow_client.AsyncSession", return_value=session):
                    with self.assertRaisesRegex(Exception, "text request failed"):
                        await client._make_text_request(
                            method="POST", url=url, raw_body="test-body",
                            allow_http1_fallback=True, redact_sensitive_logs=True,
                        )
                session.post.assert_awaited_once()

    async def test_default_text_request_keeps_existing_transport_without_retry(self):
        client = self.client()
        session = _Session([ConnectionError("connection lost", code=56)])
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            with self.assertRaisesRegex(Exception, "text request failed"):
                await client._make_text_request(
                    method="POST", url=RPC_URL + "?rpcids=nzlxg", raw_body="test-body",
                )
        session.post.assert_awaited_once()
        self.assertNotIn("http_version", session.post.await_args.kwargs)

    async def test_explicit_http1_is_not_retried_again(self):
        client = self.client()
        session = _Session([ConnectionError("connection lost", code=56)])
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            with self.assertRaisesRegex(Exception, "text request failed"):
                await client._make_text_request(
                    method="POST", url=RPC_URL + "?rpcids=nzlxg", raw_body="test-body",
                    http_version=CurlHttpVersion.V1_1, allow_http1_fallback=True,
                )
        session.post.assert_awaited_once()
        self.assertEqual(session.post.await_args.kwargs["http_version"], CurlHttpVersion.V1_1)

    async def test_get_request_cannot_opt_into_post_replay(self):
        client = self.client()
        session = _Session([ConnectionError("connection lost", code=56)])
        with patch("src.services.flow_client.AsyncSession", return_value=session):
            with self.assertRaisesRegex(Exception, "text request failed"):
                await client._make_text_request(
                    method="GET", url=RPC_URL + "?rpcids=nzlxg", allow_http1_fallback=True,
                )
        session.get.assert_awaited_once()
        session.post.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
