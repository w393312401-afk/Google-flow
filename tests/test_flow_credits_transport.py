import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs

from curl_cffi.const import CurlHttpVersion
from curl_cffi.requests.exceptions import ConnectionError, HTTPError

from src.services.flow_client import FlowClient
from src.services.flow_frontend import FlowRPCRejected


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
            with self.assertRaisesRegex(Exception, "HTTP Error 401"):
                await self.call_rpc(client)
        session.post.assert_awaited_once()

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
