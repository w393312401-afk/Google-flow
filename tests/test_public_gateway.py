"""Public edge checks use temporary credentials and an in-process fake backend."""

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
import httpx

from deploy.public_gateway import GatewaySettings, create_app, read_backend_credentials


PUBLIC_KEY = "sk-public-G8zMEi9SfJ2nLBsP7Vd0QaCw8Ht5Ru61"
PUBLIC_PASSWORD = "public-admin-U3Ke91Pa7N4qL0hzrB2Cs6Mv"
BACKEND_KEY = "han1234"
BACKEND_PASSWORD = "admin"
SESSION = "admin-fake-independent-session"


class PublicGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.directory.name) / "test.db")
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                "CREATE TABLE admin_config (id INTEGER PRIMARY KEY, username TEXT, password TEXT, api_key TEXT)"
            )
            connection.execute("INSERT INTO admin_config VALUES (1, ?, ?, ?)",
                               ("admin", BACKEND_PASSWORD, BACKEND_KEY))
        self.settings = GatewaySettings(
            public_origin="https://flow2api.example.com", api_key=PUBLIC_KEY,
            admin_username="admin", admin_password=PUBLIC_PASSWORD,
            backend_url="http://127.0.0.1:38000", database_path=self.database_path,
        )
        self.seen = []
        self.backend_key = BACKEND_KEY
        self.backend_password = BACKEND_PASSWORD
        backend = FastAPI()

        @backend.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
        async def fake_backend(request: Request, path: str):
            body = await request.body()
            self.seen.append({"path": request.url.path, "query": str(request.url.query),
                              "headers": dict(request.headers), "body": body})
            if request.url.path in {"/v1/models/", "/api/login/", "/api/admin/login/"}:
                location = (request.headers.get("x-forwarded-proto", "http") + "://" +
                            request.headers["host"] + request.url.path.rstrip("/"))
                return Response(status_code=307, headers={"location": location})
            if request.url.path.rstrip("/") in {"/api/login", "/api/admin/login"}:
                payload = json.loads(body)
                if payload != {"username": "admin", "password": self.backend_password}:
                    return JSONResponse({"detail": "Invalid backend credentials"}, status_code=401)
                response = JSONResponse({"success": True, "token": SESSION, "username": "admin"})
                response.set_cookie("admin_session", SESSION, httponly=True, samesite="lax")
                response.set_cookie("other_cookie", "second", httponly=True)
                return response
            if request.url.path.startswith(("/v1", "/models")):
                if request.headers.get("authorization") != "Bearer " + self.backend_key:
                    return JSONResponse({"detail": "Bad upstream key"}, status_code=401)
                if request.url.path.endswith("streamGenerateContent"):
                    async def events():
                        yield b"data: first\n\n"
                        await asyncio.sleep(0)
                        yield b"data: second\n\n"
                    return StreamingResponse(events(), media_type="text/event-stream")
                return JSONResponse({"forwarded": True, "body": body.decode()})
            if request.url.path == "/health":
                return JSONResponse({"backend_running": True, "has_active_tokens": True,
                                     "private_runtime_status": "personal-browser"})
            if request.url.path == "/tmp/example.mp4":
                if request.headers.get("range") == "bytes=2-5":
                    return Response(b"2345", status_code=206, headers={
                        "content-range": "bytes 2-5/10", "accept-ranges": "bytes",
                    }, media_type="video/mp4")
                return Response(b"0123456789", media_type="video/mp4")
            if request.url.path in {"/", "/login"}:
                return Response("<html>native login</html>", media_type="text/html")
            if request.url.path == "/api/redirect-test":
                return Response(status_code=307, headers={"location": "http://127.0.0.1:38000/login"})
            authenticated = request.cookies.get("admin_session") == SESSION or (
                request.headers.get("authorization") == "Bearer " + SESSION
            )
            if not authenticated:
                return JSONResponse({"detail": "Missing authorization"}, status_code=401)
            if request.url.path.rstrip("/") == "/api/admin/config":
                return JSONResponse({"admin_username": "admin", "api_key": self.backend_key,
                                     "error_ban_threshold": 3, "debug_enabled": False})
            if request.url.path in {"/manage", "/test"}:
                return Response("<html>native protected page</html>", media_type="text/html")
            return JSONResponse({"admin": True})

        self.app = create_app(self.settings, httpx.ASGITransport(app=backend))
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                        base_url=self.settings.public_origin)

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)
        self.directory.cleanup()

    async def test_backend_weak_key_and_missing_key_rejected_on_all_api_families(self):
        for route in ("/v1/models", "/v1beta/models", "/models", "/models/gemini:generateContent"):
            for headers, query in (({}, ""), ({"authorization": "Bearer " + BACKEND_KEY}, ""),
                                   ({"x-goog-api-key": BACKEND_KEY}, ""), ({}, "?key=" + BACKEND_KEY)):
                with self.subTest(route=route, headers=headers):
                    response = await self.client.get(route + query, headers=headers)
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.headers["access-control-allow-origin"], "*")
        self.assertEqual(self.seen, [])

    async def test_openai_body_and_key_rewrite_remove_supplied_other_credentials(self):
        payload = b'{"model":"model","messages":[{"role":"user","content":"hello"}]}'
        response = await self.client.post("/v1/chat/completions?key=wrong&stream=true", content=payload,
            headers={"authorization": "Bearer " + PUBLIC_KEY, "x-goog-api-key": "also-wrong",
                     "content-type": "application/json", "x-forwarded-host": "attacker.example",
                     "x-forwarded-proto": "http", "forwarded": "host=attacker.example;proto=http",
                     "x-spark-submission-id": "client-submission", "range": "bytes=0-5"})
        self.assertEqual(response.status_code, 200)
        forwarded = self.seen[-1]
        self.assertEqual(forwarded["body"], payload)
        self.assertEqual(forwarded["query"], "stream=true")
        self.assertEqual(forwarded["headers"]["authorization"], "Bearer " + BACKEND_KEY)
        self.assertNotIn("x-goog-api-key", forwarded["headers"])
        self.assertNotIn("forwarded", forwarded["headers"])
        self.assertEqual(forwarded["headers"]["x-forwarded-host"], "flow2api.example.com")
        self.assertEqual(forwarded["headers"]["x-forwarded-proto"], "https")
        self.assertEqual(forwarded["headers"]["host"], "flow2api.example.com")
        self.assertEqual(forwarded["headers"]["x-spark-submission-id"], "client-submission")
        self.assertEqual(forwarded["headers"]["range"], "bytes=0-5")

    async def test_gemini_header_and_query_auth_forwarded_as_backend_bearer(self):
        for path, headers in (("/v1beta/models?key=wrong", {"x-goog-api-key": PUBLIC_KEY}),
                              ("/models?key=" + PUBLIC_KEY + "&alt=sse", {})):
            response = await self.client.get(path, headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(self.seen[-1]["headers"]["authorization"], "Bearer " + BACKEND_KEY)
            self.assertNotIn("key=", self.seen[-1]["query"])
            self.assertNotIn("x-goog-api-key", self.seen[-1]["headers"])

    async def test_auth_priority_does_not_fall_back_from_invalid_higher_priority(self):
        response = await self.client.get("/models?key=" + PUBLIC_KEY,
            headers={"authorization": "Bearer " + BACKEND_KEY, "x-goog-api-key": PUBLIC_KEY})
        self.assertEqual(response.status_code, 401)
        response = await self.client.get("/models?key=" + PUBLIC_KEY,
                                        headers={"x-goog-api-key": BACKEND_KEY})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.seen, [])

    async def test_login_rejects_private_password_and_rewrites_public_credentials(self):
        for path in ("/api/login", "/api/admin/login", "/api/login/", "/api/%6cogin"):
            rejected = await self.client.post(path, json={"username": "admin", "password": BACKEND_PASSWORD})
            self.assertEqual(rejected.status_code, 401)
        self.assertEqual(self.seen, [])
        for path in ("/api/login", "/api/admin/login"):
            response = await self.client.post(path, json={"username": "admin", "password": PUBLIC_PASSWORD})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(json.loads(self.seen[-1]["body"]),
                             {"username": "admin", "password": BACKEND_PASSWORD})
            cookies = response.headers.get_list("set-cookie")
            self.assertEqual(len(cookies), 2)
            self.assertIn("Secure", next(cookie for cookie in cookies if cookie.startswith("admin_session=")))
            self.assertIn("HttpOnly", cookies[0])
            self.assertEqual(response.json()["token"], SESSION)
        for page in ("/manage", "/test"):
            self.assertEqual((await self.client.get(page)).status_code, 200)

    async def test_shared_backend_client_never_forwards_another_users_cookie(self):
        await self.client.post("/api/login", json={"username": "admin", "password": PUBLIC_PASSWORD})
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                    base_url=self.settings.public_origin) as anonymous:
            response = await anonymous.get("/api/admin/config")
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("cookie", self.seen[-1]["headers"])

    async def test_admin_config_requires_admin_session_and_replaces_private_key(self):
        unauthenticated = await self.client.get("/api/admin/config", headers={"authorization": "Bearer " + PUBLIC_KEY})
        self.assertEqual(unauthenticated.status_code, 401)
        response = await self.client.get("/api/admin/config", headers={"authorization": "Bearer " + SESSION})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["api_key"], PUBLIC_KEY)
        self.assertEqual(response.json()["error_ban_threshold"], 3)
        self.assertNotIn(BACKEND_KEY, response.text)
        self.assertEqual(int(response.headers["content-length"]), len(response.content))
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertNotIn("access-control-allow-origin", response.headers)

    async def test_database_credential_changes_apply_to_next_request_without_restarting(self):
        self.backend_key = "changed-local-only-key"
        self.backend_password = "changed-local-only-password"
        with sqlite3.connect(self.database_path) as connection:
            connection.execute("UPDATE admin_config SET api_key = ?, password = ? WHERE id=1",
                               (self.backend_key, self.backend_password))
        response = await self.client.get("/v1/models", headers={"authorization": "Bearer " + PUBLIC_KEY})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.seen[-1]["headers"]["authorization"], "Bearer " + self.backend_key)
        response = await self.client.post("/api/login", json={"username": "admin", "password": PUBLIC_PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(self.seen[-1]["body"])["password"], self.backend_password)
        self.assertEqual(read_backend_credentials(self.database_path).api_key, self.backend_key)

    async def test_blocked_endpoints_never_reach_backend(self):
        for path in ("/metrics", "/metrics/", "/captcha_ws", "/api/admin/change-password",
                     "/api/admin/password/", "/api/admin/apikey", "/api/admin/config",
                     "/api/cache/base-url", "/api/cache/config", "/api/plugin/update-token",
                     "/api/plugin/check-tokens", "/api/admin/%70assword"):
            response = await self.client.post(path, headers={"authorization": "Bearer " + SESSION}, json={})
            self.assertEqual(response.status_code, 403, path)
        self.assertEqual(self.seen, [])

    async def test_double_encoding_does_not_become_login_at_backend(self):
        response = await self.client.post("/api/%256cogin", json={"username": "admin", "password": BACKEND_PASSWORD})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.seen, [])

    async def test_redirects_stay_public_without_being_followed_at_the_gateway(self):
        response = await self.client.get("/v1/models/", headers={"authorization": "Bearer " + PUBLIC_KEY})
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], self.settings.public_origin + "/v1/models")
        self.assertEqual(len(self.seen), 1)
        response = await self.client.post("/api/login/", json={"username": "admin", "password": PUBLIC_PASSWORD})
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], self.settings.public_origin + "/api/login")
        self.assertEqual(json.loads(self.seen[-1]["body"])["password"], BACKEND_PASSWORD)
        response = await self.client.get("/api/redirect-test")
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], self.settings.public_origin + "/login")

    async def test_raw_asgi_traversal_paths_cannot_reach_weak_login_or_mutations(self):
        for path, raw_path in (
            ("/api/x/../admin/login", b"/api/x/../admin/login"),
            ("/api/x/../admin/login", b"/api/x/%2e%2e/admin/login"),
            ("/api/admin/config/../apikey", b"/api/admin/config/%2e%2e/apikey"),
            ("/api/x/%2e%2e/admin/login", b"/api/x/%252e%252e/admin/login"),
            ("/api/admin/config\\..\\apikey", b"/api/admin/config\\..\\apikey"),
            ("/api//admin/login", b"/api//admin/login"),
        ):
            scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
                     "http_version": "1.1", "method": "POST", "scheme": "https",
                     "path": path, "raw_path": raw_path, "query_string": b"", "root_path": "",
                     "server": ("flow2api.example.com", 443), "client": ("127.0.0.1", 1234), "headers": []}
            messages = []

            async def receive():
                return {"type": "http.request", "body": b'{"username":"admin","password":"admin"}', "more_body": False}

            async def send(message):
                messages.append(message)

            await self.app(scope, receive, send)
            self.assertEqual(messages[0]["status"], 404, raw_path)
        self.assertEqual(self.seen, [])

    async def test_health_is_minimal_and_random_media_supports_ranges(self):
        response = await self.client.get("/health")
        self.assertEqual(response.json(), {"backend_running": True})
        response = await self.client.get("/tmp/example.mp4", headers={"range": "bytes=2-5"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.content, b"2345")
        self.assertEqual(response.headers["content-range"], "bytes 2-5/10")
        self.assertEqual(response.headers["accept-ranges"], "bytes")
        self.assertEqual(response.headers["content-type"], "video/mp4")

    async def test_api_sse_response_preserves_event_stream(self):
        response = await self.client.post("/models/gemini:streamGenerateContent?alt=sse",
                                        headers={"x-goog-api-key": PUBLIC_KEY}, json={"contents": []})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"data: first\n\ndata: second\n\n")
        self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
        self.assertNotIn("content-length", response.headers)

    async def test_cors_preflight_scoped_to_api_and_allowlisted_headers(self):
        response = await self.client.options("/v1/chat/completions", headers={
            "origin": "https://client.example", "access-control-request-method": "POST",
            "access-control-request-headers": "Authorization, Content-Type, X-SPARK-Submission-ID",
        })
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers["access-control-allow-origin"], "*")
        self.assertNotIn("access-control-allow-credentials", response.headers)
        self.assertEqual((await self.client.options("/api/login")).status_code, 405)
        response = await self.client.options("/models", headers={"access-control-request-headers": "x-unapproved"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.seen, [])

    async def test_unknown_documentation_paths_are_not_exposed(self):
        for path in ("/docs", "/openapi.json", "/redoc", "/not-a-route"):
            self.assertEqual((await self.client.get(path)).status_code, 404)
        self.assertEqual(self.seen, [])

    async def test_request_errors_are_generic_and_health_failure_reports_down(self):
        async def failing(request):
            raise httpx.ConnectError("contains-private-secret-" + BACKEND_KEY, request=request)
        app = create_app(self.settings, httpx.MockTransport(failing))
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=self.settings.public_origin) as client:
                response = await client.get("/v1/models", headers={"authorization": "Bearer " + PUBLIC_KEY})
                self.assertEqual(response.status_code, 502)
                self.assertNotIn(BACKEND_KEY, response.text)
                response = await client.get("/health")
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json(), {"backend_running": False})

    async def test_response_is_streamed_before_upstream_finishes_and_closes_on_cancel(self):
        release = asyncio.Event()
        first_chunk = asyncio.Event()

        class ControlledStream(httpx.AsyncByteStream):
            closed = False

            async def __aiter__(self):
                yield b"data: first\n\n"
                await release.wait()
                yield b"data: second\n\n"

            async def aclose(self):
                self.closed = True

        upstream_stream = ControlledStream()

        async def transport(request):
            await request.aread()
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=upstream_stream)

        app = create_app(self.settings, httpx.MockTransport(transport))
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
                 "http_version": "1.1", "method": "POST", "scheme": "https",
                 "path": "/v1/chat/completions", "raw_path": b"/v1/chat/completions",
                 "query_string": b"", "root_path": "", "server": ("flow2api.example.com", 443),
                 "client": ("127.0.0.1", 1234),
                 "headers": [(b"authorization", ("Bearer " + PUBLIC_KEY).encode())]}

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(message):
            if message["type"] == "http.response.body" and message.get("body"):
                first_chunk.set()

        async with app.router.lifespan_context(app):
            task = asyncio.create_task(app(scope, receive, send))
            await asyncio.wait_for(first_chunk.wait(), timeout=2)
            self.assertFalse(task.done(), "Gateway must forward first SSE chunk before upstream finishes")
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(upstream_stream.closed)

    async def test_midstream_failure_is_observable_and_sanitized_and_closes_upstream(self):
        class BrokenStream(httpx.AsyncByteStream):
            closed = False

            async def __aiter__(self):
                yield b"data: first\n\n"
                raise httpx.ReadError("secret-private-url-" + BACKEND_KEY)

            async def aclose(self):
                self.closed = True

        upstream_stream = BrokenStream()

        async def transport(request):
            await request.aread()
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=upstream_stream)

        app = create_app(self.settings, httpx.MockTransport(transport))
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=self.settings.public_origin) as client:
                with self.assertRaisesRegex(RuntimeError, "Backend response stream interrupted") as captured:
                    await client.post("/v1/chat/completions", headers={"authorization": "Bearer " + PUBLIC_KEY}, json={})
                self.assertNotIn(BACKEND_KEY, str(captured.exception))
                self.assertIsNone(captured.exception.__cause__)
        self.assertTrue(upstream_stream.closed)

    async def test_request_body_reaches_upstream_before_upload_completes(self):
        uploaded_first = asyncio.Event()
        release_upload = asyncio.Event()
        forwarded_chunks = []

        class BodyStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"ok"

        class UploadTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                async for chunk in request.stream:
                    forwarded_chunks.append(chunk)
                    if chunk:
                        uploaded_first.set()
                return httpx.Response(200, stream=BodyStream())

        app = create_app(self.settings, UploadTransport())
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
                 "http_version": "1.1", "method": "POST", "scheme": "https",
                 "path": "/v1/chat/completions", "raw_path": b"/v1/chat/completions",
                 "query_string": b"", "root_path": "", "server": ("flow2api.example.com", 443),
                 "client": ("127.0.0.1", 1234),
                 "headers": [(b"authorization", ("Bearer " + PUBLIC_KEY).encode())]}
        received_first = False

        async def receive():
            nonlocal received_first
            if not received_first:
                received_first = True
                return {"type": "http.request", "body": b"first", "more_body": True}
            await release_upload.wait()
            return {"type": "http.request", "body": b"second", "more_body": False}

        async def send(message):
            pass

        async with app.router.lifespan_context(app):
            task = asyncio.create_task(app(scope, receive, send))
            await asyncio.wait_for(uploaded_first.wait(), timeout=2)
            self.assertFalse(task.done())
            self.assertEqual(b"".join(forwarded_chunks), b"first")
            release_upload.set()
            await asyncio.wait_for(task, timeout=2)
            self.assertEqual(b"".join(forwarded_chunks), b"firstsecond")


class LocalAdminAuthenticationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.directory.name) / "local-admin.db")
        self.local_username = "local-operator"
        self.local_password = "local-admin-N4jA8vwK2M5zC6xB1wY3Pa0dQ"
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                "CREATE TABLE admin_config (id INTEGER PRIMARY KEY, username TEXT, password TEXT, api_key TEXT)"
            )
            connection.execute("INSERT INTO admin_config VALUES (1, ?, ?, ?)",
                               (self.local_username, self.local_password, BACKEND_KEY))
        self.settings = GatewaySettings(
            public_origin="https://flow2api.example.com", api_key=PUBLIC_KEY,
            admin_username="", admin_password="", admin_auth_mode="local",
            backend_url="http://127.0.0.1:38000", database_path=self.database_path,
        )
        self.seen = []
        self.backend = FastAPI()

        @self.backend.api_route("/{path:path}", methods=["GET", "POST"])
        async def fake_backend(request: Request, path: str):
            body = await request.body()
            self.seen.append({"path": request.url.path, "headers": dict(request.headers), "body": body})
            credentials = read_backend_credentials(self.database_path)
            if request.url.path in {"/api/login", "/api/admin/login"}:
                if json.loads(body) != {"username": credentials.username, "password": credentials.password}:
                    return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
                response = JSONResponse({"success": True, "username": credentials.username, "token": SESSION})
                response.set_cookie("admin_session", SESSION, httponly=True, samesite="lax")
                return response
            if request.url.path in {"/v1/models", "/v1beta/models", "/models"}:
                if request.headers.get("authorization") != "Bearer " + credentials.api_key:
                    return JSONResponse({"detail": "Invalid API key"}, status_code=401)
                return JSONResponse({"data": []})
            if request.cookies.get("admin_session") != SESSION:
                return JSONResponse({"detail": "Missing authorization"}, status_code=401)
            if request.url.path == "/api/admin/config":
                return JSONResponse({"admin_username": credentials.username, "api_key": credentials.api_key})
            return JSONResponse({"admin": True})

        self.app = create_app(self.settings, httpx.ASGITransport(app=self.backend))
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                        base_url=self.settings.public_origin)

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)
        self.directory.cleanup()

    async def test_local_credentials_work_on_both_login_aliases_without_static_admin_config(self):
        for path in ("/api/login", "/api/admin/login"):
            with self.subTest(path=path):
                response = await self.client.post(path, json={
                    "username": self.local_username, "password": self.local_password,
                })
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["username"], self.local_username)
                self.assertEqual(response.json()["token"], SESSION)
                self.assertEqual(json.loads(self.seen[-1]["body"]), {
                    "username": self.local_username, "password": self.local_password,
                })
                self.assertIn("Secure", response.headers["set-cookie"])
                self.assertIn("HttpOnly", response.headers["set-cookie"])

    async def test_local_mode_rejects_old_independent_password_and_wrong_username_before_upstream(self):
        for path in ("/api/login", "/api/admin/login"):
            for username, password in ((self.local_username, PUBLIC_PASSWORD),
                                       ("wrong-operator", self.local_password),
                                       ("", "")):
                with self.subTest(path=path, username=username):
                    response = await self.client.post(path, json={"username": username, "password": password})
                    self.assertEqual(response.status_code, 401)
        self.assertEqual(self.seen, [])

    async def test_local_mode_follows_database_username_and_password_rotation_without_restart(self):
        old_username, old_password = self.local_username, self.local_password
        initial = await self.client.post("/api/login", json={"username": old_username, "password": old_password})
        self.assertEqual(initial.status_code, 200)
        self.local_username = "rotated-local-operator"
        self.local_password = "rotated-local-R4e2Az7Kc8P3vX1m9Lb0Wn6Q"
        with sqlite3.connect(self.database_path) as connection:
            connection.execute("UPDATE admin_config SET username = ?, password = ? WHERE id = 1",
                               (self.local_username, self.local_password))
        self.seen.clear()
        for username, password in ((old_username, old_password),
                                   (old_username, self.local_password),
                                   (self.local_username, old_password)):
            rejected = await self.client.post("/api/login", json={"username": username, "password": password})
            self.assertEqual(rejected.status_code, 401)
        self.assertEqual(self.seen, [])
        for path in ("/api/login", "/api/admin/login"):
            response = await self.client.post(path, json={
                "username": self.local_username, "password": self.local_password,
            })
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["username"], self.local_username)
            self.assertEqual(json.loads(self.seen[-1]["body"]), {
                "username": self.local_username, "password": self.local_password,
            })

    async def test_local_login_preserves_independent_public_api_key_and_config_display(self):
        await self.client.post("/api/login", json={
            "username": self.local_username, "password": self.local_password,
        })
        self.seen.clear()
        for route in ("/v1/models", "/v1beta/models", "/models"):
            for key in (BACKEND_KEY, self.local_password):
                rejected = await self.client.get(route, headers={"authorization": "Bearer " + key})
                self.assertEqual(rejected.status_code, 401)
            self.assertEqual((await self.client.get(route)).status_code, 401)
        self.assertEqual(self.seen, [])
        for route, headers in (("/v1/models", {"authorization": "Bearer " + PUBLIC_KEY}),
                               ("/v1beta/models", {"x-goog-api-key": PUBLIC_KEY}),
                               ("/models?key=" + PUBLIC_KEY, {})):
            response = await self.client.get(route, headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(self.seen[-1]["headers"]["authorization"], "Bearer " + BACKEND_KEY)
        response = await self.client.get("/api/admin/config")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"admin_username": self.local_username, "api_key": PUBLIC_KEY})

    async def test_startup_rejects_public_api_key_equal_to_backend_key_in_both_admin_modes(self):
        with sqlite3.connect(self.database_path) as connection:
            connection.execute("UPDATE admin_config SET api_key = ? WHERE id = 1", (PUBLIC_KEY,))
        for settings in (self.settings, replace(self.settings, admin_auth_mode="independent",
                                              admin_username="public-operator", admin_password=PUBLIC_PASSWORD)):
            with self.subTest(mode=settings.admin_auth_mode):
                app = create_app(settings, httpx.ASGITransport(app=self.backend))
                with self.assertRaisesRegex(RuntimeError, "requires independent credentials"):
                    async with app.router.lifespan_context(app):
                        self.fail("Matching public/backend API keys must prevent startup")

    async def test_independent_mode_still_rejects_same_admin_password_at_startup(self):
        settings = replace(self.settings, admin_auth_mode="independent",
                           admin_username=self.local_username, admin_password=self.local_password)
        app = create_app(settings, httpx.ASGITransport(app=self.backend))
        with self.assertRaisesRegex(RuntimeError, "requires independent credentials"):
            async with app.router.lifespan_context(app):
                self.fail("Independent administrator mode must retain password separation")

    async def test_local_mode_fails_closed_if_database_credentials_disappear(self):
        with sqlite3.connect(self.database_path) as connection:
            connection.execute("DELETE FROM admin_config")
        response = await self.client.post("/api/login", json={
            "username": self.local_username, "password": self.local_password,
        })
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(self.local_password, response.text)
        self.assertEqual(self.seen, [])


class GatewaySettingsTests(unittest.TestCase):
    def test_invalid_public_secrets_and_nonloopback_upstream_rejected(self):
        base = dict(public_origin="https://flow2api.example.com", api_key=PUBLIC_KEY,
                    admin_username="admin", admin_password=PUBLIC_PASSWORD,
                    backend_url="http://127.0.0.1:38000", database_path="/tmp/fake.db")
        for changes in ({"api_key": "han1234"}, {"api_key": "a" * 64},
                        {"admin_password": "admin"}, {"backend_url": "http://attacker.example"},
                        {"backend_url": "http://127.0.0.1:38000/other"},
                        {"public_origin": "http://flow2api.example.com"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                GatewaySettings(**(base | changes))

    def test_unknown_administrator_authentication_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported administrator authentication mode"):
            GatewaySettings(public_origin="https://flow2api.example.com", api_key=PUBLIC_KEY,
                            admin_username="", admin_password="", admin_auth_mode="unknown",
                            backend_url="http://127.0.0.1:38000", database_path="/tmp/fake.db")


if __name__ == "__main__":
    unittest.main()
