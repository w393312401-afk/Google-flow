"""Isolated public edge for the existing, unchanged loopback Flow2API service.

Run with FLOW2API_PUBLIC_CONFIG pointing at a private JSON file containing
public_origin, api_key, admin_username, admin_password, backend_url and
database_path. Running this file directly binds only 127.0.0.1:38001 and disables
access logging, including query-string API keys. No backend settings are written.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass, field
import hmac
import json
import os
from pathlib import Path
import sqlite3
from typing import AsyncIterator
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import anyio
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, Response, StreamingResponse
import httpx


HOP_HEADERS = {
    b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization",
    b"te", b"trailer", b"transfer-encoding", b"upgrade", b"proxy-connection",
}
API_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
CORS_HEADERS = {
    "accept", "authorization", "content-type", "range", "x-goog-api-key",
    "x-goog-api-client", "x-goog-user-project", "x-spark-submission-id",
    "openai-beta", "openai-organization", "openai-project",
    "x-stainless-lang", "x-stainless-package-version", "x-stainless-os",
    "x-stainless-arch", "x-stainless-runtime", "x-stainless-runtime-version",
    "x-stainless-retry-count", "x-stainless-timeout", "x-stainless-helper-method",
}
LOGIN_PATHS = {"/api/login", "/api/admin/login"}
CREDENTIAL_PATHS = {
    "/api/admin/change-password", "/api/admin/password", "/api/admin/apikey",
}
LOCAL_MUTATION_PATHS = {"/api/cache/base-url", "/api/cache/config"}
LOCAL_PLUGIN_PATHS = {"/api/plugin/update-token", "/api/plugin/check-tokens"}
MAX_LOGIN_BYTES = 16384
MAX_CONFIG_BYTES = 65536


@dataclass(frozen=True)
class GatewaySettings:
    public_origin: str
    api_key: str = field(repr=False)
    admin_username: str
    admin_password: str = field(repr=False)
    backend_url: str
    database_path: str

    def __post_init__(self) -> None:
        public = urlsplit(self.public_origin)
        backend = urlsplit(self.backend_url)
        if (
            public.scheme != "https" or not public.hostname
            or public.username or public.password or public.query or public.fragment
            or public.path not in {"", "/"}
        ):
            raise ValueError("public_origin must be an HTTPS origin")
        if (
            backend.scheme != "http"
            or backend.hostname not in {"127.0.0.1", "localhost", "::1"}
            or backend.username or backend.password or backend.query or backend.fragment
            or backend.path not in {"", "/"}
        ):
            raise ValueError("backend_url must be a loopback HTTP origin")
        # Force port parsing here, so malformed configuration fails before serving.
        public.port
        backend.port
        for secret, minimum in ((self.api_key, 32), (self.admin_password, 24)):
            if not isinstance(secret, str) or len(secret) < minimum or len(set(secret)) < 8:
                raise ValueError("Public credentials must be long, independent secrets")
        if not isinstance(self.admin_username, str) or not self.admin_username:
            raise ValueError("A public admin username is required")
        if not Path(self.database_path).is_absolute():
            raise ValueError("database_path must be absolute")

    @property
    def public_host(self) -> str:
        return urlsplit(self.public_origin).netloc


def load_settings() -> GatewaySettings:
    try:
        filename = os.environ["FLOW2API_PUBLIC_CONFIG"]
        with open(filename, encoding="utf-8") as handle:
            return GatewaySettings(**json.load(handle))
    except (OSError, KeyError, TypeError, ValueError):
        # Do not include the file's contents or submitted credentials in errors.
        raise RuntimeError("Public gateway configuration is unavailable or invalid") from None


@dataclass(frozen=True)
class BackendCredentials:
    username: str
    password: str = field(repr=False)
    api_key: str = field(repr=False)


def read_backend_credentials(database_path: str) -> BackendCredentials:
    """Read the effective admin row without opening any writable SQLite handle."""
    uri = Path(database_path).as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=2)) as connection:
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute(
            "SELECT username, password, api_key FROM admin_config WHERE id = 1"
        ).fetchone()
    if row is None or not all(isinstance(value, str) and value for value in row):
        raise ValueError("Backend credentials are unavailable")
    return BackendCredentials(*row)


def _matches(candidate: object, expected: str) -> bool:
    return isinstance(candidate, str) and hmac.compare_digest(
        candidate.encode("utf-8"), expected.encode("utf-8")
    )


def _api_path(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/")
               for prefix in ("/v1", "/v1beta", "/models"))


def _blocked(path: str, method: str) -> bool:
    normalized = path.rstrip("/") or "/"
    return (
        normalized in CREDENTIAL_PATHS
        or normalized in LOCAL_PLUGIN_PATHS
        or normalized in LOCAL_MUTATION_PATHS and method not in {"GET", "HEAD"}
        or normalized == "/api/admin/config" and method not in {"GET", "HEAD"}
        or any(normalized == prefix or normalized.startswith(prefix + "/")
               for prefix in ("/metrics", "/captcha_ws"))
    )


def _public_api_key(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "").split(None, 1)
    if len(authorization) == 2 and authorization[0].lower() == "bearer":
        return authorization[1]
    return request.headers.get("x-goog-api-key") or request.query_params.get("key")


def _connection_headers(headers: list[tuple[bytes, bytes]]) -> set[bytes]:
    nominated = set()
    for name, value in headers:
        if name.lower() == b"connection":
            nominated.update(item.strip().lower() for item in value.split(b","))
    return HOP_HEADERS | nominated


def _request_headers(request: Request, settings: GatewaySettings, *, api_key: str | None,
                     rewritten_body: bool = False) -> list[tuple[bytes, bytes]]:
    raw = list(request.headers.raw)
    dropped = _connection_headers(raw) | {b"host", b"forwarded", b"accept-encoding"}
    if api_key is not None:
        dropped |= {b"authorization", b"x-goog-api-key"}
    if rewritten_body:
        dropped |= {b"content-length", b"content-type", b"content-encoding"}
    headers = [(name, value) for name, value in raw
               if name.lower() not in dropped and not name.lower().startswith(b"x-forwarded-")]
    headers.extend([
        (b"host", settings.public_host.encode("ascii")),
        (b"x-forwarded-host", settings.public_host.encode("ascii")),
        (b"x-forwarded-proto", b"https"),
        (b"accept-encoding", b"identity"),
    ])
    if api_key is not None:
        headers.append((b"authorization", ("Bearer " + api_key).encode("utf-8")))
    if rewritten_body:
        headers.append((b"content-type", b"application/json"))
    return headers


def _response_headers(upstream: httpx.Response, settings: GatewaySettings,
                      *, transformed: bool = False) -> list[tuple[bytes, bytes]]:
    raw = list(upstream.headers.raw)
    dropped = _connection_headers(raw)
    if transformed:
        dropped |= {b"content-length", b"content-encoding", b"etag", b"content-md5", b"cache-control"}
    headers = []
    for name, value in raw:
        lowered = name.lower()
        if lowered in dropped or lowered.startswith(b"access-control-"):
            continue
        if lowered == b"set-cookie" and value.split(b"=", 1)[0].strip() == b"admin_session":
            if b"secure" not in {part.strip().lower() for part in value.split(b";")[1:]}:
                value += b"; Secure"
        if lowered == b"location":
            # Absolute loopback redirects should stay on the public origin.
            backend = settings.backend_url.rstrip("/").encode("ascii")
            if value == backend or value.startswith(backend + b"/"):
                value = settings.public_origin.rstrip("/").encode("ascii") + value[len(backend):]
        headers.append((lowered, value))
    return headers


def _cors(response: Response) -> Response:
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Expose-Headers"] = (
        "Content-Range, Accept-Ranges, X-SPARK-Submission-ID, X-Request-ID"
    )
    return response


def _error(status: int, detail: str, *, api: bool = False) -> Response:
    response = JSONResponse({"detail": detail}, status_code=status)
    return _cors(response) if api else response


async def _close(upstream: httpx.Response) -> None:
    with anyio.CancelScope(shield=True):
        await upstream.aclose()


async def _raw_stream(upstream: httpx.Response) -> AsyncIterator[bytes]:
    try:
        async for chunk in upstream.aiter_raw():
            yield chunk
    except httpx.HTTPError:
        # Keep interruption observable to clients without exposing exception text
        # containing a private upstream URL or request headers.
        raise RuntimeError("Backend response stream interrupted") from None
    finally:
        await _close(upstream)


class UpstreamStreamingResponse(StreamingResponse):
    """Also close when the client disconnects before the iterator first runs."""

    def __init__(self, upstream: httpx.Response):
        self.upstream = upstream
        super().__init__(_raw_stream(upstream), status_code=upstream.status_code)

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await _close(self.upstream)


async def _limited_body(chunks: AsyncIterator[bytes], maximum: int) -> bytes:
    body = bytearray()
    async for chunk in chunks:
        if len(body) + len(chunk) > maximum:
            raise ValueError("Payload too large")
        body.extend(chunk)
    return bytes(body)


def create_app(settings: GatewaySettings | None = None,
               transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        configuration = settings or load_settings()
        try:
            credentials = await asyncio.to_thread(read_backend_credentials, configuration.database_path)
        except (sqlite3.Error, OSError, ValueError):
            raise RuntimeError("Public gateway backend credentials are unavailable") from None
        if _matches(configuration.api_key, credentials.api_key) or _matches(
            configuration.admin_password, credentials.password
        ):
            raise RuntimeError("Public gateway requires independent credentials")
        application.state.settings = configuration
        async with httpx.AsyncClient(
            transport=transport, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(connect=10, read=3600, write=3600, pool=30),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        ) as client:
            application.state.client = client
            yield

    application = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @application.websocket("/{path:path}")
    async def reject_websocket(websocket: WebSocket, path: str):
        await websocket.close(code=1008)

    @application.api_route("/{path:path}", methods=sorted(API_METHODS))
    async def proxy(request: Request, path: str):
        configuration: GatewaySettings = request.app.state.settings
        client: httpx.AsyncClient = request.app.state.client
        public_path = request.url.path
        normalized = public_path.rstrip("/") or "/"
        api = _api_path(public_path)
        # httpx normalizes literal dot segments. Reject them before forwarding so
        # an allowed admin path cannot become an unguarded login/config endpoint.
        if "\\" in public_path or "%" in public_path or "//" in public_path or any(
            segment in {".", ".."} for segment in public_path.split("/")
        ):
            return _error(404, "Not found", api=api)
        if _blocked(public_path, request.method):
            return _error(403, "This endpoint is available only on the local service", api=api)
        if not (api or public_path.startswith("/api/") or public_path.startswith("/tmp/")
                or normalized in {"/", "/login", "/manage", "/test", "/health"}):
            return _error(404, "Not found")
        if request.method == "OPTIONS":
            if not api:
                return _error(405, "Method not allowed")
            method = request.headers.get("access-control-request-method", "GET").upper()
            wanted = {item.strip().lower() for item in request.headers.get(
                "access-control-request-headers", ""
            ).split(",") if item.strip()}
            if method not in API_METHODS - {"OPTIONS"} or not wanted.issubset(CORS_HEADERS):
                return _error(400, "Unsupported CORS preflight", api=True)
            response = _cors(Response(status_code=204))
            response.headers["Access-Control-Allow-Methods"] = "GET, HEAD, POST, PUT, PATCH, DELETE"
            response.headers["Access-Control-Allow-Headers"] = ", ".join(sorted(CORS_HEADERS))
            response.headers["Access-Control-Max-Age"] = "600"
            return response
        if api and not _matches(_public_api_key(request), configuration.api_key):
            return _error(401, "Invalid API key", api=True)

        backend_key = None
        body: bytes | AsyncIterator[bytes] = request.stream()
        rewrite_login = normalized in LOGIN_PATHS
        if rewrite_login and request.method != "POST":
            return _error(405, "Method not allowed")
        if api or rewrite_login:
            try:
                credentials = await asyncio.to_thread(read_backend_credentials, configuration.database_path)
            except (sqlite3.Error, OSError, ValueError):
                return _error(503, "Backend credentials are unavailable", api=api)
            if api:
                backend_key = credentials.api_key
            else:
                try:
                    submitted = json.loads(await _limited_body(request.stream(), MAX_LOGIN_BYTES))
                except (ValueError, UnicodeDecodeError):
                    return _error(400, "Invalid login request")
                if not isinstance(submitted, dict) or not (
                    _matches(submitted.get("username"), configuration.admin_username)
                    and _matches(submitted.get("password"), configuration.admin_password)
                ):
                    return _error(401, "Invalid credentials")
                body = json.dumps({"username": credentials.username, "password": credentials.password}).encode()

        query = request.scope.get("query_string", b"")
        if api or rewrite_login:
            query = urlencode([(name, value) for name, value in parse_qsl(
                query.decode("latin-1"), keep_blank_values=True
            ) if name != "key"]).encode("ascii")
        # Preserve original escapes; passing the already decoded path would decode
        # percent-escaped paths a second time at the backend and bypass guards.
        raw_path = request.scope.get("raw_path") or quote(public_path, safe="/").encode("ascii")
        url = httpx.URL(configuration.backend_url).copy_with(
            raw_path=raw_path + (b"?" + query if query else b"")
        )
        headers = _request_headers(request, configuration, api_key=backend_key, rewritten_body=rewrite_login)
        # Explicit Request avoids applying the shared AsyncClient cookie jar.
        # Session cookies received for one user must never authenticate another.
        outgoing = httpx.Request(request.method, url, headers=headers, content=body)
        try:
            upstream = await client.send(outgoing, stream=True)
        except httpx.HTTPError:
            if normalized == "/health":
                return JSONResponse({"backend_running": False}, status_code=503)
            return _error(502, "Backend request failed", api=api)

        if normalized == "/health":
            running = upstream.is_success
            await _close(upstream)
            return JSONResponse({"backend_running": running}, status_code=200 if running else 503)
        if normalized == "/api/admin/config" and request.method == "GET" and upstream.is_success:
            try:
                payload = json.loads(await _limited_body(upstream.aiter_bytes(), MAX_CONFIG_BYTES))
                if not isinstance(payload, dict) or "api_key" not in payload:
                    raise ValueError("Invalid backend configuration")
                payload["api_key"] = configuration.api_key
                response = JSONResponse(payload, status_code=upstream.status_code)
                replacement_length = response.headers["content-length"].encode("ascii")
                response.raw_headers = _response_headers(upstream, configuration, transformed=True)
                response.raw_headers.append((b"content-length", replacement_length))
                response.raw_headers.append((b"cache-control", b"no-store"))
                return response
            except (ValueError, UnicodeDecodeError, httpx.HTTPError):
                return _error(502, "Backend configuration is unavailable")
            finally:
                await _close(upstream)
        response = UpstreamStreamingResponse(upstream)
        response.raw_headers = _response_headers(upstream, configuration)
        return _cors(response) if api else response

    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=38001, access_log=False, proxy_headers=False)
