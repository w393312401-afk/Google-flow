"""Management sessions persist in isolated storage and expire/revoke correctly."""

import ast
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
from http.cookies import SimpleCookie
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
import httpx

from src.api import admin
from src.core.config import config
from src.core.database import Database


USERNAME = "session-admin"
PASSWORD = "session-test-password"
API_KEY = "sk-session-api-key"
SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
MAIN_SOURCE = Path(__file__).resolve().parents[1] / "src" / "main.py"


def page_handlers(static_path):
    """Load actual page handlers without constructing live service components."""
    names = {
        "_static_page_response", "_ensure_admin_page_session", "index",
        "login_page", "manage_page", "test_page",
    }
    source = ast.parse(MAIN_SOURCE.read_text(encoding="utf-8"), str(MAIN_SOURCE))
    handlers = []
    for node in source.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            node.decorator_list = []
            handlers.append(node)
    namespace = {
        "admin": admin, "static_path": static_path, "Path": Path,
        "Request": Request, "FileResponse": FileResponse,
        "HTMLResponse": HTMLResponse, "RedirectResponse": RedirectResponse,
        "_STATIC_PAGE_NO_CACHE_HEADERS": {"Cache-Control": "no-store"},
    }
    exec(compile(ast.Module(body=handlers, type_ignores=[]), str(MAIN_SOURCE), "exec"), namespace)
    return namespace


class AdminSessionPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database_path = str(Path(directory.name) / "sessions.db")
        self.db = Database(self.database_path)
        await self.db.init_db()
        await self.db.init_config_from_toml({"global": {
            "admin_username": USERNAME, "admin_password": PASSWORD, "api_key": API_KEY,
        }}, is_first_startup=True)
        self.enterContext(patch.object(admin, "db", self.db))
        self.enterContext(patch.object(config, "_config", deepcopy(config.get_raw_config())))
        self.enterContext(patch.object(config, "_admin_username", USERNAME))
        self.enterContext(patch.object(config, "_admin_password", PASSWORD))
        config.api_key = API_KEY

        async def reload_admin_config():
            stored = await self.db.get_admin_config()
            config.set_admin_username_from_db(stored.username)
            config.set_admin_password_from_db(stored.password)
            config.api_key = stored.api_key

        self.enterContext(patch.object(self.db, "reload_config_to_memory",
                                      AsyncMock(side_effect=reload_admin_config)))
        self.static_path = Path(directory.name) / "static"
        self.static_path.mkdir()
        for name in ("login", "manage", "test"):
            (self.static_path / f"{name}.html").write_text(
                f"<html><body>{name} fixture</body></html>", encoding="utf-8")
        self.client = self.new_client()

    def new_client(self, base_url="http://session.test"):
        app = FastAPI()
        app.include_router(admin.router)
        handlers = page_handlers(self.static_path)
        for path, name in (("/", "index"), ("/login", "login_page"),
                           ("/manage", "manage_page"), ("/test", "test_page")):
            app.add_api_route(path, handlers[name], methods=["GET"])

        @app.get("/admin-session-probe")
        async def protected(token: str = Depends(admin.verify_admin_token)):
            return {"authenticated": True}

        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                   base_url=base_url, follow_redirects=False)
        self.addAsyncCleanup(client.aclose)
        return client

    async def login(self, client=None, path="/api/login"):
        response = await (client or self.client).post(path, json={
            "username": USERNAME, "password": PASSWORD,
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["success"])
        self.assertEqual(response.json()["username"], USERNAME)
        return response

    async def assert_token_rejected(self, token):
        client = self.new_client()
        for headers in ({"Authorization": f"Bearer {token}"},
                        {"Cookie": f"admin_session={token}"}):
            response = await client.get("/admin-session-probe", headers=headers)
            self.assertEqual(response.status_code, 401, response.text)
        for path in ("/manage", "/test"):
            response = await client.get(path, headers={"Cookie": f"admin_session={token}"})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["location"], "/login")

    async def test_login_aliases_issue_persistent_http_only_cookie(self):
        for path in ("/api/login", "/api/admin/login"):
            with self.subTest(path=path):
                response = await self.login(path=path)
                cookie = SimpleCookie()
                cookie.load(response.headers["set-cookie"])
                session_cookie = cookie["admin_session"]
                self.assertEqual(session_cookie.value, response.json()["token"])
                self.assertTrue(session_cookie["httponly"])
                self.assertEqual(session_cookie["samesite"].lower(), "lax")
                self.assertEqual(session_cookie["path"], "/")
                self.assertEqual(int(session_cookie["max-age"]), SESSION_TTL_SECONDS)
                expires = parsedate_to_datetime(session_cookie["expires"])
                expected = datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL_SECONDS)
                self.assertLess(abs((expires - expected).total_seconds()), 5)
                self.assertTrue(await self.db.is_admin_session_valid(response.json()["token"]))

    async def test_https_login_uses_secure_cookie(self):
        client = self.new_client(base_url="https://session.test")
        response = await self.login(client=client)
        cookie = SimpleCookie()
        cookie.load(response.headers["set-cookie"])
        self.assertTrue(cookie["admin_session"]["secure"])
        result = await client.get("/manage")
        self.assertEqual(result.status_code, 200, result.text)

    async def test_cookie_and_bearer_survive_new_database_and_app(self):
        response = await self.login()
        token = response.json()["token"]
        cookie = response.headers["set-cookie"].split(";", 1)[0]
        if hasattr(admin, "active_admin_tokens"):
            admin.active_admin_tokens.discard(token)
        reopened = Database(self.database_path)
        await reopened.init_db()
        with patch.object(admin, "db", reopened):
            client = self.new_client()
            for headers in ({"Cookie": cookie}, {"Authorization": f"Bearer {token}"}):
                result = await client.get("/admin-session-probe", headers=headers)
                self.assertEqual(result.status_code, 200, result.text)
            for path in ("/manage", "/test"):
                result = await client.get(path, headers={"Cookie": cookie})
                self.assertEqual(result.status_code, 200, result.text)
                self.assertIn("fixture", result.text)
                self.assertIn("no-store", result.headers["cache-control"])

    async def test_logged_in_return_visits_skip_login_page(self):
        await self.login()
        for path in ("/", "/login"):
            with self.subTest(path=path):
                response = await self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["location"], "/manage")

    async def test_missing_or_forged_cookie_cannot_access_protected_pages(self):
        for headers in ({}, {"Cookie": "admin_session=admin-forged-test-session"}):
            for path in ("/manage", "/test"):
                with self.subTest(headers=headers, path=path):
                    response = await self.client.get(path, headers=headers)
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response.headers["location"], "/login")
        for path in ("/", "/login"):
            self.assertEqual((await self.client.get(path)).status_code, 200)

    async def test_expired_cookie_and_bearer_are_rejected(self):
        token = (await self.login()).json()["token"]
        async with self.db._connect(write=True) as connection:
            await connection.execute("UPDATE admin_sessions SET expires_at = 0 WHERE token_hash = ?",
                                     (hashlib.sha256(token.encode()).hexdigest(),))
            await connection.commit()
        await self.assert_token_rejected(token)

    async def test_logout_aliases_revoke_session_across_database_instances(self):
        for path in ("/api/logout", "/api/admin/logout"):
            with self.subTest(path=path):
                token = (await self.login()).json()["token"]
                logout = await self.client.post(path)
                self.assertEqual(logout.status_code, 200, logout.text)
                self.assertTrue(logout.json()["success"])
                cookie = SimpleCookie()
                cookie.load(logout.headers["set-cookie"])
                self.assertEqual(cookie["admin_session"]["max-age"], "0")
                reopened = Database(self.database_path)
                self.assertFalse(await reopened.is_admin_session_valid(token))
                with patch.object(admin, "db", reopened):
                    await self.assert_token_rejected(token)

    async def test_password_change_revokes_all_sessions(self):
        first = (await self.login()).json()["token"]
        second = (await self.login()).json()["token"]
        response = await self.client.post("/api/admin/change-password", json={
            "old_password": PASSWORD, "new_password": "replacement-session-password",
        })
        self.assertEqual(response.status_code, 200, response.text)
        cookie = SimpleCookie()
        cookie.load(response.headers["set-cookie"])
        self.assertEqual(cookie["admin_session"]["max-age"], "0")
        self.assertEqual((await self.db.get_admin_config()).password,
                         "replacement-session-password")
        reopened = Database(self.database_path)
        with patch.object(admin, "db", reopened):
            for token in (first, second):
                self.assertFalse(await reopened.is_admin_session_valid(token))
                await self.assert_token_rejected(token)

    async def test_logout_revokes_distinct_cookie_and_bearer_sessions(self):
        for path in ("/api/logout", "/api/admin/logout"):
            with self.subTest(path=path):
                first = (await self.login()).json()["token"]
                second = (await self.login()).json()["token"]
                response = await self.client.post(path, headers={
                    "Authorization": f"Bearer {first}",
                })
                self.assertEqual(response.status_code, 200, response.text)
                reopened = Database(self.database_path)
                with patch.object(admin, "db", reopened):
                    for token in (first, second):
                        self.assertFalse(await reopened.is_admin_session_valid(token))
                        await self.assert_token_rejected(token)

    async def test_password_change_does_not_revoke_a_later_login_using_new_credentials(self):
        await self.login()
        issued = []

        async def concurrent_login_after_change():
            stored = await self.db.get_admin_config()
            token = "new-credentials-concurrent-session"
            await self.db.create_admin_session(
                token, expected_credentials=(stored.username, stored.password))
            issued.append(token)

        self.db.reload_config_to_memory.side_effect = concurrent_login_after_change
        response = await self.client.post("/api/admin/change-password", json={
            "old_password": PASSWORD, "new_password": "replacement-session-password",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(issued), 1)
        self.assertTrue(await self.db.is_admin_session_valid(issued[0]))

    async def test_login_uses_current_database_credentials(self):
        config.set_admin_password_from_db("stale-cached-password")
        await self.login()
        response = await self.new_client().post("/api/login", json={
            "username": USERNAME, "password": "stale-cached-password",
        })
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("set-cookie", response.headers)

    async def test_api_key_is_not_an_admin_session(self):
        await self.assert_token_rejected(API_KEY)

    async def test_invalid_login_never_sets_cookie(self):
        for path in ("/api/login", "/api/admin/login"):
            response = await self.client.post(path, json={
                "username": USERNAME, "password": "wrong-password",
            })
            self.assertEqual(response.status_code, 401)
            self.assertNotIn("set-cookie", response.headers)

    async def test_wrong_old_password_keeps_other_sessions_valid(self):
        first = (await self.login()).json()["token"]
        second = (await self.login()).json()["token"]
        response = await self.client.post("/api/admin/change-password", json={
            "old_password": "wrong-password", "new_password": "replacement-session-password",
        })
        self.assertEqual(response.status_code, 400)
        for token in (first, second):
            self.assertTrue(await self.db.is_admin_session_valid(token))


if __name__ == "__main__":
    unittest.main()
