"""Audit persistence, redaction, contention and admin authentication on real SQLite."""
import asyncio
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock

from fastapi import FastAPI
import httpx

from src.api import account_logs, admin
from src.core.account_audit import audit_account_operation, audit_account_operation_sync
from src.core.database import Database
from src.core.models import Token


class AccountOperationLogTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "flow.db")
        self.db = Database(self.path)
        await self.db.init_db()
        self.token_id = await self.db.add_token(Token(
            st="secret-st", at="secret-at", email="audit@example.test",
            login_account="audit@example.test", adspower_serial=32,
            google_cookies="SID=secret-cookie", login_password="secret-password",
            proxy_url="http://user:secret-proxy@private.example:8080",
        ))

    async def log(self, **kwargs):
        return await audit_account_operation(
            self.db, self.token_id, operation="refresh_at", status="success", **kwargs)

    async def test_snapshot_survives_deletion_and_reopen(self):
        first = await self.log(reason="credential_refreshed")
        await self.db.delete_token(self.token_id)
        row = await Database(self.path).get_account_operation_log(first)
        self.assertEqual(row["token_id"], self.token_id)
        self.assertEqual(row["token_email"], "audit@example.test")
        self.assertEqual(row["token_serial"], "32")
        self.assertEqual(row["reason"], "credential_refreshed")
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(list(connection.execute("PRAGMA foreign_key_list(account_operation_logs)")), [])

    async def test_writer_allows_only_categories_and_safe_details(self):
        first = await audit_account_operation(
            self.db, self.token_id,
            operation="secret-op", status="secret-status", source="secret-source",
            stage="secret-stage", reason="Cookie: secret-cookie Password: secret-password",
            details={"credits": 75, "http_status": 401, "credential_changed": True,
                     "auth_evidence": "http_401", "category": "protocol_probe",
                     "password": "secret-password", "cookie": "secret-cookie",
                     "proxy_url": "secret-proxy", "error_code": "secret-body",
                     "count": "secret-count", "duration_ms": float("nan"),
                     "threshold": float("inf"), "total": 10**1000},
            event_key="secret-deduplication-key",
        )
        row = await self.db.get_account_operation_log(first)
        for field in ("operation", "status", "source", "stage", "reason"):
            self.assertEqual(row[field], "unknown")
        self.assertEqual(row["details"], {"credits": 75, "http_status": 401,
                                         "credential_changed": True, "auth_evidence": "http_401",
                                         "category": "protocol_probe"})
        with sqlite3.connect(self.path) as connection:
            stored = json.dumps(connection.execute("SELECT * FROM account_operation_logs").fetchall())
        self.assertNotIn("secret", stored)

    async def test_external_stdlib_worker_lazy_table_and_deduplication(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TABLE account_operation_logs")
        first = await asyncio.to_thread(
            audit_account_operation_sync, self.path, self.token_id,
            operation="cookie_sync", status="error", source="adspower_sync",
            reason="local_transport_failed", event_key="same-event")
        second = await audit_account_operation(
            self.db, self.token_id, operation="cookie_sync", status="failed",
            source="cookie_sync", reason="local_transport_failed", event_key="same-event")
        self.assertEqual(first, second)
        data = await self.db.get_account_operation_logs()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["status"], "failed")
        self.assertEqual(data["items"][0]["source"], "cookie_sync")
        self.assertEqual(data["items"][0]["token_email"], "audit@example.test")

    async def test_browser_cleanup_audit_preserves_safe_reason(self):
        for status, reason in (("success", "browser_closed"), ("deferred", "browser_close_deferred")):
            event = await audit_account_operation(
                self.db, self.token_id, operation="auto_login", status=status,
                stage="browser_close", source="cookie_sync", reason=reason,
                details={"retry_reason": "profile_state_unknown", "browser_url": "secret-browser"})
            row = await self.db.get_account_operation_log(event)
            self.assertEqual(row["stage"], "browser_close")
            self.assertEqual(row["reason"], reason)
            self.assertEqual(row["details"], {"retry_reason": "profile_state_unknown"})

    async def test_no_snapshot_token_or_service_schema_needed(self):
        bare = str(Path(self.path).with_name("bare.db"))
        first = audit_account_operation_sync(
            bare, operation="batch_refresh", status="info", source="history",
            reason="history_snapshot", token_email="before@example.test", token_serial=19)
        row = await Database(bare).get_account_operation_log(first)
        self.assertIsNone(row["token_id"])
        self.assertEqual(row["token_serial"], "19")
        self.assertEqual(row["token_email"], "before@example.test")

    async def test_filters_pagination_and_literal_search(self):
        for i in range(5):
            await self.log(reason="credential_refreshed", event_key=f"row-{i}")
        audit_account_operation_sync(self.path, operation="auto_login", status="deferred",
                                     source="login_host", reason="login_timeout",
                                     token_email="other@example.test", token_serial=7)
        rows = await self.db.get_account_operation_logs(
            page=2, page_size=2, operation="refresh_at", status="success", source="system",
            token_id=self.token_id, q="AUDIT@")
        self.assertEqual(rows["total"], 5)
        self.assertEqual(len(rows["items"]), 2)
        self.assertGreater(rows["items"][0]["id"], rows["items"][1]["id"])
        self.assertEqual((await self.db.get_account_operation_logs(q="32"))["total"], 5)
        for query in ("%", "_", "' OR 1=1 --", "\\"):
            self.assertEqual((await self.db.get_account_operation_logs(q=query))["total"], 0)
        self.assertEqual((await self.db.get_account_operation_logs(page_size=1000))["page_size"], 100)

    async def test_created_at_is_utc_and_influences_sort(self):
        local = datetime(2026, 10, 6, 23, 15, tzinfo=timezone(timedelta(hours=8)))
        first = await self.log(created_at=local)
        row = await self.db.get_account_operation_log(first)
        self.assertEqual(row["created_at"], "2026-10-06T15:15:00.000000+00:00")

    async def test_async_and_external_writers_share_real_sqlite_safely(self):
        async def external(i):
            return await asyncio.to_thread(audit_account_operation_sync, self.path, self.token_id,
                operation="cookie_sync", status="success", source="cookie_sync", event_key=f"external-{i}")
        ids = await asyncio.gather(*[self.log(event_key=f"async-{i}") for i in range(8)],
                                   *[external(i) for i in range(8)])
        self.assertTrue(all(type(item) is int for item in ids))
        self.assertEqual(len(set(ids)), 16)
        self.assertEqual((await self.db.get_account_operation_logs())["total"], 16)

    async def test_lock_failure_is_bounded_and_does_not_escape(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            self.assertIsNone(await self.log())
            self.assertLess(time.monotonic() - started, 2.5)
            started = time.monotonic()
            self.assertIsNone(await asyncio.to_thread(audit_account_operation_sync, self.path,
                operation="cookie_sync", status="failed"))
            self.assertLess(time.monotonic() - started, 2.5)
        self.assertIsInstance(await self.log(), int)

    async def test_bad_connection_and_bad_snapshot_are_best_effort(self):
        self.assertIsNone(audit_account_operation_sync(str(Path(self.path) / "not-a-database"),
                                                     operation="update", status="success"))
        fake = AsyncMock()
        fake.append_account_operation_log.side_effect = RuntimeError("secret-cookie")
        self.assertIsNone(await audit_account_operation(fake, operation="update", status="success"))
        row_id = audit_account_operation_sync(self.path, operation="update", status="success",
                                              token_email="Cookie: secret-cookie", token_serial="secret-token")
        row = await self.db.get_account_operation_log(row_id)
        self.assertEqual(row["token_email"], "")
        self.assertEqual(row["token_serial"], "")

    async def test_migration_restores_table_without_rewriting_account(self):
        previous = (await self.db.get_token(self.token_id)).model_dump()
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TABLE account_operation_logs")
        await self.db.check_and_migrate_db()
        self.assertEqual(previous, (await self.db.get_token(self.token_id)).model_dump())
        self.assertIsInstance(await self.log(), int)

    async def test_api_auth_filters_detail_and_strict_client_export(self):
        app = FastAPI()
        app.include_router(account_logs.router)
        previous_db = account_logs.db
        account_logs.set_database(self.db)
        self.addCleanup(account_logs.set_database, previous_db)
        session = "admin-audit-test-session"
        previous_admin_db = admin.db
        admin.db = self.db
        self.addCleanup(setattr, admin, "db", previous_admin_db)
        await self.db.init_config_from_toml({}, is_first_startup=True)
        await self.db.create_admin_session(session)
        self.addAsyncCleanup(self.db.revoke_admin_session, session)
        first = await self.log()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://audit.test") as client:
            for path in ("/api/account-logs", f"/api/account-logs/{first}"):
                self.assertEqual((await client.get(path)).status_code, 401)
            payload = {"operation": "export", "status": "success", "reason": "export_complete", "details": {"count": 2}}
            self.assertEqual((await client.post("/api/account-logs/events", json=payload)).status_code, 401)
            client.headers["Authorization"] = f"Bearer {session}"
            response = await client.get("/api/account-logs", params={"q": "audit@", "page_size": 1})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["total"], 1)
            self.assertIn("refresh_at", response.json()["operations"])
            self.assertEqual((await client.get(f"/api/account-logs/{first}")).json()["token_serial"], "32")
            self.assertEqual((await client.get("/api/account-logs/99999")).status_code, 404)
            self.assertEqual((await client.get("/api/account-logs?page_size=101")).status_code, 422)
            self.assertEqual((await client.get("/api/account-logs?source=unsafe-source")).status_code, 400)
            self.assertEqual((await client.post("/api/account-logs/events", json=payload)).status_code, 200)
            for unsafe in ({**payload, "source": "history"}, {**payload, "reason": "secret-cookie"},
                           {**payload, "operation": "disable"}, {**payload, "details": {"count": True}},
                           {**payload, "details": {"count": 1, "password": "secret-password"}}):
                self.assertEqual((await client.post("/api/account-logs/events", json=unsafe)).status_code, 422)
        self.assertEqual((await self.db.get_account_operation_logs())["total"], 2)

    def test_sync_module_imports_with_only_python_stdlib(self):
        path = Path(__file__).resolve().parents[1] / "src/core/account_audit.py"
        result = subprocess.run([sys.executable, "-S", "-c",
            "import importlib.util; s=importlib.util.spec_from_file_location('audit', " + repr(str(path)) +
            "); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert callable(m.audit_account_operation_sync)"],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
