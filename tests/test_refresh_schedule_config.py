"""Persist refresh scheduling atomically without touching credentials or live accounts."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
import httpx

from src.api import admin
from src.core.account_operation_context import account_operation_source
from src.core.database import Database
from src.core.models import Token
from src.services.token_manager import TokenManager


class RefreshScheduleConfigTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "schedule.db")
        self.db = Database(self.path)
        await self.db.init_db()
        self.manager = TokenManager(self.db, SimpleNamespace())
        self.enterContext(patch.object(admin, "db", self.db))
        self.enterContext(patch.object(admin, "token_manager", self.manager))
        self.enterContext(patch.object(admin, "refresh_all_running", False))
        now = datetime.now(timezone.utc)
        self.recent = await self.add_token("recent", auto_refresh_enabled=False,
            refresh_interval_minutes=120, last_st_refresh_at=now - timedelta(minutes=5))
        self.overdue = await self.add_token("overdue", auto_refresh_enabled=True,
            refresh_interval_minutes=120, last_st_refresh_at=now - timedelta(minutes=11))
        self.disabled = await self.add_token("disabled", is_active=False,
            auto_refresh_enabled=False, refresh_interval_minutes=17,
            last_st_refresh_at=now - timedelta(minutes=20))
        self.unchanged = await self.add_token("unchanged", auto_refresh_enabled=True,
            refresh_interval_minutes=10, last_st_refresh_at=now - timedelta(minutes=5))
        app = FastAPI()
        app.include_router(admin.router)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                      base_url="http://isolated.test")
        self.addAsyncCleanup(self.client.aclose)
        session = "admin-refresh-schedule-test-session"
        await self.db.init_config_from_toml({}, is_first_startup=True)
        await self.db.create_admin_session(session)
        self.addAsyncCleanup(self.db.revoke_admin_session, session)
        self.client.headers["Authorization"] = f"Bearer {session}"

    async def add_token(self, label, **overrides):
        fields = {"st": f"SECRET_ST_{label}", "at": f"SECRET_AT_{label}",
                  "email": f"{label}@example.test", "login_account": f"{label}@example.test",
                  "google_cookies": f"SID=SECRET_COOKIE_{label}", "login_password": "SECRET_PASSWORD",
                  "proxy_url": "http://user:SECRET_PROXY@private.example:8080",
                  "protocol_mode": "protocol", "is_active": True, "credits": 100,
                  "adspower_serial": 20}
        fields.update(overrides)
        return await self.db.add_token(Token(**fields))

    async def snapshots(self):
        return {token.id: token.model_dump() for token in await self.db.get_all_tokens()}

    async def save(self, **payload):
        return await self.client.post("/api/token-refresh/config", json=payload)

    async def rows(self):
        return (await self.db.get_account_operation_logs(operation="config_update"))["items"]

    async def test_admin_auth_required_for_read_and_save(self):
        self.client.headers.pop("Authorization")
        before = await self.snapshots()
        previous = (await self.db.get_token_refresh_config()).model_dump()
        self.assertEqual((await self.client.get("/api/token-refresh/config")).status_code, 401)
        self.assertEqual((await self.save(enabled=True, refresh_interval_minutes=10,
                                        apply_to_active_tokens=True)).status_code, 401)
        self.assertEqual(await self.snapshots(), before)
        self.assertEqual((await self.db.get_token_refresh_config()).model_dump(), previous)
        self.assertEqual(await self.rows(), [])

    async def test_config_reports_protocol_gate_separately_from_always_on_at_refresh(self):
        await self.db.update_token_refresh_config(enabled=False)
        response = await self.client.get("/api/token-refresh/config")
        self.assertEqual(response.status_code, 200)
        config = response.json()["config"]
        self.assertIs(config["at_auto_refresh_enabled"], True)
        self.assertIs(config["protocol_refresh_enabled"], False)
        self.assertEqual(config["refresh_interval_minutes"], 120)

    async def test_minute_range_and_new_apply_flag_strict_boolean(self):
        before = await self.snapshots()
        for minutes in (0, -1, 525601, "not-minutes", 1.5):
            with self.subTest(minutes=minutes):
                response = await self.save(enabled=True, refresh_interval_minutes=minutes,
                                           apply_to_active_tokens=True)
                self.assertEqual(response.status_code, 422)
        for flag in ("true", "false", 0, 1, None, {}, []):
            with self.subTest(flag=flag):
                response = await self.save(enabled=True, refresh_interval_minutes=10,
                                           apply_to_active_tokens=flag)
                self.assertEqual(response.status_code, 422)
        self.assertEqual(await self.snapshots(), before)
        self.assertEqual((await self.db.get_token_refresh_config()).refresh_interval_minutes, 120)
        self.assertEqual(await self.rows(), [])

    async def test_range_boundaries_persist_after_database_reopen(self):
        for minutes in (1, 525600):
            response = await self.save(enabled=True, refresh_interval_minutes=minutes)
            self.assertEqual(response.status_code, 200)
            reopened = await Database(self.path).get_token_refresh_config()
            self.assertEqual(reopened.refresh_interval_minutes, minutes)

    async def test_explicit_apply_unifies_active_preferences_only(self):
        before = await self.snapshots()
        response = await self.save(enabled=True, refresh_interval_minutes=10,
                                   apply_to_active_tokens=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["config"]["refresh_interval_minutes"], 10)
        self.assertTrue(response.json()["config"]["protocol_refresh_enabled"])
        after = await self.snapshots()
        for token_id, previous in before.items():
            current = dict(after[token_id])
            if previous["is_active"]:
                self.assertIs(current["auto_refresh_enabled"], True)
                self.assertEqual(current["refresh_interval_minutes"], 10)
                current["auto_refresh_enabled"] = previous["auto_refresh_enabled"]
                current["refresh_interval_minutes"] = previous["refresh_interval_minutes"]
            self.assertEqual(current, previous)
        per_account = [row for row in await self.rows() if row["token_id"] is not None]
        self.assertEqual({row["token_id"] for row in per_account}, {self.recent, self.overdue})
        self.assertEqual(len(per_account), 2)
        self.assertNotIn(self.disabled, {row["token_id"] for row in per_account})
        self.assertNotIn(self.unchanged, {row["token_id"] for row in per_account})

    async def test_legacy_save_without_apply_preserves_every_account_preference(self):
        before = await self.snapshots()
        response = await self.save(enabled=True, refresh_interval_minutes=30)
        self.assertEqual(response.status_code, 200)
        self.assertEqual((await self.db.get_token_refresh_config()).refresh_interval_minutes, 30)
        self.assertEqual(await self.snapshots(), before)
        self.assertEqual([row for row in await self.rows() if row["token_id"] is not None], [])

    async def test_switching_off_with_apply_changes_only_global_config(self):
        before = await self.snapshots()
        response = await self.save(enabled=False, refresh_interval_minutes=30,
                                   apply_to_active_tokens=True)
        self.assertEqual(response.status_code, 200)
        refresh_config = await self.db.get_token_refresh_config()
        self.assertFalse(refresh_config.enabled)
        self.assertEqual(refresh_config.refresh_interval_minutes, 30)
        self.assertEqual(await self.snapshots(), before)
        with patch.object(self.manager, "_refresh_protocol_token", AsyncMock()) as refresh:
            await self.manager.run_protocol_refresh_once()
            refresh.assert_not_awaited()

    async def test_applied_interval_controls_periodic_due_check(self):
        with patch.object(self.manager, "_refresh_protocol_token", AsyncMock()) as refresh:
            await self.manager.run_protocol_refresh_once()
            refresh.assert_not_awaited()
            response = await self.save(enabled=True, refresh_interval_minutes=10,
                                       apply_to_active_tokens=True)
            self.assertEqual(response.status_code, 200)
            await self.manager.run_protocol_refresh_once()
            self.assertEqual(refresh.await_count, 1)
            due = refresh.await_args.args[0]
            self.assertEqual(due.id, self.overdue)
            self.assertEqual(due.refresh_interval_minutes, 10)
            self.assertTrue(due.auto_refresh_enabled)
        self.assertEqual(account_operation_source.get(), "system")

    async def test_periodic_scope_is_every_cookie_account_and_manual_scope_is_all_active(self):
        session_id = await self.add_token("legacy-session", protocol_mode="session", auto_refresh_enabled=False)
        missing_id = await self.add_token("missing-cookies", google_cookies="", auto_refresh_enabled=False)
        await self.save(enabled=True, refresh_interval_minutes=10, apply_to_active_tokens=True)
        with patch.object(self.manager, "_refresh_protocol_token", AsyncMock()) as periodic:
            await self.manager.run_protocol_refresh_once()
            periodic_ids = {call.args[0].id for call in periodic.await_args_list}
        # Current Flow sessions are Cookie based, so legacy-mode rows renew too;
        # accounts without Cookies have nothing to renew.
        self.assertEqual(periodic_ids, {self.overdue, session_id})
        async def successful_manual(item):
            return {"id": item.id, "success": True}
        with patch.object(admin, "_refresh_token_for_batch", AsyncMock(side_effect=successful_manual)) as manual:
            response = await self.client.post("/api/tokens/refresh-all")
            manual_ids = {call.args[0].id for call in manual.await_args_list}
        self.assertEqual(response.status_code, 200)
        self.assertIn(session_id, manual_ids)
        self.assertIn(missing_id, manual_ids)
        self.assertIn(self.recent, manual_ids)
        self.assertNotIn(self.disabled, manual_ids)

    async def test_token_update_failure_rolls_back_global_and_all_account_settings(self):
        before = await self.snapshots()
        previous_config = (await self.db.get_token_refresh_config()).model_dump()
        async with self.db._connect(write=True) as connection:
            await connection.execute(f"""CREATE TRIGGER fail_schedule_update
                BEFORE UPDATE OF auto_refresh_enabled, refresh_interval_minutes ON tokens
                WHEN NEW.id = {self.overdue}
                BEGIN SELECT RAISE(ABORT, 'SECRET_FORCED_TRANSACTION_FAILURE'); END""")
            await connection.commit()
        response = await self.save(enabled=True, refresh_interval_minutes=10,
                                   apply_to_active_tokens=True)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(await self.snapshots(), before)
        self.assertEqual((await self.db.get_token_refresh_config()).model_dump(), previous_config)
        rows = await self.rows()
        self.assertEqual({row["status"] for row in rows}, {"started", "failed"})
        self.assertTrue(all(row["token_id"] is None for row in rows))
        self.assertNotIn("SECRET", json.dumps(rows))
        self.assertEqual(account_operation_source.get(), "system")

    async def test_changed_account_audit_is_safe_and_inherits_request_source(self):
        response = await self.save(enabled=True, refresh_interval_minutes=10,
                                   apply_to_active_tokens=True)
        self.assertEqual(response.status_code, 200)
        rows = await self.rows()
        self.assertEqual({row["source"] for row in rows}, {"admin"})
        per_account = [row for row in rows if row["token_id"] is not None]
        self.assertEqual(len(per_account), 2)
        for row in per_account:
            self.assertEqual(row["details"], {"setting": "token_refresh", "auto_refresh_enabled": True,
                                              "refresh_interval_minutes": 10})
            self.assertEqual(row["reason"], "settings_updated")
        with sqlite3.connect(self.path) as connection:
            stored = json.dumps(connection.execute("SELECT * FROM account_operation_logs").fetchall())
        self.assertNotIn("SECRET", stored)
        self.assertEqual(account_operation_source.get(), "system")

    async def test_audit_write_failure_does_not_fail_committed_schedule_change(self):
        with patch.object(self.db, "append_account_operation_log", AsyncMock(side_effect=RuntimeError("SECRET_AUDIT_FAILURE"))):
            response = await self.save(enabled=True, refresh_interval_minutes=10,
                                       apply_to_active_tokens=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual((await self.db.get_token_refresh_config()).refresh_interval_minutes, 10)
        self.assertTrue((await self.db.get_token(self.recent)).auto_refresh_enabled)
        self.assertEqual((await self.db.get_token(self.overdue)).refresh_interval_minutes, 10)
        self.assertEqual((await self.db.get_token(self.disabled)).refresh_interval_minutes, 17)
        self.assertEqual(await self.rows(), [])


if __name__ == "__main__":
    unittest.main()
