"""Exercise audited admin handlers and token lifecycle with isolated real storage."""
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, HTTPException
import httpx

from src.api import admin
from src.core.account_operation_context import account_operation_source
from src.core.database import Database
from src.core.models import Token
from src.services.captcha_errors import BrowserCaptchaError
from src.services.load_balancer import LoadBalancer
from src.services.token_manager import TokenManager


class AccountOperationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "flow.db")
        self.db = Database(self.path)
        await self.db.init_db()
        self.manager = TokenManager(self.db, SimpleNamespace())
        self.enterContext(patch.object(admin, "db", self.db))
        self.enterContext(patch.object(admin, "token_manager", self.manager))
        self.enterContext(patch.object(admin, "concurrency_manager", None))
        self.enterContext(patch.object(admin, "refresh_all_running", False))
        self.token_id = await self.db.add_token(Token(
            st="SECRET_ST", at="SECRET_AT", email="integrated@example.test",
            login_account="integrated@example.test", adspower_serial=48,
            google_cookies="SID=SECRET_COOKIE", login_password="SECRET_PASSWORD",
            proxy_url="http://user:SECRET_PROXY@private.example:8080", credits=65,
        ))
        app = FastAPI()
        app.include_router(admin.router)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://isolated.test")
        self.addAsyncCleanup(self.client.aclose)
        session = "admin-integrated-test-session"
        await self.db.init_config_from_toml({}, is_first_startup=True)
        await self.db.create_admin_session(session)
        self.addAsyncCleanup(self.db.revoke_admin_session, session)
        self.client.headers["Authorization"] = f"Bearer {session}"

    async def rows(self, **filters):
        return (await self.db.get_account_operation_logs(**filters))["items"]

    async def test_admin_auth_prevents_action_and_audit(self):
        self.client.headers.pop("Authorization")
        response = await self.client.post(f"/api/tokens/{self.token_id}/disable")
        self.assertEqual(response.status_code, 401)
        self.assertTrue((await self.db.get_token(self.token_id)).is_active)
        self.assertEqual(await self.rows(), [])

    async def test_enable_disable_preserve_response_and_carry_source_to_service(self):
        response = await self.client.post(f"/api/tokens/{self.token_id}/disable")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"success": True, "message": "Token已禁用"})
        self.assertFalse((await self.db.get_token(self.token_id)).is_active)
        rows = await self.rows(operation="disable")
        self.assertEqual({row["status"] for row in rows}, {"started", "disabled", "success"})
        self.assertEqual({row["source"] for row in rows}, {"admin"})
        self.assertEqual({row["reason"] for row in rows if row["status"] != "started"}, {"manual_disable"})
        self.assertEqual(account_operation_source.get(), "system")
        response = await self.client.post(f"/api/tokens/{self.token_id}/enable")
        self.assertEqual(response.status_code, 200)
        self.assertTrue((await self.db.get_token(self.token_id)).is_active)
        rows = await self.rows(operation="enable")
        self.assertEqual({row["source"] for row in rows}, {"admin"})
        self.assertIn("enabled", {row["status"] for row in rows})

    async def test_cookie_sync_disable_reason_and_context_restoration(self):
        response = await self.client.post(f"/api/tokens/{self.token_id}/disable",
            headers={"X-Account-Operation-Source": "cookie_sync"})
        self.assertEqual(response.status_code, 200)
        rows = await self.rows(operation="disable")
        self.assertEqual({row["source"] for row in rows}, {"cookie_sync"})
        self.assertEqual({row["reason"] for row in rows if row["status"] != "started"}, {"low_balance_disabled"})
        self.assertEqual(account_operation_source.get(), "system")
        await self.manager.enable_token(self.token_id)
        self.assertEqual((await self.rows(operation="enable"))[0]["source"], "system")

    async def test_unrecognized_source_header_never_becomes_free_text(self):
        response = await self.client.post(f"/api/tokens/{self.token_id}/disable",
            headers={"X-Account-Operation-Source": "SECRET_COOKIE"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual({row["source"] for row in await self.rows()}, {"admin"})

    async def test_http_failure_has_only_fixed_safe_reason_and_resets_context(self):
        error = HTTPException(status_code=400,
            detail="connection timed out Cookie=SECRET_COOKIE password=SECRET_PASSWORD proxy=SECRET_PROXY")
        with patch.object(self.manager, "enable_token", AsyncMock(side_effect=error)):
            response = await self.client.post(f"/api/tokens/{self.token_id}/enable",
                headers={"X-Account-Operation-Source": "login_host"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], error.detail)
        rows = await self.rows(operation="enable")
        failure = next(row for row in rows if row["status"] == "failed")
        self.assertEqual(failure["reason"], "network_or_proxy_unavailable")
        self.assertEqual(failure["source"], "login_host")
        self.assertEqual(failure["details"]["http_status"], 400)
        self.assertEqual(account_operation_source.get(), "system")
        with sqlite3.connect(self.path) as connection:
            stored = json.dumps(connection.execute("SELECT * FROM account_operation_logs").fetchall())
        self.assertNotIn("SECRET", stored)

    async def test_refresh_network_failure_preserves_reason_in_request_audit(self):
        refresh = AsyncMock(side_effect=RuntimeError("connection failed SECRET_COOKIE"))
        with patch.object(self.manager, "_st_to_at_for_token", refresh), \
             patch.object(admin, "refresh_all_retry_delays", (0, 0)):
            response = await self.client.post(f"/api/tokens/{self.token_id}/refresh-at")

        self.assertEqual(response.status_code, 500)
        self.assertIn("网络或代理暂时不可用", response.json()["detail"])
        self.assertEqual(refresh.await_count, 3)
        self.assertTrue((await self.db.get_token(self.token_id)).is_active)
        rows = await self.rows(operation="refresh_at")
        failure = next(row for row in rows if row["stage"] == "request" and row["status"] == "failed")
        self.assertEqual(failure["reason"], "network_or_proxy_unavailable")
        self.assertEqual(failure["details"]["http_status"], 500)
        self.assertEqual({row["reason"] for row in rows if row["status"] == "failed"},
                         {"network_or_proxy_unavailable"})
        self.assertNotIn("SECRET", json.dumps(rows))
        self.assertEqual(account_operation_source.get(), "system")

    async def test_delete_keeps_pre_delete_snapshot_for_service_and_request_events(self):
        response = await self.client.delete(f"/api/tokens/{self.token_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(await self.db.get_token(self.token_id))
        rows = await self.rows(operation="delete")
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(row["token_email"], "integrated@example.test")
            self.assertEqual(row["token_serial"], "48")
            self.assertEqual(row["token_id"], self.token_id)
            self.assertEqual(row["source"], "admin")

    async def test_batch_partial_failure_keeps_original_result_and_safe_totals(self):
        await self.db.add_token(Token(st="SECOND_ST", email="second@example.test"))
        with patch.object(admin, "_refresh_token_for_batch", AsyncMock(side_effect=[
            {"id": self.token_id, "success": True},
            {"id": self.token_id + 1, "success": False, "error": "SECRET_COOKIE upstream detail"},
        ])):
            response = await self.client.post("/api/tokens/refresh-all")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body["success"], body["total"], body["succeeded"], body["failed"]), (True, 2, 1, 1))
        rows = await self.rows(operation="batch_refresh")
        result = next(row for row in rows if row["status"] != "started")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "batch_partial_failed")
        self.assertEqual(result["details"]["total"], 2)
        self.assertEqual(result["details"]["failed_count"], 1)
        self.assertEqual(result["details"]["success_count"], 1)
        self.assertNotIn("SECRET", json.dumps(rows))
        self.assertFalse(admin.refresh_all_running)
        self.assertEqual(account_operation_source.get(), "system")

    async def test_audit_storage_failure_never_changes_business_action(self):
        with patch.object(self.db, "append_account_operation_log", AsyncMock(side_effect=RuntimeError("SECRET_DB_ERROR"))):
            response = await self.client.post(f"/api/tokens/{self.token_id}/disable")
        self.assertEqual(response.status_code, 200)
        self.assertFalse((await self.db.get_token(self.token_id)).is_active)
        self.assertEqual(await self.rows(), [])
        self.assertEqual(account_operation_source.get(), "system")

    async def test_binding_request_signature_and_settings_category(self):
        response = await self.client.put(f"/api/tokens/{self.token_id}/adspower-serial", json={"adspower_serial": 78})
        self.assertEqual(response.status_code, 200)
        self.assertEqual((await self.db.get_token(self.token_id)).adspower_serial, 78)
        rows = await self.rows(operation="binding")
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["details"].get("setting") for row in rows}, {"ads_serial"})
        self.assertEqual({row["token_serial"] for row in rows}, {"48"})

    async def test_typed_routing_cooldown_stage_and_reason_survive_whitelist(self):
        balancer = LoadBalancer(self.manager)
        token = await self.db.get_token(self.token_id)
        error = BrowserCaptchaError("editor_readiness", "editor_missing")
        error.submission_pending = False
        self.assertTrue(await balancer.record_generation_failure(self.token_id, error,
            for_video_generation=True, token=token))
        row = (await self.rows(operation="generation"))[0]
        self.assertEqual((row["status"], row["stage"], row["reason"]),
                         ("cooldown", "editor_readiness", "editor_missing"))
        self.assertEqual(row["details"]["cooldown_seconds"], 60)

    async def test_concurrent_request_sources_are_context_local(self):
        entered = asyncio.Event()
        release = asyncio.Event()
        async def paused_enable(token_id):
            self.assertEqual(account_operation_source.get(), "login_host")
            entered.set()
            await release.wait()
            await TokenManager.enable_token(self.manager, token_id)
        with patch.object(self.manager, "enable_token", paused_enable):
            task = asyncio.create_task(self.client.post(f"/api/tokens/{self.token_id}/enable",
                headers={"X-Account-Operation-Source": "login_host"}))
            await asyncio.wait_for(entered.wait(), 2)
            try:
                response = await self.client.post(f"/api/tokens/{self.token_id}/disable",
                    headers={"X-Account-Operation-Source": "cookie_sync"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(account_operation_source.get(), "system")
            finally:
                release.set()
            self.assertEqual((await task).status_code, 200)
        self.assertEqual({row["source"] for row in await self.rows(operation="enable")}, {"login_host"})
        self.assertEqual({row["source"] for row in await self.rows(operation="disable")}, {"cookie_sync"})

    async def personal_refresh(self, *, result=None, error=None):
        await self.db.update_token(self.token_id, current_project_id="isolated-personal-project")
        token = await self.db.get_token(self.token_id)
        browser = SimpleNamespace(refresh_session_token=AsyncMock(return_value=result, side_effect=error))
        with patch("src.core.config.config", SimpleNamespace(captcha_method="personal")), \
             patch("src.services.browser_captcha_personal.BrowserCaptchaService.get_instance", AsyncMock(return_value=browser)):
            outcome = await self.manager._try_refresh_st(self.token_id, token)
        return outcome, browser

    async def test_personal_new_session_is_logged_without_claiming_at_validation(self):
        context = account_operation_source.set("admin")
        try:
            outcome, browser = await self.personal_refresh(result="SECRET_NEW_ST")
        finally:
            account_operation_source.reset(context)
        self.assertEqual(outcome, "SECRET_NEW_ST")
        browser.refresh_session_token.assert_awaited_once_with("isolated-personal-project")
        token = await self.db.get_token(self.token_id)
        self.assertEqual(token.st, "SECRET_NEW_ST")
        self.assertEqual(token.at, "SECRET_AT")
        self.assertFalse(self.manager._has_recent_at_validation(self.token_id))
        rows = await self.rows(operation="refresh_st")
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["stage"] for row in rows}, {"ST_REFRESH"})
        self.assertEqual({row["source"] for row in rows}, {"admin"})
        self.assertEqual(rows[0]["reason"], "browser_session_refreshed")
        self.assertEqual(rows[0]["details"], {"credential_changed": True})
        self.assertNotIn("SECRET", json.dumps(rows))

    async def test_personal_session_failure_outcomes_preserve_credentials(self):
        for result, error, reason in (
            ("SECRET_ST", None, "session_token_unchanged"),
            (None, None, "session_token_unavailable"),
            (None, asyncio.TimeoutError(), "timeout"),
            (None, RuntimeError("connection failed SECRET_COOKIE"), "network_or_proxy_unavailable"),
        ):
            with self.subTest(reason=reason):
                self.manager._last_st_refresh_error.pop(self.token_id, None)
                previous_count = len(await self.rows(operation="refresh_st"))
                outcome, _ = await self.personal_refresh(result=result, error=error)
                self.assertIsNone(outcome)
                self.assertEqual((await self.db.get_token(self.token_id)).st, "SECRET_ST")
                rows = await self.rows(operation="refresh_st")
                self.assertEqual(len(rows), previous_count + 2)
                self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("failed", reason))
                self.assertNotIn("SECRET", json.dumps(rows))

    async def test_personal_cancellation_is_logged_and_propagated(self):
        entered = asyncio.Event()
        async def wait_for_cancellation(_project):
            entered.set()
            await asyncio.Event().wait()
        task = asyncio.create_task(self.personal_refresh(error=wait_for_cancellation))
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(task.cancelled())
        rows = await self.rows(operation="refresh_st")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["reason"], "operation_cancelled")
        self.assertEqual((await self.db.get_token(self.token_id)).st, "SECRET_ST")

    async def test_ineligible_personal_refresh_does_not_generate_skip_noise(self):
        token = await self.db.get_token(self.token_id)
        with patch("src.core.config.config", SimpleNamespace(captcha_method="browser")):
            self.assertIsNone(await self.manager._try_refresh_st(self.token_id, token))
        with patch("src.core.config.config", SimpleNamespace(captcha_method="personal")):
            self.assertIsNone(await self.manager._try_refresh_st(self.token_id, token))
        self.assertEqual(await self.rows(), [])

    async def test_project_prepare_failure_has_one_event_per_attempt(self):
        error = RuntimeError("connection failed SECRET_PROXY")
        with patch.object(self.manager, "_get_project_pool_size", return_value=1), \
             patch.object(self.manager, "_flow_call_for_token", AsyncMock(side_effect=error)):
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, "Failed to prepare project pool"):
                    await self.manager.ensure_project_exists(self.token_id)
        rows = await self.rows(operation="project")
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["reason"] for row in rows}, {"project_creation_failed"})
        self.assertEqual({row["status"] for row in rows}, {"failed"})
        self.assertEqual({row["token_email"] for row in rows}, {"integrated@example.test"})
        self.assertNotIn("SECRET", json.dumps(rows))

    async def test_direct_project_creation_failure_keeps_original_exception(self):
        error = RuntimeError("SECRET_PROJECT_DETAIL")
        with patch.object(self.manager, "_flow_call_for_token", AsyncMock(side_effect=error)):
            with self.assertRaises(RuntimeError) as caught:
                await self.manager._create_project_for_token(await self.db.get_token(self.token_id), 1)
        self.assertIs(caught.exception, error)
        rows = await self.rows(operation="project")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["reason"], "project_creation_failed")

    async def test_first_project_failure_during_add_has_identity_snapshot(self):
        with patch.object(self.manager, "_flow_call_with_proxy", AsyncMock(side_effect=[
            {"access_token": "SECRET_CANDIDATE_AT", "user": {"email": "new@example.test"}},
            {"credits": 100}, RuntimeError("SECRET_PROJECT_DETAIL"),
        ])):
            with self.assertRaisesRegex(ValueError, "创建项目失败"):
                await self.manager.add_token("NEW_ISOLATED_ST", adspower_serial=52)
        rows = await self.rows(operation="project")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["token_email"], "new@example.test")
        self.assertEqual(rows[0]["token_serial"], "52")
        self.assertIsNone(rows[0]["token_id"])
        self.assertIsNone(await self.db.get_token_by_email("new@example.test"))
        self.assertNotIn("SECRET", json.dumps(rows))

    async def make_protocol_due(self):
        await self.db.update_token(self.token_id, protocol_mode="protocol", auto_refresh_enabled=True,
                                   last_st_refresh_at=None)

    async def test_due_protocol_refresh_has_source_and_no_repeat_skip_noise(self):
        await self.make_protocol_due()
        with patch("src.services.protocol_login.protocol_loginer.login", AsyncMock(return_value={
            "success": True, "session_token": "SECRET_PROTOCOL_ST"})), \
             patch.object(self.manager, "_st_to_at_for_token", AsyncMock(return_value={"access_token": "SECRET_PROTOCOL_AT"})), \
             patch.object(self.manager, "_get_credits_for_token", AsyncMock(return_value={"credits": 90})):
            await self.manager.run_protocol_refresh_once()
            count = len(await self.rows())
            await self.manager.run_protocol_refresh_once()
        rows = await self.rows()
        self.assertEqual(len(rows), count)
        self.assertEqual({row["source"] for row in rows}, {"protocol_refresh"})
        protocol_rows = [row for row in rows if row["operation"] == "protocol_refresh"]
        self.assertEqual({row["status"] for row in protocol_rows}, {"started", "success"})
        self.assertEqual(account_operation_source.get(), "system")
        token = await self.db.get_token(self.token_id)
        self.assertEqual((token.at, token.credits), ("SECRET_PROTOCOL_AT", 90))
        self.assertNotIn("SECRET", json.dumps(rows))

    async def test_protocol_probe_failure_has_safe_source_and_cycle_result(self):
        await self.make_protocol_due()
        with patch("src.services.protocol_login.protocol_loginer.login", AsyncMock(return_value={
            "success": False, "error": "connection failed SECRET_COOKIE"})):
            await self.manager.run_protocol_refresh_once()
        rows = await self.rows()
        self.assertEqual({row["source"] for row in rows}, {"protocol_refresh"})
        self.assertEqual(len([row for row in rows if row["operation"] == "protocol_refresh"]), 2)
        failure = next(row for row in rows if row["operation"] == "protocol_refresh" and row["status"] == "failed")
        self.assertEqual(failure["reason"], "protocol_refresh_failed")
        self.assertEqual(failure["details"].get("retry_reason"), "network_or_proxy_unavailable")
        self.assertEqual(account_operation_source.get(), "system")
        self.assertTrue((await self.db.get_token(self.token_id)).is_active)
        self.assertNotIn("SECRET", json.dumps(rows))

    async def test_protocol_outer_failure_is_logged_and_loop_semantics_preserved(self):
        await self.make_protocol_due()
        with patch.object(self.manager, "_refresh_protocol_token", AsyncMock(side_effect=RuntimeError("SECRET_OUTER_ERROR"))):
            await self.manager.run_protocol_refresh_once()
        rows = await self.rows(operation="protocol_refresh")
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["source"], rows[0]["reason"]), ("protocol_refresh", "protocol_refresh_failed"))
        self.assertEqual(account_operation_source.get(), "system")
        self.assertNotIn("SECRET", json.dumps(rows))
        with patch.object(self.db, "get_token_refresh_config", AsyncMock(side_effect=RuntimeError("SECRET_CONFIG_ERROR"))):
            await self.manager.run_protocol_refresh_once()
        rows = await self.rows(operation="protocol_refresh")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["stage"], "settings")

    async def test_protocol_cancellation_restores_background_source(self):
        await self.make_protocol_due()
        async def cancel_during_refresh(_token, _now):
            self.assertEqual(account_operation_source.get(), "protocol_refresh")
            raise asyncio.CancelledError()
        with patch.object(self.manager, "_refresh_protocol_token", cancel_during_refresh):
            with self.assertRaises(asyncio.CancelledError):
                await self.manager.run_protocol_refresh_once()
        self.assertEqual(account_operation_source.get(), "system")
        self.assertTrue((await self.db.get_token(self.token_id)).is_active)
        self.assertEqual((await self.db.get_token(self.token_id)).st, "SECRET_ST")


if __name__ == "__main__":
    unittest.main()
