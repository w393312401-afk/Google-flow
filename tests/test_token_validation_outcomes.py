"""Validation results must stay attached to the session that was actually checked."""

import asyncio
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

from src.core.database import Database
from src.core.models import Token
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager


class TokenValidationOutcomeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Database(db_path=self.directory.name + "/test.db")
        await self.db.init_db()
        self.token_id = await self.db.add_token(Token(
            st="frontend-old", at=FlowClient.FRONTEND_ACCESS_TOKEN,
            at_expires=datetime.now(timezone.utc) + timedelta(hours=1),
            email="audit@example.test", google_cookies="OSID=old; SID=old",
            protocol_mode="protocol", auto_refresh_enabled=False,
            proxy_url="http://old-route.example:8080", credits=77,
        ))
        proxy = Mock()
        proxy.normalize_proxy_url = lambda value: value.strip()
        proxy.get_request_proxy_url = AsyncMock(return_value=None)
        self.flow = FlowClient(proxy_manager=proxy, db=self.db)
        self.flow._current_rpc = AsyncMock(return_value=[123])
        self.manager = TokenManager(self.db, self.flow)
        self.login = self.enterContext(patch(
            "src.services.protocol_login.protocol_loginer.login", new_callable=AsyncMock,
            return_value={"success": False, "error": "HTTP 401"},
        ))

    async def token(self):
        return await self.db.get_token(self.token_id)

    async def health(self):
        async with self.db._connect() as connection:
            row = await (await connection.execute(
                "SELECT reason FROM token_health WHERE token_id=?", (self.token_id,),
            )).fetchone()
        return row[0] if row else None

    async def test_old_check_failure_preserves_new_session_success_and_actual_outcome(self):
        original = await self.token()

        async def old_check(**kwargs):
            if kwargs["google_cookies"] == "OSID=new; SID=new":
                return [456]
            await self.manager.update_token(
                self.token_id, st="frontend-new", google_cookies="OSID=new; SID=new",
            )
            self.assertTrue(await self.manager._refresh_at(self.token_id))
            raise TimeoutError("old request failed after new session succeeded")

        self.flow._current_rpc.side_effect = old_check
        self.assertIsNone(await self.manager.ensure_valid_token(original))
        fresh = await self.token()
        self.assertEqual(fresh.credits, 456)
        self.assertIsNone(await self.health())
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
        self.assertIsNone(self.manager._last_at_refresh_error.get(self.token_id))
        self.assertTrue(self.manager._has_recent_at_validation(
            self.token_id, token=fresh, proxy_url=fresh.proxy_url,
        ))
        outcome = self.manager.consume_validation_outcome(self.token_id)
        self.assertFalse(outcome.success)
        self.assertEqual(outcome.identity, self.manager.health_identity(original))
        self.assertEqual(outcome.reason, "AT_CHECK: network or proxy unavailable")
        self.assertIsNone(self.manager.consume_validation_outcome(self.token_id))

    async def test_atomic_failure_cas_preserves_replacement_health(self):
        original = await self.token()
        original_commit = self.db.commit_token_health_result

        async def replace_before_write(expected, *, reason, updates=None):
            await self.db.update_token(self.token_id, proxy_url="http://new-route.example:8080")
            await self.db.set_token_health(self.token_id, "AT_CHECK: upstream unavailable (HTTP 429)")
            self.manager._last_validation_error[self.token_id] = "new route result"
            return await original_commit(expected, reason=reason, updates=updates)

        with patch.object(self.db, "commit_token_health_result", side_effect=replace_before_write):
            await self.manager._record_at_failure(
                self.token_id, "AT_CHECK: network or proxy unavailable", token=original,
            )
        self.assertEqual(await self.health(), "AT_CHECK: upstream unavailable (HTTP 429)")
        self.assertEqual(self.manager.get_last_validation_error(self.token_id), "new route result")
        self.assertEqual(self.manager.consume_validation_outcome(self.token_id).identity,
                         self.manager.health_identity(original))

    async def test_old_refresh_success_cannot_overwrite_replacement_metadata(self):
        original = await self.token()

        async def old_refresh(*args, **kwargs):
            await self.manager.update_token(
                self.token_id, st="new-session", at="new-at",
                google_cookies="OSID=new; SID=new",
            )
            await self.db.update_token(self.token_id, credits=999)
            await self.db.set_token_health(self.token_id, "new session health")
            return {"access_token": "validated-old-at"}

        self.flow.st_to_at = AsyncMock(side_effect=old_refresh)
        self.assertTrue(await self.manager._refresh_at(self.token_id))
        current = await self.token()
        self.assertEqual((current.st, current.at, current.credits), ("new-session", "new-at", 999))
        self.assertEqual(await self.health(), "new session health")
        outcome = self.manager.consume_refresh_outcome(self.token_id)
        self.assertTrue(outcome.success)
        self.assertIsNone(outcome.reason)
        self.assertEqual(outcome.identity, self.manager.health_identity(
            original.model_copy(update={"at": "validated-old-at"}),
        ))
        self.assertNotEqual(outcome.identity, self.manager.health_identity(current))

    async def test_coalesced_callers_consume_same_immutable_actual_attempt(self):
        started, release = asyncio.Event(), asyncio.Event()
        original = await self.token()

        async def fail_old(**kwargs):
            started.set()
            await release.wait()
            raise TimeoutError()

        async def caller():
            success = await self.manager._refresh_at(self.token_id)
            outcome = self.manager.consume_refresh_outcome(self.token_id)
            self.assertIsNone(self.manager.consume_refresh_outcome(self.token_id))
            return success, outcome

        self.flow._current_rpc.side_effect = fail_old
        first = asyncio.create_task(caller())
        await started.wait()
        await self.manager.update_token(self.token_id, proxy_url="http://new-route.example:8080")
        second = asyncio.create_task(caller())
        await asyncio.sleep(0)
        release.set()
        first_result, second_result = await asyncio.gather(first, second)
        self.assertFalse(first_result[0])
        self.assertFalse(second_result[0])
        self.assertIs(first_result[1], second_result[1])
        outcome = first_result[1]
        self.assertEqual(outcome.identity, self.manager.health_identity(original))
        self.assertEqual(outcome.reason, "AT_REFRESH: network or proxy unavailable")
        self.assertIsNone(self.manager.consume_refresh_outcome(self.token_id))
        with self.assertRaises(FrozenInstanceError):
            outcome.reason = "changed"
        self.flow._current_rpc.assert_awaited_once()

    async def test_success_rechecks_final_identity_after_audit_await(self):
        original_audit = self.manager._audit

        async def change_after_commit(token_id, operation, status, *args, **kwargs):
            await original_audit(token_id, operation, status, *args, **kwargs)
            if operation == "health_check" and status == "success":
                await self.db.update_token(token_id, proxy_url="http://new-route.example:8080")

        self.manager._audit = change_after_commit
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        outcome = self.manager.consume_validation_outcome(self.token_id)
        self.assertTrue(outcome.success)
        self.assertNotEqual(outcome.identity, self.manager.health_identity(await self.token()))

    async def test_success_does_not_return_account_disabled_during_audit(self):
        original_audit = self.manager._audit

        async def disable_after_commit(token_id, operation, status, *args, **kwargs):
            await original_audit(token_id, operation, status, *args, **kwargs)
            if operation == "health_check" and status == "success":
                await self.db.update_token(token_id, is_active=False)

        self.manager._audit = disable_after_commit
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertFalse((await self.token()).is_active)

    async def test_auth_disable_uses_atomic_identity_guard(self):
        self.flow._current_rpc.side_effect = RuntimeError("HTTP 401")
        original_disable = self.db.disable_token_if_health_matches

        async def replace_before_disable(expected):
            await self.manager.update_token(
                self.token_id, st="new-session", google_cookies="OSID=new; SID=new",
            )
            return await original_disable(expected)

        with patch.object(self.db, "disable_token_if_health_matches", side_effect=replace_before_disable):
            self.assertFalse(await self.manager._refresh_at(self.token_id))
        self.assertTrue((await self.token()).is_active)
        self.assertEqual((await self.token()).st, "new-session")
        self.assertIsNone(await self.health())

    async def test_validation_cas_ignores_unrelated_metadata_but_guards_route_and_credentials(self):
        original = await self.token()
        await self.db.update_token(self.token_id, credits=321, remark="unrelated", at_expires=datetime.now(timezone.utc))
        self.assertTrue(await self.db.commit_token_health_result(original, reason="same identity"))
        for field, value in (
            ("st", "changed-st"), ("at", "changed-at"),
            ("google_cookies", "OSID=changed; SID=changed"),
            ("proxy_url", "http://changed-route.example:8080"),
            ("captcha_proxy_url", "http://changed-captcha.example:8080"),
            ("extension_route_key", "changed-extension"), ("protocol_mode", "session"),
        ):
            with self.subTest(field=field):
                before = await self.token()
                await self.db.update_token(self.token_id, **{field: value})
                await self.db.set_token_health(self.token_id, "new identity result")
                self.assertFalse(await self.db.commit_token_health_result(
                    before, reason=None, updates={"credits": 0},
                ))
                self.assertEqual((await self.token()).credits, 321)
                self.assertEqual(await self.health(), "new identity result")

    async def test_old_cookie_refresh_failure_cannot_postpone_new_route_renewal(self):
        old_time = datetime.now(timezone.utc) - timedelta(hours=3)
        await self.db.update_token(
            self.token_id, auto_refresh_enabled=True, last_st_refresh_at=old_time,
            last_st_refresh_result="previous result",
        )
        original = await self.token()

        async def stale_protocol(*args, **kwargs):
            await self.db.update_token(self.token_id, proxy_url="http://new-route.example:8080")
            await self.db.set_token_health(self.token_id, "new route health")
            return {"success": False, "error": "TimeoutError: old route timed out"}

        self.login.side_effect = stale_protocol
        await self.manager._refresh_protocol_token(original, datetime.now(timezone.utc))
        current = await self.token()
        self.assertEqual(current.last_st_refresh_at, original.last_st_refresh_at)
        self.assertEqual(current.last_st_refresh_result, "previous result")
        self.assertEqual(await self.health(), "new route health")
        self.assertIsNone(self.manager._last_st_refresh_error.get(self.token_id))
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
        outcome = self.manager.consume_validation_outcome(self.token_id)
        self.assertEqual(outcome.reason, "ST_REFRESH: network or proxy unavailable")
        self.assertEqual(outcome.identity, self.manager.health_identity(original))


if __name__ == "__main__":
    unittest.main()
