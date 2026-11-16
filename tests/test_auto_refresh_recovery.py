"""Offline expiry, background retry, and shared refresh cancellation probes."""

import asyncio
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

from src.core.config import config
from src.core.account_admission import AccountAdmissionBusy
from src.core.database import Database
from src.core.models import Token
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager


class AutoRefreshRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Database(db_path=directory.name + "/offline.db")
        await self.db.init_db()
        self.now = datetime.now(timezone.utc)
        clock = Mock(wraps=datetime)
        clock.now.side_effect = lambda tz=None: self.now if tz is not None else self.now.replace(tzinfo=None)
        self.monotonic = Mock(return_value=1000.0)
        self.enterContext(patch("src.services.token_manager.datetime", clock))
        self.enterContext(patch("src.services.token_manager.time", SimpleNamespace(monotonic=self.monotonic)))
        self.enterContext(patch.object(type(config), "captcha_method", new_callable=PropertyMock, return_value="yescaptcha"))
        self.db.get_token_refresh_config = AsyncMock(return_value=SimpleNamespace(
            enabled=True, refresh_interval_minutes=120,
        ))
        self.token_id = await self.db.add_token(Token(
            st="frontend-offline", at=FlowClient.FRONTEND_ACCESS_TOKEN,
            email="offline@example.test", google_cookies="OSID=offline; SID=offline",
            at_expires=self.now - timedelta(minutes=1),
            auto_refresh_enabled=True, refresh_interval_minutes=120,
            last_st_refresh_at=self.now - timedelta(hours=3),
            last_st_refresh_result="success",
        ))
        proxy = SimpleNamespace(get_request_proxy_url=AsyncMock(return_value=None))
        self.flow = FlowClient(proxy_manager=proxy, db=self.db)
        self.flow._current_rpc = AsyncMock(return_value=[123])
        self.manager = TokenManager(self.db, self.flow)
        self.login = self.enterContext(patch(
            "src.services.protocol_login.protocol_loginer.login", new_callable=AsyncMock,
            return_value={"success": True, "google_cookies": "OSID=renewed; SID=renewed",
                          "email": "offline@example.test"},
        ))

    async def token(self):
        return await self.db.get_token(self.token_id)

    async def test_expired_at_refreshes_on_demand_even_with_background_disabled(self):
        await self.db.update_token(self.token_id, auto_refresh_enabled=False)
        results = await asyncio.gather(*[
            self.manager.ensure_valid_token(await self.token()) for _ in range(14)
        ])
        self.assertTrue(all(result is not None for result in results))
        self.flow._current_rpc.assert_awaited_once()
        self.assertGreater((await self.token()).at_expires, self.now)

    async def test_background_does_not_opt_in_disabled_cookie_renewal_accounts(self):
        await self.db.update_token(self.token_id, auto_refresh_enabled=False)
        await self.manager.run_protocol_refresh_once()
        self.login.assert_not_awaited()
        self.flow._current_rpc.assert_not_awaited()

    async def test_expired_at_failure_uses_one_attempt_then_recovers_after_backoff(self):
        await self.db.update_token(self.token_id, auto_refresh_enabled=False)
        self.flow._current_rpc.side_effect = TimeoutError()
        results = await asyncio.gather(*[
            self.manager.ensure_valid_token(await self.token()) for _ in range(14)
        ])
        self.assertEqual(results, [None] * 14)
        self.flow._current_rpc.assert_awaited_once()
        self.assertTrue((await self.token()).is_active)
        self.monotonic.return_value += 61
        self.now += timedelta(seconds=61)
        self.flow._current_rpc.side_effect = None
        self.assertIsNotNone(await self.manager.ensure_valid_token(await self.token()))
        self.assertEqual(self.flow._current_rpc.await_count, 2)

    async def test_background_refreshes_expired_at_before_cookie_interval(self):
        await self.db.update_token(
            self.token_id, last_st_refresh_at=self.now - timedelta(minutes=56),
        )
        await self.manager.run_protocol_refresh_once()
        self.login.assert_awaited_once()
        self.assertGreater((await self.token()).at_expires, self.now)

    async def test_background_network_failure_retries_after_backoff_not_full_interval(self):
        # Separate retry scheduling from expiry: this AT remains usable while
        # the due Cookie renewal suffers a short network outage.
        await self.db.update_token(self.token_id, at_expires=self.now + timedelta(minutes=30))
        self.login.side_effect = [
            {"success": False, "error": "TimeoutError: offline network outage"},
            {"success": True, "google_cookies": "OSID=renewed; SID=renewed", "email": "offline@example.test"},
        ]
        await self.manager.run_protocol_refresh_once()
        self.assertEqual(self.login.await_count, 1)
        self.assertTrue((await self.token()).is_active)
        self.monotonic.return_value += 61
        self.now += timedelta(seconds=61)
        await self.manager.run_protocol_refresh_once()
        self.assertEqual(self.login.await_count, 2)
        self.assertGreater((await self.token()).at_expires, self.now)

    async def test_cookie_probe_failure_preserves_rpc_valid_at_and_retry_evidence(self):
        await self.db.update_token(self.token_id, at_expires=self.now + timedelta(minutes=30))
        self.assertIsNotNone(await self.manager.ensure_valid_token(await self.token()))
        self.flow._current_rpc.reset_mock()
        self.login.return_value = {"success": False, "error": "TimeoutError: cookie page unavailable"}

        await self.manager.run_protocol_refresh_once()

        current = await self.token()
        self.flow._current_rpc.assert_awaited_once()
        self.assertIsNone(self.manager.get_validation_cooldown_reason(current))
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
        self.assertIn("network or proxy unavailable", current.last_st_refresh_result)
        self.assertEqual(current.last_st_refresh_at, self.now)
        self.assertIsNotNone(await self.manager.ensure_valid_token(current))
        await self.manager.run_protocol_refresh_once()
        self.login.assert_awaited_once()
        self.flow._current_rpc.assert_awaited_once()

    async def test_cookie_probe_failure_uses_actual_at_failure_and_backoff(self):
        await self.db.update_token(self.token_id, at_expires=self.now + timedelta(minutes=30))
        self.login.return_value = {"success": False, "error": "HTTP 503"}
        self.flow._current_rpc.side_effect = TimeoutError()

        await self.manager.run_protocol_refresh_once()
        current = await self.token()
        self.assertEqual(self.manager.get_last_validation_error(self.token_id),
                         "AT_CHECK: network or proxy unavailable")
        self.assertIn("HTTP 503", current.last_st_refresh_result)
        results = await asyncio.gather(*[
            self.manager.ensure_valid_token(current) for _ in range(14)
        ])
        self.assertEqual(results, [None] * 14)
        await self.manager.run_protocol_refresh_once()
        self.login.assert_awaited_once()
        self.flow._current_rpc.assert_awaited_once()
        self.assertTrue((await self.token()).is_active)

    async def test_cookie_failure_at_check_replacement_preserves_new_health(self):
        for rpc_fails in (False, True):
            with self.subTest(rpc_fails=rpc_fails):
                await self.db.update_token(
                    self.token_id, last_st_refresh_at=self.now - timedelta(hours=3),
                    last_st_refresh_result="success", proxy_url="http://old.example.test:80",
                )
                self.login.return_value = {"success": False, "error": "TimeoutError: cookie page unavailable"}
                self.manager._protocol_retry_after.clear()
                old = await self.token()
                entered, release = asyncio.Event(), asyncio.Event()

                async def replaceable_rpc(**kwargs):
                    entered.set()
                    await release.wait()
                    if rpc_fails:
                        raise TimeoutError()
                    return [123]

                self.flow._current_rpc.side_effect = replaceable_rpc
                pending = asyncio.create_task(self.manager.run_protocol_refresh_once())
                try:
                    await asyncio.wait_for(entered.wait(), 2)
                    await self.db.update_token(self.token_id, proxy_url="http://new.example.test:80")
                    await self.db.set_token_health(self.token_id, "new route health")
                    fresh = await self.token()
                    self.manager._mark_at_valid(self.token_id, token=fresh, proxy_url=fresh.proxy_url)
                    release.set()
                    await asyncio.wait_for(pending, 2)
                finally:
                    release.set()
                    if not pending.done():
                        pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
                async with self.db._connect() as connection:
                    row = await (await connection.execute(
                        "SELECT reason FROM token_health WHERE token_id=?", (self.token_id,),
                    )).fetchone()
                self.assertEqual(row[0], "new route health")
                self.assertNotEqual(self.manager.health_identity(old), self.manager.health_identity(fresh))
                self.assertTrue(self.manager._has_recent_at_validation(
                    self.token_id, token=fresh, proxy_url=fresh.proxy_url,
                ))
                self.assertIsNone(self.manager.get_validation_cooldown_reason(fresh))

    async def test_concurrent_background_cookie_failures_share_one_due_attempt(self):
        await self.db.update_token(self.token_id, at_expires=self.now + timedelta(minutes=30))
        self.login.return_value = {"success": False, "error": "TimeoutError: cookie page unavailable"}
        await asyncio.gather(*[self.manager.run_protocol_refresh_once() for _ in range(14)])
        self.login.assert_awaited_once()
        self.flow._current_rpc.assert_awaited_once()

    async def test_background_rechecks_cooldown_after_waiting_for_validation(self):
        lock = await self.manager._get_token_lock(
            self.manager._validation_locks, self.manager._validation_lock_guard, self.token_id,
        )
        await lock.acquire()
        pending = asyncio.create_task(self.manager.run_protocol_refresh_once())
        try:
            await asyncio.sleep(0.01)
            await self.manager._record_at_failure(
                self.token_id, "AT_CHECK: network or proxy unavailable", token=await self.token(),
            )
        finally:
            lock.release()
        await asyncio.wait_for(pending, 2)
        self.login.assert_not_awaited()
        self.flow._current_rpc.assert_not_awaited()

    async def test_maintenance_defers_background_without_renewal_or_failure(self):
        original = await self.token()
        with self.manager.account_admission.maintenance(self.token_id):
            await self.manager.run_protocol_refresh_once()
        self.login.assert_not_awaited()
        self.flow._current_rpc.assert_not_awaited()
        self.assertEqual((await self.token()).model_dump(), original.model_dump())
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
        self.assertIsNone(self.manager.get_validation_cooldown_reason(await self.token()))

    async def test_background_holds_admission_through_rpc_and_commit(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original_commit = self.db.commit_token_health_result

        async def held_commit(*args, **kwargs):
            entered.set()
            await release.wait()
            return await original_commit(*args, **kwargs)

        with patch.object(self.db, "commit_token_health_result", side_effect=held_commit):
            pending = asyncio.create_task(self.manager.run_protocol_refresh_once())
            try:
                await asyncio.wait_for(entered.wait(), 2)
                with self.assertRaises(AccountAdmissionBusy):
                    self.manager.account_admission.maintenance(self.token_id)
                self.flow._current_rpc.assert_awaited_once()
            finally:
                release.set()
                await asyncio.wait_for(pending, 2)
        with self.manager.account_admission.maintenance(self.token_id):
            pass

    async def test_cancelled_background_releases_admission_and_both_locks(self):
        entered = asyncio.Event()

        async def stalled_login(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()

        self.login.side_effect = stalled_login
        original = await self.token()
        pending = asyncio.create_task(self.manager.run_protocol_refresh_once())
        try:
            await asyncio.wait_for(entered.wait(), 2)
            with self.assertRaises(AccountAdmissionBusy):
                self.manager.account_admission.maintenance(self.token_id)
            pending.cancel()
            result = await asyncio.gather(pending, return_exceptions=True)
            self.assertIsInstance(result[0], asyncio.CancelledError)
        finally:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
        with self.manager.account_admission.maintenance(self.token_id):
            pass
        self.assertFalse(self.manager._validation_locks[self.token_id].locked())
        self.assertFalse(self.manager._refresh_locks[self.token_id].locked())
        self.assertEqual((await self.token()).model_dump(), original.model_dump())

    async def test_background_auth_failure_does_not_retry_each_expired_at_tick(self):
        self.login.return_value = {"success": False, "error": "HTTP 401"}
        await self.manager.run_protocol_refresh_once()
        for _ in range(5):
            self.monotonic.return_value += 61
            self.now += timedelta(seconds=61)
            await self.manager.run_protocol_refresh_once()
        self.login.assert_awaited_once()
        self.assertTrue((await self.token()).is_active)

    async def test_background_traffic_failure_respects_five_minute_backoff(self):
        self.login.side_effect = [
            {"success": False, "error": "PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC"},
            {"success": True, "google_cookies": "OSID=renewed; SID=renewed", "email": "offline@example.test"},
        ]
        await self.manager.run_protocol_refresh_once()
        self.monotonic.return_value += 61
        self.now += timedelta(seconds=61)
        await self.manager.run_protocol_refresh_once()
        self.assertEqual(self.login.await_count, 1)
        self.monotonic.return_value += 240
        self.now += timedelta(seconds=240)
        await self.manager.run_protocol_refresh_once()
        self.assertEqual(self.login.await_count, 2)
        self.assertGreater((await self.token()).at_expires, self.now)

    async def test_background_protocol_traffic_survives_browser_timeout(self):
        await self.db.update_token(self.token_id, at_expires=self.now + timedelta(minutes=30))
        self.login.return_value = {
            "success": False, "error": "PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC",
        }
        browser = SimpleNamespace(refresh_google_cookies=AsyncMock(side_effect=TimeoutError()))
        module = SimpleNamespace(BrowserCaptchaService=SimpleNamespace(
            get_instance=AsyncMock(return_value=browser),
        ))
        with patch.object(type(config), "captcha_method", new_callable=PropertyMock, return_value="browser"), \
             patch.dict("sys.modules", {"src.services.browser_captcha": module}):
            await self.manager.run_protocol_refresh_once()
            self.assertIn("PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC",
                          (await self.token()).last_st_refresh_result)
            self.assertIsNone(self.manager.get_last_validation_error(self.token_id))
            self.assertIsNotNone(await self.manager.ensure_valid_token(await self.token()))
            for delay in (61, 238):
                self.monotonic.return_value += delay
                self.now += timedelta(seconds=delay)
                await self.manager.run_protocol_refresh_once()
                self.login.assert_awaited_once()
                browser.refresh_google_cookies.assert_awaited_once()
                self.flow._current_rpc.assert_awaited_once()
            self.monotonic.return_value += 2
            self.now += timedelta(seconds=2)
            await self.manager.run_protocol_refresh_once()
        self.assertEqual(self.login.await_count, 2)
        self.assertEqual(browser.refresh_google_cookies.await_count, 2)
        self.assertEqual(self.flow._current_rpc.await_count, 2)
        logs = await self.db.get_account_operation_logs(
            token_id=self.token_id, operation="refresh_st", page_size=100,
        )
        self.assertIn(("ST_REFRESH", "network_or_proxy_unavailable"), {
            (row["stage"], row["reason"]) for row in logs["items"] if row["status"] == "failed"
        })

    async def test_background_auth_takes_priority_over_protocol_or_browser_traffic(self):
        traffic = "PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC"
        for protocol_error, browser_error in ((traffic, "HTTP 401"), ("HTTP 401", traffic)):
            with self.subTest(protocol_error=protocol_error):
                await self.db.update_token(
                    self.token_id, last_st_refresh_at=self.now - timedelta(hours=3),
                    last_st_refresh_result="success", at_expires=self.now + timedelta(minutes=30),
                )
                self.manager._protocol_retry_after.clear()
                self.login.reset_mock()
                self.login.return_value = {"success": False, "error": protocol_error}
                browser = SimpleNamespace(refresh_google_cookies=AsyncMock(
                    side_effect=RuntimeError(browser_error),
                ))
                module = SimpleNamespace(BrowserCaptchaService=SimpleNamespace(
                    get_instance=AsyncMock(return_value=browser),
                ))
                with patch.object(type(config), "captcha_method", new_callable=PropertyMock, return_value="browser"), \
                     patch.dict("sys.modules", {"src.services.browser_captcha": module}):
                    await self.manager.run_protocol_refresh_once()
                    reason = (await self.token()).last_st_refresh_result
                    self.assertNotIn("PUBLIC_ERROR_UNUSUAL_ACTIVITY", reason)
                    self.assertTrue(self.manager._is_authentication_failure(reason)
                                    or "credential recovery required" in reason)
                    self.monotonic.return_value += 301
                    self.now += timedelta(seconds=301)
                    await self.manager.run_protocol_refresh_once()
                self.login.assert_awaited_once()
                browser.refresh_google_cookies.assert_awaited_once()

    async def test_cancelling_one_refresh_caller_does_not_cancel_other_waiter(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def shared_rpc(**kwargs):
            entered.set()
            await release.wait()
            return [123]

        self.flow._current_rpc.side_effect = shared_rpc
        first = asyncio.create_task(self.manager._refresh_at(self.token_id))
        second = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            second = asyncio.create_task(self.manager._refresh_at(self.token_id))
            await asyncio.sleep(0)
            first.cancel()
            await asyncio.sleep(0)
            release.set()
            results = await asyncio.gather(first, second, return_exceptions=True)
            self.assertIsInstance(results[0], asyncio.CancelledError)
            self.assertIs(results[1], True)
            self.flow._current_rpc.assert_awaited_once()
            self.assertTrue((await self.token()).is_active)
        finally:
            release.set()
            for task in (first, second):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(task for task in (first, second) if task is not None), return_exceptions=True)

    async def test_cancelling_all_refresh_callers_cleans_task_and_allows_new_attempt(self):
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def abandoned_rpc(**kwargs):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        self.flow._current_rpc.side_effect = abandoned_rpc
        first = asyncio.create_task(self.manager._refresh_at(self.token_id))
        second = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            second = asyncio.create_task(self.manager._refresh_at(self.token_id))
            await asyncio.sleep(0)
            first.cancel()
            second.cancel()
            results = await asyncio.wait_for(asyncio.gather(first, second, return_exceptions=True), 2)
            self.assertTrue(all(isinstance(result, asyncio.CancelledError) for result in results))
            self.assertTrue(cancelled.is_set())
            self.assertEqual(self.manager._refresh_futures, {})
            self.assertEqual(self.manager._refresh_waiters, {})
            self.assertFalse(self.manager._refresh_locks[self.token_id].locked())
            self.flow._current_rpc.side_effect = None
            self.assertTrue(await self.manager._refresh_at(self.token_id))
            self.assertEqual(self.flow._current_rpc.await_count, 2)
        finally:
            for task in (first, second):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(task for task in (first, second) if task is not None), return_exceptions=True)

    async def test_admitted_revalidation_forces_rpc_without_relocking_maintenance(self):
        await self.db.update_token(self.token_id, at_expires=self.now + timedelta(minutes=30))
        token = await self.token()
        self.manager._mark_at_valid(self.token_id, token=token)
        with self.manager.account_admission.maintenance(self.token_id):
            self.assertIsNone(await self.manager.ensure_valid_token(token))
            self.flow._current_rpc.assert_not_awaited()
            validated = await self.manager.revalidate_token_under_admission(token)
        self.assertIsNotNone(validated)
        self.flow._current_rpc.assert_awaited_once()
        self.assertTrue(self.manager.consume_validation_outcome(self.token_id).success)

    async def test_admitted_revalidation_preserves_current_failure_backoff(self):
        self.flow._current_rpc.side_effect = TimeoutError()
        self.assertIsNone(await self.manager.ensure_valid_token(await self.token()))
        with self.manager.account_admission.maintenance(self.token_id):
            self.assertIsNone(await self.manager.revalidate_token_under_admission(await self.token()))
        self.flow._current_rpc.assert_awaited_once()
        self.assertFalse(self.manager.consume_validation_outcome(self.token_id).success)


if __name__ == "__main__":
    unittest.main()
