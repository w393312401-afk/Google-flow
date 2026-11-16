"""Independent offline cancellation and forced-validation boundary checks."""

import asyncio
from datetime import datetime, timedelta, timezone
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from src.core.account_admission import AccountAdmissionBusy
from src.core.database import Database
from src.core.models import Token
from src.services.token_manager import TokenManager


class RefreshCancellationBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Database(db_path=directory.name + "/offline.db")
        await self.db.init_db()
        self.token_id = await self.db.add_token(Token(
            email="boundary@example.test", st="offline-session", at="expired-at",
            at_expires=datetime.now(timezone.utc) - timedelta(seconds=1),
            proxy_url="http://offline.example.test:8000",
            captcha_proxy_url="http://offline.example.test:8000",
        ))
        self.manager = TokenManager(self.db, SimpleNamespace())
        self.refresh_value = {
            "access_token": "validated-new-at",
            "expires": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        }
        self.manager._st_to_at_for_token = AsyncMock(return_value=self.refresh_value)
        self.manager._get_credits_for_token = AsyncMock(return_value={"credits": 123})

    async def token(self):
        return await self.db.get_token(self.token_id)

    def assert_locks_released(self):
        for locks in (self.manager._validation_locks, self.manager._refresh_locks):
            if self.token_id in locks:
                self.assertFalse(locks[self.token_id].locked())
        self.assertEqual(self.manager._refresh_futures, {})
        self.assertEqual(self.manager._refresh_waiters, {})
        with self.manager.account_admission.maintenance(self.token_id):
            pass

    async def test_double_cancel_during_last_waiter_cleanup_releases_locks_for_new_request(self):
        entered, cleanup_entered, cleanup_finished = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def pending_refresh(*_args):
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleanup_entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cleanup_finished.set()
                raise

        self.manager._st_to_at_for_token.side_effect = pending_refresh
        first = asyncio.create_task(self.manager.ensure_valid_token(await self.token()))
        replacement = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            first.cancel()
            await asyncio.wait_for(cleanup_entered.wait(), 2)
            with self.assertRaises(AccountAdmissionBusy):
                self.manager.account_admission.maintenance(self.token_id)
            self.manager._st_to_at_for_token.side_effect = None
            replacement = asyncio.create_task(self.manager.ensure_valid_token(await self.token()))
            await asyncio.sleep(0)
            first.cancel()
            results = await asyncio.wait_for(asyncio.gather(first, replacement, return_exceptions=True), 2)
            self.assertIsInstance(results[0], asyncio.CancelledError)
            self.assertIsInstance(results[1], Token)
            self.assertTrue(cleanup_finished.is_set())
            self.assertEqual(self.manager._st_to_at_for_token.await_count, 2)
            self.assert_locks_released()
        finally:
            for task in (first, replacement):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(task for task in (first, replacement) if task is not None), return_exceptions=True)

    async def test_replacement_refresh_does_not_join_or_get_removed_by_abandoned_task(self):
        entered, cleanup_entered, finish_cleanup = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def pending_refresh(*_args):
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleanup_entered.set()
                await finish_cleanup.wait()
                raise

        self.manager._st_to_at_for_token.side_effect = pending_refresh
        first = asyncio.create_task(self.manager._refresh_at(self.token_id))
        replacement = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            old_runner = self.manager._refresh_futures[self.token_id]
            first.cancel()
            await asyncio.wait_for(cleanup_entered.wait(), 2)
            self.manager._st_to_at_for_token.side_effect = None
            replacement = asyncio.create_task(self.manager._refresh_at(self.token_id))
            await asyncio.sleep(0)
            new_runner = self.manager._refresh_futures[self.token_id]
            self.assertIsNot(old_runner, new_runner)
            finish_cleanup.set()
            results = await asyncio.wait_for(asyncio.gather(first, replacement, return_exceptions=True), 2)
            self.assertIsInstance(results[0], asyncio.CancelledError)
            self.assertIs(results[1], True)
            self.assert_locks_released()
        finally:
            finish_cleanup.set()
            for task in (first, replacement):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(task for task in (first, replacement) if task is not None), return_exceptions=True)

    async def test_cancelled_validation_subscriber_cannot_cancel_remaining_refresh_subscriber(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def pending_refresh(*_args):
            entered.set()
            await release.wait()
            return self.refresh_value

        self.manager._st_to_at_for_token.side_effect = pending_refresh
        first = asyncio.create_task(self.manager.ensure_valid_token(await self.token()))
        remaining = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            remaining = asyncio.create_task(self.manager._refresh_at(self.token_id))
            await asyncio.sleep(0)
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
            self.assertFalse(self.manager._validation_locks[self.token_id].locked())
            self.assertFalse(remaining.done())
            release.set()
            self.assertTrue(await asyncio.wait_for(remaining, 2))
            self.assertEqual(self.manager._st_to_at_for_token.await_count, 1)
            self.assert_locks_released()
        finally:
            release.set()
            for task in (first, remaining):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(task for task in (first, remaining) if task is not None), return_exceptions=True)

    async def test_force_revalidation_cancel_releases_caller_maintenance_and_validation_lock(self):
        await self.db.update_token(self.token_id, at_expires=datetime.now(timezone.utc) + timedelta(days=1))
        entered = asyncio.Event()

        async def pending_credits(*_args):
            entered.set()
            await asyncio.Event().wait()

        self.manager._get_credits_for_token.side_effect = pending_credits

        async def admitted_validation():
            with self.manager.account_admission.maintenance(self.token_id):
                return await self.manager.revalidate_token_under_admission(await self.token())

        pending = asyncio.create_task(admitted_validation())
        try:
            await asyncio.wait_for(entered.wait(), 2)
            pending.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await pending
            self.assert_locks_released()
            self.manager._get_credits_for_token.side_effect = None
            with self.manager.account_admission.maintenance(self.token_id):
                self.assertIsNotNone(await self.manager.revalidate_token_under_admission(await self.token()))
            self.assert_locks_released()
        finally:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)

    async def test_force_revalidation_does_not_return_success_for_replaced_identity(self):
        await self.db.update_token(self.token_id, at_expires=datetime.now(timezone.utc) + timedelta(days=1))
        original = await self.token()
        self.manager._mark_at_valid(self.token_id, token=original, proxy_url=original.proxy_url)
        entered, release = asyncio.Event(), asyncio.Event()

        async def pending_credits(*_args):
            entered.set()
            await release.wait()
            return {"credits": 123}

        self.manager._get_credits_for_token.side_effect = pending_credits

        async def admitted_validation():
            with self.manager.account_admission.generation(self.token_id):
                validated = await self.manager.revalidate_token_under_admission(original)
                return validated, self.manager.consume_validation_outcome(self.token_id)

        pending = asyncio.create_task(admitted_validation())
        try:
            await asyncio.wait_for(entered.wait(), 2)
            await self.db.update_token(self.token_id, at="replacement-at")
            release.set()
            validated, outcome = await asyncio.wait_for(pending, 2)
            self.assertIsNone(validated)
            self.assertTrue(outcome.success)
            self.assertEqual(outcome.identity, TokenManager.health_identity(original))
            self.assertNotEqual(outcome.identity, TokenManager.health_identity(await self.token()))
            self.assertFalse(self.manager._has_recent_at_validation(
                self.token_id, token=await self.token(), proxy_url=original.proxy_url,
            ))
            self.assert_locks_released()
        finally:
            release.set()
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
