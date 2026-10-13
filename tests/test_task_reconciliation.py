"""Offline reconciliation tests: no live account, browser, or upstream mutation."""
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from src.core.database import Database
from src.core.models import RequestLog, Task, Token
from src.services.submission_ledger import SubmissionLedger
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager


spec = importlib.util.spec_from_file_location(
    "reconciliation_cookie_sync", Path(__file__).resolve().parents[1] / "local/sync_adspower_cookies.py")
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class TaskReconciliationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Database(str(Path(directory.name) / "flow.db"))
        await self.db.init_db()
        self.account = await self.db.add_token(Token(st="fixture", email="fixture@example.test"))
        self.other_account = await self.db.add_token(Token(st="other", email="other@example.test"))
        self.sid, self.operation = "fixture-submission", "fixture-operation"
        self.ledger = SubmissionLedger(self.db)
        await self.ledger.reserve(self.sid, "original-fingerprint", "fixture-model")
        self.operations = [{"name": self.operation, "operation": {"name": self.operation}, "original_evidence": "keep"}]
        await self.ledger.accepted(self.sid, self.account, "fixture-project", self.operations)
        self.task_id = await self.db.create_task(Task(
            task_id=self.operation, token_id=self.account, model="video", prompt="synthetic", status="processing"))
        self.log_id = await self.add_log()
        self.cutoff = datetime(2030, 1, 1, tzinfo=timezone.utc)

    async def add_log(self, *, owner="default", submission="default", operation="default", kind="generate_video"):
        owner = self.account if owner == "default" else owner
        submission = self.sid if submission == "default" else submission
        operation = self.operation if operation == "default" else operation
        return await self.db.add_request_log(RequestLog(
            token_id=owner, operation=kind,
            request_body=json.dumps({"client_submission_id": submission} if submission else {}),
            response_body=json.dumps({"task_id": operation} if operation else {}),
            status_code=102, status_text="video_polling", duration=0, progress=45))

    async def log(self, log_id=None):
        async with self.db._connect() as connection:
            cursor = await connection.execute("SELECT status_code,status_text,response_body,token_id FROM request_logs WHERE id=?",
                                              (self.log_id if log_id is None else log_id,))
            row = await cursor.fetchone()
        return row[0], row[1], json.loads(row[2]), row[3]

    def handler(self, status="MEDIA_GENERATION_STATUS_SUCCESSFUL", error=None):
        self.db.get_token = AsyncMock(return_value=SimpleNamespace(id=self.account, at="fixture", google_cookies="fixture"))
        checked = {"operations": [{"name": self.operation, "status": status}]}
        client = SimpleNamespace(
            check_video_status=AsyncMock(side_effect=error) if error else AsyncMock(return_value=checked),
            _find_flow_content_url=lambda *_: "https://offline.test/video.mp4" if status.endswith("SUCCESSFUL") else None,
            generate_video=AsyncMock(),
        )
        context = FlowClient(None)
        client.get_request_fingerprint = context.get_request_fingerprint
        client._set_request_fingerprint = context._set_request_fingerprint
        return SimpleNamespace(flow_client=client, token_manager=TokenManager(self.db, client))

    async def restart(self, **values):
        return await self.db.reconcile_interrupted_requests(
            before=self.cutoff, local_workers_stopped=True, **values)

    async def test_observed_success_finishes_receipt_task_and_log_together(self):
        handler = self.handler()
        observed = await self.ledger.observe(self.sid, handler)
        self.assertEqual(observed["state"], "confirmed")
        self.assertEqual((await self.db.get_task(self.operation)).status, "completed")
        self.assertEqual((await self.log())[:2], (200, "completed"))
        self.assertFalse(sync.flow_busy(self.db.db_path, self.account))
        self.assertEqual((await self.ledger.get(self.sid))["operations"], self.operations)
        handler.flow_client.generate_video.assert_not_awaited()

    async def test_observed_failure_finishes_receipt_task_and_log_together(self):
        handler = self.handler("MEDIA_GENERATION_STATUS_FAILED")
        observed = await self.ledger.observe(self.sid, handler)
        self.assertEqual(observed["state"], "failed")
        self.assertEqual((await self.db.get_task(self.operation)).status, "failed")
        self.assertEqual((await self.log())[:2], (502, "failed"))
        self.assertFalse(sync.flow_busy(self.db.db_path, self.account))
        handler.flow_client.generate_video.assert_not_awaited()

    async def test_auth_failure_and_active_observation_do_not_release_live_generation(self):
        for handler in (self.handler(error=RuntimeError("401")), self.handler("MEDIA_GENERATION_STATUS_ACTIVE")):
            with self.subTest(handler=handler):
                result = await self.ledger.observe(self.sid, handler)
                self.assertEqual(result["state"], "pending")
                self.assertEqual((await self.db.get_task(self.operation)).status, "processing")
                self.assertEqual((await self.log())[:2], (102, "video_polling"))
                self.assertTrue(sync.flow_busy(self.db.db_path, self.account))

    async def test_confirmed_and_failed_early_returns_repair_old_projections_without_polling(self):
        cases = [("confirmed", {"video_url": "https://offline.test/video.mp4"}, "completed", 200),
                 ("failed", {"error": {"code": "video_generation_failed", "submission_pending": False,
                                       "upstream_accepted": True}}, "failed", 502)]
        for state, fields, task_status, code in cases:
            with self.subTest(state=state):
                await self.db.update_task(self.operation, status="processing")
                async with self.db._connect(write=True) as connection:
                    await connection.execute("UPDATE request_logs SET status_code=102,status_text='video_polling' WHERE id=?", (self.log_id,))
                    await connection.commit()
                await self.ledger.update(self.sid, state=state, **fields)
                receipt_before = await self.ledger.get(self.sid)
                handler = self.handler()
                await self.ledger.observe(self.sid, handler)
                self.assertEqual((await self.db.get_task(self.operation)).status, task_status)
                self.assertEqual((await self.log())[:2], (code, task_status))
                self.assertEqual(await self.ledger.get(self.sid), receipt_before)
                handler.flow_client.check_video_status.assert_not_awaited()

    async def test_exact_binding_rejects_other_accounts_operations_and_submissions(self):
        wrong_owner = await self.add_log(owner=self.other_account)
        wrong_operation = await self.add_log(operation="other-operation")
        wrong_submission = await self.add_log(submission="other-submission")
        anonymous_exact = await self.add_log(owner=None, operation=None)
        await self.ledger.observe(self.sid, self.handler())
        for log_id in (wrong_owner, wrong_operation, wrong_submission):
            self.assertEqual((await self.log(log_id))[:2], (102, "video_polling"))
        self.assertEqual((await self.log(anonymous_exact))[:2], (200, "completed"))
        self.assertEqual((await self.log(anonymous_exact))[3], self.account)
        result = await self.db.reconcile_submission_terminal(
            self.sid, account_id=self.other_account, operation_id=self.operation)
        self.assertEqual(result["status"], "binding_mismatch")

    async def test_terminal_transaction_rolls_back_receipt_task_when_log_update_fails(self):
        async with self.db._connect(write=True) as connection:
            await connection.execute("CREATE TRIGGER reject_log_update BEFORE UPDATE ON request_logs BEGIN SELECT RAISE(ABORT,'fixture'); END")
            await connection.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            await self.db.reconcile_submission_terminal(
                self.sid, account_id=self.account, operation_id=self.operation,
                state="confirmed", video_url="https://offline.test/video.mp4")
        self.assertEqual((await self.ledger.get(self.sid))["state"], "pending")
        self.assertEqual((await self.db.get_task(self.operation)).status, "processing")
        self.assertEqual((await self.log())[:2], (102, "video_polling"))

    async def test_unproven_failure_and_terminal_conflicts_cannot_end_or_downgrade_receipts(self):
        await self.ledger.update(self.sid, state="failed", error={"code": "generic_local_failure"})
        await self.db.reconcile_submission_terminal(self.sid, account_id=self.account, operation_id=self.operation)
        self.assertEqual((await self.db.get_task(self.operation)).status, "processing")
        await self.ledger.update(self.sid, state="confirmed", video_url="https://offline.test/saved.mp4")
        result = await self.db.reconcile_submission_terminal(
            self.sid, account_id=self.account, operation_id=self.operation, state="failed",
            error={"code": "video_generation_failed", "submission_pending": False, "upstream_accepted": True,
                   "operation_id": self.operation})
        self.assertEqual(result["status"], "receipt_conflict")
        self.assertEqual((await self.ledger.get(self.sid))["state"], "confirmed")

    async def test_restart_requires_explicit_stopped_worker_proof_and_aware_cutoff(self):
        for arguments in ({"before": self.cutoff}, {"before": self.cutoff.replace(tzinfo=None), "local_workers_stopped": True}):
            with self.assertRaises(ValueError):
                await self.db.reconcile_interrupted_requests(**arguments)
        self.assertEqual((await self.db.get_task(self.operation)).status, "processing")
        self.assertEqual((await self.log())[:2], (102, "video_polling"))

    async def test_restart_preserves_original_pending_receipt_and_closes_local_observer(self):
        await self.ledger.update(self.sid, error={"code": "video_status_unknown", "reason": "poll_failed",
                                                 "submission_pending": True, "upstream_accepted": True})
        receipt_before = await self.ledger.get(self.sid)
        result = await self.restart()
        task = await self.db.get_task(self.operation)
        self.assertEqual(result["tasks_unknown"], 1)
        self.assertEqual(task.status, "status_unknown")
        self.assertIsNone(task.completed_at)
        self.assertEqual(await self.ledger.get(self.sid), receipt_before)
        log = await self.log()
        self.assertEqual(log[:2], (502, "video_status_unknown"))
        self.assertTrue(log[2]["error"]["upstream_accepted"])
        self.assertTrue(log[2]["error"]["submission_pending"])
        self.assertFalse(sync.flow_busy(self.db.db_path, self.account))

    async def test_restart_repairs_proven_terminal_receipts_and_does_not_make_unknown_tasks(self):
        await self.ledger.update(self.sid, state="confirmed", video_url="https://offline.test/saved.mp4")
        await self.restart()
        self.assertEqual((await self.db.get_task(self.operation)).status, "completed")
        self.assertEqual((await self.log())[:2], (200, "completed"))
        self.assertFalse(sync.flow_busy(self.db.db_path, self.account))

    async def test_restart_unknown_pre_submit_and_anonymous_logs_end_only_local_requests(self):
        for owner, sid in ((self.account, "unknown-submission"), (None, "anonymous-submission")):
            await self.ledger.reserve(sid, sid)
            if owner is not None:
                await self.ledger.update(sid, account_id=owner)
            before = await self.ledger.get(sid)
            log_id = await self.add_log(owner=owner, submission=sid, operation=None, kind="generate_image")
            await self.restart()
            log = await self.log(log_id)
            self.assertEqual(log[:2], (503, "failed"))
            self.assertTrue(log[2]["error"]["submission_pending"])
            self.assertIsNone(log[2]["error"]["upstream_accepted"])
            self.assertEqual(await self.ledger.get(sid), before)
        self.assertFalse(sync.flow_busy(self.db.db_path, self.account))

    async def test_restart_reliable_non_submission_proof_can_refuse_without_inventing_it(self):
        sid = "unsubmitted-fixture"
        await self.ledger.reserve(sid, sid)
        await self.ledger.update(sid, account_id=self.account)
        log_id = await self.add_log(submission=sid, operation=None, kind="generate_image")
        proof = {"code": "submission_not_started", "submission_pending": False, "upstream_accepted": False}
        async with self.db._connect(write=True) as connection:
            await connection.execute("UPDATE request_logs SET response_body=? WHERE id=?", (json.dumps({"error": proof}), log_id))
            await connection.commit()
        await self.restart()
        self.assertEqual((await self.ledger.get(sid))["state"], "refused")
        self.assertEqual((await self.log(log_id))[2]["error"], proof)

    async def test_targeted_repair_and_cutoff_do_not_touch_other_or_newer_work(self):
        other_task = await self.db.create_task(Task(
            task_id="new-operation", token_id=self.account, model="video", prompt="synthetic", status="processing"))
        other_log = await self.add_log(submission="other-submission", operation="new-operation")
        await self.restart(token_id=self.account, task_ids=[self.task_id])
        self.assertEqual((await self.db.get_task("new-operation")).status, "processing")
        self.assertEqual((await self.log(other_log))[:2], (102, "video_polling"))
        async with self.db._connect(write=True) as connection:
            await connection.execute("UPDATE tasks SET created_at='2031-01-01 00:00:00' WHERE id=?", (other_task,))
            await connection.execute("UPDATE request_logs SET created_at='2031-01-01 00:00:00',updated_at='2031-01-01 00:00:00' WHERE id=?", (other_log,))
            await connection.commit()
        await self.restart()
        self.assertEqual((await self.db.get_task("new-operation")).status, "processing")
        self.assertEqual((await self.log(other_log))[:2], (102, "video_polling"))

    async def test_legacy_operation_log_and_task_without_ledger_are_preserved_as_unknown(self):
        async with self.db._connect(write=True) as connection:
            await connection.execute("DELETE FROM client_submissions WHERE client_submission_id=?", (self.sid,))
            await connection.execute("UPDATE request_logs SET request_body='{}' WHERE id=?", (self.log_id,))
            await connection.commit()
        await self.restart()
        self.assertEqual((await self.db.get_task(self.operation)).status, "status_unknown")
        self.assertEqual((await self.log())[:2], (502, "video_status_unknown"))
        self.assertTrue((await self.log())[2]["error"]["upstream_accepted"])
        self.assertFalse(sync.flow_busy(self.db.db_path, self.account))


if __name__ == "__main__":
    unittest.main()
