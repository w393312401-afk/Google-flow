"""Offline cross-process account admission tests; all files are temporary."""

import errno
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.core.account_admission import AccountAdmission, AccountAdmissionBusy


class AccountAdmissionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.admission = AccountAdmission(self.root / "synthetic.db")

    def assert_busy(self, acquire, reason=None):
        with self.assertRaises(AccountAdmissionBusy) as caught:
            acquire()
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)

    def assert_closed(self, descriptor):
        with self.assertRaises(OSError) as caught:
            os.fstat(descriptor)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_generation_shares_account_with_other_generation(self):
        with self.admission.generation(7), self.admission.generation(7):
            self.assert_busy(lambda: self.admission.maintenance(7), "generation_busy")
        with self.admission.maintenance(7):
            pass

    def test_accounts_are_independent_during_generation_and_maintenance(self):
        with self.admission.generation(7), self.admission.maintenance(8):
            with self.admission.generation(9):
                pass
            self.assert_busy(lambda: self.admission.generation(8), "generation_busy")

    def test_maintenance_blocks_generation_and_second_maintenance(self):
        with self.admission.maintenance(7):
            self.assertTrue(self.admission.maintenance_active(7))
            self.assert_busy(lambda: self.admission.generation(7), "generation_busy")
            self.assert_busy(lambda: self.admission.maintenance(7), "already_running")
        self.assertFalse(self.admission.maintenance_active(7))

    def test_existing_maintenance_lease_can_be_delegated_without_relocking(self):
        with self.admission.maintenance(7) as lease:
            self.admission.validate_maintenance_lease(lease, 7)
            self.assert_busy(lambda: self.admission.generation(7))
        with self.admission.generation(7):
            pass

    def test_delegation_rejects_wrong_account_closed_owner_and_non_owner(self):
        with self.admission.maintenance(7) as lease:
            self.assert_busy(lambda: self.admission.validate_maintenance_lease(lease, 8))
            other = AccountAdmission(self.root / "other.db")
            self.assert_busy(lambda: other.validate_maintenance_lease(lease, 7))
            with self.admission.worker(7, lease.capability) as worker:
                self.assert_busy(lambda: self.admission.validate_maintenance_lease(worker, 7))
        self.assert_busy(lambda: self.admission.validate_maintenance_lease(lease, 7))
        with self.admission.generation(7) as generation:
            self.assert_busy(lambda: self.admission.validate_maintenance_lease(generation, 7))

    def test_delegation_rejects_an_unlocked_or_replaced_owner(self):
        import fcntl

        with self.admission.maintenance(7) as lease:
            fcntl.flock(lease.fd, fcntl.LOCK_UN)
            self.assert_busy(lambda: self.admission.validate_maintenance_lease(lease, 7))
        with self.admission.maintenance(7) as lease:
            (self.admission.directory / "7.owner.lock").unlink()
            self.assert_busy(lambda: self.admission.validate_maintenance_lease(lease, 7))

    def test_host_return_to_sync_commit_gap_keeps_owner_lock(self):
        with self.admission.maintenance(7) as parent:
            with self.admission.worker(7, parent.capability):
                self.assert_busy(lambda: self.admission.generation(7))
            # The host's worker lease ended, while sync is still owned by parent.
            self.assert_busy(lambda: self.admission.generation(7))
        with self.admission.generation(7):
            pass

    def test_worker_keeps_generation_and_new_maintenance_out_after_parent_exits(self):
        parent = self.admission.maintenance(7)
        worker = self.admission.worker(7, parent.capability)
        self.addCleanup(worker.close)
        parent.close()
        self.assert_busy(lambda: self.admission.generation(7), "generation_busy")
        self.assert_busy(lambda: self.admission.maintenance(7), "already_running")
        worker.close()
        with self.admission.generation(7):
            pass
        with self.admission.maintenance(7):
            pass

    def test_worker_rejects_missing_owner_and_wrong_or_stale_capability(self):
        self.assert_busy(lambda: self.admission.worker(7, "a" * 64), "busy_state_unknown")
        with self.admission.maintenance(7) as first:
            old_capability = first.capability
            wrong_capability = "0" * 64 if old_capability != "0" * 64 else "1" * 64
            self.assert_busy(lambda: self.admission.worker(7, wrong_capability), "busy_state_unknown")
            with self.admission.worker(7, old_capability):
                pass
        with self.admission.maintenance(7) as second:
            self.assertNotEqual(old_capability, second.capability)
            self.assert_busy(lambda: self.admission.worker(7, old_capability), "busy_state_unknown")
            with self.admission.worker(7, second.capability):
                pass

    def test_new_owner_fences_old_capability_before_probing_worker(self):
        old = self.admission.maintenance(7)
        old_capability = old.capability
        old.close()
        original_lock = self.admission._lock
        checked = []

        def inspect_worker_probe(descriptor, mode):
            import fcntl

            if mode == fcntl.LOCK_SH:
                owner_path = self.admission.directory / "7.owner.lock"
                owner = os.open(owner_path, os.O_RDONLY)
                try:
                    current = self.admission._metadata(owner).get("capability")
                finally:
                    os.close(owner)
                checked.append(current)
                self.assertNotEqual(current, old_capability)
            return original_lock(descriptor, mode)

        with patch.object(self.admission, "_lock", side_effect=inspect_worker_probe):
            with self.admission.maintenance(7):
                pass
        self.assertEqual(len(checked), 1)

    def test_worker_lock_is_exclusive_for_delegates(self):
        with self.admission.maintenance(7) as parent:
            with self.admission.worker(7, parent.capability):
                self.assert_busy(lambda: self.admission.worker(7, parent.capability), "already_running")

    def test_real_child_inherits_worker_lock_after_parent_and_host_close(self):
        parent = self.admission.maintenance(7)
        worker = self.admission.worker(7, parent.capability)
        self.addCleanup(parent.close)
        self.addCleanup(worker.close)
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import os,sys; os.fstat(int(sys.argv[1])); print('ready',flush=True); sys.stdin.buffer.read(1)",
             str(worker.fd)],
            pass_fds=worker.pass_fds, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=False,
        )
        try:
            ready, _, _ = select.select([child.stdout], [], [], 5)
            self.assertTrue(ready, "Synthetic child did not acknowledge its inherited descriptor")
            self.assertEqual(child.stdout.readline(), b"ready\n")
            worker.close()
            parent.close()
            self.assert_busy(lambda: self.admission.generation(7), "generation_busy")
            self.assert_busy(lambda: self.admission.maintenance(7), "already_running")
            child.communicate(input=b"x", timeout=5)
            self.assertEqual(child.returncode, 0)
            with self.admission.generation(7):
                pass
            with self.admission.maintenance(7):
                pass
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            for pipe in (child.stdin, child.stdout):
                if pipe is not None:
                    pipe.close()

    def test_generation_failure_closes_first_descriptor(self):
        original_open = self.admission._open
        opened = []

        def fail_worker(name):
            if name.endswith(".worker.lock"):
                raise AccountAdmissionBusy("busy_state_unknown")
            descriptor = original_open(name)
            opened.append(descriptor)
            return descriptor

        with patch.object(self.admission, "_open", side_effect=fail_worker):
            self.assert_busy(lambda: self.admission.generation(7), "busy_state_unknown")
        self.assertEqual(len(opened), 1)
        self.assert_closed(opened[0])
        with self.admission.maintenance(7):
            pass

    def test_generation_worker_contention_releases_owner_shared_lock(self):
        parent = self.admission.maintenance(7)
        worker = self.admission.worker(7, parent.capability)
        self.addCleanup(worker.close)
        parent.close()
        self.assert_busy(lambda: self.admission.generation(7))
        # A leaked generation A SH would report generation_busy here; B is busy.
        self.assert_busy(lambda: self.admission.maintenance(7), "already_running")

    def test_maintenance_metadata_failure_closes_owner_descriptor(self):
        original_open = self.admission._open
        opened = []

        def track_open(name):
            descriptor = original_open(name)
            opened.append(descriptor)
            return descriptor

        with patch.object(self.admission, "_open", side_effect=track_open), \
                patch("src.core.account_admission.os.fsync", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                self.admission.maintenance(7)
        self.assertEqual(len(opened), 1)
        self.assert_closed(opened[0])
        with self.admission.generation(7):
            pass

    def test_worker_validation_failure_closes_worker_and_probe_descriptors(self):
        original_open = self.admission._open
        opened = []

        def track_open(name):
            descriptor = original_open(name)
            opened.append(descriptor)
            return descriptor

        with patch.object(self.admission, "_open", side_effect=track_open):
            self.assert_busy(lambda: self.admission.worker(7, "a" * 64), "busy_state_unknown")
        self.assertEqual(len(opened), 2)
        for descriptor in opened:
            self.assert_closed(descriptor)
        with self.admission.maintenance(7) as parent:
            with self.admission.worker(7, parent.capability):
                pass

    def test_context_exception_and_repeated_close_release_every_descriptor(self):
        lease = self.admission.generation(7)
        descriptors = lease.pass_fds
        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            with lease:
                raise RuntimeError("synthetic")
        lease.close()
        for descriptor in descriptors:
            self.assert_closed(descriptor)
        with self.admission.maintenance(7):
            pass

    def test_service_owner_excludes_second_service_and_releases_on_close(self):
        with self.admission.service_owner():
            self.assert_busy(self.admission.service_owner, "already_running")
        with self.admission.service_owner():
            pass

    def test_invalid_identity_and_capability_do_not_create_ownership(self):
        for token_id in (0, -1, True, "7", None):
            self.assert_busy(lambda: self.admission.generation(token_id), "busy_state_unknown")
        for capability in (None, "", "a" * 63, "A" * 64, "z" * 64):
            self.assert_busy(lambda: self.admission.worker(7, capability), "busy_state_unknown")
        with self.admission.generation(7):
            pass


if __name__ == "__main__":
    unittest.main()
