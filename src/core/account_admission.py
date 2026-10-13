"""Cross-process account admission for generation and credential maintenance.

Generation keeps shared owner/worker locks for its entire account use. Credential
maintenance keeps an exclusive owner lock through login and commit. A delegated
login host holds a separate exclusive worker lock, inherited by its subprocesses,
so a caller or host exiting cannot admit generation while a worker is still alive.
The kernel releases ownership after the last descriptor closes; no TTL is used.
"""

import fcntl
import json
import os
from pathlib import Path
import secrets


class AccountAdmissionBusy(Exception):
    def __init__(self, reason="generation_busy"):
        self.reason = reason
        super().__init__(reason)


class AccountLease:
    def __init__(self, descriptors, *, capability=None):
        self._descriptors = list(descriptors)
        self.capability = capability

    @property
    def fd(self):
        if not self._descriptors:
            raise AccountAdmissionBusy("busy_state_unknown")
        return self._descriptors[-1]

    @property
    def pass_fds(self):
        return tuple(self._descriptors)

    def close(self):
        # Do not LOCK_UN: a login child can share this open-file-description.
        # Its inherited descriptor must retain ownership after the host exits.
        while self._descriptors:
            os.close(self._descriptors.pop())

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class AccountAdmission:
    busy_error = AccountAdmissionBusy

    def __init__(self, db_path):
        self.directory = Path(db_path).resolve().parent / ".account-operations"

    def _open(self, name):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.is_symlink():
            raise AccountAdmissionBusy("busy_state_unknown")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            return os.open(self.directory / name, flags, 0o600)
        except OSError:
            raise AccountAdmissionBusy("busy_state_unknown") from None

    @staticmethod
    def _token(token_id):
        if type(token_id) is not int or token_id <= 0:
            raise AccountAdmissionBusy("busy_state_unknown")
        return str(token_id)

    @staticmethod
    def _lock(fd, mode):
        try:
            fcntl.flock(fd, mode | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False
        except OSError:
            raise AccountAdmissionBusy("busy_state_unknown") from None

    @staticmethod
    def _metadata(fd):
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 4097)
            if len(raw) > 4096:
                raise ValueError()
            value = json.loads(raw)
            return value if isinstance(value, dict) else {}
        except (ValueError, OSError, UnicodeError):
            return {}

    def generation(self, token_id):
        token = self._token(token_id)
        descriptors = []
        try:
            for suffix in ("owner", "worker"):
                fd = self._open(f"{token}.{suffix}.lock")
                descriptors.append(fd)
                if not self._lock(fd, fcntl.LOCK_SH):
                    raise AccountAdmissionBusy("generation_busy")
            return AccountLease(descriptors)
        except BaseException:
            for fd in reversed(descriptors):
                os.close(fd)
            raise

    def maintenance_active(self, token_id):
        try:
            with self.generation(token_id):
                return False
        except AccountAdmissionBusy:
            return True

    def maintenance(self, token_id):
        token = self._token(token_id)
        owner = self._open(f"{token}.owner.lock")
        try:
            if not self._lock(owner, fcntl.LOCK_EX):
                probe = self._open(f"{token}.owner.lock")
                try:
                    reason = "generation_busy" if self._lock(probe, fcntl.LOCK_SH) else "already_running"
                finally:
                    os.close(probe)
                raise AccountAdmissionBusy(reason)
            capability = secrets.token_hex(32)
            metadata = json.dumps({"capability": capability, "pid": os.getpid()}).encode()
            # Fence a delayed delegate from the previous owner before probing B.
            os.ftruncate(owner, 0)
            os.lseek(owner, 0, os.SEEK_SET)
            os.write(owner, metadata)
            os.fsync(owner)
            worker = self._open(f"{token}.worker.lock")
            try:
                if not self._lock(worker, fcntl.LOCK_SH):
                    raise AccountAdmissionBusy("already_running")
            finally:
                os.close(worker)
            return AccountLease([owner], capability=capability)
        except BaseException:
            os.close(owner)
            raise

    def worker(self, token_id, capability):
        token = self._token(token_id)
        if (not isinstance(capability, str) or len(capability) != 64
                or any(c not in "0123456789abcdef" for c in capability)):
            raise AccountAdmissionBusy("busy_state_unknown")
        worker = self._open(f"{token}.worker.lock")
        try:
            if not self._lock(worker, fcntl.LOCK_EX):
                raise AccountAdmissionBusy("already_running")
            owner = self._open(f"{token}.owner.lock")
            try:
                # A nonblocking SH probe fails only while an EX owner exists.
                if self._lock(owner, fcntl.LOCK_SH):
                    raise AccountAdmissionBusy("busy_state_unknown")
                actual = self._metadata(owner).get("capability")
                if not isinstance(actual, str) or not secrets.compare_digest(actual, capability):
                    raise AccountAdmissionBusy("busy_state_unknown")
            finally:
                os.close(owner)
            return AccountLease([worker], capability=capability)
        except BaseException:
            os.close(worker)
            raise

    def service_owner(self):
        fd = self._open("service.lock")
        try:
            if not self._lock(fd, fcntl.LOCK_EX):
                raise AccountAdmissionBusy("already_running")
            return AccountLease([fd])
        except BaseException:
            os.close(fd)
            raise
