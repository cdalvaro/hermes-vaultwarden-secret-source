"""Container-local runtime state for one Vaultwarden bootstrap: the shared
lock file and the cached ``bw`` session, both scoped to a task's runtime_dir.

Kept isolated from ``vaultwarden_source.py`` because none of it is mocked in
tests -- it is pure filesystem and locking logic, exercised for real against
temporary directories.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import stat
import time
from pathlib import Path
from typing import Optional

_SESSION_FILENAME = "session"
_LOCK_FILENAME = "bootstrap.lock"


def remaining_seconds(deadline: float) -> Optional[float]:
    remaining = deadline - time.monotonic()
    return remaining if remaining > 0 else None


def prepare_runtime_dir(runtime_dir: Path) -> bool:
    try:
        if runtime_dir.is_symlink():
            return False
        runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Re-check post-creation: mkdir(exist_ok=True) silently accepts a path
        # that already resolves to a directory, even if the last component is
        # a symlink planted between the check above and this call.
        if runtime_dir.is_symlink() or not stat.S_ISDIR(runtime_dir.stat().st_mode):
            return False
        os.chmod(runtime_dir, 0o700)
    except OSError:
        return False
    return True


def acquire_runtime_lock(runtime_dir: Path, deadline: float) -> Optional[int]:
    try:
        fd = os.open(runtime_dir / _LOCK_FILENAME, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        return None
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            remaining = remaining_seconds(deadline)
            if remaining is None:
                os.close(fd)
                return None
            time.sleep(min(0.05, remaining))
        except OSError:
            os.close(fd)
            return None


def release_runtime_lock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def read_runtime_session(runtime_dir: Path) -> Optional[str]:
    path = runtime_dir / _SESSION_FILENAME
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            return None
        session = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return session or None


def write_runtime_session(runtime_dir: Path, session: str) -> bool:
    path = runtime_dir / _SESSION_FILENAME
    temporary = (
        runtime_dir / f".{_SESSION_FILENAME}.{os.getpid()}.{time.monotonic_ns()}"
    )
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(session)
        os.replace(temporary, path)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    return True


def invalidate_runtime_bootstrap(runtime_dir: Path) -> None:
    for path in (runtime_dir / _SESSION_FILENAME, runtime_dir / ".config"):
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        except OSError:
            pass
