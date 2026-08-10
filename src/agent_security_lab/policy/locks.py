"""Session-scoped locks (adapted from quant-selector locks.py).

Risk check + execution must hold the same lock to prevent TOCTOU races.
"""

from __future__ import annotations

import threading
import time
import uuid
from contextlib import contextmanager
from typing import Generator

_LOCAL_LOCKS: dict[str, threading.Lock] = {}
_LOCAL_META = threading.Lock()


def _local_lock(key: str) -> threading.Lock:
    with _LOCAL_META:
        if key not in _LOCAL_LOCKS:
            _LOCAL_LOCKS[key] = threading.Lock()
        return _LOCAL_LOCKS[key]


class SessionLockError(RuntimeError):
    """Raised when a session lock cannot be acquired in time."""


class SessionLock:
    """Session-scoped lock for the critical policy+execute section."""

    def __init__(self, wait_seconds: float = 10.0) -> None:
        self.wait_seconds = wait_seconds

    @contextmanager
    def hold(self, key: str) -> Generator[str, None, None]:
        token = uuid.uuid4().hex
        lock = _local_lock(key)
        got = lock.acquire(timeout=self.wait_seconds)
        if not got:
            raise SessionLockError(f"timeout acquiring session lock for {key}")
        try:
            yield token
        finally:
            lock.release()


_SESSION_LOCK: SessionLock | None = None


def get_session_lock() -> SessionLock:
    global _SESSION_LOCK
    if _SESSION_LOCK is None:
        _SESSION_LOCK = SessionLock()
    return _SESSION_LOCK


def reset_session_lock_for_tests() -> None:
    global _SESSION_LOCK
    _SESSION_LOCK = None
    with _LOCAL_META:
        _LOCAL_LOCKS.clear()
