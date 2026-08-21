"""Crash-safe, process-locked client invocation-counter persistence."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class InvocationCounterError(RuntimeError):
    """An invocation counter cannot be allocated without risking reuse."""


def _lock(stream: Any) -> None:
    if os.name == "nt":
        import msvcrt

        stream.seek(0)
        if not stream.read(1):
            stream.write("\0")
            stream.flush()
        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
    else:
        import fcntl

        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)


def _unlock(stream: Any) -> None:
    if os.name == "nt":
        import msvcrt

        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def counter_identity(
    *,
    meter_identity: str,
    client_system_title: bytes,
    client_address: int,
    server_address: int,
) -> dict[str, Any]:
    return {
        "meter_identity": meter_identity,
        "client_system_title": client_system_title.hex().upper(),
        "client_address": int(client_address),
        "server_address": int(server_address),
    }


def _identity_key(identity: dict[str, Any]) -> str:
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class InvocationCounterLease:
    """Exclusive lease for one client/meter counter identity."""

    path: Path
    identity: dict[str, Any]
    next_counter: int
    _lock_stream: Any
    _state: dict[str, Any]
    _closed: bool = False

    @property
    def identity_key(self) -> str:
        return _identity_key(self.identity)

    def _write_state(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        try:
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(self._state, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, self.path)
            if os.name != "nt":
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass

    def persist_next(self, value: int) -> None:
        """Persist the next unused value before its generated packet is sent."""

        if self._closed:
            raise InvocationCounterError("invocation-counter lease is already closed")
        if not isinstance(value, int) or value < self.next_counter:
            raise InvocationCounterError("refusing to roll the invocation counter backward")
        if value > 0xFFFFFFFF:
            raise InvocationCounterError("client invocation counter is exhausted")
        self.next_counter = value
        self._state["records"][self.identity_key] = {
            "identity": self.identity,
            "next_counter": value,
        }
        self._write_state()

    def close(self) -> None:
        if self._closed:
            return
        try:
            _unlock(self._lock_stream)
        finally:
            self._lock_stream.close()
            self._closed = True

    def __enter__(self) -> "InvocationCounterLease":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def acquire_counter_lease(
    path: str | Path,
    identity: dict[str, Any],
    *,
    meter_reported_counter: int | None,
    unsafe_override: int | None = None,
) -> InvocationCounterLease:
    """Lock state and choose a next counter that cannot repeat or move backward."""

    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = destination.with_suffix(destination.suffix + ".lock")
    lock_stream = lock_path.open("a+", encoding="utf-8")
    if os.name != "nt":
        os.chmod(lock_path, 0o600)
    _lock(lock_stream)
    try:
        if destination.exists():
            try:
                state = json.loads(destination.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise InvocationCounterError(
                    f"cannot safely read invocation-counter state: {type(exc).__name__}"
                ) from None
            if not isinstance(state, dict) or state.get("schema_version") != 1 or not isinstance(state.get("records"), dict):
                raise InvocationCounterError("invocation-counter state has an unsupported structure")
        else:
            state = {"schema_version": 1, "records": {}}

        key = _identity_key(identity)
        record = state["records"].get(key)
        persisted = record.get("next_counter") if isinstance(record, dict) else None
        if persisted is not None and (not isinstance(persisted, int) or not 1 <= persisted <= 0xFFFFFFFF):
            raise InvocationCounterError("persisted invocation counter is invalid")

        if meter_reported_counter is None:
            if unsafe_override is None:
                raise InvocationCounterError(
                    "the public invocation counter could not be read; set the advanced "
                    "profiles[0].invocation_counter.unsafe_override only after independently "
                    "establishing a safe next counter"
                )
            requested = unsafe_override
        else:
            if not 0 <= meter_reported_counter <= 0xFFFFFFFF:
                raise InvocationCounterError("meter returned an invalid invocation counter")
            requested = meter_reported_counter + 1

        # The persisted value protects counters generated locally, while the
        # meter value includes counters accepted from any authorized process
        # using this client identity. Advancing to the greater boundary is
        # monotonic in either case and cannot reuse or roll back a counter.
        next_counter = max(requested, persisted or 0)
        if next_counter > 0xFFFFFFFF:
            raise InvocationCounterError("client invocation counter is exhausted")
        lease = InvocationCounterLease(destination, identity, next_counter, lock_stream, state)
        lease.persist_next(next_counter)
        return lease
    except Exception:
        _unlock(lock_stream)
        lock_stream.close()
        raise
