"""Durable run store: SQLite journal (WAL, synchronous=FULL) + content-addressed artifacts.

Pure stdlib. Everything stored is strict JSON (no pickle, no code loading).
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import math
import os
import pathlib
import re
import sqlite3
import stat
import threading
import time
import uuid

try:
    import fcntl

    _F_FULLFSYNC = getattr(fcntl, "F_FULLFSYNC", None)
except ImportError:  # pragma: no cover
    fcntl = None
    _F_FULLFSYNC = None

_O_NOFOLLOW = os.O_NOFOLLOW
_O_DIRECTORY = os.O_DIRECTORY
_O_NONBLOCK = os.O_NONBLOCK  # so opening a FIFO planted in artifacts/ cannot hang us

SCHEMA_VERSION = 1
BUSY_TIMEOUT_SECONDS = 60.0
MAX_EVENTS_LIMIT = 10000
MAX_JSON_DEPTH = 64
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

_SUFFIX_RE = re.compile(r"\.[A-Za-z0-9]{1,16}")
_ARTIFACT_RE = re.compile(r"artifacts/([0-9a-f]{64})(\.[A-Za-z0-9]{1,16})")

# Top-level state fields that update() may not change.
PROTECTED_FIELDS = frozenset({"run_id", "config", "revision", "updated_at"})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time REAL NOT NULL,
    event TEXT NOT NULL,
    data TEXT NOT NULL,
    key TEXT UNIQUE,
    revision INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
"""


# --------------------------------------------------------------------------- JSON


def _check_json(value, path="$", depth=0):
    """Reject anything that is not strictly JSON (str keys, finite numbers, no tuples/sets/bytes)."""
    if depth > MAX_JSON_DEPTH:
        raise ValueError(f"{path}: JSON nesting too deep")
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path}: non-finite float is not valid JSON")
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check_json(item, f"{path}[{i}]", depth + 1)
        return
    if isinstance(value, dict):
        for k, item in value.items():
            if not isinstance(k, str):
                raise ValueError(f"{path}: object keys must be str, got {type(k).__name__}")
            _check_json(item, f"{path}.{k}", depth + 1)
        return
    raise ValueError(f"{path}: {type(value).__name__} is not JSON-serializable")


def _reject_constant(name):
    raise ValueError(f"invalid JSON constant {name}")


def _dumps(value) -> str:
    _check_json(value)
    return json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _loads(text: str):
    return json.loads(text, parse_constant=_reject_constant)


def _require_name(value, what):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} must be a non-empty str")
    return value


# --------------------------------------------------------------------------- Store


class Store:
    def __init__(self, root):
        self._root = pathlib.Path(root)
        self._lock = threading.RLock()
        self._conn = None
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._artifacts = self._root / "artifacts"
        self._ensure_artifacts_dir()
        db_path = self._root / "journal.sqlite3"
        if not db_path.exists():
            fd = os.open(db_path, os.O_RDWR | os.O_CREAT, 0o600)
            os.close(fd)
        os.chmod(db_path, 0o600)
        conn = sqlite3.connect(
            db_path,
            timeout=BUSY_TIMEOUT_SECONDS,
            isolation_level=None,  # explicit transactions only
            check_same_thread=False,
        )
        try:
            conn.execute("PRAGMA fullfsync=ON")
            mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise RuntimeError(f"could not enable WAL (got {mode!r})")
            conn.execute("PRAGMA synchronous=FULL")
            self._conn = conn
            self._init_schema()
        except BaseException:
            self._conn = None
            conn.close()
            raise

    def _ensure_artifacts_dir(self):
        try:
            os.mkdir(self._artifacts, 0o700)
        except FileExistsError:
            pass
        st = os.lstat(self._artifacts)
        if not stat.S_ISDIR(st.st_mode):  # lstat: a symlink here is refused
            raise ValueError("artifacts path is not a real directory")
        os.chmod(self._artifacts, 0o700)

    # -- lifecycle

    def close(self):
        with self._lock:
            conn, self._conn = self._conn, None
            if conn is not None:
                conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -- transactions

    @contextlib.contextmanager
    def _tx(self):
        with self._lock:
            conn = self._conn
            if conn is None:
                raise ValueError("store is closed")
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def _init_schema(self):
        with self._tx() as conn:
            row = None
            has_meta = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
            ).fetchone()
            if has_meta:
                row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is not None:
                try:
                    version = int(row[0])
                except ValueError:
                    raise ValueError("corrupt schema_version metadata") from None
                if version > SCHEMA_VERSION:
                    raise ValueError(
                        f"journal schema version {version} is newer than supported {SCHEMA_VERSION}"
                    )
                if version < SCHEMA_VERSION:
                    raise ValueError(f"unsupported old journal schema version {version}")
                return
            for stmt in _split_script(_SCHEMA):
                conn.execute(stmt)
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),)
            )

    # -- state

    @staticmethod
    def _read_state(conn):
        row = conn.execute("SELECT json FROM state WHERE id=1").fetchone()
        return None if row is None else _loads(row[0])

    @staticmethod
    def _insert_event(conn, now, event, data_json, key, revision):
        cur = conn.execute(
            "INSERT INTO events(time, event, data, key, revision) VALUES(?,?,?,?,?)",
            (now, event, data_json, key, revision),
        )
        return {
            "id": cur.lastrowid,
            "time": now,
            "event": event,
            "data": _loads(data_json),
            "key": key,
            "revision": revision,
        }

    def initialize(self, config: dict) -> dict:
        if not isinstance(config, dict):
            raise ValueError("config must be a dict")
        _check_json(config)
        now = time.time()
        state = {
            "run_id": uuid.uuid4().hex,
            "config": config,
            "phase": "bootstrap",
            "accepted_version": None,
            "candidate_version": None,
            "attempt": None,
            "attempt_index": 0,
            "findings": [],
            "active": False,
            "stopped": False,
            "retry_count": 0,
            "next_retry_at": 0,
            "revision": 1,
            "updated_at": now,
        }
        state_json = _dumps(state)
        data_json = _dumps({"run_id": state["run_id"]})
        with self._tx() as conn:
            if conn.execute("SELECT 1 FROM state WHERE id=1").fetchone():
                raise ValueError("store is already initialized")
            conn.execute("INSERT INTO state(id, revision, json) VALUES(1, 1, ?)", (state_json,))
            self._insert_event(conn, now, "initialize", data_json, None, 1)
        return _loads(state_json)

    def state(self) -> dict:
        with self._tx() as conn:  # read inside a transaction for a consistent snapshot
            state = self._read_state(conn)
        if state is None:
            raise ValueError("store is not initialized")
        return state

    def update(self, event: str, data: dict | None = None, **changes) -> dict:
        _require_name(event, "event")
        data = {} if data is None else data
        if not isinstance(data, dict):
            raise ValueError("data must be a dict or None")
        bad = PROTECTED_FIELDS.intersection(changes)
        if bad:
            raise ValueError(f"cannot update protected state field(s): {sorted(bad)}")
        _check_json(changes)
        data_json = _dumps(data)
        with self._tx() as conn:
            state = self._read_state(conn)
            if state is None:
                raise ValueError("store is not initialized")
            now = time.time()
            state.update(_loads(_dumps(changes)))  # deep-copied, validated
            state["revision"] = int(state["revision"]) + 1
            state["updated_at"] = now
            state_json = _dumps(state)
            conn.execute(
                "UPDATE state SET revision=?, json=? WHERE id=1", (state["revision"], state_json)
            )
            self._insert_event(conn, now, event, data_json, None, state["revision"])
        return _loads(state_json)

    # -- events

    @staticmethod
    def _row_to_event(row):
        return {
            "id": row[0],
            "time": row[1],
            "event": row[2],
            "data": _loads(row[3]),
            "key": row[4],
            "revision": row[5],
        }

    def log(self, event: str, data: dict | None = None, key: str | None = None) -> dict:
        _require_name(event, "event")
        data = {} if data is None else data
        if not isinstance(data, dict):
            raise ValueError("data must be a dict or None")
        if key is not None:
            _require_name(key, "key")
        data_json = _dumps(data)
        with self._tx() as conn:
            if key is not None:
                row = conn.execute(
                    "SELECT id, time, event, data, key, revision FROM events WHERE key=?", (key,)
                ).fetchone()
                if row is not None:
                    return self._row_to_event(row)
            rev_row = conn.execute("SELECT revision FROM state WHERE id=1").fetchone()
            revision = 0 if rev_row is None else rev_row[0]
            return self._insert_event(conn, time.time(), event, data_json, key, revision)

    def events(self, limit: int = 100) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive int")
        limit = min(limit, MAX_EVENTS_LIMIT)
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT id, time, event, data, key, revision FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_event(r) for r in reversed(rows)]

    # -- artifacts

    def _check_open(self):
        if self._conn is None:
            raise ValueError("store is closed")

    @contextlib.contextmanager
    def _artifacts_dirfd(self):
        """Open artifacts/ without following a symlink; yield an fd for *at-style operations."""
        self._check_open()
        try:
            fd = os.open(self._artifacts, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENOTDIR):
                raise ValueError("artifacts path is not a real directory") from None
            raise
        try:
            yield fd
        finally:
            os.close(fd)

    @staticmethod
    def _read_artifact_bytes(dirfd, name):
        """Read a regular, non-symlink file by name relative to dirfd.

        Returns None if absent. Raises ValueError for symlinks, non-regular or oversize files.
        """
        try:
            fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK, dir_fd=dirfd)
        except FileNotFoundError:
            return None
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.EMLINK):
                raise ValueError(f"artifact {name} is a symlink") from None
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"artifact {name} is not a regular file")
            if st.st_size > MAX_ARTIFACT_BYTES:
                raise ValueError(f"artifact {name} is too large")
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    raise ValueError(f"artifact {name} is too large")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def put(self, text: str, suffix: str = ".txt") -> str:
        if not isinstance(text, str):
            raise ValueError("artifact text must be str")
        if not isinstance(suffix, str) or not _SUFFIX_RE.fullmatch(suffix):
            raise ValueError("suffix must look like '.ext' with 1-16 ASCII letters/digits")
        try:
            data = text.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("artifact text is not valid Unicode text") from None
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ValueError("artifact too large")
        name = hashlib.sha256(data).hexdigest() + suffix
        with self._artifacts_dirfd() as dirfd:
            self._publish(dirfd, name, data)
        return f"artifacts/{name}"

    def _publish(self, dirfd, name, data):
        existing = self._read_artifact_bytes(dirfd, name)
        if existing is not None:
            if existing != data:
                raise ValueError(f"artifact {name} exists with divergent contents")
            _full_fsync(dirfd)  # make sure an earlier crashed publish is durable
            return
        tmp = f".tmp-{uuid.uuid4().hex}"
        fd = os.open(
            tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW, 0o600, dir_fd=dirfd
        )
        try:
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                _full_fsync(fd)
            finally:
                os.close(fd)
            try:
                # link() never replaces an existing name, so publish is atomic and no-overwrite.
                os.link(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
            except FileExistsError:
                other = self._read_artifact_bytes(dirfd, name)
                if other != data:
                    raise ValueError(f"artifact {name} exists with divergent contents") from None
        finally:
            try:
                os.unlink(tmp, dir_fd=dirfd)
            except FileNotFoundError:
                pass
        _full_fsync(dirfd)

    def get(self, artifact: str) -> str:
        if not isinstance(artifact, str):
            raise ValueError("artifact id must be str")
        m = _ARTIFACT_RE.fullmatch(artifact)
        if m is None:
            raise ValueError("invalid artifact id")
        digest, name = m.group(1), m.group(1) + m.group(2)
        with self._artifacts_dirfd() as dirfd:
            data = self._read_artifact_bytes(dirfd, name)
        if data is None:
            raise FileNotFoundError(artifact)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"artifact {artifact} is corrupt (hash mismatch)")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"artifact {artifact} is not valid UTF-8") from None


def _full_fsync(fd):
    """fsync, using F_FULLFSYNC on macOS where plain fsync does not flush the drive cache."""
    if _F_FULLFSYNC is not None:
        try:
            fcntl.fcntl(fd, _F_FULLFSYNC)
            return
        except OSError:
            pass
    os.fsync(fd)


def _split_script(script: str):
    """Split the schema script into statements (triggers contain ';' inside BEGIN..END)."""
    stmts, buf = [], []
    in_trigger = False
    for line in script.strip().splitlines():
        buf.append(line)
        s = line.strip().upper()
        if s.startswith("CREATE TRIGGER"):
            in_trigger = True
        if in_trigger:
            if s.endswith("END;"):
                in_trigger = False
                stmts.append("\n".join(buf))
                buf = []
        elif s.endswith(";"):
            stmts.append("\n".join(buf))
            buf = []
    return stmts
