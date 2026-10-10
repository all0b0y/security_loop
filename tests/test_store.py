"""Tests for security_loop.store (durable journal + content-addressed artifacts)."""

import hashlib
import os
import pathlib
import sqlite3
import stat
import tempfile
import threading
import unittest
import uuid

from security_loop.store import Store

CONFIG = {
    "models": {"builder": "model-a", "attacker": "model-b"},
    "contract": {"immutable": True, "ops": ["read", "write"]},
}


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name) / "store"
        self._stores = []
        self.addCleanup(self._close_all)

    def _close_all(self):
        for s in self._stores:
            s.close()

    def open(self, root=None):
        s = Store(root if root is not None else self.root)
        self._stores.append(s)
        return s


class InitializeReopenTests(StoreTestCase):
    def test_constructor_creates_layout_with_private_modes(self):
        self.open()
        self.assertTrue((self.root / "journal.sqlite3").is_file())
        self.assertTrue((self.root / "artifacts").is_dir())
        self.assertEqual(stat.S_IMODE((self.root / "artifacts").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / "journal.sqlite3").stat().st_mode), 0o600)

    def test_accepts_str_root(self):
        s = Store(str(self.root))
        self._stores.append(s)
        self.assertTrue((self.root / "journal.sqlite3").is_file())

    def test_wal_full_sync_and_schema_version(self):
        s = self.open()
        self.assertEqual(s._conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(s._conn.execute("PRAGMA synchronous").fetchone()[0], 2)  # FULL
        raw = sqlite3.connect(self.root / "journal.sqlite3")
        try:
            row = raw.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        finally:
            raw.close()
        self.assertEqual(row[0], "1")

    def test_newer_schema_version_is_refused(self):
        self.open().close()
        raw = sqlite3.connect(self.root / "journal.sqlite3")
        raw.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        raw.commit()
        raw.close()
        with self.assertRaises(ValueError):
            Store(self.root)

    def test_state_uninitialized_raises(self):
        with self.assertRaises(ValueError):
            self.open().state()

    def test_initialize_creates_default_state(self):
        st = self.open().initialize(CONFIG)
        self.assertEqual(uuid.UUID(hex=st["run_id"]).hex, st["run_id"])
        expected = {
            "config": CONFIG,
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
        }
        for k, v in expected.items():
            self.assertEqual(st[k], v, k)
        self.assertIsInstance(st["revision"], int)
        self.assertIsInstance(st["updated_at"], float)

    def test_initialize_only_once_even_after_reopen(self):
        s = self.open()
        first = s.initialize(CONFIG)
        with self.assertRaises(ValueError):
            s.initialize({"other": 1})
        s.close()
        s2 = self.open()
        with self.assertRaises(ValueError):
            s2.initialize({"other": 1})
        self.assertEqual(s2.state(), first)

    def test_initialize_rejects_non_json_config(self):
        s = self.open()
        for bad in ({"x": float("nan")}, {"x": {1, 2}}, {"x": b"b"}, {1: "a"}, [1], None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                s.initialize(bad)
        with self.assertRaises(ValueError):
            s.state()  # failed initialize left nothing behind

    def test_reopen_retains_state_and_config(self):
        s = self.open()
        s.initialize(CONFIG)
        s.update("phase_change", {"why": "test"}, phase="attack", attempt_index=3)
        before = s.state()
        s.close()
        after = self.open().state()
        self.assertEqual(after, before)
        self.assertEqual(after["config"], CONFIG)

    def test_close_is_idempotent_and_blocks_use(self):
        s = self.open()
        s.initialize(CONFIG)
        s.close()
        s.close()
        with self.assertRaises(ValueError):
            s.state()

    def test_context_manager(self):
        with Store(self.root) as s:
            s.initialize(CONFIG)
        with Store(self.root) as s:
            self.assertEqual(s.state()["config"], CONFIG)


class UpdateLogEventsTests(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.store = self.open()
        self.initial = self.store.initialize(CONFIG)

    def test_update_merges_and_bumps_revision(self):
        s1 = self.store.update("a", {"k": 1}, phase="attack")
        s2 = self.store.update("b", None, findings=[{"id": "f1"}], active=True)
        self.assertEqual(s1["phase"], "attack")
        self.assertEqual(s2["phase"], "attack")  # earlier change kept
        self.assertEqual(s2["findings"], [{"id": "f1"}])
        self.assertTrue(s2["active"])
        self.assertEqual(s1["revision"], self.initial["revision"] + 1)
        self.assertEqual(s2["revision"], self.initial["revision"] + 2)
        self.assertGreaterEqual(s2["updated_at"], s1["updated_at"])
        self.assertEqual(self.store.state(), s2)
        self.assertEqual(s2["run_id"], self.initial["run_id"])

    def test_update_event_carries_type_data_and_new_revision(self):
        st = self.store.update("stage_done", {"stage": "build"}, phase="verify")
        ev = self.store.events(1)[0]
        self.assertEqual(ev["event"], "stage_done")
        self.assertEqual(ev["data"], {"stage": "build"})
        self.assertEqual(ev["revision"], st["revision"])
        self.assertIsNone(ev["key"])
        self.assertEqual(set(ev), {"id", "time", "event", "data", "key", "revision"})

    def test_update_is_atomic_when_event_data_invalid(self):
        before = self.store.state()
        n_events = len(self.store.events())
        with self.assertRaises(ValueError):
            self.store.update("bad", {"x": float("inf")}, phase="changed")
        with self.assertRaises(ValueError):
            self.store.update("bad", {"x": 1}, phase={"s"})
        self.assertEqual(self.store.state(), before)
        self.assertEqual(len(self.store.events()), n_events)

    def test_update_rolls_back_state_if_event_insert_fails(self):
        before = self.store.state()
        # A pre-existing row with a conflicting key can't be reused by update; instead break
        # the events table through a trigger so the insert fails after the state UPDATE ran.
        self.store._conn.execute(
            "CREATE TEMP TRIGGER boom BEFORE INSERT ON main.events "
            "WHEN NEW.event='boom' BEGIN SELECT RAISE(ABORT,'boom'); END"
        )
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.update("boom", {}, phase="changed")
        self.assertEqual(self.store.state(), before)
        self.assertEqual(self.store.update("ok", {}, phase="fine")["phase"], "fine")

    def test_update_protects_identity_fields(self):
        for field in ("run_id", "config", "revision", "updated_at"):
            with self.assertRaises(ValueError, msg=field):
                self.store.update("x", {}, **{field: "tampered"})
        self.assertEqual(self.store.state(), self.initial)

    def test_update_requires_initialized_store_and_event_name(self):
        other = self.open(self.root.parent / "other")
        with self.assertRaises(ValueError):
            other.update("x", {}, phase="y")
        for bad in ("", None, 3):
            with self.assertRaises(ValueError):
                self.store.update(bad, {})
        with self.assertRaises(ValueError):
            self.store.update("x", ["not", "dict"])

    def test_returned_state_is_a_copy(self):
        st = self.store.state()
        st["findings"].append("mutated")
        st["config"]["models"]["builder"] = "evil"
        self.assertEqual(self.store.state(), self.initial)

    def test_log_appends_without_changing_state(self):
        before = self.store.state()
        ev = self.store.log("vm_result", {"exit": 0})
        self.assertEqual(self.store.state(), before)
        self.assertEqual(ev["event"], "vm_result")
        self.assertEqual(ev["data"], {"exit": 0})
        self.assertEqual(ev["revision"], before["revision"])
        self.assertIsNone(ev["key"])
        self.assertIsInstance(ev["id"], int)
        self.assertIsInstance(ev["time"], float)
        self.assertEqual(self.store.events(1), [ev])

    def test_log_key_is_idempotent(self):
        first = self.store.log("provider_reply", {"n": 1}, key="req-1")
        again = self.store.log("provider_reply", {"n": 2}, key="req-1")
        self.assertEqual(again, first)
        self.assertEqual(again["data"], {"n": 1})
        self.assertEqual(len([e for e in self.store.events() if e["key"] == "req-1"]), 1)
        other = self.store.log("provider_reply", {"n": 3}, key="req-2")
        self.assertNotEqual(other["id"], first["id"])

    def test_log_key_dedupe_survives_reopen_and_event_survives(self):
        first = self.store.log("x", {"a": [1, 2]}, key="k")
        self.store.close()
        s2 = self.open()
        self.assertEqual(s2.log("x", {"a": []}, key="k"), first)
        self.assertIn(first, s2.events())

    def test_log_works_before_initialize_and_validates(self):
        other = self.open(self.root.parent / "other")
        self.assertEqual(other.log("early")["revision"], 0)
        for args in (("",), ("e", {"x": b""}), ("e", [1]), ("e", {}, ""), ("e", {}, 5)):
            with self.assertRaises(ValueError, msg=repr(args)):
                other.log(*args)

    def test_events_are_chronological_and_limited(self):
        for i in range(5):
            self.store.log("e", {"i": i})
        evs = self.store.events(3)
        self.assertEqual([e["data"]["i"] for e in evs], [2, 3, 4])
        ids = [e["id"] for e in self.store.events()]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(self.store.events()[0]["event"], "initialize")

    def test_events_limit_bounds(self):
        for bad in (0, -1, 1.5, "5", None, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.store.events(bad)
        self.assertLessEqual(len(self.store.events(10**9)), 10000)

    def test_events_are_append_only(self):
        self.store.log("x")
        with self.assertRaises(sqlite3.DatabaseError):
            self.store._conn.execute("UPDATE events SET event='y'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.store._conn.execute("DELETE FROM events")


class ConcurrencyTests(StoreTestCase):
    def test_parallel_stores_do_not_lose_fields_or_revisions(self):
        n_threads, per_thread = 6, 8
        errors = []
        start = threading.Barrier(n_threads)

        def worker(t):
            try:
                s = Store(self.root)  # each thread has its own connection
                try:
                    start.wait(timeout=30)
                    for i in range(per_thread):
                        s.update("w", {"t": t, "i": i}, **{f"field_{t}_{i}": [t, i]})
                finally:
                    s.close()
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        root_store = self.open()
        root_store.initialize(CONFIG)
        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=120)
        self.assertEqual(errors, [])
        st = root_store.state()
        for t in range(n_threads):
            for i in range(per_thread):
                self.assertEqual(st[f"field_{t}_{i}"], [t, i])
        total = n_threads * per_thread
        self.assertEqual(st["revision"], 1 + total)
        revs = [e["revision"] for e in root_store.events(1000) if e["event"] == "w"]
        self.assertEqual(sorted(revs), list(range(2, 2 + total)))
        self.assertEqual(revs, sorted(revs))  # event order matches revision order

    def test_parallel_processes_do_not_lose_fields(self):
        import subprocess
        import sys

        self.open().initialize(CONFIG)
        code = (
            "import sys\n"
            "from security_loop.store import Store\n"
            "p = int(sys.argv[2])\n"
            "with Store(sys.argv[1]) as s:\n"
            "    for i in range(10):\n"
            "        s.update('proc', {'p': p}, **{f'p{p}_{i}': i})\n"
            "        s.log('seen', {'p': p, 'i': i}, key=f'dup-{i}')\n"
        )
        project = str(pathlib.Path(__file__).resolve().parent.parent)
        env = dict(os.environ, PYTHONPATH=project)
        procs = [
            subprocess.Popen([sys.executable, "-c", code, str(self.root), str(p)], env=env)
            for p in range(4)
        ]
        self.assertEqual([p.wait(timeout=120) for p in procs], [0, 0, 0, 0])
        s = self.open()
        st = s.state()
        for p in range(4):
            for i in range(10):
                self.assertEqual(st[f"p{p}_{i}"], i)
        self.assertEqual(st["revision"], 1 + 40)
        keyed = [e for e in s.events(1000) if e["key"]]
        self.assertEqual(sorted(e["key"] for e in keyed), sorted(f"dup-{i}" for i in range(10)))

    def test_concurrent_log_with_same_key_records_once(self):
        self.open().initialize(CONFIG)
        results, errors = [], []

        def worker():
            try:
                with Store(self.root) as s:
                    results.append(s.log("once", {"v": threading.get_ident()}, key="same"))
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=60)
        self.assertEqual(errors, [])
        self.assertEqual(len({r["id"] for r in results}), 1)
        self.assertEqual(len([e for e in self.open().events(1000) if e["key"] == "same"]), 1)

    def test_shared_store_used_from_many_threads(self):
        s = self.open()
        s.initialize(CONFIG)
        errors = []

        def worker(t):
            try:
                for i in range(5):
                    s.update("shared", {}, **{f"s{t}_{i}": True})
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=60)
        self.assertEqual(errors, [])
        self.assertEqual(s.state()["revision"], 1 + 20)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ArtifactTests(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.store = self.open()

    def artifact_files(self):
        return sorted(p.name for p in (self.root / "artifacts").iterdir())

    def test_put_returns_content_addressed_relative_path_and_get_roundtrips(self):
        text = "héllo \u2603 wörld\nline2"
        ref = self.store.put(text)
        self.assertEqual(ref, f"artifacts/{sha(text)}.txt")
        self.assertEqual(self.store.get(ref), text)
        self.assertEqual((self.root / ref).read_bytes(), text.encode("utf-8"))

    def test_put_custom_suffix_and_empty_text(self):
        ref = self.store.put("", ".log")
        self.assertEqual(ref, f"artifacts/{sha('')}.log")
        self.assertEqual(self.store.get(ref), "")
        self.assertEqual(self.store.put("x", ".JSON"), f"artifacts/{sha('x')}.JSON")

    def test_modes_are_private(self):
        ref = self.store.put("secret")
        self.assertEqual(stat.S_IMODE((self.root / ref).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / "artifacts").stat().st_mode), 0o700)

    def test_modes_are_private_under_permissive_umask(self):
        old = os.umask(0)
        try:
            ref = self.store.put("secret2")
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE((self.root / ref).stat().st_mode), 0o600)

    def test_same_bytes_dedupe_and_leave_no_temp_files(self):
        a = self.store.put("same")
        b = self.store.put("same")
        self.assertEqual(a, b)
        self.assertEqual(self.artifact_files(), [pathlib.PurePosixPath(a).name])
        self.store.put("other")
        self.assertEqual(len(self.artifact_files()), 2)
        self.assertFalse([n for n in self.artifact_files() if n.startswith(".")])

    def test_different_suffix_is_distinct_id_same_content(self):
        a, b = self.store.put("same", ".txt"), self.store.put("same", ".md")
        self.assertNotEqual(a, b)
        self.assertEqual(self.store.get(a), self.store.get(b))

    def test_artifacts_survive_reopen_and_dedupe_across_instances(self):
        ref = self.store.put("persist me", ".out")
        self.store.close()
        s2 = self.open()
        self.assertEqual(s2.get(ref), "persist me")
        self.assertEqual(s2.put("persist me", ".out"), ref)

    def test_put_rejects_bad_suffix(self):
        bad = [
            "", ".", "txt", "..", "/x", ".a/b", "./x", "../x", ".t.x", ".txt\n", ".tx t",
            ".\u00e9", "." + "a" * 40, ".txt/", "\\.txt", ".a\x00b", None, 3, b".txt",
        ]
        for suffix in bad:
            with self.assertRaises(ValueError, msg=repr(suffix)):
                self.store.put("x", suffix)
        self.assertEqual(self.artifact_files(), [])

    def test_put_rejects_non_text(self):
        for bad in (b"bytes", None, 5, ["x"], "bad \ud800 surrogate"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.store.put(bad)
        self.assertEqual(self.artifact_files(), [])

    def test_get_rejects_invalid_ids(self):
        h = sha("x")
        bad = [
            "", "x", h, f"{h}.txt", f"/{h}.txt", f"/etc/passwd", f"{self.root}/artifacts/{h}.txt",
            f"artifacts/{h}", f"artifacts/{h}.", f"artifacts/{h[:-1]}.txt",
            f"artifacts/{h.upper()}.txt", f"artifacts/{h}.txt\n", f"artifacts/{h}.txt ",
            f"artifacts//{h}.txt", f"./artifacts/{h}.txt", f"artifacts/./{h}.txt",
            f"artifacts/../artifacts/{h}.txt", "artifacts/../journal.sqlite3",
            "../journal.sqlite3", f"artifacts/sub/{h}.txt", f"artifacts\\{h}.txt",
            f"artifacts/{h}.a/b", f"xartifacts/{h}.txt", f"artifacts/{h}.t.x",
            "artifacts/" + "g" * 64 + ".txt", None, 7, b"artifacts/x", pathlib.Path(f"artifacts/{h}.txt"),
        ]
        self.store.put("x")
        for ref in bad:
            with self.assertRaises(ValueError, msg=repr(ref)):
                self.store.get(ref)

    def test_get_missing_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            self.store.get(f"artifacts/{sha('nope')}.txt")

    def test_get_detects_corruption(self):
        ref = self.store.put("original")
        (self.root / ref).write_text("tampered")
        with self.assertRaises(ValueError):
            self.store.get(ref)

    def test_get_detects_truncation_and_invalid_utf8(self):
        ref = self.store.put("original")
        (self.root / ref).write_bytes(b"")
        with self.assertRaises(ValueError):
            self.store.get(ref)
        raw = b"\xff\xfe\x00bad"
        name = f"artifacts/{hashlib.sha256(raw).hexdigest()}.bin"
        (self.root / name).write_bytes(raw)  # hash is right, but not UTF-8
        with self.assertRaises(ValueError):
            self.store.get(name)

    def test_put_does_not_overwrite_or_trust_divergent_existing_file(self):
        ref = self.store.put("original")
        (self.root / ref).write_text("tampered")
        with self.assertRaises(ValueError):
            self.store.put("original")
        self.assertEqual((self.root / ref).read_text(), "tampered")  # left for forensics

    def test_get_refuses_symlinked_artifact(self):
        ref = self.store.put("real content")
        target = self.root / "elsewhere.txt"
        target.write_text("real content")  # identical bytes: only the link itself is wrong
        (self.root / ref).unlink()
        (self.root / ref).symlink_to(target)
        with self.assertRaises(ValueError):
            self.store.get(ref)

    def test_get_refuses_dangling_symlink(self):
        ref = f"artifacts/{sha('ghost')}.txt"
        (self.root / ref).symlink_to(self.root / "does-not-exist")
        with self.assertRaises(ValueError):
            self.store.get(ref)

    def test_put_does_not_follow_symlink_at_destination(self):
        victim = self.root / "victim.txt"
        victim.write_text("keep")
        ref = f"artifacts/{sha('payload')}.txt"
        (self.root / ref).symlink_to(victim)
        with self.assertRaises(ValueError):
            self.store.put("payload")
        self.assertEqual(victim.read_text(), "keep")
        self.assertTrue((self.root / ref).is_symlink())
        dangling = f"artifacts/{sha('payload2')}.txt"
        (self.root / dangling).symlink_to(self.root / "new-victim")
        with self.assertRaises(ValueError):
            self.store.put("payload2")
        self.assertFalse((self.root / "new-victim").exists())

    def test_symlinked_artifacts_dir_is_refused(self):
        ref = self.store.put("inside")
        real = self.root / "artifacts_real"
        (self.root / "artifacts").rename(real)
        (self.root / "artifacts").symlink_to(real)
        with self.assertRaises(ValueError):
            self.store.get(ref)
        with self.assertRaises(ValueError):
            self.store.put("another")
        self.assertEqual(sorted(p.name for p in real.iterdir()), [pathlib.PurePosixPath(ref).name])
        with self.assertRaises(ValueError):
            Store(self.root)

    def test_get_refuses_non_regular_file(self):
        ref = f"artifacts/{sha('dir')}.txt"
        (self.root / ref).mkdir()
        with self.assertRaises(ValueError):
            self.store.get(ref)

    def test_closed_store_refuses_artifact_calls(self):
        ref = self.store.put("x")
        self.store.close()
        with self.assertRaises(ValueError):
            self.store.get(ref)
        with self.assertRaises(ValueError):
            self.store.put("y")

    def test_parallel_puts_of_same_content(self):
        errors, refs = [], []

        def worker():
            try:
                with Store(self.root) as s:
                    refs.append(s.put("contended " * 1000))
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=60)
        self.assertEqual(errors, [])
        self.assertEqual(len(set(refs)), 1)
        self.assertEqual(len(self.artifact_files()), 1)
        self.assertEqual(self.store.get(refs[0]), "contended " * 1000)


if __name__ == "__main__":
    unittest.main()
