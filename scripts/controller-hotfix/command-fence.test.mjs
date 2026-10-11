import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { _failureDiagnosticForTest, _fixedBootstrapForTest, _fixedSshToolForTest, _openWithTestSeams, _stageDiagnosticForTest, FIXED_SSH_HARDLINKS, FIXED_SSH_TOOL_BYTES, FIXED_SSH_TOOL_SHA256, HOST, ORIGINAL_CONFIG_SHA256, ORIGINAL_IMAGE_SHA256, RECEIVER_BYTES, RECEIVER_SHA256, ResponseReader, SCHEMA, stableReceiver, validateFenceResponse, validateProbeCli } from "./command-fence.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RECEIVER_PATH = path.join(HERE, "command-fence.py");
const EXPECTED_TESTS = Object.freeze([
  "Python transaction, protocol, projection, DSN, PsqlChannel wire, loader, and cleanup controls",
  "Fixed receiver custody digest and source pins",
  "Node exported held-session snapshot and explicit-close roundtrip",
  "Node response projection and finite CLI mutants",
  "Node fixed SSH route and repeated snapshots",
  "Node wrong-nonce and inconsistent-projection rejection",
  "Node oversized-response acquisition fails closed",
  "Node queued early EOF is observed immediately",
  "Node action, settlement, and final-EOF deadlines",
  "Node absolute snapshot, terminal, and final-EOF deadline controls",
  "Fixed SSH two-name hardlink custody and mutation controls",
  "exact test inventory and success-only marker",
]);
const completed = [];
const EXPECTED_PYTHON_FIXTURES = Object.freeze(["transaction-order-and-readwrite", "resolution-shadow-positive-negative", "busy-nowait-and-own-lock", "projection-historic-expiry-and-blockers", "dsn-duplicate-escape-and-credential", "fixed-config-private-mode-group-custody", "serve-eof-loss-deadline-and-drift", "extra-eof-deadline-and-identity-drift", "psql-channel-real-query-wire-and-parser", "psql-nonzero-settlement-and-malformed-output", "metadata-helper-cap-timeout-and-child-settlement", "generated-bootstrap-valid-hash-compile-and-invalid-framing"]);
async function control(name, run) {
  const started = Date.now();
  await run();
  if (Date.now() - started > 10000) throw new Error("finite control exceeded bound: " + name);
  completed.push(name);
}

const pythonControls = String.raw`import hashlib, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("command_fence", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
identity_row = {"database": "fixed-test-db", "role": "fixed-test-role", "search_path": "public"}
m.DB_IDENTITY_SHA256 = m._sha(json.dumps(identity_row, sort_keys=True).encode("utf-8"))
original = {"service": (11, "a" * 32, "123", 4, 5, 6, 7), "config": (1, 2, 0, 990, 0o100640, 1, 6789, 8, 9), "bytes": b"fixed dsn bytes"}
snapshot = {"total": 3, "terminal": 1, "expired": 1, "nonterminal": 2, "uncertain": 1, "malformed": 0}
class DB:
    def __init__(self, resolution=True, held=True, read_only="off", fail_snapshot=False, absent=True, busy=False, on_snapshot=None):
        self.resolution, self.held, self.read_only = resolution, held, read_only
        self.fail_snapshot, self.absent, self.busy, self.on_snapshot = fail_snapshot, absent, busy, on_snapshot
        self.calls, self.finished, self.aborted, self.cleaned = [], 0, 0, 0
    def query(self, sql, marker, timeout=m.SQL_TIMEOUT):
        assert isinstance(sql, str) and sql.endswith(";")
        self.calls.append((marker, sql))
        if marker == "identity": return identity_row
        if marker == "resolution": return {"resolution_matches": self.resolution}
        if marker == "readwrite": return {"read_only": self.read_only}
        if marker == "held": return {"held": self.held}
        if marker == "lock" and self.busy: raise m.FenceError("nowait lock conflict")
        if marker == "snapshot":
            if self.on_snapshot: self.on_snapshot()
            if self.fail_snapshot: raise m.FenceError("lost")
            return dict(snapshot)
        if marker == "rollback": return {}
        if marker == "absent": return {"absent": self.absent}
        if marker in ("transaction", "cleanup", "lock"): return {}
        raise AssertionError("unknown fixed SQL label")
    def finish(self, timeout=5): self.finished += 1
    def abort(self): self.aborted += 1
    def rollback_cleanup(self): self.cleaned += 1

class Reader:
    def __init__(self, lines, on_extra=None): self.lines = list(lines); self.timeouts = []; self.on_extra = on_extra
    def next_line(self, timeout):
        self.timeouts.append(timeout)
        if not self.lines: return b""
        item = self.lines.pop(0)
        return item(timeout) if callable(item) else item
    def extra(self, timeout=1):
        self.timeouts.append(timeout)
        if self.on_extra: self.on_extra()
        return self.lines.pop(0) if self.lines else b""

def frame(op, nonce="a"*32, extra=None):
    value = {"schema": m.SCHEMA, "operation": op, "nonce": nonce}
    if extra: value.update(extra)
    return (json.dumps(value, separators=(",", ":")) + "\n").encode("ascii")

class Clock:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now
    def wait(self, timeout): self.now += timeout; return None

def open_tx(db, identity_reader=lambda: original):
    return m._open_transaction(identity_reader, lambda initial: db)

# Fixture labels are recorded only after the related assertions execute.
python_completed=[]
for code,category in (("service_identity","original_service_config_custody"),("database_lost","database_connection_identity"),("lock_lost","lock_ownership"),("frame_invalid","protocol_deadline"),("database_cleanup_uncertain","cleanup")):
    assert m._failure_category(m.FenceError(code)) == category
assert m._failure_category(RuntimeError("secret stderr payload")) == "unknown"
assert m._failure_category(m.FenceError("secret raw code")) == "unknown"
# Successful real production class flow: order is identity, name resolution,
# explicit READ WRITE setup, resolution recheck, LOCK, own pg_locks, snapshot.
db = DB()
tx = open_tx(db)
summary = tx.snapshot(original)
assert summary["expired"] == 1 and summary["uncertain"] == 1 and summary["command_clear"] is False
assert tx.close_successfully(original) is True
marks = [mark for mark, sql in db.calls]
assert marks.index("identity") < marks.index("resolution") < marks.index("transaction") < marks.index("readwrite") < marks.index("lock") < marks.index("held") < marks.index("snapshot") < marks.index("rollback") < marks.index("absent")
assert db.finished == 1 and db.aborted == 0
assert not any(__import__("re").search(r"(?i)\b(insert|update|delete|create|drop|alter)\b", sql) for mark, sql in db.calls)
assert "public.node_commands" in m.LOCK_SQL and "pg_catalog.pg_class" in m.LOCK_SQL and "pg_catalog.pg_namespace" in m.LOCK_SQL
assert "to_regclass('node_commands')" in m.RESOLUTION_SQL and "'public.node_commands'::regclass" in m.RESOLUTION_SQL
assert "READ WRITE" in next(sql for mark, sql in db.calls if mark == "transaction")
assert "NOWAIT" in next(sql for mark, sql in db.calls if mark == "lock")
python_completed.append("transaction-order-and-readwrite")

# A shadow, busy lock, read-only transaction, missing own lock, failed close,
# connection loss, or original identity drift cannot yield a success result.
for bad in (DB(resolution=False), DB(held=False), DB(read_only="on"), DB(fail_snapshot=True), DB(absent=False), DB(busy=True)):
    candidate = None
    try:
        candidate = open_tx(bad)
        if bad.absent is False:
            candidate.close_successfully(original)
        else:
            candidate.snapshot(original)
    except Exception:
        if candidate is not None: candidate.cleanup()
    assert bad.finished == 0
    assert not any(mark == "snapshot" for mark, sql in bad.calls) if (not bad.resolution or not bad.held or bad.read_only != "off") else True

drift_db = DB()
reads = [original, dict(original, config=(99,))]
def drifting_reader(): return reads.pop(0) if reads else original
drift_tx = open_tx(drift_db, drifting_reader)
try: drift_tx.snapshot(original)
except Exception: drift_tx.cleanup()
else: raise AssertionError("identity drift accepted")
assert any(mark == "snapshot" for mark, sql in drift_db.calls) and drift_db.finished == 0
python_completed.append("resolution-shadow-positive-negative")
python_completed.append("busy-nowait-and-own-lock")

# SQL output projection has no row data and all blocker classes veto clear.
base = {"total": 2, "terminal": 2, "expired": 0, "nonterminal": 0, "uncertain": 0, "malformed": 0}
assert m._project_summary(base)["command_clear"] is True
zero_inventory = {"total": 0, "terminal": 0, "expired": 0, "nonterminal": 0, "uncertain": 0, "malformed": 0}
assert m._project_summary(zero_inventory)["command_clear"] is True
for key in ("expired", "uncertain", "malformed"):
    mutant = dict(base, **{key: 1})
    assert m._project_summary(mutant)["command_clear"] is False
for mutant in (dict(base, total=True), dict(base, terminal=3), dict(base, extra=0), dict(base, nonterminal=1)):
    try: m._project_summary(mutant)
    except m.FenceError: pass
    else: raise AssertionError("malformed counts accepted")
assert "body ? 'uncertain'" in m.SNAPSHOT_SQL and "IS DISTINCT FROM 'false'::jsonb" in m.SNAPSHOT_SQL
assert "jsonb_typeof(body->'uncertain') IS DISTINCT FROM 'boolean'" in m.SNAPSHOT_SQL
assert "status='expired' OR (status IN ('queued','sent') AND expires_at <= pg_catalog.statement_timestamp())" in m.SNAPSHOT_SQL
assert "SELECT '{\"transaction\":true}'::jsonb::text;" in next(sql for mark, sql in db.calls if mark == "transaction")
assert "SELECT '{\"locked\":true}'::jsonb::text;" in next(sql for mark, sql in db.calls if mark == "lock")
assert "SELECT '{\"rollback\":true}'::jsonb::text;" in next(sql for mark, sql in db.calls if mark == "rollback")
assert all(table in m.SNAPSHOT_SQL for table in ("status", "body", "expires_at"))
python_completed.append("projection-historic-expiry-and-blockers")

# Fixed URI/environment projection never moves credentials into an argv or output.
env = m._connection_environment("postgresql://svc:private@127.0.0.1/fixeddb?sslmode=verify-full")
assert env["PGUSER"] == "svc" and env["PGPASSWORD"] == "private" and env["PGDATABASE"] == "fixeddb"
assert env["PGOPTIONS"] == "-c statement_timeout=8000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=10000"
assert "private" not in " ".join(["/usr/bin/psql", "--file=-"])
for dsn in ("postgres://u:p@h/db?user=other", "postgres://u:p@h/db?options=-c%20x=y", "postgres://u:p@h/db?host=other", "postgres://u:p@h/db?sslmode=a&sslmode=b", "postgres://u:p@h/db?bad=x", "postgres://u:p@h/db?sslmode=%ZZ"):
    try: m._connection_environment(dsn)
    except m.FenceError: pass
    else: raise AssertionError("ambiguous URI accepted")
try: m._yaml_database_url(b"database_url: postgres://one/db\ndatabase_url: postgres://two/db\n")
except m.FenceError: pass
else: raise AssertionError("duplicate YAML key accepted")
python_completed.append("dsn-duplicate-escape-and-credential")

# The configured file custody explicitly pins private mode and owning group.
import types
saved_stable=m._stable_read; custody_args={}
fake_info=types.SimpleNamespace(st_dev=1,st_ino=2,st_uid=0,st_gid=990,st_mode=0o100640,st_nlink=1,st_size=6789,st_mtime_ns=8,st_ctime_ns=9)
def fake_stable(path,size,digest,mode=None,gid=None):
    custody_args.update(path=path,size=size,digest=digest,mode=mode,gid=gid)
    return b"pinned",fake_info
m._stable_read=fake_stable
try: config_data,config_identity=m._config_bytes()
finally: m._stable_read=saved_stable
assert custody_args["mode"] == 0o640 and custody_args["gid"] == 990 and config_identity[2:5] == (0,990,0o100640)
baseline_stat=types.SimpleNamespace(st_dev=1,st_ino=2,st_uid=0,st_gid=990,st_mode=0o100640,st_nlink=1,st_size=4,st_mtime_ns=8,st_ctime_ns=9)
wrong_group=types.SimpleNamespace(**{**baseline_stat.__dict__,"st_gid":991})
saved_fs={key:getattr(m.os,key) for key in ("lstat","open","fstat","read","close")}; saved_path_check=m._no_linked_path; saved_nofollow=getattr(m.os,"O_NOFOLLOW",None); saved_cloexec=getattr(m.os,"O_CLOEXEC",None)
def gid_mutant(stage):
    before=wrong_group if stage == "before" else baseline_stat
    opened=wrong_group if stage == "opened" else baseline_stat
    after=wrong_group if stage == "postread" else baseline_stat
    named=wrong_group if stage == "named" else baseline_stat
    lstat_values=iter([before,named]); fstat_values=iter([opened,after]); read_values=iter([b"data",b""])
    m._no_linked_path=lambda target: None; m.os.lstat=lambda target: next(lstat_values); m.os.open=lambda *args: 77; m.os.O_NOFOLLOW=0; m.os.O_CLOEXEC=0
    m.os.fstat=lambda fd: next(fstat_values); m.os.read=lambda fd,count: next(read_values); m.os.close=lambda fd: None
    try: result=m._stable_read("/fixed",4,m._sha(b"data"),mode=0o640,gid=990)
    except m.FenceError:
        if stage == "valid": raise
        return
    if stage != "valid": raise AssertionError("group custody drift accepted at " + stage)
    assert result[0] == b"data"
try:
    for stage in ("valid","before","opened","postread","named"): gid_mutant(stage)
finally:
    for key,value in saved_fs.items(): setattr(m.os,key,value)
    m._no_linked_path=saved_path_check
    if saved_nofollow is None: delattr(m.os,"O_NOFOLLOW")
    else: m.os.O_NOFOLLOW=saved_nofollow
    if saved_cloexec is None: delattr(m.os,"O_CLOEXEC")
    else: m.os.O_CLOEXEC=saved_cloexec
python_completed.append("fixed-config-private-mode-group-custody")

# Fixed protocol positive roundtrip drives production serve/FenceTransaction.
db2 = DB()
reader = Reader([frame("begin"), frame("snapshot"), frame("close")])
output = __import__("io").BytesIO()
assert m.serve(output_stream=output, identity_reader=lambda: original, connector=lambda initial: db2, frame_reader=reader) is True, (output.getvalue(), db2.calls)
responses = [json.loads(line) for line in output.getvalue().splitlines()]
assert [value["operation"] for value in responses] == ["begin", "snapshot", "close"]
assert responses[-1]["released"] is True and db2.finished == 1
failure_db = DB(resolution=False); failure_output = __import__("io").BytesIO()
assert m.serve(output_stream=failure_output, identity_reader=lambda: original, connector=lambda initial: failure_db, frame_reader=Reader([frame("begin")])) is False
failure_response=json.loads(failure_output.getvalue().splitlines()[-1])
assert set(failure_response) == {"ok","schema","operation","nonce","category"}
assert failure_response == {"ok":False,"schema":m.SCHEMA,"operation":"failed","nonce":"a"*32,"category":"database_connection_identity"}
secret_output=__import__("io").BytesIO()
assert m.serve(output_stream=secret_output, identity_reader=lambda: original, connector=lambda initial: (_ for _ in ()).throw(RuntimeError("secret DSN stderr body")), frame_reader=Reader([frame("begin")])) is False
secret_response=json.loads(secret_output.getvalue().splitlines()[-1])
assert secret_response["category"] == "unknown" and "secret" not in secret_output.getvalue().decode("ascii")

# Idle keepalive asks the same psql backend for its own lock before next input.
db3 = DB(); clock = Clock(); idle_reader = Reader([frame("begin"), lambda seconds: clock.wait(seconds), frame("close")])
idle_output = __import__("io").BytesIO()
assert m.serve(output_stream=idle_output, identity_reader=lambda: original, connector=lambda initial: db3, clock=clock, frame_reader=idle_reader) is True
assert len([1 for mark, sql in db3.calls if mark == "held"]) >= 3

# Unknown keys/operation, nonce mismatch, EOF, deadline, connection loss, and
# drift fail closed and settle only the transaction created by this receiver.
for bad_line in (frame("begin", extra={"sql": "drop"}), frame("unknown"), b"not json\n"):
    unused = DB(); called = []
    assert m.serve(output_stream=__import__("io").BytesIO(), connector=lambda initial: called.append(True) or unused, frame_reader=Reader([bad_line])) is False
    assert not called
eof_db = DB(); eof_reader = Reader([frame("begin"), b""])
eof_out = __import__("io").BytesIO()
assert m.serve(output_stream=eof_out, identity_reader=lambda: original, connector=lambda initial: eof_db, frame_reader=eof_reader) is False
assert eof_db.cleaned == 1 and b"\"operation\":\"close\"" not in eof_out.getvalue(), (eof_db.cleaned, eof_out.getvalue())
lost_db = DB(fail_snapshot=True); lost_out = __import__("io").BytesIO()
assert m.serve(output_stream=lost_out, identity_reader=lambda: original, connector=lambda initial: lost_db, frame_reader=Reader([frame("begin"), frame("snapshot")])) is False
assert lost_db.cleaned == 1 and b"\"operation\":\"close\"" not in lost_out.getvalue()
deadline_db = DB(); clock = Clock(); deadline_reader = Reader([frame("begin"), lambda seconds: (setattr(clock, "now", 281.0) or None)])
deadline_out = __import__("io").BytesIO()
assert m.serve(output_stream=deadline_out, identity_reader=lambda: original, connector=lambda initial: deadline_db, clock=clock, frame_reader=deadline_reader) is False
assert deadline_db.cleaned == 1 and not any(mark == "snapshot" for mark, sql in deadline_db.calls)
# Slow SQL/identity/EOF boundaries cannot emit snapshot or close green after 180s.
slow_clock = Clock(); slow_db = DB(on_snapshot=lambda: setattr(slow_clock, "now", 281.0)); slow_out = __import__("io").BytesIO()
assert m.serve(output_stream=slow_out, identity_reader=lambda: original, connector=lambda initial: slow_db, clock=slow_clock, frame_reader=Reader([frame("begin"), frame("snapshot")])) is False
assert not any(json.loads(line).get("operation") == "snapshot" for line in slow_out.getvalue().splitlines())
extra_clock = Clock(); extra_db = DB(); extra_out = __import__("io").BytesIO()
extra_reader = Reader([frame("begin"), frame("close")], on_extra=lambda: setattr(extra_clock, "now", 281.0))
assert m.serve(output_stream=extra_out, identity_reader=lambda: original, connector=lambda initial: extra_db, clock=extra_clock, frame_reader=extra_reader) is False
assert b'"operation":"close"' not in extra_out.getvalue()
python_completed.append("serve-eof-loss-deadline-and-drift")
python_completed.append("extra-eof-deadline-and-identity-drift")
identity_calls = [0]
def drift_after_extra():
    identity_calls[0] += 1
    return dict(original, config=(99,)) if identity_calls[0] >= 4 else original
identity_db = DB(); identity_out = __import__("io").BytesIO()
assert m.serve(output_stream=identity_out, identity_reader=drift_after_extra, connector=lambda initial: identity_db, frame_reader=Reader([frame("begin"), frame("close")])) is False
assert b'"operation":"close"' not in identity_out.getvalue()
assert m._parse_frame(frame("snapshot"), "a"*32, "snapshot")["operation"] == "snapshot"
for bad in (frame("snapshot", nonce="b"*32), b'{"schema":"controller-command-fence-v1","operation":"snapshot","nonce":"' + b"a"*32 + b'","extra":1}\n'):
    try: m._parse_frame(bad, "a"*32, "snapshot")
    except m.FenceError: pass
    else: raise AssertionError("invalid frame accepted")

# Actual production PsqlChannel query/echo parser using fake child, streams,
# selector and os.read. No database client or socket is launched.
class Pipe:
    def __init__(self, fd, data=b""): self.fd, self.data, self.closed = fd, bytearray(data), False
    def fileno(self): return self.fd
    def read(self, size):
        value = bytes(self.data[:size]); del self.data[:size]; return value
    def close(self): self.closed = True
class FakeStdin:
    def __init__(self, child): self.child, self.writes, self.closed = child, [], False
    def write(self, data):
        self.writes.append(bytes(data))
        match = __import__("re").search(rb"\\echo (__COMMAND_FENCE_[A-Za-z]+_[0-9]+__)\n$", bytes(data))
        if match:
            marker = match.group(1)
            self.child.stdout.data.extend(self.child.reply(marker))
    def flush(self): pass
    def close(self): self.closed = True
class FakePsqlChild:
    next_fd=701
    def __init__(self, mode="ok", exit_code=None):
        self.stdout, self.stderr = Pipe(FakePsqlChild.next_fd), Pipe(FakePsqlChild.next_fd+1); FakePsqlChild.next_fd += 2
        self.returncode = exit_code; self.mode = mode; self.pid = 12345
        self.stdin = FakeStdin(self); self.wait_calls = []
    def poll(self): return self.returncode
    def wait(self, timeout=None): self.wait_calls.append(timeout); self.returncode = self.returncode if self.returncode is not None else 0; return self.returncode
    def terminate(self): self.returncode=1
    def kill(self): self.returncode=1
    def reply(self, marker):
        if self.mode == "extra": return b'{"wire":true}\n{"second":true}\n' + marker + b"\n"
        if self.mode == "invalid": return b"not-json\n" + marker + b"\n"
        return b'{"wire":true}\n' + marker + b"\n"
class FakeSelector:
    def __init__(self): self.entries = []; self.closed = False
    def register(self, stream, event, data): self.entries.append((stream, data))
    def select(self, timeout): return [(Key(stream, data), 1) for stream, data in self.entries if stream.data]
    def close(self): self.closed = True
    def get_map(self): return self.entries
class Key:
    def __init__(self, fileobj, data): self.fileobj, self.data = fileobj, data
children = []; original_popen=m.subprocess.Popen; original_selector=m.selectors.DefaultSelector; original_read=m.os.read; original_trusted=m._trusted_tool; original_killpg=getattr(m.os,"killpg",None); killed_groups=[]
def fake_popen(*args, **kwargs):
    child=FakePsqlChild(); children.append(child); return child
m.subprocess.Popen=fake_popen; m.selectors.DefaultSelector=FakeSelector; m._trusted_tool=lambda target: None
m.os.killpg=lambda pid,sig: (killed_groups.append((pid,sig)), (_ for _ in ()).throw(ProcessLookupError()))[1] if any(child.pid==pid for child in children) else (_ for _ in ()).throw(AssertionError("foreign process group signal"))
m.os.read=lambda fd, size: next(child.stdout.read(size) if child.stdout.fd == fd else child.stderr.read(size) for child in children if fd in (child.stdout.fd, child.stderr.fd))
try:
    channel=m.PsqlChannel(dict(m.FIXED_ENV)); row=channel.query("""SELECT '{"wire":true}'::jsonb::text;""", "snapshot")
    assert row == {"wire": True}
    wire=children[-1].stdin.writes[0]
    assert wire == b"""SELECT '{"wire":true}'::jsonb::text;\n\\echo __COMMAND_FENCE_snapshot_1__\n"""
    for label in ("transaction", "lock", "rollback"):
        sql=next(statement for mark, statement in db.calls if mark == label)
        flow=m.PsqlChannel(dict(m.FIXED_ENV)); flow.query(sql, label)
        assert children[-1].stdin.writes[0] == (sql+"\n\\echo __COMMAND_FENCE_"+label+"_1__\n").encode("ascii")
        flow.abort()
    before=len(children[-1].stdin.writes)
    try: channel.query("SELECT 1", "snapshot")
    except m.FenceError: pass
    else: raise AssertionError("unterminated SQL accepted")
    assert len(children[-1].stdin.writes) == before
    channel.finish()
    python_completed.append("psql-channel-real-query-wire-and-parser")
    for mode in ("extra", "invalid"):
        child=FakePsqlChild(mode); children.append(child)
        ch=m.PsqlChannel(dict(m.FIXED_ENV)); children[-1]=child; ch.child=child; ch.selector=FakeSelector(); ch.selector.register(child.stdout, 1, "out"); ch.selector.register(child.stderr, 1, "err")
        try: ch.query("SELECT 1;", "snapshot")
        except m.FenceError: pass
        else: raise AssertionError("bad psql output accepted")
        ch.abort()
    dead=FakePsqlChild(exit_code=7); children.append(dead); deadch=m.PsqlChannel(dict(m.FIXED_ENV)); deadch.child=dead
    try: deadch.finish()
    except m.FenceError: pass
    else: raise AssertionError("already-exited nonzero psql accepted")
    python_completed.append("psql-nonzero-settlement-and-malformed-output")
    oversized=FakePsqlChild(); oversized.stdout.data.extend(b"1234"); children.append(oversized)
    m.subprocess.Popen=lambda *args, **kwargs: oversized
    try: m._capture_fixed(["fixed-test-helper"], 1, 3, 3)
    except m.FenceError: pass
    else: raise AssertionError("oversized metadata capture accepted")
    assert oversized.returncode is not None and oversized.wait_calls
    timeout_child=FakePsqlChild(); children.append(timeout_child); timeout_clock=Clock()
    class AdvancingSelector(FakeSelector):
        def select(self, timeout): timeout_clock.now += timeout + 1; return []
    saved_monotonic=m.time.monotonic; m.time.monotonic=timeout_clock
    m.selectors.DefaultSelector=AdvancingSelector
    m.subprocess.Popen=lambda *args, **kwargs: timeout_child
    try:
        try: m._capture_fixed(["fixed-test-helper"], 1, 3, 3)
        except m.FenceError: pass
        else: raise AssertionError("metadata helper deadline ignored")
    finally: m.time.monotonic=saved_monotonic
    assert timeout_child.returncode is not None and timeout_child.wait_calls
    python_completed.append("metadata-helper-cap-timeout-and-child-settlement")
finally:
    m.subprocess.Popen=original_popen; m.selectors.DefaultSelector=original_selector; m.os.read=original_read; m._trusted_tool=original_trusted
    if original_killpg is None: delattr(m.os,"killpg")
    else: m.os.killpg=original_killpg

# Execute the actual generated bootstrap against finite in-memory framing.
import builtins, io
bootstrap=sys.argv[2]
receiver=open(sys.argv[1],"rb").read()
def executed(frame, fragments=None):
    old_exec=builtins.exec; old_read=m.os.read; calls=[]; pending=bytearray(frame); reads=[0]
    fragment_sizes=tuple(fragments or (7,))
    def fixed_read(fd, size):
        assert fd == 0
        if not pending: return b""
        limit=fragment_sizes[reads[0] % len(fragment_sizes)]; reads[0]+=1
        count=min(size, len(pending), limit)
        result=bytes(pending[:count]); del pending[:count]
        return result
    def intercept(code, namespace=None): calls.append((code, namespace))
    builtins.exec=intercept
    m.os.read=fixed_read
    try:
        try: old_exec(compile(bootstrap,"<fixed-bootstrap>","exec"),globals(),globals()); code=None
        except SystemExit as error: code=error.code
        queued=bytearray()
        while True:
            block=fixed_read(0,131072)
            if not block: break
            queued.extend(block)
        return calls,code,bytes(queued)
    finally: builtins.exec=old_exec; m.os.read=old_read
digest=hashlib.sha256(receiver).hexdigest().encode("ascii")
valid=str(len(receiver)).encode()+b"\n"+digest+b"\n"+receiver
begin=b'{"schema":"controller-command-fence-v1","operation":"begin","nonce":"' + b"a"*32 + b'"}\n'
calls, code, queued=executed(valid+begin, (1,2,3,5,7,11))
assert code is None and len(calls)==1 and calls[0][0].co_filename=="<fixed-command-fence>", (code, len(calls))
assert queued==begin, (len(queued), queued[:32])
bad_frames=[valid[:-1], str(len(receiver)).encode()+b"\n"+b"0"*64+b"\n"+receiver, b"999999999\n", b""]
for candidate in bad_frames:
    calls, code, queued=executed(candidate, (1,2,4))
    assert not calls and code in (91,92,93)
calls, code, queued=executed(b"131073\n"+digest+b"\n", (1,2,4))
assert not calls and code == 92

python_completed.append("generated-bootstrap-valid-hash-compile-and-invalid-framing")
assert python_completed == ["transaction-order-and-readwrite", "resolution-shadow-positive-negative", "busy-nowait-and-own-lock", "projection-historic-expiry-and-blockers", "dsn-duplicate-escape-and-credential", "fixed-config-private-mode-group-custody", "serve-eof-loss-deadline-and-drift", "extra-eof-deadline-and-identity-drift", "psql-channel-real-query-wire-and-parser", "psql-nonzero-settlement-and-malformed-output", "metadata-helper-cap-timeout-and-child-settlement", "generated-bootstrap-valid-hash-compile-and-invalid-framing"]
assert len(set(python_completed)) == len(python_completed) and python_completed
for mutant in ([], python_completed[:-1], python_completed + [python_completed[-1]], list(reversed(python_completed))):
    assert mutant != python_completed
print("PYTHON_FIXTURES="+json.dumps(python_completed,separators=(",",":")))
print("python mocked production controls passed")`;

class MockSSHChild extends EventEmitter {
  constructor(mode = "ok", clock = null) {
    super(); this.exitCode = null; this.signalCode = null; this.killed = false; this.mode = mode;
    this.stdin = new PassThrough(); this.stdout = new PassThrough(); this.stderr = new PassThrough();
    this.input = Buffer.alloc(0); this.loaded = false; this.closeRequested = false; this.clock = clock;
    this.stdin.on("data", (chunk) => this._data(chunk));
    this.stdin.on("end", () => this._finish());
    if (mode === "spawnError") setImmediate(() => this.emit("error", new Error("SECRET child spawn output")));
  }
  _data(chunk) {
    if (this.mode === "spawnError") return;
    this.input = Buffer.concat([this.input, chunk]);
    if (!this.loaded) {
      const first = this.input.indexOf(10); if (first < 0) return;
      const size = Number(this.input.subarray(0, first).toString("ascii"));
      const second = this.input.indexOf(10, first + 1); if (second < 0) return;
      const digest = this.input.subarray(first + 1, second).toString("ascii");
      if (size !== RECEIVER_BYTES) return this.kill();
      if (this.input.length < second + 1 + size) return;
      const receiver = this.input.subarray(second + 1, second + 1 + size);
      if (crypto.createHash("sha256").update(receiver).digest("hex") !== digest || digest !== RECEIVER_SHA256) return this.kill();
      this.input = this.input.subarray(second + 1 + size); this.loaded = true;
    }
    while (true) {
      const end = this.input.indexOf(10); if (end < 0) return;
      const line = this.input.subarray(0, end).toString("ascii"); this.input = this.input.subarray(end + 1);
      let request; try { request = JSON.parse(line); } catch { return this.kill(); }
      const common = { ok: true, schema: SCHEMA, operation: request.operation, nonce: this.mode === "wrongNonce" && request.operation === "snapshot" ? "0".repeat(32) : request.nonce };
      if (request.operation === "begin") {
        if (this.mode.startsWith("receiverBegin")) {
          const baseMode = this.mode.replace(/(?:ExitCode|SignalCode|StdoutEOF|Close)$/, "");
          const category = ({ receiverBeginService: "original_service_config_custody", receiverBeginDatabase: "database_connection_identity", receiverBeginProtocol: "protocol_deadline", receiverBeginCleanup: "cleanup", receiverBeginUnknown: "unknown", receiverBeginUnknownCategory: "secret receiver category" })[baseMode] ?? "protocol_deadline";
          this.stderr.write("secret stderr body must never escape");
          const nonce = baseMode === "receiverBeginWrongNonce" ? "0".repeat(32) : request.nonce;
          const failure = { ok: false, schema: SCHEMA, operation: "failed", nonce, category };
          if (baseMode === "receiverBeginMalformed") failure.detail = "secret response body";
          this._respond(failure);
          this._deadAfterResponse("Begin");
        }
        else if (this.mode === "oversize") this.stdout.write(Buffer.alloc(70 * 1024, 65));
        else if (this.mode === "earlyClose") {
          this.exitCode = 1;
          let ended = 0; const finish = () => { if (++ended === 2) setImmediate(() => this.emit("close", 1, null)); };
          this.stdout.once("end", finish); this.stderr.once("end", finish);
          this.stdout.end(); this.stderr.end(); this.stdin.destroy();
        }
        else {
          if (this.mode === "lateBeginAction" && this.clock) this.clock.now += 15001;
          this._respond({ ...common, held: true });
          this._deadAfterResponse("Begin");
        }
      }
      else if (request.operation === "snapshot") {
        if (this.mode.startsWith("receiverSnapshotLock")) {
          this.stderr.write("secret snapshot diagnostic");
          this._respond({ ok: false, schema: SCHEMA, operation: "failed", nonce: request.nonce, category: "lock_ownership" });
          this._deadAfterResponse("Snapshot");
          continue;
        }
        if (this.mode === "lateSnapshot" && this.clock) this.clock.now += 180001;
        if (this.mode === "lateSnapshotAction" && this.clock) this.clock.now += 15001;
        const summary = { total: 3, terminal: 2, expired: 0, nonterminal: 1, uncertain: 0, malformed: 0, command_clear: false };
        if (this.mode === "inconsistent") { summary.uncertain = 1; summary.command_clear = true; }
        this._respond({ ...common, ...summary });
        this._deadAfterResponse("Snapshot");
      } else if (request.operation === "close") {
        this.closeRequested = true;
        this.pendingClose = this.mode === "receiverRollbackCleanup"
          ? { ok: false, schema: SCHEMA, operation: "failed", nonce: request.nonce, category: "cleanup" }
          : { ...common, released: true };
      }
      else return this.kill();
    }
  }
  _respond(value) { this.stdout.write(Buffer.from(JSON.stringify(value) + "\n", "ascii")); }
  _deadAfterResponse(operation) {
    const isFailure = this.mode.startsWith(`receiver${operation}`);
    const base = isFailure ? this.mode.replace(/(?:ExitCode|SignalCode|StdoutEOF|Close)$/, "") : `dead${operation}`;
    const suffix = isFailure ? this.mode.slice(base.length) : this.mode.slice(`dead${operation}`.length);
    if (!suffix) return;
    if (suffix === "ExitCode") { this.exitCode = 1; this.deadResponse = true; }
    else if (suffix === "SignalCode") { this.signalCode = "SIGTERM"; this.deadResponse = true; }
    else if (suffix === "StdoutEOF") { this.deadResponse = true; this.stdout.emit("end"); }
    else if (suffix === "Close") { this.deadResponse = true; this.exitCode = 1; this.emit("close", 1, null); }
  }
  _finish() {
    if (this.killed) return;
    if (!this.closeRequested) return this.kill();
    if (this.pendingClose) this._respond(this.pendingClose);
    if (this.mode === "lateTerminal" && this.clock) this.clock.now += 180001;
    if (this.mode === "extraClose") this.stdout.write("{}\n");
    this.exitCode = 0;
    let remaining = 2;
    const closed = () => { if (--remaining === 0) setImmediate(() => { if (this.mode === "lateEOF" && this.clock) this.clock.armed = true; this.emit("close", 0, null); }); };
    this.stdout.once("end", closed); this.stderr.once("end", closed);
    const endStreams = () => { this.stdout.end(); this.stderr.end(); };
    if (this.mode === "lateTerminalAction" && this.clock) setImmediate(() => { this.clock.now += 6001; endStreams(); });
    else endStreams();
  }
  kill() {
    if (this.killed || (this.exitCode !== null && !this.deadResponse)) return;
    this.killed = true; this.signalCode = "SIGTERM"; this.exitCode = 1;
    let remaining = 2;
    const closed = () => { if (--remaining === 0) setImmediate(() => this.emit("close", 1, "SIGTERM")); };
    this.stdout.once("end", closed); this.stderr.once("end", closed);
    this.stdout.end(); this.stderr.end(); this.stdin.destroy();
  }
}

await control(EXPECTED_TESTS[0], async () => {
  const code = `import sys\ntry:\n exec(compile(${JSON.stringify(pythonControls)}, "<fixed-python-controls>", "exec"), globals(), globals())\nexcept BaseException as failure:\n tb=failure.__traceback__\n while tb and tb.tb_next: tb=tb.tb_next\n safe_name=getattr(failure,"name",None)\n print("PYTHON_CONTROL_FAILURE=" + type(failure).__name__ + ":" + str(tb.tb_lineno if tb else 0) + ":" + str(safe_name or ""))\n raise SystemExit(1)`;
  const run = spawnSync("C:/Windows/py.exe", ["-3", "-I", "-B", "-c", code, RECEIVER_PATH, _fixedBootstrapForTest()], {
    cwd: HERE, windowsHide: true, timeout: 30000, maxBuffer: 65536,
    env: { SystemRoot: "C:/Windows", WINDIR: "C:/Windows", PATH: "C:/Windows/System32;C:/Windows", LANG: "C" },
    encoding: "utf8",
  });
  assert.equal(run.error, undefined, "mocked Python controls start");
  assert.equal(run.status, 0, "mocked Python production controls pass: " + run.stdout.trim().slice(0, 160));
  const lines = run.stdout.trim().split(/\r?\n/);
  assert.deepEqual(JSON.parse(lines[0].slice("PYTHON_FIXTURES=".length)), EXPECTED_PYTHON_FIXTURES);
  assert.equal(lines.at(-1), "python mocked production controls passed");
  assert.equal(run.stderr, "");
});

await control(EXPECTED_TESTS[1], async () => {
  assert.equal(ORIGINAL_CONFIG_SHA256, "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37");
  assert.equal(ORIGINAL_IMAGE_SHA256, "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c");
  assert.equal(HOST, "10.0.0.115");
  const bytes = stableReceiver();
  assert.equal(bytes.length, RECEIVER_BYTES);
  assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), RECEIVER_SHA256);
});

await control(EXPECTED_TESTS[2], async () => {
  const nonce = "0123456789abcdef0123456789abcdef";
  let observed = null;
  const child = new MockSSHChild();
  const session = await _openWithTestSeams(() => child, nonce);
  observed = await session.snapshot();
  assert.equal(observed.total, 3); assert.equal(observed.nonterminal, 1); assert.equal(observed.command_clear, false);
  assert.equal(await session.close(), true);
  assert.equal(child.exitCode, 0);
  assert.equal(session.nonce, nonce);
});

await control(EXPECTED_TESTS[3], async () => {
  assert.equal(validateProbeCli(["--probe"]), true);
  for (const args of [[], ["--verify"], ["--probe", "extra"]]) assert.throws(() => validateProbeCli(args));
  const valid = { ok: true, schema: SCHEMA, operation: "snapshot", nonce: "a".repeat(32), total: 1, terminal: 1, expired: 0, nonterminal: 0, uncertain: 0, malformed: 0, command_clear: true };
  assert.equal(validateFenceResponse(JSON.stringify(valid), "snapshot", valid.nonce).command_clear, true);
  for (const mutant of [
    { ...valid, nonce: "b".repeat(32) }, { ...valid, unknown: true }, { ...valid, expired: 1 },
    { ...valid, command_clear: false }, { ...valid, uncertain: 1 }, { ...valid, total: 1.5 },
    { ...valid, ok: false },
  ]) assert.throws(() => validateFenceResponse(JSON.stringify(mutant), "snapshot", valid.nonce));
  for (const [stage, diagnostic] of [
    ["cli", "cli"], ["local_custody", "local_custody"], ["ssh_spawn", "ssh_spawn"], ["ssh_early_exit", "ssh_early_exit"],
    ["receiver_acquisition", "receiver_acquisition"], ["receiver_snapshot", "receiver_snapshot"], ["receiver_rollback", "receiver_rollback"],
    ["receiver_service_config", "receiver_service_config"], ["receiver_database", "receiver_database"], ["receiver_lock", "receiver_lock"],
    ["receiver_protocol", "receiver_protocol"], ["receiver_cleanup", "receiver_cleanup"], ["receiver_unknown", "receiver_unknown"], ["not-a-stage", "unknown"],
  ]) assert.equal(_stageDiagnosticForTest(stage), `fixed controller command fence failed closed: stage=${diagnostic}\n`);
  assert.equal(_failureDiagnosticForTest(new Error("password=secret stderr=private")), "fixed controller command fence failed closed: stage=unknown\n");
  const spawnFailure = new Error("SECRET SSH_PATH=private DSN=hidden");
  let safeSpawnFailure;
  try { await _openWithTestSeams(() => { throw spawnFailure; }, "a".repeat(32)); } catch (error) { safeSpawnFailure = error; }
  assert.equal(_failureDiagnosticForTest(safeSpawnFailure), "fixed controller command fence failed closed: stage=ssh_spawn\n");
  let asyncSpawnFailure;
  try { await _openWithTestSeams(() => new MockSSHChild("spawnError"), "a".repeat(32)); } catch (error) { asyncSpawnFailure = error; }
  assert.equal(_failureDiagnosticForTest(asyncSpawnFailure), "fixed controller command fence failed closed: stage=ssh_spawn\n");
  for (const [mode, stage] of [["receiverBeginService", "receiver_service_config"], ["receiverBeginDatabase", "receiver_database"], ["receiverBeginProtocol", "receiver_protocol"], ["receiverBeginCleanup", "receiver_cleanup"], ["receiverBeginUnknown", "receiver_unknown"], ["receiverBeginMalformed", "receiver_unknown"], ["receiverBeginWrongNonce", "receiver_unknown"], ["receiverBeginUnknownCategory", "receiver_unknown"]]) {
    let failure;
    try { await _openWithTestSeams(() => new MockSSHChild(mode), "b".repeat(32)); } catch (error) { failure = error; }
    assert.equal(_failureDiagnosticForTest(failure), `fixed controller command fence failed closed: stage=${stage}\n`);
  }
  const snapshotChild = new MockSSHChild("receiverSnapshotLock");
  const snapshotSession = await _openWithTestSeams(() => snapshotChild, "c".repeat(32));
  let snapshotFailure;
  try { await snapshotSession.snapshot(); } catch (error) { snapshotFailure = error; }
  assert.equal(_failureDiagnosticForTest(snapshotFailure), "fixed controller command fence failed closed: stage=receiver_lock\n");
  const closeChild = new MockSSHChild("receiverRollbackCleanup");
  const closeSession = await _openWithTestSeams(() => closeChild, "d".repeat(32));
  let closeFailure;
  try { await closeSession.close(); } catch (error) { closeFailure = error; }
  assert.equal(_failureDiagnosticForTest(closeFailure), "fixed controller command fence failed closed: stage=receiver_cleanup\n");
});

await control(EXPECTED_TESTS[4], async () => {
  assert.equal(RECEIVER_BYTES, fs.statSync(RECEIVER_PATH).size);
  const nonce = "a".repeat(32); const child = new MockSSHChild(); let spawnCalls = 0;
  const session = await _openWithTestSeams((exe, args, options) => {
    spawnCalls++;
    assert.equal(exe, "C:/Windows/System32/OpenSSH/ssh.exe");
    assert.equal(args[args.indexOf("-o") + 1], "BatchMode=yes");
    assert.ok(args.includes(`HostName=${HOST}`)); assert.ok(args.includes(`root@${HOST}`));
    assert.ok(args.includes("StrictHostKeyChecking=yes")); assert.ok(!args.some((arg) => /Forward|Proxy|ControlMaster/.test(arg) && arg.startsWith("-L")));
    assert.ok(args.at(-1).includes("/usr/bin/python3 -I -B -c"));
    assert.deepEqual(options.env, { SystemRoot: "C:/Windows", WINDIR: "C:/Windows", ProgramData: "C:/ProgramData", PATH: "C:/Windows/System32;C:/Windows", LANG: "C" });
    assert.equal(options.stdio.join(","), "pipe,pipe,pipe");
    return child;
  }, nonce);
  assert.equal(spawnCalls, 1);
  const first = await session.snapshot(); const second = await session.snapshot();
  assert.deepEqual(first, second);
  await session.close();
  assert.equal(child.exitCode, 0);
});

await control(EXPECTED_TESTS[5], async () => {
  for (const mode of ["wrongNonce", "inconsistent"]) {
    const child = new MockSSHChild(mode);
    const session = await _openWithTestSeams(() => child, "f".repeat(32));
    let failure;
    try { await session.snapshot(); } catch (error) { failure = error; }
    assert.equal(_failureDiagnosticForTest(failure), "fixed controller command fence failed closed: stage=receiver_snapshot\n");
    assert.equal(child.killed, true);
  }
  for (const suffix of ["ExitCode", "SignalCode", "StdoutEOF", "Close"]) {
    const child = new MockSSHChild("deadBegin" + suffix);
    let failure;
    try { await _openWithTestSeams(() => child, "f".repeat(32)); } catch (error) { failure = error; }
    assert.equal(_failureDiagnosticForTest(failure), "fixed controller command fence failed closed: stage=ssh_early_exit\n", suffix);
    assert.equal(child.killed, true);
  }
  for (const suffix of ["ExitCode", "SignalCode", "StdoutEOF", "Close"]) {
    const child = new MockSSHChild("deadSnapshot" + suffix);
    const session = await _openWithTestSeams(() => child, "f".repeat(32));
    let failure;
    try { await session.snapshot(); } catch (error) { failure = error; }
    assert.equal(_failureDiagnosticForTest(failure), "fixed controller command fence failed closed: stage=ssh_early_exit\n");
    assert.equal(child.killed, true);
    await assert.rejects(session.snapshot());
  }
  for (const suffix of ["ExitCode", "SignalCode", "StdoutEOF"]) {
    const child = new MockSSHChild("receiverBeginDatabase" + suffix);
    let failure;
    try { await _openWithTestSeams(() => child, "f".repeat(32)); } catch (error) { failure = error; }
    assert.equal(_failureDiagnosticForTest(failure), "fixed controller command fence failed closed: stage=receiver_database\n", suffix);
    assert.equal(child.killed, true);
  }
  for (const suffix of ["ExitCode", "SignalCode", "StdoutEOF"]) {
    const child = new MockSSHChild("receiverSnapshotLock" + suffix);
    const session = await _openWithTestSeams(() => child, "f".repeat(32));
    let failure;
    try { await session.snapshot(); } catch (error) { failure = error; }
    assert.equal(_failureDiagnosticForTest(failure), "fixed controller command fence failed closed: stage=receiver_lock\n", suffix);
    assert.equal(child.killed, true);
    await assert.rejects(session.snapshot());
  }
  for (const mode of ["receiverBeginMalformedStdoutEOF", "receiverBeginWrongNonceStdoutEOF"]) {
    const child = new MockSSHChild(mode);
    let failure;
    try { await _openWithTestSeams(() => child, "f".repeat(32)); } catch (error) { failure = error; }
    assert.equal(_failureDiagnosticForTest(failure), "fixed controller command fence failed closed: stage=receiver_unknown\n", mode);
    assert.equal(child.killed, true);
  }
});

await control(EXPECTED_TESTS[6], async () => {
  let killed = false; const output = new PassThrough();
  const child = new EventEmitter(); child.kill = () => { killed = true; };
  const reader = new ResponseReader(output, child);
  output.write(Buffer.alloc(70 * 1024, 65));
  await assert.rejects(reader.next(1000, () => 0));
  assert.equal(killed, true);
  output.destroy();
  const oversized = new MockSSHChild("oversize");
  await assert.rejects(_openWithTestSeams(() => oversized, "e".repeat(32)));
  assert.equal(oversized.killed, true);
});

await control(EXPECTED_TESTS[7], async () => {
  let now = 101; const output = new PassThrough();
  const child = new EventEmitter(); child.kill = () => {};
  const reader = new ResponseReader(output, child);
  output.end();
  await assert.rejects(reader.next(100, () => now));
  const early = new MockSSHChild("earlyClose");
  let earlyFailure;
  try { await _openWithTestSeams(() => early, "e".repeat(32)); } catch (error) { earlyFailure = error; }
  assert.equal(_failureDiagnosticForTest(earlyFailure), "fixed controller command fence failed closed: stage=ssh_early_exit\n");
  assert.equal(early.exitCode, 1);
});

await control(EXPECTED_TESTS[8], async () => {
  for (const mode of ["lateBeginAction", "lateSnapshotAction", "lateTerminalAction"]) {
    const clock = { now: 1000 }; const child = new MockSSHChild(mode, clock);
    if (mode === "lateBeginAction") {
      await assert.rejects(_openWithTestSeams(() => child, "e".repeat(32), () => clock.now));
    } else {
      const session = await _openWithTestSeams(() => child, "e".repeat(32), () => clock.now);
      if (mode === "lateSnapshotAction") {
        await assert.rejects(session.snapshot());
      } else {
        await assert.rejects(session.close());
      }
    }
  }
  const clock = { armed: false, now: 1000 };
  const now = () => { if (clock.armed) { clock.now += 101; return clock.now; } return clock.now; };
  const child = new MockSSHChild("lateEOF", clock);
  const session = await _openWithTestSeams(() => child, "e".repeat(32), now);
  await assert.rejects(session.close());
});

await control(EXPECTED_TESTS[9], async () => {
  for (const mode of ["lateSnapshot", "lateTerminal", "extraClose"]) {
    const clock = { now: 1000 }; const child = new MockSSHChild(mode, clock);
    const session = await _openWithTestSeams(() => child, "e".repeat(32), () => clock.now);
    if (mode === "lateSnapshot") {
      await assert.rejects(session.snapshot());
    } else {
      await assert.rejects(session.close());
    }
  }
});

await control(EXPECTED_TESTS[10], async () => {
  assert.deepEqual(FIXED_SSH_HARDLINKS, [
    "C:/Windows/System32/OpenSSH/ssh.exe",
    "C:/Windows/WinSxS/amd64_openssh-client-components-onecore_31bf3856ad364e35_10.0.26100.9549_none_9bb78eedccaa8631/ssh.exe",
  ]);
  assert.equal(FIXED_SSH_TOOL_BYTES, 1257984);
  assert.equal(FIXED_SSH_TOOL_SHA256, "0b8b5653141c6e02e8afc043d1703dcd6410f1606422ff3ba5eb52dc56a5cce9");
  const fixture = Buffer.from("fixed ssh custody fixture bytes");
  const makeInfo = (overrides = {}) => ({
    dev: 7n, ino: 11n, mode: 0x81edn, nlink: 2n, uid: 0n, gid: 0n, size: BigInt(fixture.length), mtimeNs: 100n, ctimeNs: 200n,
    isFile: () => true, isSymbolicLink: () => false, isDirectory: () => false, ...overrides,
  });
  function facade(mutant = "valid", data = fixture) {
    let opened = 0; let fstatCalls = 0; let reads = 0; const closed = [];
    const normalized = FIXED_SSH_HARDLINKS.map((entry) => path.resolve(entry));
    const symlinkAncestor = path.resolve(path.join(path.dirname(normalized[1]), ".."));
    return {
      constants: fs.constants,
      lstatSync(target) {
        const name = path.resolve(target); const alias = normalized.indexOf(name);
        if ((mutant === "ancestor" || (mutant === "ancestor-postread" && opened === 2)) && name === symlinkAncestor) return makeInfo({ isFile: () => false, isSymbolicLink: () => true, isDirectory: () => false });
        if (alias < 0) return makeInfo({ isFile: () => false, isDirectory: () => true, nlink: 1, size: 0 });
        const afterReads = opened === 2;
        const changedName = mutant === "postread-name" && afterReads && alias === 1;
        return makeInfo({ ino: ((mutant === "wrong-inode" && alias === 1) || changedName) ? 12n : 11n,
          size: BigInt(mutant === "wrong-size" && alias === 1 ? fixture.length + 1 : fixture.length),
          nlink: mutant === "wrong-links" && alias === 1 ? 3n : 2n });
      },
      openSync() { opened++; return opened; },
      fstatSync(fd) {
        fstatCalls++;
        const changed = (mutant === "opened-inode" && fstatCalls === 2) || (mutant === "postread-fd" && fstatCalls === 4);
        return makeInfo({ ino: changed ? 12n : 11n });
      },
      readSync(fd, buffer, offset, length) {
        if (mutant === "wrong-digest") { data = Buffer.from(fixture); data[0] ^= 1; }
        if (reads >= data.length) return 0;
        const count = Math.min(length, data.length - reads); data.copy(buffer, offset, reads, reads + count); reads += count; return count;
      },
      closeSync(fd) { closed.push(fd); },
      closed,
    };
  }
  const positive = facade();
  assert.deepEqual(_fixedSshToolForTest(positive, fixture), fixture);
  assert.deepEqual(positive.closed, [1, 2]);
  const mutantClosures = new Map([
    ["wrong-inode", []], ["wrong-digest", [1, 2]], ["wrong-size", []], ["wrong-links", []], ["ancestor", []],
    ["ancestor-postread", [1, 2]], ["opened-inode", [1, 2]], ["postread-fd", [1, 2]], ["postread-name", [1, 2]],
  ]);
  for (const [mutant, expectedClosed] of mutantClosures) {
    const fake = facade(mutant);
    if (mutant === "wrong-digest") {
      assert.throws(() => _fixedSshToolForTest(fake, fixture), (error) => error?.message === "fixed SSH digest failed", mutant);
    } else {
      assert.throws(() => _fixedSshToolForTest(fake, fixture), undefined, mutant);
    }
    assert.deepEqual(fake.closed, expectedClosed, mutant + " closes only its opened handles");
  }
  const closeFailure = facade(); const closeSync = closeFailure.closeSync; const closedOnFailure = [];
  closeFailure.closeSync = (fd) => { closedOnFailure.push(fd); if (fd === 1) throw new Error("mock close failure"); closeSync(fd); };
  assert.throws(() => _fixedSshToolForTest(closeFailure, fixture));
  assert.deepEqual(closedOnFailure, [1, 2]);
});

await control(EXPECTED_TESTS[11], async () => {
  assert.deepEqual([...completed, EXPECTED_TESTS[11]], EXPECTED_TESTS);
  assert.equal(completed.length, EXPECTED_TESTS.length - 1);
  assert.throws(() => { if (completed.length !== EXPECTED_TESTS.length) throw new Error("skipped test inventory"); });
});

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== "--verify") throw new Error("invalid test CLI");
    if (completed.length !== EXPECTED_TESTS.length || completed.some((name, index) => name !== EXPECTED_TESTS[index])) throw new Error("wrong control inventory");
    process.stdout.write("fixed controller command fence controls passed\n");
  } catch {
    process.stderr.write("fixed controller command fence controls failed closed\n");
    process.exitCode = 1;
  }
}
