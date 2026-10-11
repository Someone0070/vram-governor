#!/usr/bin/env python3
"""Fixed root receiver for the LB controller node-command table SHARE fence.

The lock protects this PostgreSQL command route only; it is not native/public
admission closure or proof of installed controller source provenance.
"""
import hashlib
import json
import os
import re
import select
import selectors
import signal
import stat
import subprocess
import sys
import time
import urllib.parse

HOST = "10.0.0.115"
CONFIG_PATH = "/etc/vram-governor/controller.yaml"
CONFIG_BYTES = 6789
CONFIG_SHA256 = "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37"
IMAGE_PATH = "/usr/local/bin/vram-governor-controller"
IMAGE_BYTES = 12976280
IMAGE_SHA256 = "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c"
UNIT = "vram-governor-controller.service"
DB_IDENTITY_SHA256 = "e69838d8ed3f02ea67ce661f8993636981db9cf69ada53974d97dfa403b9407c"
SCHEMA = "controller-command-fence-v1"
MAX_FRAME = 4096
MAX_INPUT = 128 * 1024
MAX_SQL_OUTPUT = 64 * 1024
SESSION_SECONDS = 180
KEEPALIVE_SECONDS = 4
SQL_TIMEOUT = 8
FIXED_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/nonexistent", "PGCONNECT_TIMEOUT": "8", "PGAPPNAME": "lb-node-command-share-fence"}


class FenceError(Exception):
    """Safe internal failure class; messages are never emitted."""


def _fail(code):
    raise FenceError(code)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_field")
        result[key] = value
    return result


def _no_linked_path(target):
    if not os.path.isabs(target) or ".." in target.split(os.sep):
        _fail("path_shape")
    cursor = os.sep
    for part in target.strip(os.sep).split(os.sep)[:-1]:
        cursor = os.path.join(cursor, part)
        info = os.lstat(cursor)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _fail("path_custody")


def _same_file(a, b):
    keys = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns", "st_uid", "st_gid")
    return all(getattr(a, key) == getattr(b, key) for key in keys)


def _trusted_tool(target):
    _no_linked_path(target)
    info = os.lstat(target)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or not info.st_mode & 0o111:
        _fail("tool_custody")


def _stable_read(target, expected_size, expected_sha, mode=None, gid=None):
    _no_linked_path(target)
    before = os.lstat(target)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_size != expected_size or before.st_mode & 0o022:
        _fail("file_custody")
    if mode is not None and stat.S_IMODE(before.st_mode) != mode:
        _fail("file_mode")
    if gid is not None and before.st_gid != gid:
        _fail("file_group")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            _fail("file_changed")
        chunks = []
        total = 0
        while total < expected_size:
            block = os.read(fd, min(65536, expected_size - total))
            if not block:
                _fail("file_short")
            chunks.append(block)
            total += len(block)
        if os.read(fd, 1):
            _fail("file_grew")
        after = os.fstat(fd)
        named = os.lstat(target)
        if not _same_file(before, after) or not _same_file(before, named):
            _fail("file_changed")
        data = b"".join(chunks)
        if _sha(data) != expected_sha:
            _fail("file_identity")
        return data, before
    finally:
        os.close(fd)


def _capture_fixed(argv, timeout, stdout_limit, stderr_limit):
    child = None
    selector = None
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={"PATH": FIXED_ENV["PATH"], "LANG": "C", "LC_ALL": "C"},
                                 close_fds=True, cwd="/", start_new_session=True, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ, ("out", stdout_limit))
        selector.register(child.stderr, selectors.EVENT_READ, ("err", stderr_limit))
        captured = {"out": bytearray(), "err": bytearray()}
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("service_timeout")
            for key, _ in selector.select(min(0.1, remaining)):
                kind, maximum = key.data
                try:
                    block = os.read(key.fileobj.fileno(), min(4096, maximum + 1 - len(captured[kind])))
                except Exception:
                    _fail("service_capture")
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                captured[kind].extend(block)
                if len(captured[kind]) > maximum:
                    _fail("service_output_bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("service_timeout")
        try:
            code = child.wait(timeout=remaining)
        except Exception:
            _fail("service_timeout")
        if code != 0:
            _fail("service_exit")
        return bytes(captured["out"]), bytes(captured["err"])
    except FenceError:
        raise
    except Exception:
        _fail("service_observation")
    finally:
        if selector is not None:
            selector.close()
        if child is not None:
            if child.poll() is None:
                _kill_child_group(child)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass


def _service_identity():
    _trusted_tool("/usr/bin/systemctl")
    output, errors = _capture_fixed(["/usr/bin/systemctl", "show", "--property=MainPID,InvocationID,ActiveState,SubState,User", UNIT], 5, 4096, 1024)
    if errors:
        _fail("service_observation")
    props = {}
    try:
        for line in output.decode("ascii").splitlines():
            key, sep, value = line.partition("=")
            if not sep or key in props or key not in {"MainPID", "InvocationID", "ActiveState", "SubState", "User"}:
                _fail("service_shape")
            props[key] = value
    except Exception:
        _fail("service_shape")
    if set(props) != {"MainPID", "InvocationID", "ActiveState", "SubState", "User"} or props["ActiveState"] != "active" or props["SubState"] != "running" or props["User"] != "vram-governor" or not props["MainPID"].isdigit() or int(props["MainPID"]) <= 1 or not re.fullmatch(r"[0-9a-f]{32}", props["InvocationID"]):
        _fail("service_identity")
    pid = props["MainPID"]
    proc = "/proc/" + pid
    try:
        proc_info = os.stat(proc)
        exe_info = os.stat(proc + "/exe")
        with open(proc + "/cmdline", "rb") as stream:
            cmdline = stream.read(65537)
        with open(proc + "/stat", "rb") as stream:
            statline = stream.read(8193)
    except Exception:
        _fail("service_process")
    expected_cmd = IMAGE_PATH.encode("ascii") + b"\0-config\0" + CONFIG_PATH.encode("ascii") + b"\0"
    fields = statline.rsplit(b")", 1)[-1].strip().split()
    if len(cmdline) > 65536 or cmdline != expected_cmd or len(fields) < 20 or exe_info.st_ino == 0:
        _fail("service_command")
    try:
        start = fields[19].decode("ascii")
    except Exception:
        _fail("service_process")
    image, image_info = _stable_read(IMAGE_PATH, IMAGE_BYTES, IMAGE_SHA256, mode=0o755)
    del image
    if (image_info.st_dev, image_info.st_ino) != (exe_info.st_dev, exe_info.st_ino):
        _fail("running_image_identity")
    return (int(pid), props["InvocationID"], start, proc_info.st_dev, proc_info.st_ino, exe_info.st_dev, exe_info.st_ino)


def _config_bytes():
    data, info = _stable_read(CONFIG_PATH, CONFIG_BYTES, CONFIG_SHA256, mode=0o640, gid=990)
    return data, (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _yaml_database_url(raw):
    try:
        import yaml
        class UniqueLoader(yaml.SafeLoader):
            pass
        def construct_mapping(loader, node, deep=False):
            mapping = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if key in mapping:
                    _fail("config_duplicate")
                mapping[key] = loader.construct_object(value_node, deep=deep)
            return mapping
        UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
        config = yaml.load(raw.decode("utf-8", "strict"), Loader=UniqueLoader)
    except FenceError:
        raise
    except Exception:
        _fail("config_parse")
    if not isinstance(config, dict) or not isinstance(config.get("database_url"), str) or not config["database_url"] or len(config["database_url"]) > 8192:
        _fail("config_database_url")
    return config["database_url"]


def _connection_environment(dsn):
    if not isinstance(dsn, str) or "\x00" in dsn or "\n" in dsn or "\r" in dsn:
        _fail("database_uri")
    if re.search(r"%(?![0-9a-fA-F]{2})", dsn):
        _fail("database_uri_escape")
    try:
        uri = urllib.parse.urlsplit(dsn)
        if uri.scheme not in ("postgres", "postgresql") or uri.fragment or not uri.path.startswith("/"):
            _fail("database_uri")
        decode = lambda text: urllib.parse.unquote(text, encoding="utf-8", errors="strict")
        fields = {}
        for key, value in (("PGDATABASE", decode(uri.path[1:])), ("PGUSER", decode(uri.username) if uri.username is not None else None), ("PGPASSWORD", decode(uri.password) if uri.password is not None else None), ("PGHOST", uri.hostname), ("PGPORT", str(uri.port) if uri.port is not None else None)):
            if value is not None:
                if "\x00" in value or "\n" in value or "\r" in value:
                    _fail("database_uri")
                fields[key] = value
        mapping = {"host": "PGHOST", "hostaddr": "PGHOSTADDR", "port": "PGPORT", "dbname": "PGDATABASE", "user": "PGUSER", "password": "PGPASSWORD", "sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "application_name": "PGAPPNAME", "connect_timeout": "PGCONNECT_TIMEOUT"}
        seen = set()
        pairs = urllib.parse.parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True, encoding="utf-8", errors="strict") if uri.query else []
        for key, value in pairs:
            if key not in mapping or key in seen or mapping[key] in fields or "\x00" in value or "\n" in value or "\r" in value:
                _fail("database_uri_option")
            seen.add(key)
            fields[mapping[key]] = value
        if "PGOPTIONS" in fields or not fields.get("PGDATABASE"):
            _fail("database_uri_option")
        if "PGHOST" in fields and "PGHOSTADDR" in fields:
            _fail("database_host_ambiguous")
    except FenceError:
        raise
    except Exception:
        _fail("database_uri")
    env = dict(FIXED_ENV)
    env.update(fields)
    # Ignore DSN options and set only receiver-owned connection bounds.
    env["PGOPTIONS"] = "-c statement_timeout=8000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=10000"
    env["PGCONNECT_TIMEOUT"] = "8"
    env["PGAPPNAME"] = "lb-node-command-share-fence"
    env["PGSERVICEFILE"] = "/dev/null"
    return env


IDENTITY_SQL = "SELECT pg_catalog.jsonb_build_object('database',pg_catalog.current_database(),'role',current_user,'search_path',pg_catalog.current_setting('search_path'))::text;"
LOCK_SQL = "SELECT pg_catalog.jsonb_build_object('held',count(*)=1)::text FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_class c ON c.oid=l.relation JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE l.locktype='relation' AND l.relation='public.node_commands'::regclass AND n.nspname='public' AND c.relname='node_commands' AND l.pid=pg_catalog.pg_backend_pid() AND l.mode='ShareLock' AND l.granted;"
ABSENT_SQL = "SELECT pg_catalog.jsonb_build_object('absent',count(*)=0)::text FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_class c ON c.oid=l.relation JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE l.locktype='relation' AND l.relation='public.node_commands'::regclass AND n.nspname='public' AND c.relname='node_commands' AND l.pid=pg_catalog.pg_backend_pid() AND l.mode='ShareLock' AND l.granted;"
RESOLUTION_SQL = "SELECT pg_catalog.jsonb_build_object('resolution_matches',pg_catalog.to_regclass('node_commands')='public.node_commands'::regclass)::text;"
READ_WRITE_SQL = "SELECT pg_catalog.jsonb_build_object('read_only',pg_catalog.current_setting('transaction_read_only'))::text;"
SNAPSHOT_SQL = """SELECT pg_catalog.jsonb_build_object(
 'total',count(*),
 'terminal',count(*) FILTER (WHERE status IN ('succeeded','failed','expired')),
 'expired',count(*) FILTER (WHERE status='expired' OR (status IN ('queued','sent') AND expires_at <= pg_catalog.statement_timestamp())),
 'nonterminal',count(*) FILTER (WHERE status NOT IN ('succeeded','failed','expired')),
 'uncertain',count(*) FILTER (WHERE body ? 'uncertain' AND body->'uncertain' IS DISTINCT FROM 'false'::jsonb),
 'malformed',count(*) FILTER (WHERE pg_catalog.jsonb_typeof(body) IS DISTINCT FROM 'object' OR pg_catalog.jsonb_typeof(body->'status') IS DISTINCT FROM 'string' OR body->>'status' IS DISTINCT FROM status OR status NOT IN ('queued','sent','succeeded','failed','expired') OR (body ? 'uncertain' AND pg_catalog.jsonb_typeof(body->'uncertain') IS DISTINCT FROM 'boolean'))
)::text FROM public.node_commands;"""


def _validate_identity(row):
    if not isinstance(row, dict) or set(row) != {"database", "role", "search_path"} or any(not isinstance(row[k], str) for k in row):
        _fail("database_identity")
    canonical = json.dumps(row, sort_keys=True).encode("utf-8")
    if _sha(canonical) != DB_IDENTITY_SHA256:
        _fail("database_identity")


def _project_summary(row):
    fields = ("total", "terminal", "expired", "nonterminal", "uncertain", "malformed")
    if not isinstance(row, dict) or set(row) != set(fields) or any(type(row[key]) is not int or row[key] < 0 or row[key] > 1000000000 for key in fields):
        _fail("snapshot_schema")
    if row["terminal"] > row["total"] or row["nonterminal"] > row["total"] or row["terminal"] + row["nonterminal"] != row["total"] or any(row[key] > row["total"] for key in ("expired", "uncertain", "malformed")):
        _fail("snapshot_counts")
    clear = row["expired"] == 0 and row["nonterminal"] == 0 and row["uncertain"] == 0 and row["malformed"] == 0
    return {**row, "command_clear": clear}


def _parse_frame(line, expected_nonce, expected_op):
    if not isinstance(line, bytes) or len(line) > MAX_FRAME or not line.endswith(b"\n"):
        _fail("frame_invalid")
    try:
        value = json.loads(line[:-1].decode("ascii"), object_pairs_hook=_pairs)
    except FenceError:
        raise
    except Exception:
        _fail("frame_invalid")
    if not isinstance(value, dict) or set(value) != {"schema", "operation", "nonce"} or value["schema"] != SCHEMA or value["operation"] != expected_op or value["nonce"] != expected_nonce:
        _fail("frame_invalid")
    return value


def _nonce(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def _probe_service_and_config():
    service = _service_identity()
    config, config_identity = _config_bytes()
    return {"service": service, "config": config_identity, "bytes": config}


class PsqlChannel:
    """One private psql process; raw diagnostics are discarded."""
    def __init__(self, env):
        _trusted_tool("/usr/sbin/runuser")
        _trusted_tool("/usr/lib/postgresql/16/bin/psql")
        argv = ["/usr/sbin/runuser", "--user", "vram-governor", "--preserve-environment", "--", "/usr/lib/postgresql/16/bin/psql", "--no-psqlrc", "--quiet", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--set", "VERBOSITY=sqlstate", "--file=-"]
        try:
            self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, close_fds=True, cwd="/", start_new_session=True, bufsize=0)
        except Exception:
            _fail("database_spawn")
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.child.stdout, selectors.EVENT_READ, "out")
        self.selector.register(self.child.stderr, selectors.EVENT_READ, "err")
        self.out = bytearray()
        self.out_lines = []
        self.out_total = 0
        self.err_total = 0
        self.seq = 0
        self.closed = False

    def query(self, sql, expected_marker, timeout=SQL_TIMEOUT):
        if self.closed or self.child.poll() is not None:
            _fail("database_lost")
        self.seq += 1
        if expected_marker not in {"identity", "resolution", "transaction", "readwrite", "lock", "held", "snapshot", "rollback", "absent", "cleanup"}:
            _fail("database_query_unknown")
        if not isinstance(sql, str) or not sql.endswith(";") or "\n\\echo" in sql:
            _fail("database_sql_shape")
        marker = "__COMMAND_FENCE_" + expected_marker + "_" + str(self.seq) + "__"
        try:
            self.child.stdin.write((sql + "\n\\echo " + marker + "\n").encode("ascii"))
            self.child.stdin.flush()
        except Exception:
            _fail("database_lost")
        deadline = time.monotonic() + timeout + 1
        lines = []
        while time.monotonic() < deadline:
            if self.child.poll() is not None:
                _fail("database_lost")
            ready = self.selector.select(min(0.2, max(0, deadline - time.monotonic())))
            for key, _ in ready:
                try:
                    block = os.read(key.fileobj.fileno(), 4096)
                except Exception:
                    _fail("database_lost")
                if not block:
                    _fail("database_lost")
                if key.data == "err":
                    self.err_total += len(block)
                    if self.err_total > 16384:
                        _fail("database_output_bound")
                    continue
                self.out_total += len(block)
                if self.out_total > MAX_SQL_OUTPUT:
                    _fail("database_output_bound")
                self.out.extend(block)
                while b"\n" in self.out:
                    raw, _, remainder = self.out.partition(b"\n")
                    self.out[:] = remainder
                    if len(raw) > 16384:
                        _fail("database_line_bound")
                    try:
                        line = raw.decode("utf-8", "strict")
                    except Exception:
                        _fail("database_output_invalid")
                    if line == marker:
                        if len(lines) != 1:
                            _fail("database_output_invalid")
                        try:
                            value = json.loads(lines[0])
                        except Exception:
                            _fail("database_output_invalid")
                        if not isinstance(value, dict):
                            _fail("database_output_invalid")
                        return value
                    lines.append(line)
                    if len(lines) > 1:
                        _fail("database_output_invalid")
        _fail("database_timeout")

    def finish(self, timeout=5):
        if self.closed:
            return
        self.closed = True
        try:
            if self.child.poll() is None:
                try:
                    self.child.stdin.write(b"\\q\n")
                    self.child.stdin.flush()
                    self.child.stdin.close()
                except Exception:
                    pass
                try:
                    code = self.child.wait(timeout=timeout)
                except Exception:
                    _kill_child_group(self.child)
                    code = self.child.wait(timeout=2)
            else:
                code = self.child.returncode
            if code != 0:
                _fail("database_exit")
        finally:
            self.selector.close()
            for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
                try:
                    stream.close()
                except Exception:
                    pass

    def abort(self):
        if self.closed:
            return
        self.closed = True
        _kill_child_group(self.child)
        self.selector.close()
        for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
            try:
                stream.close()
            except Exception:
                pass

    def rollback_cleanup(self):
        if self.closed:
            return
        try:
            if self.child.poll() is None:
                self.query("ROLLBACK; SELECT '{\"rollback\":true}'::jsonb::text;", "cleanup", timeout=2)
        finally:
            self.abort()


def _kill_child_group(child):
    if child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except Exception:
        try:
            child.terminate()
        except Exception:
            pass
    try:
        child.wait(timeout=1)
    except Exception:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except Exception:
            try:
                child.kill()
            except Exception:
                pass
        try:
            child.wait(timeout=2)
        except Exception:
            _fail("database_cleanup_uncertain")


class FenceTransaction:
    def __init__(self, initial, db, identity_reader=_probe_service_and_config, deadline=None, clock=time.monotonic):
        self.initial = initial
        self.db = db
        self.identity_reader = identity_reader
        self.deadline = deadline
        self.clock = clock
        self.started = False
        self.rolled_back = False
        self.closed = False
        identity = self.query(IDENTITY_SQL, "identity")
        _validate_identity(identity)
        self.assert_resolution()
        self.query("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE; SET LOCAL statement_timeout='8s'; SET LOCAL lock_timeout='2s'; SET LOCAL idle_in_transaction_session_timeout='10s'; SELECT '{\"transaction\":true}'::jsonb::text;", "transaction")
        if self.query(READ_WRITE_SQL, "readwrite") != {"read_only": "off"}:
            _fail("database_not_read_write")
        self.assert_resolution()
        self.query("LOCK TABLE public.node_commands IN SHARE MODE NOWAIT; SELECT '{\"locked\":true}'::jsonb::text;", "lock")
        self.started = True
        held = self.query(LOCK_SQL, "held")
        if held != {"held": True}:
            _fail("lock_not_owned")

    def assert_held(self):
        if self.query(LOCK_SQL, "held") != {"held": True}:
            _fail("lock_lost")

    def check_deadline(self):
        if self.deadline is not None and self.clock() >= self.deadline:
            _fail("session_deadline")

    def query(self, sql, marker):
        self.check_deadline()
        timeout = SQL_TIMEOUT if self.deadline is None else min(SQL_TIMEOUT, self.deadline - self.clock())
        if timeout <= 0:
            _fail("session_deadline")
        value = self.db.query(sql, marker, timeout=timeout)
        self.check_deadline()
        return value

    def assert_resolution(self):
        if self.query(RESOLUTION_SQL, "resolution") != {"resolution_matches": True}:
            _fail("relation_shadowed")

    def snapshot(self, current):
        self.assert_resolution()
        self.assert_held()
        if not _same_original(self.initial, current):
            _fail("original_identity_changed")
        raw = self.query(SNAPSHOT_SQL, "snapshot")
        summary = _project_summary(raw)
        self.assert_resolution()
        self.assert_held()
        if not _same_original(self.initial, self.identity_reader()):
            _fail("original_identity_changed")
        return summary

    def close_successfully(self, current):
        self.assert_resolution()
        self.assert_held()
        if not _same_original(self.initial, current):
            _fail("original_identity_changed")
        self.query("ROLLBACK; SELECT '{\"rollback\":true}'::jsonb::text;", "rollback")
        self.rolled_back = True
        absent = self.query(ABSENT_SQL, "absent")
        if absent != {"absent": True}:
            _fail("lock_still_owned")
        self.check_deadline()
        current_identity = self.identity_reader()
        self.check_deadline()
        if not _same_original(self.initial, current_identity):
            _fail("original_identity_changed")
        timeout = 5 if self.deadline is None else min(5, self.deadline - self.clock())
        if timeout <= 0:
            _fail("session_deadline")
        self.db.finish(timeout=timeout)
        self.check_deadline()
        self.closed = True
        return True

    def cleanup(self):
        if self.closed:
            return
        try:
            if self.started and not self.rolled_back:
                self.db.rollback_cleanup()
                self.rolled_back = True
        except Exception:
            pass
        try:
            self.db.abort()
        finally:
            self.closed = True


def _same_original(first, second):
    return first["service"] == second["service"] and first["config"] == second["config"]


def _production_connect(initial):
    dsn = _yaml_database_url(initial["bytes"])
    env = _connection_environment(dsn)
    return PsqlChannel(env)


def _open_transaction(identity_reader=_probe_service_and_config, connector=_production_connect, deadline=None, clock=time.monotonic):
    if deadline is not None and clock() >= deadline:
        _fail("session_deadline")
    initial = identity_reader()
    if deadline is not None and clock() >= deadline:
        _fail("session_deadline")
    db = connector(initial)
    try:
        return FenceTransaction(initial, db, identity_reader, deadline, clock)
    except Exception:
        try:
            db.abort()
        except Exception:
            pass
        raise


def _response(operation, nonce, **fields):
    return {"ok": True, "schema": SCHEMA, "operation": operation, "nonce": nonce, **fields}


_FAILURE_CODE_CATEGORIES = {
    "original_service_config_custody": frozenset((
        "path_shape", "path_custody", "tool_custody", "file_custody", "file_mode", "file_group", "file_changed",
        "file_short", "file_grew", "file_identity", "service_timeout", "service_capture", "service_output_bound",
        "service_exit", "service_observation", "service_shape", "service_identity", "service_process",
        "service_command", "running_image_identity", "config_duplicate", "config_parse", "config_database_url",
        "original_identity_changed",
    )),
    "database_connection_identity": frozenset((
        "database_uri", "database_uri_escape", "database_uri_option", "database_host_ambiguous", "database_identity",
        "database_spawn", "database_lost", "database_query_unknown", "database_sql_shape", "database_output_bound",
        "database_line_bound", "database_output_invalid", "database_timeout", "database_exit", "database_not_read_write",
        "relation_shadowed",
    )),
    "lock_ownership": frozenset(("lock_not_owned", "lock_lost", "lock_still_owned")),
    "protocol_deadline": frozenset((
        "duplicate_field", "snapshot_schema", "snapshot_counts", "session_deadline", "session_deadline_or_original_changed",
        "frame_bound", "frame_truncated", "frame_read", "session_bound", "session_eof", "frame_close_not_final",
        "frame_trailing", "frame_invalid", "response_bound",
    )),
    "cleanup": frozenset(("database_cleanup_uncertain",)),
}


def _failure_category(error):
    if type(error) is not FenceError or len(error.args) != 1 or not isinstance(error.args[0], str):
        return "unknown"
    code = error.args[0]
    for category, codes in _FAILURE_CODE_CATEGORIES.items():
        if code in codes:
            return category
    return "unknown"


def _emit(value, output=None):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > MAX_FRAME:
        _fail("response_bound")
    target = output or sys.stdout.buffer
    target.write(raw)
    target.flush()


class FrameReader:
    """Nonblocking fixed JSONL reader so deadlines and keepalives fire while idle."""
    def __init__(self, stream):
        self.fd = stream.fileno()
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.fd, selectors.EVENT_READ)
        self.buffer = bytearray()
        self.total = 0
        self.eof = False

    def next_line(self, timeout):
        deadline = time.monotonic() + max(0, timeout)
        while True:
            pos = self.buffer.find(b"\n")
            if pos >= 0:
                if pos + 1 > MAX_FRAME:
                    _fail("frame_bound")
                result = bytes(self.buffer[:pos + 1])
                del self.buffer[:pos + 1]
                return result
            if len(self.buffer) > MAX_FRAME:
                _fail("frame_bound")
            if self.eof:
                if self.buffer:
                    _fail("frame_truncated")
                return b""
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            if not self.selector.select(min(left, 0.2)):
                continue
            try:
                block = os.read(self.fd, 8192)
            except Exception:
                _fail("frame_read")
            if not block:
                self.eof = True
            else:
                self.total += len(block)
                if self.total > MAX_INPUT:
                    _fail("session_bound")
                self.buffer.extend(block)

    def extra(self, timeout=1):
        if self.buffer:
            return bytes(self.buffer)
        line = self.next_line(timeout)
        if line is None:
            return None
        return line

    def close(self):
        self.selector.close()


def serve(input_stream=None, output_stream=None, identity_reader=_probe_service_and_config, connector=_production_connect, clock=time.monotonic, frame_reader=None):
    """Mockable production protocol loop; only fixed operations cross JSONL."""
    source = input_stream if input_stream is not None else sys.stdin.buffer
    target = output_stream if output_stream is not None else sys.stdout.buffer
    reader = frame_reader or FrameReader(source)
    deadline = clock() + SESSION_SECONDS
    tx = None
    nonce = None
    count = 0
    bytes_seen = 0
    next_keepalive = clock() + KEEPALIVE_SECONDS
    try:
        first = reader.next_line(min(8, deadline - clock()))
        if first is None:
            _fail("session_deadline")
        if len(first) > MAX_FRAME or not first.endswith(b"\n"):
            _fail("frame_bound")
        try:
            begin = json.loads(first[:-1].decode("ascii"), object_pairs_hook=_pairs)
        except FenceError:
            raise
        except Exception:
            _fail("frame_invalid")
        if not isinstance(begin, dict) or set(begin) != {"schema", "operation", "nonce"} or begin.get("schema") != SCHEMA or begin.get("operation") != "begin" or not _nonce(begin.get("nonce")):
            _fail("frame_invalid")
        nonce = begin["nonce"]
        bytes_seen += len(first)
        tx = _open_transaction(identity_reader, connector, deadline, clock)
        if clock() >= deadline:
            _fail("session_deadline")
        _emit(_response("begin", nonce, held=True), target)
        while True:
            now = clock()
            if now >= deadline:
                _fail("session_deadline")
            line = reader.next_line(min(deadline - now, max(0, next_keepalive - now)))
            if line is None:
                tx.assert_held()
                if not _same_original(tx.initial, identity_reader()):
                    _fail("original_identity_changed")
                next_keepalive = clock() + KEEPALIVE_SECONDS
                continue
            if not line:
                _fail("session_eof")
            bytes_seen += len(line)
            count += 1
            if bytes_seen > MAX_INPUT or count > 60:
                _fail("session_bound")
            try:
                frame = json.loads(line[:-1].decode("ascii"), object_pairs_hook=_pairs) if line.endswith(b"\n") and len(line) <= MAX_FRAME else None
            except FenceError:
                raise
            except Exception:
                frame = None
            if not isinstance(frame, dict) or frame.get("schema") != SCHEMA or frame.get("nonce") != nonce or frame.get("operation") not in ("snapshot", "close") or set(frame) != {"schema", "operation", "nonce"}:
                _fail("frame_invalid")
            if frame["operation"] == "snapshot":
                summary = tx.snapshot(identity_reader())
                if clock() >= deadline:
                    _fail("session_deadline")
                _emit(_response("snapshot", nonce, **summary), target)
            else:
                tx.close_successfully(identity_reader())
                if clock() >= deadline:
                    _fail("session_deadline")
                remaining = deadline - clock()
                if remaining <= 0:
                    _fail("session_deadline")
                extra = reader.extra(min(1, remaining))
                if extra is None:
                    _fail("frame_close_not_final")
                if extra:
                    _fail("frame_trailing")
                current_identity = identity_reader()
                if clock() >= deadline or not _same_original(tx.initial, current_identity) or clock() >= deadline:
                    _fail("session_deadline_or_original_changed")
                _emit(_response("close", nonce, released=True), target)
                return True
            next_keepalive = clock() + KEEPALIVE_SECONDS
    except Exception as error:
        try:
            _emit({"ok": False, "schema": SCHEMA, "operation": "failed", "nonce": nonce if _nonce(nonce) else None, "category": _failure_category(error)}, target)
        except Exception:
            pass
        return False
    finally:
        if tx is not None:
            tx.cleanup()
        if frame_reader is None:
            reader.close()


def main():
    if os.name != "posix" or os.geteuid() != 0:
        return 1
    return 0 if serve() else 1


if __name__ == "__main__":
    raise SystemExit(main())
