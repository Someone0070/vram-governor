#!/usr/bin/env python3
"""Private fixed phase-contract helpers for the controller-only rollout.

The CLI cannot reach applying operations. The fixed adapters below are exercised
only by local boundary fixtures until separate root activation acceptance.
"""
import time
import hashlib
import json
import math
import os
import secrets
import re
import selectors
import select
import socket
import ssl
import stat
import subprocess
import sys
import threading
import types

CONTROLLER_UNIT = "vram-governor-controller.service"
CONTROLLER_IMAGE = "/usr/local/bin/vram-governor-controller"
CONTROLLER_CONFIG = "/etc/vram-governor/controller.yaml"
CONTROLLER_CGROUP = "/system.slice/vram-governor-controller.service"
STAGE_DIR = "/var/lib/vram-governor-controller-staging/d771b06efb5715b296d04d891f3d854d"
CANDIDATE_STAGE = STAGE_DIR + "/candidate.bin"
ORIGINAL_STAGE = STAGE_DIR + "/original.bin"
ROLLOUT_DIR = "/var/lib/vram-governor-controller-staging/rollout-d771b06efb5715b296d04d891f3d854d"
ROLLOUT_JOURNAL = ROLLOUT_DIR + "/d771b06efb5715b296d04d891f3d854d.jsonl"
CANDIDATE_SHA256 = "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543"
ORIGINAL_SHA256 = "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c"
IMAGE_BYTES = 12976280
CONFIG_SHA256 = "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37"
CONFIG_BYTES = 6789
CONTROLLER_ADDRESS = "10.0.0.115"
CONTROLLER_HEALTH_PORT = 8443
CONTROLLER_HEALTH_PATH = "/healthz"
CONTROLLER_HEALTH_BODY = b'{"status":"ok"}\n'
CONTROLLER_CA = "/etc/vram-governor/tls/controller.crt"
CONTROLLER_CA_BYTES = 1484
CONTROLLER_CA_SHA256 = "ddc7359a3f730b1817c7adff7ede84439bdf31cc56ff7cf658142473042c1944"
CT_STAT_U64_MAX = (1 << 64) - 1
CONTROLLER_NODE_REJOIN_SQL = """SELECT pg_catalog.jsonb_build_object(
 'found',count(*)=1,
 'connected',pg_catalog.bool_and(body->'observed'->>'connectivity'='connected'),
 'ready',pg_catalog.bool_and(body->'observed'->>'ready'='true'),
 'heartbeat_epoch',pg_catalog.max(pg_catalog.date_part('epoch',(body->'observed'->>'last_heartbeat')::timestamptz))
)::text FROM public.controller_nodes WHERE id='{}';"""
PHASE_LOCK_SQL = """SELECT pg_catalog.jsonb_build_object(
 'resolution_matches',pg_catalog.to_regclass('node_commands')='public.node_commands'::regclass,
 'held',pg_catalog.count(*)=1
)::text FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_class c ON c.oid=l.relation JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE l.locktype='relation' AND l.relation='public.node_commands'::regclass AND n.nspname='public' AND c.relname='node_commands'
 AND l.pid=pg_catalog.pg_backend_pid() AND l.mode='ShareLock' AND l.granted;"""
BRIDGE_SCHEMA = "controller-transport-rollout-bridge-v1"
BRIDGE_FRAME_MAX = 32768
BRIDGE_SESSION_MAX = 180
BRIDGE_MAX_FRAMES = 12
BRIDGE_MAX_BYTES = 128 * 1024
MAX_CAPTURE = 16384
_JOURNAL_STARTED = False

SESSION_LIMIT_MS = 180_000
KEEPALIVE_LIMIT_MS = 5_000
PROTECTED_OBSERVATION_LIMIT_MS = 10_000
ROLLOUT_BUDGETS = {
    "session_ms": SESSION_LIMIT_MS,
    "stop_ms": 20_000,
    "install_ms": 10_000,
    "start_ms": 5_000,
    "health_ms": 10_000,
    "protected_ms": 10_000,
    "rollback_reserve_ms": 80_000,
    "cleanup_ms": 5_000,
}
PHASES = frozenset(("preflight", "original-active", "original-stopped", "candidate-active", "rollback-original-active", "settled", "handoff"))
TRANSITIONS = {
    ("preflight", "accept"): "original-active",
    ("original-active", "stop-verified"): "original-stopped",
    ("original-stopped", "install-verified"): "original-stopped",
    ("original-stopped", "candidate-start-verified"): "candidate-active",
    ("candidate-active", "accept"): "settled",
    ("original-stopped", "rollback-started"): "rollback-original-active",
    ("candidate-active", "rollback-started"): "rollback-original-active",
    ("rollback-original-active", "original-verified"): "settled",
}


class RolloutRefused(Exception):
    """Closed non-sensitive local state-machine refusal."""


def _fail():
    raise RolloutRefused("phase or custody boundary rejected")


def _fixed_controller_health_get(deadline):
    """Pinned-CA loopback GET. The accepted GET /healthz handler is constant and read-only."""
    if type(deadline) not in (int, float) or deadline <= time.monotonic():
        _fail()
    ca, _ = _read_pinned_file(CONTROLLER_CA, CONTROLLER_CA_BYTES, CONTROLLER_CA_SHA256, None)
    left = deadline - time.monotonic()
    if left <= 0:
        _fail()
    try:
        context = ssl.create_default_context(cadata=ca.decode("ascii", "strict"))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        raw = socket.create_connection(("127.0.0.1", CONTROLLER_HEALTH_PORT), timeout=left)
        with raw:
            left = deadline - time.monotonic()
            if left <= 0:
                _fail()
            raw.settimeout(left)
            with context.wrap_socket(raw, server_hostname=CONTROLLER_ADDRESS) as conn:
                left = deadline - time.monotonic()
                if left <= 0:
                    _fail()
                conn.settimeout(left)
                request = ("GET " + CONTROLLER_HEALTH_PATH + " HTTP/1.1\r\nHost: " + CONTROLLER_ADDRESS + "\r\nConnection: close\r\nAccept: application/json\r\n\r\n").encode("ascii")
                conn.sendall(request)
                response = bytearray()
                while len(response) <= 4096:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        _fail()
                    conn.settimeout(left)
                    block = conn.recv(min(1024, 4097 - len(response)))
                    if not block:
                        break
                    response.extend(block)
                if len(response) > 4096:
                    _fail()
    except Exception:
        _fail()
    head, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator or len(body) > 512:
        _fail()
    lines = head.split(b"\r\n")
    if not lines or lines[0] != b"HTTP/1.1 200 OK":
        _fail()
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if not sep or not key or key.lower() in headers:
            _fail()
        headers[key.lower()] = value.strip().lower()
    if time.monotonic() >= deadline or headers.get(b"content-type") != b"application/json" or headers.get(b"content-length") != str(len(CONTROLLER_HEALTH_BODY)).encode("ascii") or b"transfer-encoding" in headers or body != CONTROLLER_HEALTH_BODY:
        _fail()
    return True


def _fixed_node_rejoin_query(fence, node_id, started_wall, deadline):
    """Read the stored heartbeat for the exact protected CT identity, never arbitrary SQL."""
    if not isinstance(fence, PhaseFence) or type(node_id) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", node_id) is None or type(started_wall) not in (int, float):
        _fail()
    sql = CONTROLLER_NODE_REJOIN_SQL.format(node_id)
    deadline = min(fence.deadline, deadline)
    while time.monotonic() < deadline:
        if not fence.keepalive():
            _fail()
        left = min(0.75, deadline - time.monotonic(), fence.deadline - time.monotonic())
        if left <= 0:
            _fail()
        row = fence._query(sql, "snapshot", timeout=left)
        if type(row) is not dict or set(row) != {"found", "connected", "ready", "heartbeat_epoch"}:
            _fail()
        stamp = row["heartbeat_epoch"]
        now_wall = time.time()
        if row["found"] is True and row["connected"] is True and row["ready"] is True and type(stamp) in (int, float) and math.isfinite(float(stamp)) and started_wall < stamp <= now_wall + 2 and now_wall - stamp <= 15:
            if not fence.keepalive() or time.monotonic() >= deadline or time.time() > now_wall + 2:
                _fail()
            return True
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
    _fail()


def _same_stat(a, b):
    return (a.st_dev, a.st_ino, a.st_mode, a.st_nlink, a.st_uid, a.st_gid, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (b.st_dev, b.st_ino, b.st_mode, b.st_nlink, b.st_uid, b.st_gid, b.st_size, b.st_mtime_ns, b.st_ctime_ns)


def _fixed_parents(filename):
    absolute = os.path.abspath(filename)
    parts = absolute.split(os.sep)
    current = os.sep
    for index, part in enumerate(p for p in parts if p):
        current = os.path.join(current, part)
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or (index < len([p for p in parts if p]) - 1 and not stat.S_ISDIR(info.st_mode)):
            _fail()
        if info.st_uid != 0 or (info.st_mode & 0o022):
            _fail()
    return absolute


def _read_pinned_file(filename, length, digest, mode, uid=0, gid=0, keep_open=False):
    filename = _fixed_parents(filename)
    before = os.lstat(filename)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != length or (mode is not None and stat.S_IMODE(before.st_mode) != mode) or before.st_uid != uid or before.st_gid != gid or before.st_mode & 0o022:
        _fail()
    fd = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    retained = False
    try:
        opened = os.fstat(fd)
        if not _same_stat(before, opened):
            _fail()
        h = hashlib.sha256()
        chunks = []
        total = 0
        while total < length:
            block = os.read(fd, min(65536, length - total))
            if not block:
                _fail()
            total += len(block)
            h.update(block)
            chunks.append(block)
        if os.read(fd, 1):
            _fail()
        after = os.fstat(fd)
        named = os.lstat(filename)
        _fixed_parents(filename)
        if not _same_stat(before, after) or not _same_stat(before, named) or h.hexdigest() != digest:
            _fail()
        result = (b"".join(chunks), (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_size, before.st_mtime_ns, before.st_ctime_ns))
        if keep_open:
            retained = True
            return result + (fd,)
        return result
    finally:
        if not retained:
            os.close(fd)


def _fixed_capture(argv, timeout_ms, input_bytes=None, output_limit=MAX_CAPTURE, on_spawn=None, absolute_deadline=None):
    """Bounded fixed-child capture. Callers supply only internally constructed argv."""
    if type(argv) is not list or not argv or argv[0] != "/usr/bin/systemctl" or any(type(a) is not str or len(a) > 256 for a in argv):
        _fail()
    if type(timeout_ms) is not int or timeout_ms <= 0 or timeout_ms > 180000:
        _fail()
    child = None
    selector = selectors.DefaultSelector()
    buffers = {"out": bytearray(), "err": bytearray()}
    local_deadline = time.monotonic() + timeout_ms / 1000
    if absolute_deadline is not None and (type(absolute_deadline) not in (int, float) or not math.isfinite(absolute_deadline)):
        selector.close()
        _fail()
    total_deadline = min(local_deadline, absolute_deadline) if absolute_deadline is not None else local_deadline
    child_deadline = total_deadline - 1.05
    if child_deadline <= time.monotonic():
        selector.close()
        _fail()
    try:
        child = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}, start_new_session=True)
        if on_spawn is not None:
            if not callable(on_spawn):
                _fail()
            on_spawn(child)
        if time.monotonic() >= child_deadline:
            _fail()
        if input_bytes is not None:
            if type(input_bytes) is not bytes or len(input_bytes) > 65536:
                _fail()
            child.stdin.write(input_bytes)
            child.stdin.close()
        selector.register(child.stdout, selectors.EVENT_READ, "out")
        selector.register(child.stderr, selectors.EVENT_READ, "err")
        while selector.get_map():
            remaining = child_deadline - time.monotonic()
            if remaining <= 0:
                _fail()
            for key, _ in selector.select(min(remaining, 0.25)):
                block = os.read(key.fileobj.fileno(), min(4096, output_limit + 1 - len(buffers[key.data])))
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(block)
                if len(buffers[key.data]) > output_limit:
                    _fail()
        remaining = child_deadline - time.monotonic()
        if remaining <= 0:
            _fail()
        code = child.wait(timeout=remaining)
        if code != 0 or buffers["err"] or time.monotonic() >= child_deadline:
            _fail()
        return bytes(buffers["out"])
    except Exception:
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, 9)
            except Exception:
                try:
                    child.kill()
                except Exception:
                    pass
            try:
                cleanup_left = total_deadline - time.monotonic()
                if cleanup_left > 0:
                    child.wait(timeout=min(1, cleanup_left))
            except Exception:
                pass
        _fail()
    finally:
        selector.close()
        if child is not None:
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass


def _systemd_timeout_us(value):
    if type(value) is not str or not value or len(value) > 64:
        _fail()
    units = {"us": 1, "ms": 1000, "s": 1000000, "min": 60000000, "h": 3600000000, "d": 86400000000}
    matches = list(re.finditer(r"([0-9]+)(us|ms|min|s|h|d)", value))
    if not matches or "".join(match.group(0) for match in matches) != value.replace(" ", ""):
        _fail()
    total = sum(int(match.group(1)) * units[match.group(2)] for match in matches)
    if total <= 0 or total > ROLLOUT_BUDGETS["stop_ms"] * 1000:
        _fail()
    return total


def _unit_properties(timeout_ms=5000, deadline=None):
    if deadline is not None:
        timeout_ms = min(timeout_ms, int(max(0, deadline-time.monotonic())*1000))
    raw = _fixed_capture(["/usr/bin/systemctl", "show", "--property=MainPID,InvocationID,ActiveState,SubState,Job,ControlGroup,TimeoutStopUSec", CONTROLLER_UNIT], timeout_ms, output_limit=4096, absolute_deadline=deadline)
    values = {}
    try:
        for line in raw.decode("ascii").splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in {"MainPID", "InvocationID", "ActiveState", "SubState", "Job", "ControlGroup", "TimeoutStopUSec"} or key in values:
                _fail()
            values[key] = value
    except Exception:
        _fail()
    if set(values) != {"MainPID", "InvocationID", "ActiveState", "SubState", "Job", "ControlGroup", "TimeoutStopUSec"}:
        _fail()
    values["_TimeoutStopUSec"] = str(_systemd_timeout_us(values.pop("TimeoutStopUSec")))
    return values


def _controller_cgroup(control_group):
    if control_group not in ("", CONTROLLER_CGROUP):
        _fail()
    if not control_group:
        return []
    directory = "/sys/fs/cgroup" + control_group
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        _fail()
    fd = os.open(os.path.join(directory, "cgroup.procs"), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        raw = os.read(fd, 8193)
        if len(raw) > 8192 or (raw and not raw.endswith(b"\n")):
            _fail()
    finally:
        os.close(fd)
    members = []
    for item in raw.splitlines():
        if not item.isdigit() or int(item) <= 1:
            _fail()
        members.append(int(item))
    if len(members) != len(set(members)):
        _fail()
    return members


def _owned_cgroup_members_if_present():
    root = "/sys/fs/cgroup"
    cursor = root
    for part in CONTROLLER_CGROUP.strip("/").split("/"):
        cursor = os.path.join(cursor, part)
        try:
            info = os.lstat(cursor)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            _fail()
    fd = os.open(os.path.join(cursor, "cgroup.procs"), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        raw = os.read(fd, 8193)
        if len(raw) > 8192 or (raw and not raw.endswith(b"\n")):
            _fail()
    finally:
        os.close(fd)
    members = []
    for item in raw.splitlines():
        if not item.isdigit() or int(item) <= 1:
            _fail()
        members.append(int(item))
    if len(members) != len(set(members)):
        _fail()
    return members


def _controller_file_identities():
    image_path = _fixed_parents(CONTROLLER_IMAGE)
    image_info = os.lstat(image_path)
    if not stat.S_ISREG(image_info.st_mode) or image_info.st_nlink != 1 or image_info.st_uid != 0 or image_info.st_gid != 0 or stat.S_IMODE(image_info.st_mode) != 0o755 or image_info.st_size != IMAGE_BYTES:
        _fail()
    image_hash = hashlib.sha256()
    image_fd = os.open(image_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not _same_stat(image_info, os.fstat(image_fd)):
            _fail()
        total = 0
        while total < IMAGE_BYTES:
            block = os.read(image_fd, min(65536, IMAGE_BYTES - total))
            if not block:
                _fail()
            total += len(block)
            image_hash.update(block)
        if os.read(image_fd, 1) or not _same_stat(image_info, os.fstat(image_fd)) or not _same_stat(image_info, os.lstat(image_path)):
            _fail()
    finally:
        os.close(image_fd)
    image_digest = image_hash.hexdigest()
    if image_digest not in (ORIGINAL_SHA256, CANDIDATE_SHA256):
        _fail()
    _, config_meta = _read_pinned_file(CONTROLLER_CONFIG, CONFIG_BYTES, CONFIG_SHA256, 0o640, 0, 990)
    unit_path = "/etc/systemd/system/vram-governor-controller.service"
    unit_info = os.lstat(unit_path)
    if not stat.S_ISREG(unit_info.st_mode) or unit_info.st_nlink != 1 or unit_info.st_uid != 0 or unit_info.st_gid != 0 or stat.S_IMODE(unit_info.st_mode) != 0o644 or unit_info.st_size > 262144:
        _fail()
    unit_fd = os.open(unit_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not _same_stat(unit_info, os.fstat(unit_fd)):
            _fail()
        chunks = []
        total = 0
        while total <= 262144:
            block = os.read(unit_fd, min(8192, 262145 - total))
            if not block:
                break
            total += len(block)
            chunks.append(block)
        if total != unit_info.st_size or total > 262144 or not _same_stat(unit_info, os.fstat(unit_fd)) or not _same_stat(unit_info, os.lstat(unit_path)):
            _fail()
        unit_digest = hashlib.sha256(b"".join(chunks)).hexdigest()
    finally:
        os.close(unit_fd)
    stage_unit, _ = _read_pinned_file(os.path.join(STAGE_DIR, CONTROLLER_UNIT), unit_info.st_size, unit_digest, 0o600, 0, 0)
    if hashlib.sha256(stage_unit).hexdigest() != unit_digest:
        _fail()
    return {"image_dev": image_info.st_dev, "image_ino": image_info.st_ino, "image_sha256": image_digest,
            "config_sha256": CONFIG_SHA256, "unit_sha256": unit_digest,
            "config_identity": config_meta, "unit_identity": (unit_info.st_dev, unit_info.st_ino, unit_info.st_mtime_ns, unit_info.st_ctime_ns)}


def _observe_controller_fixed(deadline=None):
    if deadline is not None and (type(deadline) not in (int, float) or time.monotonic() >= deadline):
        _fail()
    files = _controller_file_identities()
    if deadline is not None and time.monotonic() >= deadline:
        _fail()
    props = _unit_properties(5000 if deadline is None else max(1, min(5000, int((deadline-time.monotonic())*1000))), deadline)
    if deadline is not None and time.monotonic() >= deadline:
        _fail()
    if props["Job"] not in ("-", ""):
        _fail()
    members = _controller_cgroup(props["ControlGroup"])
    if props["ActiveState"] == "active" and props["SubState"] == "running":
        if not props["MainPID"].isdigit() or int(props["MainPID"]) <= 1 or re.fullmatch(r"[a-f0-9]{32}", props["InvocationID"]) is None or props["ControlGroup"] != CONTROLLER_CGROUP:
            _fail()
        pid = int(props["MainPID"])
        if members != [pid]:
            _fail()
        proc_path = "/proc/" + str(pid)
        proc_info = os.stat(proc_path)
        exe_info = os.stat(proc_path + "/exe")
        with open(proc_path + "/stat", "rb", buffering=0) as stream:
            statline = stream.read(8193)
        with open(proc_path + "/cmdline", "rb", buffering=0) as stream:
            command = stream.read(8193)
        try:
            exe_target = os.readlink(proc_path + "/exe")
        except Exception:
            _fail()
        fields = statline.rsplit(b")", 1)[-1].strip().split()
        if len(statline) > 8192 or len(command) > 8192 or len(fields) < 20 or exe_target != CONTROLLER_IMAGE:
            _fail()
        start = fields[19].decode("ascii", "strict")
        expected_command = CONTROLLER_IMAGE.encode("ascii") + b"\0-config\0" + CONTROLLER_CONFIG.encode("ascii") + b"\0"
        if not start.isdigit() or command != expected_command:
            _fail()
        image_now = os.stat(CONTROLLER_IMAGE)
        if (exe_info.st_dev, exe_info.st_ino) != (files["image_dev"], files["image_ino"]) or (image_now.st_dev, image_now.st_ino) != (files["image_dev"], files["image_ino"]):
            _fail()
        props_after = _unit_properties(5000 if deadline is None else max(1, min(5000, int((deadline-time.monotonic())*1000))), deadline)
        members_after = _controller_cgroup(props_after["ControlGroup"])
        proc_after = os.stat(proc_path)
        exe_after = os.stat(proc_path + "/exe")
        with open(proc_path + "/stat", "rb", buffering=0) as stream:
            stat_after = stream.read(8193)
        fields_after = stat_after.rsplit(b")", 1)[-1].strip().split()
        if props_after != props or members_after != [pid] or (proc_info.st_dev, proc_info.st_ino) != (proc_after.st_dev, proc_after.st_ino) or (exe_info.st_dev, exe_info.st_ino) != (exe_after.st_dev, exe_after.st_ino) or len(stat_after) > 8192 or len(fields_after) < 20 or fields_after[19].decode("ascii", "strict") != start:
            _fail()
        if deadline is not None and time.monotonic() >= deadline:
            _fail()
        return {"phase": "candidate-active" if files["image_sha256"] == CANDIDATE_SHA256 else "original-active",
                "identity": {"pid": pid, "invocation": props["InvocationID"], "start": start, "proc_dev": proc_info.st_dev, "proc_ino": proc_info.st_ino, "cgroup": CONTROLLER_CGROUP,
                             "timeout_stop_us": int(props["_TimeoutStopUSec"]),
                             "image_dev": files["image_dev"], "image_ino": files["image_ino"], "image_sha256": files["image_sha256"],
                             "config_sha256": files["config_sha256"], "unit_sha256": files["unit_sha256"]}}
    if props["ActiveState"] == "inactive" and props["SubState"] == "dead" and props["MainPID"] == "0" and not members and props["ControlGroup"] in ("", CONTROLLER_CGROUP):
        owned_members = _owned_cgroup_members_if_present()
        if deadline is not None and time.monotonic() >= deadline:
            _fail()
        if owned_members not in (None, []):
            _fail()
        return {"phase": "original-stopped", "identity": {"mainpid": 0, "active_state": "inactive", "sub_state": "dead", "job_empty": True,
                "cgroup": props["ControlGroup"], "cgroup_pids": [], "image_dev": files["image_dev"], "image_ino": files["image_ino"], "image_sha256": files["image_sha256"],
                "config_sha256": files["config_sha256"], "unit_sha256": files["unit_sha256"], "timeout_stop_us": int(props["_TimeoutStopUSec"])}}
    _fail()


def _write_private_journal(phase, effects, uncertain):
    global _JOURNAL_STARTED
    if phase not in {"preflight", "stop_intent", "stop_requested", "original_stopped", "candidate_installed", "candidate_start_requested", "settled_candidate", "settled_original", "handoff_fence_lost", "handoff_uncertain"} or type(effects) is not bool or type(uncertain) is not bool:
        _fail()
    staging_parent = _fixed_parents("/var/lib/vram-governor-controller-staging")
    staging_info = os.lstat(staging_parent)
    if not stat.S_ISDIR(staging_info.st_mode) or staging_info.st_uid != 0 or stat.S_IMODE(staging_info.st_mode) != 0o700:
        _fail()
    try:
        os.mkdir(ROLLOUT_DIR, 0o700)
    except FileExistsError:
        pass
    parent = _fixed_parents(ROLLOUT_DIR)
    parent_info = os.lstat(parent)
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o700 or parent_info.st_nlink < 2:
        _fail()
    line = (json.dumps({"schema": "controller-transport-rollout-journal-v1", "nonce": "d771b06efb5715b296d04d891f3d854d", "phase": phase, "effects_possible": effects, "uncertain": uncertain}, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    try:
        journal_before = os.lstat(ROLLOUT_JOURNAL)
    except FileNotFoundError:
        journal_before = None
    if not _JOURNAL_STARTED and journal_before is not None:
        _fail()
    if journal_before is not None and (not stat.S_ISREG(journal_before.st_mode) or journal_before.st_uid != 0 or stat.S_IMODE(journal_before.st_mode) != 0o600 or journal_before.st_nlink != 1 or journal_before.st_size > 4096):
        _fail()
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_CREAT | os.O_EXCL if journal_before is None else 0
    fd = os.open(ROLLOUT_JOURNAL, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 4096:
            _fail()
        if journal_before is not None and not _same_stat(journal_before, info):
            _fail()
        if os.write(fd, line) != len(line):
            _fail()
        os.fsync(fd)
        after = os.fstat(fd)
        if after.st_size != info.st_size + len(line) or after.st_nlink != 1 or after.st_uid != 0 or stat.S_IMODE(after.st_mode) != 0o600 or not _same_stat(after, os.lstat(ROLLOUT_JOURNAL)):
            _fail()
        _JOURNAL_STARTED = True
    finally:
        os.close(fd)
    directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _atomic_inactive_replace_guard(fence, preserve, deadline):
    if not isinstance(fence, PhaseFence) or fence.closed or not fence.heartbeat.is_alive() or fence.heartbeat_error.is_set() or type(preserve) is not dict or not _inactive_identity(preserve) or time.monotonic() >= deadline:
        _fail()
    if fence.keepalive() is not True or time.monotonic() >= deadline:
        _fail()
    observed = _observe_controller_fixed(deadline)
    if observed.get("phase") != "original-stopped" or any(observed["identity"].get(key) != preserve.get(key) for key in ("mainpid", "active_state", "sub_state", "job_empty", "cgroup", "cgroup_pids", "image_dev", "image_ino", "image_sha256", "config_sha256", "unit_sha256", "timeout_stop_us")):
        _fail()
    if fence.keepalive() is not True or time.monotonic() >= deadline:
        _fail()


def _atomic_install_fixed(source_path, expected_hash, expected_bytes, preserve, deadline, fence):
    if type(deadline) not in (int, float) or deadline <= time.monotonic():
        _fail()
    source_bytes, source_identity, source_fd = _read_pinned_file(source_path, expected_bytes, expected_hash, 0o700 if source_path == CANDIDATE_STAGE else 0o600, keep_open=True)
    parent_fd = target_fd = temp_fd = None
    parent = image = temp = None
    renamed = False
    try:
        if time.monotonic() >= deadline:
            _fail()
        image = _fixed_parents(CONTROLLER_IMAGE)
        parent = os.path.dirname(image)
        image_name = os.path.basename(image)
        temp = ".vram-governor-controller.rollout-" + secrets.token_hex(12)
        parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        parent_identity = os.fstat(parent_fd)
        parent_now = os.lstat(parent)
        if not stat.S_ISDIR(parent_identity.st_mode) or (parent_identity.st_dev, parent_identity.st_ino, parent_identity.st_mode, parent_identity.st_uid, parent_identity.st_gid) != (parent_now.st_dev, parent_now.st_ino, parent_now.st_mode, parent_now.st_uid, parent_now.st_gid):
            _fail()
        current = os.stat(image_name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or current.st_uid != 0 or current.st_gid != 0 or stat.S_IMODE(current.st_mode) != 0o755 or current.st_size != IMAGE_BYTES:
            _fail()
        target_fd = os.open(image_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        if not _same_stat(current, os.fstat(target_fd)):
            _fail()
        current_hash = hashlib.sha256()
        while True:
            block = os.read(target_fd, 65536)
            if not block:
                break
            current_hash.update(block)
        if current_hash.hexdigest() != preserve["image_sha256"] or (current.st_dev, current.st_ino) != (preserve["image_dev"], preserve["image_ino"]):
            _fail()
        temp_fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=parent_fd)
        cursor = 0
        while cursor < len(source_bytes):
            if time.monotonic() >= deadline:
                _fail()
            written = os.write(temp_fd, source_bytes[cursor:cursor + 65536])
            if written <= 0:
                _fail()
            cursor += written
        os.fchown(temp_fd, current.st_uid, current.st_gid)
        os.fchmod(temp_fd, stat.S_IMODE(current.st_mode))
        if time.monotonic() >= deadline:
            _fail()
        os.fsync(temp_fd)
        made = os.fstat(temp_fd)
        if not stat.S_ISREG(made.st_mode) or made.st_nlink != 1 or made.st_uid != current.st_uid or made.st_gid != current.st_gid or stat.S_IMODE(made.st_mode) != stat.S_IMODE(current.st_mode) or made.st_size != expected_bytes:
            _fail()
        source_opened = os.fstat(source_fd)
        source_named = os.lstat(source_path)
        initial_source = (source_opened.st_dev, source_opened.st_ino, source_opened.st_mode, source_opened.st_uid, source_opened.st_gid, source_opened.st_size, source_opened.st_mtime_ns, source_opened.st_ctime_ns)
        if initial_source != source_identity or not _same_stat(source_opened, source_named):
            _fail()
        if not _same_stat(current, os.fstat(target_fd)) or not _same_stat(current, os.stat(image_name, dir_fd=parent_fd, follow_symlinks=False)) or not _same_stat(made, os.stat(temp, dir_fd=parent_fd, follow_symlinks=False)):
            _fail()
        parent_now = os.lstat(parent)
        if (parent_identity.st_dev, parent_identity.st_ino, parent_identity.st_mode, parent_identity.st_uid, parent_identity.st_gid) != (os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino, os.fstat(parent_fd).st_mode, os.fstat(parent_fd).st_uid, os.fstat(parent_fd).st_gid) or (parent_identity.st_dev, parent_identity.st_ino, parent_identity.st_mode, parent_identity.st_uid, parent_identity.st_gid) != (parent_now.st_dev, parent_now.st_ino, parent_now.st_mode, parent_now.st_uid, parent_now.st_gid):
            _fail()
        _atomic_inactive_replace_guard(fence, preserve, deadline)
        if time.monotonic() >= deadline:
            _fail()
        os.replace(temp, image_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        renamed = True
        if time.monotonic() >= deadline:
            _fail()
        installed = os.stat(image_name, dir_fd=parent_fd, follow_symlinks=False)
        parent_after = os.lstat(parent)
        parent_fd_after = os.fstat(parent_fd)
        if not _same_stat(made, installed) or not _same_stat(source_opened, os.fstat(source_fd)) or not _same_stat(source_opened, os.lstat(source_path)) or (parent_identity.st_dev, parent_identity.st_ino, parent_identity.st_mode, parent_identity.st_uid, parent_identity.st_gid) != (parent_fd_after.st_dev, parent_fd_after.st_ino, parent_fd_after.st_mode, parent_fd_after.st_uid, parent_fd_after.st_gid) or (parent_identity.st_dev, parent_identity.st_ino, parent_identity.st_mode, parent_identity.st_uid, parent_identity.st_gid) != (parent_after.st_dev, parent_after.st_ino, parent_after.st_mode, parent_after.st_uid, parent_after.st_gid):
            _fail()
        if time.monotonic() >= deadline:
            _fail()
        os.fsync(parent_fd)
        if time.monotonic() >= deadline:
            _fail()
        verified = _controller_file_identities()
        if time.monotonic() >= deadline or (verified["image_dev"], verified["image_ino"], verified["image_sha256"]) != (made.st_dev, made.st_ino, expected_hash):
            _fail()
    finally:
        cleanup_failed = False
        if not renamed and parent_fd is not None and temp is not None:
            try:
                temp_info = os.stat(temp, dir_fd=parent_fd, follow_symlinks=False)
                temp_fd_info = os.fstat(temp_fd) if temp_fd is not None else None
                if temp_fd_info is not None and stat.S_ISREG(temp_info.st_mode) and (temp_fd_info.st_dev, temp_fd_info.st_ino) == (temp_info.st_dev, temp_info.st_ino) and temp_info.st_nlink == 1 and temp_info.st_uid == 0:
                    os.unlink(temp, dir_fd=parent_fd)
                    try:
                        os.stat(temp, dir_fd=parent_fd, follow_symlinks=False)
                        cleanup_failed = True
                    except FileNotFoundError:
                        pass
                else:
                    cleanup_failed = True
            except FileNotFoundError:
                pass
            except Exception:
                cleanup_failed = True
        for fd in (temp_fd, target_fd, parent_fd, source_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    cleanup_failed = True
        if cleanup_failed:
            _fail()


def _identity(value):
    keys = {"pid", "invocation", "start", "proc_dev", "proc_ino", "cgroup", "image_dev", "image_ino", "image_sha256", "config_sha256", "unit_sha256", "timeout_stop_us"}
    return (type(value) is dict and set(value) == keys and type(value["pid"]) is int and value["pid"] > 1 and
            type(value["invocation"]) is str and len(value["invocation"]) == 32 and
            type(value["start"]) is str and value["start"].isdigit() and type(value["proc_dev"]) is int and value["proc_dev"] >= 0 and type(value["proc_ino"]) is int and value["proc_ino"] > 0 and
            type(value["cgroup"]) is str and value["cgroup"].startswith("/system.slice/") and
            type(value["image_dev"]) is int and type(value["image_ino"]) is int and value["image_ino"] > 0 and
            type(value["image_sha256"]) is str and len(value["image_sha256"]) == 64 and
            type(value["config_sha256"]) is str and len(value["config_sha256"]) == 64 and
            type(value["unit_sha256"]) is str and len(value["unit_sha256"]) == 64 and type(value["timeout_stop_us"]) is int and 0 < value["timeout_stop_us"] <= ROLLOUT_BUDGETS["stop_ms"] * 1000)


def _inactive_identity(value):
    keys = {"mainpid", "active_state", "sub_state", "job_empty", "cgroup", "cgroup_pids", "image_dev", "image_ino", "image_sha256", "config_sha256", "unit_sha256", "timeout_stop_us"}
    return (type(value) is dict and set(value) == keys and value["mainpid"] == 0 and value["active_state"] == "inactive" and
            value["sub_state"] == "dead" and value["job_empty"] is True and value["cgroup_pids"] == [] and
            type(value["cgroup"]) is str and value["cgroup"] in ("", "/system.slice/vram-governor-controller.service") and
            type(value["image_dev"]) is int and value["image_dev"] >= 0 and type(value["image_ino"]) is int and value["image_ino"] > 0 and
            all(type(value[k]) is str and len(value[k]) == 64 for k in ("image_sha256", "config_sha256", "unit_sha256")) and type(value["timeout_stop_us"]) is int and 0 < value["timeout_stop_us"] <= ROLLOUT_BUDGETS["stop_ms"] * 1000)


class PhaseMachine:
    """Fixtureable validator; every effect is preceded by a fresh lock and phase observation."""
    def __init__(self, deadline_ms, clock=None):
        self.clock = clock or (lambda: time.monotonic_ns() // 1_000_000)
        self.started = self.clock()
        self.deadline = deadline_ms
        if type(deadline_ms) is not int or deadline_ms <= 0 or deadline_ms > SESSION_LIMIT_MS:
            _fail()
        self.phase = "preflight"
        self.last_keepalive = self.started
        self.fence_open = True
        self.effects = []

    def _fresh(self, lock, observation):
        now = self.clock()
        if not self.fence_open or lock is not True or now >= self.started + self.deadline or now - self.last_keepalive > KEEPALIVE_LIMIT_MS or not _identity(observation):
            _fail()
        self.last_keepalive = now

    def transition(self, event, lock, observed_phase, observation):
        self._fresh(lock, observation)
        if observed_phase != self.phase:
            self.phase = "handoff"
            _fail()
        next_phase = TRANSITIONS.get((self.phase, event))
        if next_phase is None:
            self.phase = "handoff"
            _fail()
        self.phase = next_phase
        return self.phase

    def effect_boundary(self, effect, lock, observed_phase, observation):
        self._fresh(lock, observation)
        allowed = {"controller-stop": "original-active", "image-install": "original-stopped", "controller-start": "original-stopped",
                   "candidate-stop": "rollback-original-active", "original-restore": "rollback-original-active", "original-restart": "rollback-original-active"}
        if effect not in allowed or self.phase != allowed[effect] or observed_phase != self.phase:
            self.phase = "handoff"
            _fail()
        if self.phase == "rollback-original-active":
            has_candidate = "controller-start" in self.effects
            rollback_effects = [item for item in self.effects if item in ("candidate-stop", "original-restore", "original-restart")]
            expected = (["candidate-stop", "original-restore", "original-restart"] if has_candidate else ["original-restore", "original-restart"])
            if len(rollback_effects) >= len(expected) or effect != expected[len(rollback_effects)]:
                self.phase = "handoff"
                _fail()
        self.effects.append(effect)
        return True

    def release(self, lock_absent, settled, lock, observed_phase, observation):
        self._fresh(lock, observation)
        if lock_absent is not True or settled is not True or self.phase != "settled" or observed_phase != "settled":
            self.phase = "handoff"
            _fail()
        self.fence_open = False
        return True


def _call_contract(ops, name, *args):
    method = getattr(ops, name, None)
    if not callable(method):
        _fail()
    return method(*args)


def _keep(fence, ops):
    if _call_contract(fence, "keepalive") is not True:
        _fail()
    _call_contract(ops, "check_deadline")
    bridge_check = getattr(ops, "check_bridge", None)
    if callable(bridge_check):
        bridge_check()


def _require_remaining(ops, minimum_ms):
    if type(minimum_ms) is not int or minimum_ms < 0 or _call_contract(ops, "remaining_ms") < minimum_ms:
        _fail()


def _phase(fence, ops, expected):
    _keep(fence, ops)
    value = _call_contract(ops, "observe_controller")
    valid = _inactive_identity(value.get("identity")) if type(value) is dict and expected == "original-stopped" else (type(value) is dict and _identity(value.get("identity")))
    if type(value) is not dict or set(value) != {"phase", "identity"} or value["phase"] != expected or not valid:
        _fail()
    return value["identity"]


def run_controller_rollout(fence, ops, budgets):
    """Production coordinator. FixedOperations supplies only hard-coded syscalls.

    The caller-visible CLI never reaches this function; it remains behind the
    independent activation amendment. Local tests execute this exact flow with
    a closed mock of its fixed syscall/process/database boundary.
    """
    if type(budgets) is not dict or set(budgets) != {"session_ms", "stop_ms", "install_ms", "start_ms", "health_ms", "protected_ms", "rollback_reserve_ms", "cleanup_ms"}:
        _fail()
    if any(type(value) is not int or value <= 0 for value in budgets.values()) or budgets["session_ms"] > SESSION_LIMIT_MS:
        _fail()
    forward = 2 * budgets["stop_ms"] + budgets["install_ms"] + budgets["start_ms"] + budgets["health_ms"] + 2 * budgets["protected_ms"]
    rollback = 2 * budgets["stop_ms"] + budgets["install_ms"] + budgets["start_ms"] + budgets["health_ms"] + budgets["protected_ms"] + budgets["cleanup_ms"]
    if budgets["rollback_reserve_ms"] < rollback or forward + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"] > budgets["session_ms"]:
        _fail()
    if _call_contract(ops, "remaining_ms") < forward + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"]:
        _fail()
    if _call_contract(ops, "repeat_preflight", fence) is not True:
        _fail()
    if _call_contract(ops, "remaining_ms") < forward + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"]:
        _fail()
    _keep(fence, ops)
    original = _phase(fence, ops, "original-active")
    protected_before = _call_contract(ops, "observe_protected")
    if type(protected_before) is not dict or set(protected_before) != {"ct_agent", "native_units"}:
        _fail()
    if _call_contract(ops, "remaining_ms") < forward + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"]:
        _fail()
    _call_contract(ops, "write_journal", "preflight", False, False)
    effect_started = False
    stop_boundary_entered = False
    candidate = None
    protected_uncertain = False
    try:
        _phase(fence, ops, "original-active")
        if _call_contract(ops, "remaining_ms") < forward + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"]:
            _fail()
        _call_contract(ops, "write_journal", "stop_intent", True, False)
        stop_boundary_entered = True
        _phase(fence, ops, "original-active")
        _require_remaining(ops, budgets["stop_ms"] + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"])
        _call_contract(ops, "stop_controller", budgets["stop_ms"], fence)
        effect_started = True
        _call_contract(ops, "write_journal", "stop_requested", True, False)
        _keep(fence, ops)
        _require_remaining(ops, budgets["stop_ms"] + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"])
        _call_contract(ops, "wait_controller_stopped", budgets["stop_ms"], fence)
        _call_contract(ops, "write_journal", "original_stopped", True, False)
        inactive_before_install = _phase(fence, ops, "original-stopped")
        if inactive_before_install["image_sha256"] != original["image_sha256"]:
            _fail()
        _phase(fence, ops, "original-stopped")
        _require_remaining(ops, budgets["install_ms"] + budgets["start_ms"] + budgets["health_ms"] + 2 * budgets["protected_ms"] + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"])
        _call_contract(ops, "install_candidate", budgets["install_ms"], fence)
        _call_contract(ops, "write_journal", "candidate_installed", True, False)
        inactive_candidate = _phase(fence, ops, "original-stopped")
        if inactive_candidate["image_sha256"] != "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543":
            _fail()
        _require_remaining(ops, budgets["start_ms"] + budgets["health_ms"] + 2 * budgets["protected_ms"] + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"])
        _call_contract(ops, "write_journal", "candidate_start_requested", True, False)
        _call_contract(ops, "start_controller", budgets["start_ms"], fence)
        if getattr(ops, "start_command_completed", False) is not True:
            _fail()
        candidate = _phase(fence, ops, "candidate-active")
        installed = getattr(ops, "candidate_installed_identity", None)
        if type(installed) is not dict or any(candidate.get(key) != installed.get(key) for key in ("image_dev", "image_ino", "config_sha256", "unit_sha256", "timeout_stop_us")):
            _fail()
        if (candidate.get("invocation"), candidate.get("start")) == (original.get("invocation"), original.get("start")):
            _fail()
        _require_remaining(ops, budgets["health_ms"] + budgets["protected_ms"] + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"])
        _call_contract(ops, "check_readiness", budgets["health_ms"], fence)
        _require_remaining(ops, budgets["protected_ms"] + budgets["rollback_reserve_ms"] + budgets["cleanup_ms"])
        try:
            protected_after = _call_contract(ops, "observe_protected")
        except Exception:
            protected_uncertain = True
            raise
        if protected_after != protected_before:
            protected_uncertain = True
            _fail()
        _keep(fence, ops)
        _call_contract(ops, "write_journal", "settled_candidate", True, False)
        _call_contract(fence, "close_phase", "candidate-active", candidate)
        return {"phase": "candidate-active", "effects": True, "rollback": False, "native_preserved": True, "startup_admission_proven": False}
    except Exception:
        if not effect_started and stop_boundary_entered:
            handoff_phase = "handoff_uncertain"
            try:
                if _call_contract(fence, "keepalive") is not True:
                    handoff_phase = "handoff_fence_lost"
            except Exception:
                handoff_phase = "handoff_fence_lost"
            try:
                _call_contract(ops, "write_journal", handoff_phase, True, True)
            except Exception:
                pass
            return {"phase": "handoff", "effects": True, "rollback": False, "native_preserved": False, "startup_admission_proven": False}
        if not effect_started:
            raise
        if getattr(ops, "stop_command_completed", False) is not True:
            try:
                _call_contract(ops, "write_journal", "handoff_uncertain", True, True)
            except Exception:
                pass
            return {"phase": "handoff", "effects": True, "rollback": False, "native_preserved": False, "startup_admission_proven": False}
        bridge_check = getattr(ops, "check_bridge", None)
        if callable(bridge_check):
            try:
                bridge_check()
            except Exception:
                try:
                    _call_contract(ops, "write_journal", "handoff_fence_lost", True, True)
                except Exception:
                    pass
                return {"phase": "handoff", "effects": True, "rollback": False, "native_preserved": False, "startup_admission_proven": False}
        try:
            _require_remaining(ops, max(rollback, budgets["rollback_reserve_ms"]) + budgets["cleanup_ms"])
            if _call_contract(fence, "keepalive") is not True:
                _call_contract(ops, "write_journal", "handoff_fence_lost", True, True)
                return {"phase": "handoff", "effects": True, "rollback": False, "native_preserved": False, "startup_admission_proven": False}
            current = _call_contract(ops, "observe_controller")
            if type(current) is not dict or set(current) != {"phase", "identity"}:
                _fail()
            phase = current["phase"]
            needs_restore = True
            if phase == "candidate-active":
                if candidate is None:
                    installed = getattr(ops, "candidate_installed_identity", None)
                    if type(installed) is not dict or getattr(ops, "start_command_completed", False) is not True or getattr(ops, "start_attempted", False) is not True or getattr(ops, "start_requested_digest", None) != "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543" or any(current["identity"].get(key) != installed.get(key) for key in ("image_dev", "image_ino", "config_sha256", "unit_sha256", "timeout_stop_us")) or current["identity"].get("image_sha256") != "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543" or (current["identity"].get("invocation"), current["identity"].get("start")) == (original.get("invocation"), original.get("start")):
                        _fail()
                    candidate = current["identity"]
                if current["identity"] != candidate:
                    _fail()
                _require_remaining(ops, 2 * budgets["stop_ms"] + budgets["install_ms"] + budgets["start_ms"] + budgets["health_ms"] + budgets["protected_ms"] + budgets["cleanup_ms"])
                _call_contract(ops, "stop_candidate", candidate, budgets["stop_ms"], fence)
                _require_remaining(ops, budgets["stop_ms"] + budgets["install_ms"] + budgets["start_ms"] + budgets["health_ms"] + budgets["protected_ms"] + budgets["cleanup_ms"])
                _call_contract(ops, "wait_controller_stopped", budgets["stop_ms"], fence)
                stopped = _phase(fence, ops, "original-stopped")
                if stopped["image_sha256"] != "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543":
                    _fail()
            elif phase != "original-stopped":
                _fail()
            else:
                stopped = _phase(fence, ops, "original-stopped")
            if stopped["image_sha256"] == original["image_sha256"]:
                needs_restore = False
            elif stopped["image_sha256"] != "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543":
                _fail()
            restored_stopped = stopped
            if needs_restore:
                _require_remaining(ops, budgets["install_ms"] + budgets["start_ms"] + budgets["health_ms"] + budgets["protected_ms"] + budgets["cleanup_ms"])
                _call_contract(ops, "restore_original", original, budgets["install_ms"], fence)
                restored_stopped = _phase(fence, ops, "original-stopped")
                if restored_stopped["image_sha256"] != original["image_sha256"]:
                    _fail()
            _require_remaining(ops, budgets["start_ms"] + budgets["health_ms"] + budgets["protected_ms"] + budgets["cleanup_ms"])
            _call_contract(ops, "start_controller", budgets["start_ms"], fence)
            if getattr(ops, "start_command_completed", False) is not True:
                _fail()
            restored = _phase(fence, ops, "original-active")
            if restored.get("image_sha256") != original.get("image_sha256"):
                _fail()
            if any(restored.get(key) != restored_stopped.get(key) for key in ("image_dev", "image_ino", "config_sha256", "unit_sha256", "timeout_stop_us")):
                _fail()
            if (restored.get("invocation"), restored.get("start")) == (original.get("invocation"), original.get("start")):
                _fail()
            _require_remaining(ops, budgets["health_ms"] + budgets["protected_ms"] + budgets["cleanup_ms"])
            _call_contract(ops, "check_readiness", budgets["health_ms"], fence)
            _require_remaining(ops, budgets["protected_ms"] + budgets["cleanup_ms"])
            if _call_contract(ops, "observe_protected") != protected_before:
                protected_uncertain = True
                _fail()
            if protected_uncertain:
                _call_contract(ops, "write_journal", "handoff_uncertain", True, True)
                return {"phase": "handoff", "effects": True, "rollback": False, "native_preserved": False, "startup_admission_proven": False}
            _call_contract(ops, "write_journal", "settled_original", True, False)
            _call_contract(fence, "close_phase", "original-active", restored)
            return {"phase": "original-active", "effects": True, "rollback": True, "native_preserved": True, "startup_admission_proven": False}
        except Exception:
            try:
                _call_contract(ops, "write_journal", "handoff_uncertain", True, True)
            except Exception:
                pass
            return {"phase": "handoff", "effects": True, "rollback": False, "native_preserved": False, "startup_admission_proven": False}


class PhaseFence:
    """One original psql backend held across intentional controller identity changes."""
    def __init__(self, accepted_fence_namespace, session_seconds=180, clock=None):
        self.mod = accepted_fence_namespace
        self.clock = clock or time.monotonic
        self.started = self.clock()
        if type(session_seconds) is not int or session_seconds <= 0 or session_seconds > 180:
            _fail()
        self.deadline = self.started + session_seconds
        self.initial = self.mod._probe_service_and_config()
        self.config_identity = self.initial["config"]
        env = self.mod._connection_environment(self.mod._yaml_database_url(self.initial["bytes"]))
        self.db = self.mod.PsqlChannel(env)
        self.db_lock = threading.RLock()
        self.closed = False
        self.cleanup_outcome = "open"
        self.heartbeat_stop = threading.Event()
        self.heartbeat_error = threading.Event()
        try:
            self.mod._validate_identity(self._query(self.mod.IDENTITY_SQL, "identity"))
            self._resolution()
            opened = self._query("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE; SET LOCAL statement_timeout='8s'; SET LOCAL lock_timeout='2s'; SET LOCAL idle_in_transaction_session_timeout='10s'; SELECT '{\"transaction\":true}'::jsonb::text;", "transaction")
            if opened != {"transaction": True}:
                _fail()
            if self._query(self.mod.READ_WRITE_SQL, "readwrite") != {"read_only": "off"}:
                _fail()
            self._resolution()
            self._query("LOCK TABLE public.node_commands IN SHARE MODE NOWAIT; SELECT '{\"locked\":true}'::jsonb::text;", "lock")
            if self._query(self.mod.LOCK_SQL, "held") != {"held": True}:
                _fail()
            self.heartbeat = threading.Thread(target=self._heartbeat_loop, name="fixed-controller-fence-keepalive", daemon=True)
            self.heartbeat.start()
        except Exception:
            try:
                if self.deadline - self.clock() >= 3.05:
                    self.db.abort()
            finally:
                self.cleanup_outcome = "uncertain"
                self.closed = True
            raise

    def remaining_ms(self):
        value = self.deadline - self.clock()
        if value <= 0:
            _fail()
        return int(value * 1000)

    def _query(self, sql, marker, timeout=3):
        self.remaining_ms()
        with self.db_lock:
            if self.heartbeat_error.is_set():
                _fail()
            # Immutable accepted PsqlChannel adds up to one second to the
            # supplied timeout before its process-group/child wait fallback.
            left = min(float(timeout), self.deadline - self.clock() - 1.05)
            if left <= 0:
                _fail()
            value = self.db.query(sql, marker, timeout=left)
        self.remaining_ms()
        return value

    def _heartbeat_loop(self):
        while not self.heartbeat_stop.wait(0.75):
            try:
                if self.clock() >= self.deadline or not self.keepalive():
                    self.heartbeat_error.set()
                    return
            except Exception:
                self.heartbeat_error.set()
                return

    def _resolution(self):
        if self._query(self.mod.RESOLUTION_SQL, "resolution") != {"resolution_matches": True}:
            _fail()

    def keepalive(self):
        if self.closed or self.heartbeat_error.is_set() or self.clock() >= self.deadline:
            return False
        try:
            value = self._query(PHASE_LOCK_SQL, "held", timeout=0.75)
        except Exception:
            return False
        return type(value) is dict and value == {"held": True, "resolution_matches": True}

    def snapshot(self):
        if not self.keepalive():
            _fail()
        summary = self.mod._project_summary(self._query(self.mod.SNAPSHOT_SQL, "snapshot", timeout=0.75))
        if not self.keepalive():
            _fail()
        return summary

    def close_phase(self, phase, identity):
        if self.closed or phase not in ("candidate-active", "original-active") or not _identity(identity) or self.clock() >= self.deadline:
            _fail()
        observed = _observe_controller_fixed(self.deadline)
        if self.clock() >= self.deadline or observed.get("phase") != phase or observed.get("identity") != identity:
            _fail()
        self.heartbeat_stop.set()
        if hasattr(self, "heartbeat"):
            self.heartbeat.join(timeout=min(0.5, max(0.0, self.deadline - self.clock() - 5.1)))
        if self.heartbeat.is_alive() or not self.keepalive() or self.clock() >= self.deadline:
            _fail()
        current_config, current_identity = self.mod._config_bytes()
        del current_config
        if self.clock() >= self.deadline or current_identity != self.config_identity:
            _fail()
        self._query("ROLLBACK; SELECT '{\"rollback\":true}'::jsonb::text;", "rollback")
        if self._query(self.mod.ABSENT_SQL, "absent") != {"absent": True}:
            _fail()
        # finish(timeout) may spend timeout + _kill_child_group's waits (1s
        # and 2s) + its own second wait(2s) after terminating a stuck child.
        left = self.deadline - self.clock() - 5.05
        if left <= 0:
            _fail()
        self.db.finish(timeout=min(5, left))
        if self.clock() >= self.deadline:
            _fail()
        self.closed = True
        self.cleanup_outcome = "release-observed"
        return True

    def abort(self):
        if self.closed:
            return
        self.heartbeat_stop.set()
        if hasattr(self, "heartbeat"):
            self.heartbeat.join(timeout=min(0.5, max(0.0, self.deadline - self.clock() - 3.05)))
        # PsqlChannel.abort may wait three seconds (group kill plus child
        # wait). If that reserve is gone, do not invoke an unbounded cleanup
        # fallback; logical closure remains explicitly uncertain.
        try:
            if self.deadline - self.clock() >= 3.05:
                self.db.abort()
        finally:
            self.cleanup_outcome = "uncertain"
            self.closed = True


def _bridge_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _fail()
        value[key] = item
    return value


class NodeObservationWire:
    """Finite private request/reply pipe to the fixed Node-side observer."""
    def __init__(self, source, target, nonce, clock=time.monotonic):
        if type(nonce) is not str or re.fullmatch(r"[a-f0-9]{32}", nonce) is None:
            _fail()
        self.source = source
        self.target = target
        self.nonce = nonce
        self.clock = clock
        self.deadline = clock() + BRIDGE_SESSION_MAX
        self.seq = 0
        self.frames = 0
        self.bytes_seen = 0
        self.awaiting = True
        self.closed = threading.Event()
        self.lost = threading.Event()
        self.state_lock = threading.Lock()
        self.monitor_stop = threading.Event()
        try:
            self.fd = source.fileno()
        except Exception:
            self.fd = None
        try:
            self.output_fd = target.fileno()
        except Exception:
            self.output_fd = None
        self.monitor = None
        if self.fd is not None:
            self.monitor = threading.Thread(target=self._monitor_input, name="fixed-transport-bridge-input", daemon=True)
            self.monitor.start()

    def _monitor_input(self):
        while not self.monitor_stop.wait(0.1):
            with self.state_lock:
                if self.awaiting:
                    continue
                try:
                    # Keep the lock through the readiness/read decision so an
                    # exchange cannot become active between the check and a
                    # monitor read that would steal its first response byte.
                    ready, _, _ = select.select([self.fd], [], [], 0)
                    if not ready:
                        continue
                    value = os.read(self.fd, 1)
                    self.lost.set()
                    if value:
                        self.closed.set()
                    return
                except Exception:
                    self.lost.set()
                    return

    def ensure_open(self, deadline=None):
        if self.closed.is_set() or self.lost.is_set() or self.clock() >= min(self.deadline, deadline if deadline is not None else self.deadline):
            _fail()
        return True

    def _write(self, value, deadline=None):
        bound = min(self.deadline, deadline if deadline is not None else self.deadline)
        self.ensure_open(bound)
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        if len(raw) > BRIDGE_FRAME_MAX:
            _fail()
        self.bytes_seen += len(raw)
        if self.bytes_seen > BRIDGE_MAX_BYTES:
            _fail()
        try:
            if self.output_fd is None:
                self.target.write(raw)
                self.target.flush()
            else:
                view = memoryview(raw)
                while view:
                    self.ensure_open(bound)
                    left = bound - self.clock()
                    if left <= 0 or not select.select([], [self.output_fd], [], left)[1]:
                        self.lost.set()
                        _fail()
                    written = os.write(self.output_fd, view[:4096])
                    if written <= 0:
                        self.lost.set()
                        _fail()
                    view = view[written:]
            self.ensure_open(bound)
        except Exception:
            self.lost.set()
            _fail()

    def _read(self, deadline=None):
        bound = min(self.deadline, deadline if deadline is not None else self.deadline)
        self.ensure_open(bound)
        try:
            if self.fd is None:
                raw = self.source.readline(BRIDGE_FRAME_MAX + 1)
            else:
                frame = bytearray()
                while len(frame) <= BRIDGE_FRAME_MAX:
                    self.ensure_open(bound)
                    left = bound - self.clock()
                    if left <= 0 or not select.select([self.fd], [], [], left)[0]:
                        self.lost.set()
                        _fail()
                    block = os.read(self.fd, 1)
                    if not block:
                        self.lost.set()
                        _fail()
                    frame.extend(block)
                    if block == b"\n":
                        break
                raw = bytes(frame)
            self.ensure_open(bound)
        except Exception:
            self.lost.set()
            _fail()
        if not raw or len(raw) > BRIDGE_FRAME_MAX or not raw.endswith(b"\n") or b"\r" in raw or any(byte > 0x7f for byte in raw):
            self.lost.set()
            _fail()
        self.bytes_seen += len(raw)
        self.frames += 1
        if self.bytes_seen > BRIDGE_MAX_BYTES or self.frames > BRIDGE_MAX_FRAMES:
            self.lost.set()
            _fail()
        try:
            value = json.loads(raw[:-1].decode("ascii"), object_pairs_hook=_bridge_pairs)
        except Exception:
            self.lost.set()
            _fail()
        self.ensure_open(bound)
        return value

    def begin(self):
        value = self._read()
        if type(value) is not dict or set(value) != {"schema", "operation", "nonce"} or value != {"schema": BRIDGE_SCHEMA, "operation": "begin", "nonce": self.nonce}:
            _fail()
        self._write({"schema": BRIDGE_SCHEMA, "nonce": self.nonce, "seq": 0, "kind": "ready", "held": True})
        return True

    def exchange(self, operation, payload):
        self.ensure_open()
        if operation not in ("preflight_evidence", "protected_identity") or type(payload) is not dict:
            _fail()
        stage_deadline = min(self.deadline, self.clock() + PROTECTED_OBSERVATION_LIMIT_MS / 1000) if operation == "protected_identity" else self.deadline
        self.seq += 1
        self.frames += 1
        if self.seq > 4 or self.frames > BRIDGE_MAX_FRAMES:
            _fail()
        request = {"schema": BRIDGE_SCHEMA, "nonce": self.nonce, "seq": self.seq, "kind": "request", "operation": operation, "payload": payload}
        try:
            with self.state_lock:
                self.awaiting = True
            self._write(request, stage_deadline)
            reply = self._read(stage_deadline)
        finally:
            with self.state_lock:
                self.awaiting = False
        if type(reply) is not dict or set(reply) != {"schema", "nonce", "seq", "kind", "operation", "payload"} or reply["schema"] != BRIDGE_SCHEMA or reply["nonce"] != self.nonce or reply["seq"] != self.seq or reply["kind"] != "response" or reply["operation"] != operation or type(reply["payload"]) is not dict:
            self.lost.set()
            _fail()
        if operation == "preflight_evidence" and set(reply["payload"]) != {"stage", "diagnostic"}:
            _fail()
        if operation == "protected_identity" and set(reply["payload"]) != {"observation"}:
            _fail()
        self.ensure_open(stage_deadline)
        return reply["payload"]

    def finish(self, result):
        self.ensure_open()
        if type(result) is not dict or set(result) != {"phase", "effects", "rollback", "native_preserved", "startup_admission_proven"}:
            _fail()
        if result["phase"] == "candidate-active" and result["rollback"] is False:
            status = "candidate_verified"
        elif result["phase"] == "original-active" and result["rollback"] is True:
            status = "original_restored"
        else:
            status = "handoff"
        self.monitor_stop.set()
        if self.monitor is not None:
            self.monitor.join(timeout=max(0.0, min(0.5, self.deadline - self.clock())))
            if self.monitor.is_alive() or self.clock() >= self.deadline:
                self.cleanup_outcome = "uncertain"
                return False
        self.ensure_open()
        self._write({"schema": BRIDGE_SCHEMA, "nonce": self.nonce, "seq": self.seq, "kind": "complete", "status": status,
                     "effects": result["effects"], "rollback": result["rollback"], "native_preserved": result["native_preserved"], "startup_admission_proven": False})
        self.closed.set()
        self.cleanup_outcome = "complete-frame-written"
        return status in ("candidate_verified", "original_restored")


def serve_rollout_bridge(receiver_namespace, input_stream=None, output_stream=None):
    """Private dual-source bootstrap entry; no CLI flag or public dispatch reaches this."""
    source = input_stream if input_stream is not None else sys.stdin.buffer
    target = output_stream if output_stream is not None else sys.stdout.buffer
    bridge = None
    fence = None
    result = None
    exit_code = 1
    try:
        bridge = NodeObservationWire(source, target, "0" * 32)
        # A real nonce is the first fixed frame; reset validation before it can be used.
        with bridge.state_lock:
            bridge.awaiting = True
        begin = bridge._read()
        with bridge.state_lock:
            bridge.awaiting = False
        if type(begin) is not dict or set(begin) != {"schema", "operation", "nonce"} or begin.get("schema") != BRIDGE_SCHEMA or begin.get("operation") != "begin" or type(begin.get("nonce")) is not str or re.fullmatch(r"[a-f0-9]{32}", begin["nonce"]) is None:
            _fail()
        bridge.nonce = begin["nonce"]
        library = receiver_namespace if type(receiver_namespace) is types.SimpleNamespace else types.SimpleNamespace(**receiver_namespace)
        fence = PhaseFence(library, 180)
        bridge._write({"schema": BRIDGE_SCHEMA, "nonce": bridge.nonce, "seq": 0, "kind": "ready", "held": True})
        operations = FixedOperations(fence, bridge)
        result = run_controller_rollout(fence, operations, ROLLOUT_BUDGETS)
        if not bridge.finish(result):
            if not fence.closed:
                fence.abort()
            exit_code = 1
        else:
            exit_code = 0
    except Exception:
        if fence is not None and not fence.closed:
            try:
                fence.abort()
            except Exception:
                pass
        if bridge is not None and not bridge.closed.is_set():
            try:
                bridge._write({"schema": BRIDGE_SCHEMA, "nonce": bridge.nonce, "seq": bridge.seq, "kind": "failed", "code": "rollout_failed"})
            except Exception:
                pass
    finally:
        if bridge is not None:
            bridge.monitor_stop.set()
            if bridge.monitor is not None:
                bridge.monitor.join(timeout=max(0.0, min(0.5, bridge.deadline - bridge.clock())))
                if bridge.monitor.is_alive() or bridge.clock() >= bridge.deadline:
                    bridge.cleanup_outcome = "uncertain"
    return exit_code


class FixedOperations:
    """Fixed controller syscalls used only by the non-exported coordinator.

    The caller-supplied object is the private Node/LB observation wire, not a
    command, path, host, environment, or operation selector. The public CLI
    never constructs this class; --apply remains rejected before all effects.
    """
    def __init__(self, fence, observation_wire):
        if not isinstance(fence, PhaseFence) or not callable(getattr(observation_wire, "exchange", None)):
            _fail()
        self.fence = fence
        self.wire = observation_wire
        self.started = time.monotonic()
        self.initial_identity = None
        self.rollback_candidate = None
        self.candidate_installed_identity = None
        self.restored_original_identity = None
        self.ct_node_id = None
        self.start_requested_wall = None
        self.start_requested_digest = None
        self.start_attempted = False
        self.stop_command_started = False
        self.stop_command_completed = False
        self.start_command_started = False
        self.start_command_completed = False

    def remaining_ms(self):
        return self.fence.remaining_ms()

    def check_deadline(self):
        return self.fence.remaining_ms()

    def check_bridge(self):
        ensure = getattr(self.wire, "ensure_open", None)
        if not callable(ensure) or ensure() is not True:
            _fail()
        return True

    def _stage_deadline(self, budget_ms, fence):
        if fence is not self.fence or type(budget_ms) is not int or budget_ms <= 0:
            _fail()
        return min(time.monotonic() + budget_ms / 1000, fence.deadline)

    def _observe(self, deadline=None):
        bound = min(self.fence.deadline, deadline if deadline is not None else self.fence.deadline)
        if time.monotonic() >= bound or self.fence.remaining_ms() <= 0:
            _fail()
        # _observe_controller_fixed bounds every systemctl read to the time
        # left before its own child cleanup reserve; reject late observations.
        value = _observe_controller_fixed(bound)
        if time.monotonic() >= bound or self.fence.remaining_ms() <= 0:
            _fail()
        self.check_bridge()
        return value

    def _check_stage(self, deadline, fence):
        self.check_bridge()
        if fence is not self.fence or time.monotonic() >= deadline or fence.remaining_ms() <= 0:
            _fail()

    def repeat_preflight(self, fence):
        if fence is not self.fence or not fence.keepalive():
            _fail()
        stage_candidate, _ = _read_pinned_file(CANDIDATE_STAGE, IMAGE_BYTES, CANDIDATE_SHA256, 0o700)
        stage_original, _ = _read_pinned_file(ORIGINAL_STAGE, IMAGE_BYTES, ORIGINAL_SHA256, 0o600)
        del stage_candidate, stage_original
        stage_config, _ = _read_pinned_file(os.path.join(STAGE_DIR, "controller.yaml"), CONFIG_BYTES, CONFIG_SHA256, 0o600)
        del stage_config
        stage_unit = os.path.join(STAGE_DIR, CONTROLLER_UNIT)
        if not os.path.isfile(stage_unit):
            _fail()
        initial = self._observe()
        if initial["phase"] != "original-active" or initial["identity"]["image_sha256"] != ORIGINAL_SHA256:
            _fail()
        snapshot = fence.snapshot()
        if type(snapshot) is not dict or set(snapshot) != {"total", "terminal", "expired", "nonterminal", "uncertain", "malformed", "command_clear"}:
            _fail()
        evidence = self.wire.exchange("preflight_evidence", {"snapshot": snapshot})
        if type(evidence) is not dict or set(evidence) != {"stage", "diagnostic"}:
            _fail()
        valid = validate_preflight_counts(snapshot, evidence["diagnostic"])
        # The applying receiver is transport-only by contract.  Preflight may
        # report an ineligible projection, but the fixed effect path must not
        # treat mere count consistency as authority to stop the controller.
        if valid.get("transport_only_candidate") is not True:
            _fail()
        stage = evidence["stage"]
        if type(stage) is not dict or set(stage) != {"nonce", "candidate_sha256", "original_sha256", "config_sha256", "activationApproved"} or stage != {"nonce": "d771b06efb5715b296d04d891f3d854d", "candidate_sha256": CANDIDATE_SHA256, "original_sha256": ORIGINAL_SHA256, "config_sha256": CONFIG_SHA256, "activationApproved": False}:
            _fail()
        self.initial_identity = initial["identity"]
        self._preflight_projection = valid
        return True

    def observe_controller(self):
        self.check_bridge()
        self.fence.remaining_ms()
        value = self._observe()
        self.fence.remaining_ms()
        return value

    def observe_protected(self):
        self.check_bridge()
        if not self.fence.keepalive():
            _fail()
        response = self.wire.exchange("protected_identity", {})
        if type(response) is not dict or set(response) != {"observation"}:
            _fail()
        observation = validate_ct_identity(response["observation"])
        if self.ct_node_id is not None and observation["agent"]["node_id"] != self.ct_node_id:
            _fail()
        self.ct_node_id = observation["agent"]["node_id"]
        return {"ct_agent": observation["agent"], "native_units": observation["native"]}

    def write_journal(self, phase, effects, uncertain):
        return _write_private_journal(phase, effects, uncertain)

    def _effect(self, expected_phase, expected_digest, deadline=None):
        self.check_bridge()
        if not self.fence.keepalive():
            _fail()
        if deadline is not None:
            self._check_stage(deadline, self.fence)
        observed = self._observe(deadline)
        if deadline is not None:
            self._check_stage(deadline, self.fence)
        if observed["phase"] != expected_phase or observed["identity"]["image_sha256"] != expected_digest:
            _fail()
        if expected_phase == "original-active" and observed["identity"] != self.initial_identity:
            _fail()
        if expected_phase == "original-stopped" and expected_digest == ORIGINAL_SHA256 and self.initial_identity is not None:
            for key in ("image_dev", "image_ino", "config_sha256", "unit_sha256", "timeout_stop_us"):
                if observed["identity"].get(key) != self.initial_identity.get(key):
                    _fail()
        if expected_phase == "original-stopped" and expected_digest == CANDIDATE_SHA256 and self.candidate_installed_identity is not None:
            for key in ("image_dev", "image_ino", "config_sha256", "unit_sha256", "timeout_stop_us"):
                if observed["identity"].get(key) != self.candidate_installed_identity.get(key):
                    _fail()
        if expected_phase == "original-stopped" and expected_digest == CANDIDATE_SHA256 and self.candidate_installed_identity is None:
            _fail()
        return observed["identity"]

    def stop_controller(self, budget_ms, fence):
        deadline = self._stage_deadline(budget_ms, fence)
        self._effect("original-active", ORIGINAL_SHA256, deadline)
        self._check_stage(deadline, fence)
        self.stop_command_started = False
        self.stop_command_completed = False
        def spawned(child):
            self.stop_command_started = True
        _fixed_capture(["/usr/bin/systemctl", "stop", CONTROLLER_UNIT], max(1, min(int((deadline-time.monotonic())*1000), fence.remaining_ms())), output_limit=4096, on_spawn=spawned, absolute_deadline=deadline)
        if not self.stop_command_started:
            _fail()
        self.stop_command_completed = True
        self._check_stage(deadline, fence)

    def wait_controller_stopped(self, budget_ms, fence):
        if fence is not self.fence or type(budget_ms) is not int or budget_ms <= 0:
            _fail()
        deadline = min(time.monotonic() + budget_ms / 1000, fence.deadline)
        while time.monotonic() < deadline:
            self.check_bridge()
            if not fence.keepalive():
                _fail()
            if time.monotonic() >= deadline:
                _fail()
            observation = self._observe(deadline)
            # A valid-looking inactive observation is not usable if observing
            # it consumed the stop stage's remaining time or the bridge/fence
            # was lost while the syscall sequence was in flight.
            if time.monotonic() >= deadline:
                _fail()
            _keep(fence, self)
            if time.monotonic() >= deadline:
                _fail()
            if observation["phase"] == "original-stopped":
                return True
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        _fail()

    def install_candidate(self, budget_ms, fence):
        deadline = self._stage_deadline(budget_ms, fence)
        stopped = self._effect("original-stopped", ORIGINAL_SHA256, deadline)
        self._check_stage(deadline, fence)
        _atomic_install_fixed(CANDIDATE_STAGE, CANDIDATE_SHA256, IMAGE_BYTES, stopped, deadline, fence)
        self._check_stage(deadline, fence)
        installed = self._observe(deadline)
        self._check_stage(deadline, fence)
        if installed["phase"] != "original-stopped" or installed["identity"]["image_sha256"] != CANDIDATE_SHA256:
            _fail()
        self.candidate_installed_identity = installed["identity"]
        self.check_bridge()

    def start_controller(self, budget_ms, fence):
        deadline = self._stage_deadline(budget_ms, fence)
        self._check_stage(deadline, fence)
        observed = self._observe(deadline)
        self._check_stage(deadline, fence)
        if observed["phase"] != "original-stopped" or observed["identity"]["image_sha256"] not in (ORIGINAL_SHA256, CANDIDATE_SHA256) or not fence.keepalive():
            _fail()
        if observed["identity"]["image_sha256"] == ORIGINAL_SHA256 and self.initial_identity is not None:
            expected_original = self.restored_original_identity or self.initial_identity
            for key in ("image_dev", "image_ino", "config_sha256", "unit_sha256", "timeout_stop_us"):
                if observed["identity"].get(key) != expected_original.get(key):
                    _fail()
        if observed["identity"]["image_sha256"] == CANDIDATE_SHA256 and observed["identity"] != self.candidate_installed_identity:
            _fail()
        self.check_bridge()
        self.start_requested_wall = time.time()
        self.start_requested_digest = observed["identity"]["image_sha256"]
        self.start_attempted = False
        self.start_command_started = False
        self.start_command_completed = False
        def spawned(child):
            self.start_attempted = True
            self.start_command_started = True
        self._check_stage(deadline, fence)
        _fixed_capture(["/usr/bin/systemctl", "start", CONTROLLER_UNIT], max(1, min(int((deadline-time.monotonic())*1000), fence.remaining_ms())), output_limit=4096, on_spawn=spawned, absolute_deadline=deadline)
        if not self.start_command_started:
            _fail()
        self.start_command_completed = True
        self._check_stage(deadline, fence)

    def stop_candidate(self, identity, budget_ms, fence):
        deadline = self._stage_deadline(budget_ms, fence)
        if not _identity(identity):
            _fail()
        current = self._effect("candidate-active", CANDIDATE_SHA256, deadline)
        if current != identity:
            _fail()
        self._check_stage(deadline, fence)
        self.rollback_candidate = identity
        _fixed_capture(["/usr/bin/systemctl", "stop", CONTROLLER_UNIT], max(1, min(int((deadline-time.monotonic())*1000), fence.remaining_ms())), output_limit=4096, absolute_deadline=deadline)
        self._check_stage(deadline, fence)

    def restore_original(self, identity, budget_ms, fence):
        deadline = self._stage_deadline(budget_ms, fence)
        if fence is not self.fence or not _identity(identity) or identity != self.initial_identity:
            _fail()
        stopped = self._effect("original-stopped", CANDIDATE_SHA256, deadline)
        self._check_stage(deadline, fence)
        _atomic_install_fixed(ORIGINAL_STAGE, ORIGINAL_SHA256, IMAGE_BYTES, stopped, deadline, fence)
        self._check_stage(deadline, fence)
        restored = self._observe(deadline)
        self._check_stage(deadline, fence)
        if restored["phase"] != "original-stopped" or restored["identity"]["image_sha256"] != ORIGINAL_SHA256:
            _fail()
        self.restored_original_identity = restored["identity"]
        self.check_bridge()

    def check_readiness(self, budget_ms, fence):
        stage_deadline = self._stage_deadline(budget_ms, fence)
        self._check_stage(stage_deadline, fence)
        self.check_bridge()
        observed = self._observe(stage_deadline)
        self._check_stage(stage_deadline, fence)
        expected = CANDIDATE_SHA256 if observed["phase"] == "candidate-active" else ORIGINAL_SHA256
        if observed["phase"] not in ("candidate-active", "original-active") or observed["identity"]["image_sha256"] != expected:
            _fail()
        if self.start_requested_wall is None or self.ct_node_id is None:
            _fail()
        _fixed_controller_health_get(stage_deadline)
        self._check_stage(stage_deadline, fence)
        _fixed_node_rejoin_query(fence, self.ct_node_id, self.start_requested_wall, stage_deadline)
        self._check_stage(stage_deadline, fence)


def validate_preflight_counts(snapshot, diagnostic):
    if type(snapshot) is not dict or type(diagnostic) is not dict or snapshot.get("command_clear") is not False:
        _fail()
    counts = diagnostic.get("counts")
    if type(counts) is not dict or type(snapshot.get("expired")) is not int or counts.get("expired_total") != snapshot["expired"] or counts.get("selected") != snapshot["expired"]:
        _fail()
    if snapshot.get("terminal", -1) + snapshot.get("nonterminal", -1) != snapshot.get("total"):
        _fail()
    return {"command_clear": False, "expired_rows": snapshot["expired"], "startup_admission_proven": False,
            "transport_only_candidate": snapshot.get("nonterminal") == 0 and snapshot.get("uncertain") == 0 and snapshot.get("malformed") == 0 and
            counts.get("matched_pairs") == counts.get("selected") and counts.get("outcome_unknown") == 0}


def apply_cli_refusal():
    """No production activation switch exists in this package."""
    _fail()


# The following CT observer is the only worker-side route used by preflight.
# Values containing process/config identity stay in the private response frame
# and are compared by the fixed client; they are never projected to CLI output.
CT_SCHEMA = "controller-transport-ct-observation-v1"
CT_CONFIG = "/etc/vram-governor/node-agent.yaml"
CT_CONFIG_BYTES = 1821
CT_CONFIG_SHA256 = "af3d2a3fd50c61e9e0f19e4f50a6b15f31169cba028cc0dc5f5acdc34d610aa3"
CT_UNIT = "/etc/systemd/system/vram-governor-node-agent.service"
CT_UNIT_BYTES = 773
CT_UNIT_SHA256 = "202db8608a6132d6e5dabdfeb232db531037ee6e5782fc1fdb1efc88704e71b6"
CT_IMAGE = "/usr/local/bin/vram-governor-node-agent"
CT_IMAGE_BYTES = 6586520
CT_IMAGE_SHA256 = "116b7588ba359602a6ac547cab1d040ae19b0c8973332086ab8e8d70cfba2a85"
CT_FIXED_AGENT_PID = 315
CT_STATE = "/var/lib/vram-governor/node-command-state.json"
CT_NATIVE = ("llama-server.service", "comfyui.service", "comfy-harness.service", "vram-governor-runtime-tunnel.service")
CT_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/nonexistent"}


def _ct_fail():
    raise RolloutRefused("fixed CT observation failed closed")


def _strict_json(raw, limit=4096):
    if type(raw) is not bytes or not raw or len(raw) > limit or not raw.endswith(b"\n"):
        _ct_fail()
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                _ct_fail()
            out[key] = value
        return out
    try:
        return json.loads(raw[:-1].decode("ascii"), object_pairs_hook=pairs)
    except Exception:
        _ct_fail()


def _ct_hash(data):
    return hashlib.sha256(data).hexdigest()


def _ct_stat_tuple(metadata):
    if type(metadata) is not tuple or len(metadata) != 4 or any(type(value) is not int or value < 0 or value > CT_STAT_U64_MAX for value in metadata):
        _ct_fail()
    return [str(value) for value in metadata]


def _ct_wire_u64(value):
    return (type(value) is str and re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", value) is not None and int(value) <= CT_STAT_U64_MAX)


def _ct_file(path, length, digest, mode, gid):
    components = path.strip("/").split("/")
    parent = "/"
    for item in components[:-1]:
        parent = os.path.join(parent, item)
        info = os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _ct_fail()
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_uid != 0 or before.st_gid != gid or before.st_nlink != 1 or before.st_size != length or stat.S_IMODE(before.st_mode) != mode:
        _ct_fail()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_size) != (before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_size):
            _ct_fail()
        data = bytearray()
        while len(data) < length:
            chunk = os.read(fd, min(65536, length - len(data)))
            if not chunk:
                _ct_fail()
            data.extend(chunk)
        if os.read(fd, 1):
            _ct_fail()
        after = os.fstat(fd)
        named = os.lstat(path)
        identity = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_nlink, x.st_size, x.st_mtime_ns, x.st_ctime_ns, x.st_uid, x.st_gid)
        if identity(before) != identity(after) or identity(before) != identity(named) or _ct_hash(data) != digest:
            _ct_fail()
        return bytes(data), (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
    finally:
        os.close(fd)


def _ct_config_scalars(raw):
    if type(raw) is not bytes or len(raw) != CT_CONFIG_BYTES or hashlib.sha256(raw).hexdigest() != CT_CONFIG_SHA256:
        _ct_fail()
    found = {}
    try:
        for line in raw.decode("utf-8").splitlines():
            if not line or line.lstrip().startswith("#") or line[:1].isspace():
                continue
            key, sep, value = line.partition(":")
            if not sep or key not in ("node_id", "command_state_path"):
                continue
            if key in found:
                _ct_fail()
            scalar = value.strip()
            if scalar.startswith("\"") and scalar.endswith("\""):
                scalar = json.loads(scalar)
            elif scalar.startswith("'") and scalar.endswith("'"):
                scalar = scalar[1:-1].replace("''", "'")
            if type(scalar) is not str or not scalar or any(ch in scalar for ch in "\r\n\x00"):
                _ct_fail()
            found[key] = scalar
    except Exception:
        _ct_fail()
    if set(found) != {"node_id", "command_state_path"} or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", found["node_id"]) is None or found["command_state_path"] != CT_STATE:
        _ct_fail()
    return found


def _ct_capture(argv, timeout=3, bound=4096):
    child = None
    selector = None
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(CT_ENV), close_fds=True, cwd="/", start_new_session=True, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ, "out")
        selector.register(child.stderr, selectors.EVENT_READ, "err")
        data = {"out": bytearray(), "err": bytearray()}
        deadline = time.monotonic() + timeout
        while selector.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                _ct_fail()
            for key, _ in selector.select(min(left, 0.2)):
                block = os.read(key.fileobj.fileno(), min(1024, bound + 1 - len(data[key.data])))
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                data[key.data].extend(block)
                if len(data[key.data]) > bound:
                    _ct_fail()
        code = child.wait(timeout=max(0, deadline - time.monotonic()))
        if code != 0 or data["err"]:
            _ct_fail()
        return bytes(data["out"])
    except Exception:
        _ct_fail()
    finally:
        if selector is not None:
            selector.close()
        if child is not None:
            if child.poll() is None:
                try:
                    child.kill()
                except Exception:
                    pass
                try:
                    child.wait(timeout=1)
                except Exception:
                    pass
            for stream in (child.stdin, child.stdout, child.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass


def _ct_unit(unit):
    props_raw = _ct_capture(["/usr/bin/systemctl", "show", "--property=MainPID,InvocationID,ActiveState,SubState,ControlGroup", unit])
    props = {}
    try:
        for line in props_raw.decode("ascii").splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in ("MainPID", "InvocationID", "ActiveState", "SubState", "ControlGroup") or key in props:
                _ct_fail()
            props[key] = value
    except Exception:
        _ct_fail()
    if set(props) != {"MainPID", "InvocationID", "ActiveState", "SubState", "ControlGroup"} or not props["MainPID"].isdigit() or int(props["MainPID"]) <= 1 or re.fullmatch(r"[0-9a-f]{32}", props["InvocationID"]) is None or props["ActiveState"] != "active" or props["SubState"] != "running" or not props["ControlGroup"].startswith("/system.slice/"):
        _ct_fail()
    pid = int(props["MainPID"])
    group_path = os.path.join("/sys/fs/cgroup", props["ControlGroup"].lstrip("/"))
    try:
        group = os.lstat(group_path)
        if not stat.S_ISDIR(group.st_mode) or stat.S_ISLNK(group.st_mode):
            _ct_fail()
        with open(os.path.join(group_path, "cgroup.procs"), "rb", buffering=0) as stream:
            members = stream.read(8193)
        if len(members) > 8192 or not members.endswith(b"\n") or str(pid).encode() not in members.splitlines():
            _ct_fail()
        proc = os.stat("/proc/" + str(pid))
        with open("/proc/" + str(pid) + "/stat", "rb", buffering=0) as stream:
            statline = stream.read(8193)
        with open("/proc/" + str(pid) + "/cmdline", "rb", buffering=0) as stream:
            command = stream.read(8193)
        fields = statline.rsplit(b")", 1)[-1].strip().split()
        start = fields[19].decode("ascii")
        cgroup = open("/proc/" + str(pid) + "/cgroup", "rb", buffering=0).read(8193)
    except Exception:
        _ct_fail()
    if len(statline) > 8192 or len(command) > 8192 or len(fields) < 20 or len(cgroup) > 8192 or props["ControlGroup"].encode() not in cgroup:
        _ct_fail()
    return {"unit": unit, "pid": pid, "invocation": props["InvocationID"], "start": start, "proc_dev": proc.st_dev, "proc_ino": proc.st_ino, "cgroup": props["ControlGroup"], "cgroup_dev": group.st_dev, "cgroup_ino": group.st_ino, "cgroup_procs_sha256": _ct_hash(members), "command_sha256": _ct_hash(command)}


def _ct_agent():
    config, config_meta = _ct_file(CT_CONFIG, CT_CONFIG_BYTES, CT_CONFIG_SHA256, 0o640, 989)
    unit, unit_meta = _ct_file(CT_UNIT, CT_UNIT_BYTES, CT_UNIT_SHA256, 0o644, 0)
    image, image_meta = _ct_file(CT_IMAGE, CT_IMAGE_BYTES, CT_IMAGE_SHA256, 0o755, 0)
    pid = CT_FIXED_AGENT_PID
    try:
        proc = os.stat("/proc/" + str(pid))
        exe = os.stat("/proc/" + str(pid) + "/exe")
        if os.readlink("/proc/" + str(pid) + "/exe") != CT_IMAGE:
            _ct_fail()
        with open("/proc/" + str(pid) + "/cmdline", "rb", buffering=0) as stream:
            command = stream.read(8193)
    except Exception:
        _ct_fail()
    expected = CT_IMAGE.encode() + b"\0-config\0" + CT_CONFIG.encode() + b"\0"
    service = _ct_unit("vram-governor-node-agent.service")
    if command != expected or (exe.st_dev, exe.st_ino) != (image_meta[0], image_meta[1]) or service["pid"] != pid:
        _ct_fail()
    config_values = _ct_config_scalars(config)
    if len(unit) != CT_UNIT_BYTES:
        _ct_fail()
    return {"pid": pid, "node_id": config_values["node_id"], "proc_dev": proc.st_dev, "proc_ino": proc.st_ino, "exe_dev": exe.st_dev, "exe_ino": exe.st_ino, "config": _ct_stat_tuple(config_meta), "unit_file": _ct_stat_tuple(unit_meta), "image": _ct_stat_tuple(image_meta), "command_sha256": _ct_hash(command), "service": service}


def observe_ct_identity():
    return validate_ct_identity({"agent": _ct_agent(), "native": [_ct_unit(unit) for unit in CT_NATIVE]})


def validate_ct_identity(value):
    if type(value) is not dict or set(value) != {"agent", "native"} or type(value["native"]) is not list or len(value["native"]) != len(CT_NATIVE):
        _ct_fail()
    agent = value["agent"]
    agent_keys = {"pid", "node_id", "proc_dev", "proc_ino", "exe_dev", "exe_ino", "config", "unit_file", "image", "command_sha256", "service"}
    if type(agent) is not dict or set(agent) != agent_keys or agent["pid"] != CT_FIXED_AGENT_PID or type(agent["node_id"]) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", agent["node_id"]) is None or any(type(agent[k]) is not int or agent[k] < 0 for k in ("proc_dev", "proc_ino", "exe_dev", "exe_ino")) or any(type(agent[k]) is not list or len(agent[k]) != 4 or any(not _ct_wire_u64(n) for n in agent[k]) for k in ("config", "unit_file", "image")) or type(agent["command_sha256"]) is not str or re.fullmatch(r"[a-f0-9]{64}", agent["command_sha256"]) is None:
        _ct_fail()
    def validate_service(row, unit):
        expected = {"unit", "pid", "invocation", "start", "proc_dev", "proc_ino", "cgroup", "cgroup_dev", "cgroup_ino", "cgroup_procs_sha256", "command_sha256"}
        return (type(row) is dict and set(row) == expected and row["unit"] == unit and type(row["pid"]) is int and row["pid"] > 1 and
                type(row["invocation"]) is str and re.fullmatch(r"[a-f0-9]{32}", row["invocation"]) is not None and type(row["start"]) is str and re.fullmatch(r"[0-9]+", row["start"]) is not None and
                type(row["proc_dev"]) is int and row["proc_dev"] >= 0 and type(row["proc_ino"]) is int and row["proc_ino"] > 0 and
                type(row["cgroup"]) is str and row["cgroup"].startswith("/system.slice/") and type(row["cgroup_dev"]) is int and row["cgroup_dev"] >= 0 and type(row["cgroup_ino"]) is int and row["cgroup_ino"] > 0 and type(row["cgroup_procs_sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", row["cgroup_procs_sha256"]) is not None and type(row["command_sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", row["command_sha256"]) is not None)
    if not validate_service(agent["service"], "vram-governor-node-agent.service") or agent["service"]["pid"] != agent["pid"]:
        _ct_fail()
    for expected, row in zip(CT_NATIVE, value["native"]):
        if not validate_service(row, expected):
            _ct_fail()
    return value


def serve_ct_observation(input_stream=None, output_stream=None):
    source = input_stream or sys.stdin.buffer
    target = output_stream or sys.stdout.buffer
    nonce = None
    try:
        line = source.readline(4097)
        request = _strict_json(line)
        if type(request) is not dict or set(request) != {"schema", "nonce", "operation"} or request["schema"] != CT_SCHEMA or request["operation"] != "observe" or type(request["nonce"]) is not str or re.fullmatch(r"[a-f0-9]{32}", request["nonce"]) is None:
            _ct_fail()
        nonce = request["nonce"]
        observation = validate_ct_identity(observe_ct_identity())
        if source.read(1):
            _ct_fail()
        value = {"schema": CT_SCHEMA, "nonce": nonce, "ok": True, "observation": observation}
    except Exception:
        value = {"schema": CT_SCHEMA, "nonce": nonce, "ok": False, "code": "observation_failed"}
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > 8192:
        return 1
    target.write(raw)
    target.flush()
    return 0 if value.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(serve_ct_observation())
