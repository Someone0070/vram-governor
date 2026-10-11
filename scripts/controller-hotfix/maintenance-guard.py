#!/usr/bin/env python3
"""Fixed-purpose foreground maintenance guardian. No service or workload lifecycle authority."""
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time

ROLES = {
    "LB115": {
        "table": "vg_controller_maintenance", "protected": [4000, 8443, 18082, 9444, 9445],
        "lanes": [8443], "ip": "10.0.0.115", "access": "ssh",
        "unit": "vram-governor-controller.service",
    },
    "CT200": {
        "table": "vg_native_maintenance", "protected": [8080, 8188, 8190],
        "lanes": [8080, 8188, 8190], "ip": "10.0.0.58", "access": "proxmox-ct200",
        "unit": None,
    },
}
SOURCE_PORTS = (443, 444, 445)
LOCK_DIR = "/run/vram-governor-maintenance"
LOCK_PATH = LOCK_DIR + "/guardian.lock"
RECEIPT_DIR = "/var/lib/vram-governor-controller-staging"
NFT = "/usr/sbin/nft"
MAX_LINE = 16384
MAX_OUTPUT = 1024 * 1024
MAX_ACTIONS = 64
CHILD_TIMEOUT = 12
SESSION_DEADLINE = 90
IMAGE_PATH = "/usr/local/bin/vram-governor-controller"
CONFIG_PATH = "/etc/vram-governor/controller.yaml"
CA_PATH = "/etc/vram-governor/tls/controller.crt"
IMAGE_PINS = {
    "original": ("ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c", 12976280),
    "candidate": ("c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543", 12976280),
}
CONFIG_PIN = ("0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37", 6789)
CA_PIN = ("ddc7359a3f730b1817c7adff7ede84439bdf31cc56ff7cf658142473042c1944", 1484)
AGENT_IMAGE_PATH = "/usr/local/bin/vram-governor-node-agent"
AGENT_IMAGE_PIN = ("116b7588ba359602a6ac547cab1d040ae19b0c8973332086ab8e8d70cfba2a85", 6586520)
AGENT_UNIT_PATH = "/etc/systemd/system/vram-governor-node-agent.service"
AGENT_UNIT_PIN = ("202db8608a6132d6e5dabdfeb232db531037ee6e5782fc1fdb1efc88704e71b6", 773)
AGENT_CONFIG_PATH = "/etc/vram-governor/node-agent.yaml"
AGENT_CONFIG_PIN = ("af3d2a3fd50c61e9e0f19e4f50a6b15f31169cba028cc0dc5f5acdc34d610aa3", 1821)
AGENT_CGROUP_PATH = "/sys/fs/cgroup/system.slice/vram-governor-node-agent.service"
AGENT_SYSTEMD_CGROUP = "/system.slice/vram-governor-node-agent.service"
CT_NATIVE_UNITS = ("llama-server.service", "comfyui.service", "comfy-harness.service", "vram-governor-runtime-tunnel.service")
FIXED_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root"}
SAFE_CODES = frozenset({
    "request_invalid", "role_invalid", "nonce_invalid", "plan_invalid", "identity_changed",
    "lock_custody", "lock_busy", "socket_conflict", "socket_inventory", "ephemeral_conflict",
    "nft_tool_custody", "nft_read_failed", "nft_json_invalid", "nft_schema_unknown",
    "owned_table_present", "owned_table_absent", "owned_table_mismatch", "foreign_rules_changed",
    "install_uncertain", "install_verified", "release_not_verified", "release_uncertain",
    "receipt_custody", "deadline", "action_limit", "diagnostic_failed", "phase_invalid",
})


class GuardError(Exception):
    def __init__(self, code):
        self.code = code if code in SAFE_CODES else "request_invalid"
        super().__init__(self.code)


class DeadlineError(BaseException):
    """Non-consumable terminal deadline; broad operational handlers must not resume."""
    code = "deadline"


def fail(code):
    raise GuardError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("request_invalid")
        result[key] = value
    return result


def safe_record(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def parse_request(raw):
    if not isinstance(raw, bytes) or not raw.endswith(b"\n") or len(raw) > MAX_LINE:
        fail("request_invalid")
    try:
        value = json.loads(raw[:-1].decode("ascii"), object_pairs_hook=no_duplicate_pairs, parse_constant=lambda _: fail("request_invalid"))
    except GuardError:
        raise
    except Exception:
        fail("request_invalid")
    if not isinstance(value, dict) or value.get("schema") != "maintenance-guard-request-v1":
        fail("request_invalid")
    role = value.get("role")
    if not isinstance(role, str) or role not in ROLES:
        fail("role_invalid")
    operation = value.get("operation")
    if operation not in ("preflight", "inspect", "get", "install", "release"):
        fail("request_invalid")
    if "phase" in value and (operation != "preflight" or role != "CT200" or value.get("phase") != "agent_paused"):
        fail("phase_invalid")
    keys = {
        "preflight": {"schema", "role", "operation", "nonce"},
        "inspect": {"schema", "role", "operation", "nonce"},
        "get": {"schema", "role", "operation", "nonce", "plane"},
        "install": {"schema", "role", "operation", "nonce", "batch_sha256", "batch_bytes", "transaction"},
        "release": {"schema", "role", "operation", "nonce", "verification"},
    }[operation]
    if operation == "preflight" and "phase" in value:
        keys = keys | {"phase"}
    if set(value) != keys:
        fail("request_invalid")
    nonce = value.get("nonce")
    if not isinstance(nonce, str) or re.fullmatch(r"[a-f0-9]{32}", nonce) is None:
        fail("nonce_invalid")
    if operation == "install":
        transaction = value["transaction"]
        if not isinstance(transaction, str) or not transaction.isascii() or len(transaction) > 32768 or not isinstance(value["batch_bytes"], int) or isinstance(value["batch_bytes"], bool) or value["batch_bytes"] != len(transaction.encode("ascii")) or not isinstance(value["batch_sha256"], str) or re.fullmatch(r"[a-f0-9]{64}", value["batch_sha256"]) is None or sha(transaction.encode("ascii")) != value["batch_sha256"]:
            fail("plan_invalid")
    if operation == "get":
        valid = {
            "LB115": {"lb_current", "lb_candidate", "lb_rollback"},
            "CT200": {"ct_node_agent", "ct_comfy_queue"},
        }[role]
        if not isinstance(value.get("plane"), str) or value["plane"] not in valid:
            fail("request_invalid")
    if operation == "release" and not safe_record(value["verification"], ["schema", "nonce", "disposition", "receipt_sha256"]):
        fail("release_not_verified")
    return value


def expected_batch(role, nonce):
    if role not in ROLES or not isinstance(nonce, str) or re.fullmatch(r"[a-f0-9]{32}", nonce) is None:
        fail("plan_invalid")
    cfg = ROLES[role]
    lines = [
        'create table inet ' + cfg["table"] + ' { comment "vg-maintenance-owner-nonce-' + nonce + '"; }',
        "add chain inet " + cfg["table"] + " input { type filter hook input priority -150; policy accept; }",
        "add chain inet " + cfg["table"] + " output { type filter hook output priority -150; policy accept; }",
    ]
    seen_lanes = set()
    lane_lines = []
    seen_drops = set()
    drop_lines = []
    for source in SOURCE_PORTS:
        for port in cfg["lanes"]:
            values = [
                'add rule inet ' + cfg["table"] + ' input iifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport ' + str(source) + " tcp dport " + str(port) + " accept",
                'add rule inet ' + cfg["table"] + ' output oifname "lo" meta skuid 0 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport ' + str(source) + " tcp dport " + str(port) + " accept",
                'add rule inet ' + cfg["table"] + ' output oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport ' + str(source) + " tcp dport " + str(port) + " drop",
            ]
            for line in values:
                if line not in seen_lanes:
                    seen_lanes.add(line)
                    lane_lines.append(line)
    for port in cfg["protected"]:
        line = "add rule inet " + cfg["table"] + " input tcp dport " + str(port) + " drop"
        if line not in seen_drops:
            seen_drops.add(line)
            drop_lines.append(line)
    lines.extend(lane_lines)
    lines.extend(drop_lines)
    return ("\n".join(lines) + "\n").encode("ascii")


def safe_child(argv, data=None, timeout=CHILD_TIMEOUT, env=None, popen_factory=subprocess.Popen):
    """Bound and suppress fixed-command stdout/stderr; never returns raw errors."""
    child = popen_factory(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=FIXED_ENV if env is None else env)
    buffers = {child.stdout: bytearray(), child.stderr: bytearray()}
    deadline = time.monotonic() + timeout
    try:
        if data is not None:
            child.stdin.write(data)
            child.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream in buffers:
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    fail("diagnostic_failed")
                for key, _ in selector.select(min(0.1, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.fileobj].extend(chunk)
                    if sum(map(len, buffers.values())) > MAX_OUTPUT:
                        fail("diagnostic_failed")
        code = child.wait(timeout=max(0.1, deadline - time.monotonic()))
        return code, bytes(buffers[child.stdout])
    except GuardError:
        raise
    except Exception:
        fail("diagnostic_failed")
    finally:
        if child.poll() is None:
            try:
                child.kill()
            except Exception:
                pass
            try:
                child.wait(timeout=2)
            except Exception:
                pass
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass


def stable_fixed_file(path, expected_sha, expected_size, expected_mode, expected_gid):
    assert_fixed_ancestors(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except Exception:
        fail("identity_changed")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != expected_mode or (expected_gid is not None and before.st_gid != expected_gid) or before.st_size != expected_size:
            fail("identity_changed")
        parts = []
        remaining = expected_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                fail("identity_changed")
            parts.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            fail("identity_changed")
        after = os.fstat(fd)
        try:
            named = os.stat(path, follow_symlinks=False)
        except Exception:
            fail("identity_changed")
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) or (named.st_dev, named.st_ino, named.st_size, named.st_nlink) != (before.st_dev, before.st_ino, before.st_size, 1) or stat.S_ISLNK(named.st_mode):
            fail("identity_changed")
        data = b"".join(parts)
        if sha(data) != expected_sha:
            fail("identity_changed")
        return data
    finally:
        os.close(fd)


def assert_fixed_ancestors(path):
    if not isinstance(path, str) or not path.startswith("/"):
        fail("identity_changed")
    current = "/"
    for part in path.strip("/").split("/")[:-1]:
        current = os.path.join(current, part)
        try:
            info = os.stat(current, follow_symlinks=False)
        except Exception:
            fail("identity_changed")
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            fail("identity_changed")


def validate_guardian_context():
    try:
        if os.geteuid() != 0:
            fail("identity_changed")
        self_ns = os.stat("/proc/self/ns/net").st_ino
        root_ns = os.stat("/proc/1/ns/net").st_ino
        if not isinstance(self_ns, int) or isinstance(self_ns, bool) or self_ns <= 0 or self_ns != root_ns:
            fail("identity_changed")
        return {"euid": 0, "net_namespace_matches_pid1": True}
    except GuardError:
        raise
    except Exception:
        fail("identity_changed")


def stable_tool(path):
    assert_fixed_ancestors(path)
    try:
        info = os.stat(path, follow_symlinks=False)
    except Exception:
        fail("identity_changed")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or not info.st_mode & 0o111:
        fail("identity_changed")
    return info


def read_ct_addresses():
    code, output = safe_child(["/usr/bin/ip", "-j", "address", "show"])
    if code != 0 or len(output) > 32768:
        fail("identity_changed")
    try:
        interfaces = json.loads(output.decode("ascii"))
        return {info.get("local") for link in interfaces if isinstance(link, dict) for info in link.get("addr_info", []) if isinstance(info, dict)}
    except Exception:
        fail("identity_changed")


def read_paused_agent_identity():
    unit = "vram-governor-node-agent.service"
    properties = "LoadState,ActiveState,SubState,MainPID,InvocationID,ExecMainStartTimestampMonotonic,Job,ControlGroup,DropInPaths"
    code, output = safe_child(["/usr/bin/systemctl", "show", "--no-pager", "--property=" + properties, unit])
    keys = set(properties.split(","))
    if code != 0 or len(output) > 8192:
        fail("identity_changed")
    try:
        lines = output.decode("ascii", "strict").splitlines()
    except Exception:
        fail("identity_changed")
    fields = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if not sep or key in fields or key not in keys:
            fail("identity_changed")
        fields[key] = value
    if (set(fields) != keys or fields["LoadState"] != "loaded" or fields["ActiveState"] != "inactive" or
            fields["SubState"] != "dead" or fields["MainPID"] != "0" or fields["Job"] != "" or
            fields["ControlGroup"] not in ("", AGENT_SYSTEMD_CGROUP) or fields["DropInPaths"] != "" or
            (fields["InvocationID"] != "" and not re.fullmatch(r"[a-f0-9]{32}", fields["InvocationID"])) or
            (fields["ExecMainStartTimestampMonotonic"] != "" and not fields["ExecMainStartTimestampMonotonic"].isdigit())):
        fail("identity_changed")
    return fields


def validate_agent_cgroup_namespace(stat_fn=None):
    stat_fn = os.stat if stat_fn is None else stat_fn
    try:
        self_ns = stat_fn("/proc/self/ns/cgroup").st_ino
        root_ns = stat_fn("/proc/1/ns/cgroup").st_ino
        if not isinstance(self_ns, int) or isinstance(self_ns, bool) or self_ns <= 0 or self_ns != root_ns:
            fail("identity_changed")
        return True
    except GuardError:
        raise
    except Exception:
        fail("identity_changed")


def read_agent_cgroup_member(path, *, open_fn=None, read_fn=None, fstat_fn=None, stat_fn=None, close_fn=None):
    open_fn = os.open if open_fn is None else open_fn
    read_fn = os.read if read_fn is None else read_fn
    fstat_fn = os.fstat if fstat_fn is None else fstat_fn
    stat_fn = os.stat if stat_fn is None else stat_fn
    close_fn = os.close if close_fn is None else close_fn
    assert_fixed_ancestors(path)
    fd = None
    try:
        fd = open_fn(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        before = fstat_fn(fd)
        named = stat_fn(path, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o022 or
                stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or named.st_uid != 0 or named.st_nlink != 1 or
                (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino)):
            fail("identity_changed")
        data = bytearray()
        while len(data) <= 65536:
            chunk = read_fn(fd, min(4096, 65537 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = fstat_fn(fd)
        named_after = stat_fn(path, follow_symlinks=False)
        if (len(data) > 65536 or (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_nlink) !=
                (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink) or
                (named_after.st_dev, named_after.st_ino) != (before.st_dev, before.st_ino)):
            fail("identity_changed")
        return bytes(data)
    except GuardError:
        raise
    except Exception:
        fail("identity_changed")
    finally:
        if fd is not None:
            close_fn(fd)


def inspect_agent_cgroup(*, stat_fn=None, scandir_fn=None, namespace_check=None, ancestor_check=None, open_fn=None, read_fn=None, fstat_fn=None, close_fn=None):
    stat_fn = os.stat if stat_fn is None else stat_fn
    scandir_fn = os.scandir if scandir_fn is None else scandir_fn
    namespace_check = validate_agent_cgroup_namespace if namespace_check is None else namespace_check
    ancestor_check = assert_fixed_ancestors if ancestor_check is None else ancestor_check
    namespace_check()
    ancestor_check(AGENT_CGROUP_PATH)
    try:
        info = stat_fn(AGENT_CGROUP_PATH, follow_symlinks=False)
    except FileNotFoundError:
        return "absent"
    except Exception:
        fail("identity_changed")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        fail("identity_changed")
    seen = set()
    inventory = {}
    count = 0
    try:
        with scandir_fn(AGENT_CGROUP_PATH) as entries:
            for entry in entries:
                count += 1
                if count > 128 or not isinstance(entry.name, str) or entry.name in seen:
                    fail("identity_changed")
                seen.add(entry.name)
                if entry.is_symlink() or entry.is_dir(follow_symlinks=False):
                    fail("identity_changed")
                item = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or item.st_nlink != 1 or item.st_mode & 0o022:
                    fail("identity_changed")
                inventory[entry.name] = (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink)
    except GuardError:
        raise
    except Exception:
        fail("identity_changed")
    if not {"cgroup.procs", "cgroup.threads"}.issubset(seen):
        fail("identity_changed")
    for name in ("cgroup.procs", "cgroup.threads"):
        contents = read_agent_cgroup_member(os.path.join(AGENT_CGROUP_PATH, name), open_fn=open_fn, read_fn=read_fn, fstat_fn=fstat_fn, stat_fn=stat_fn, close_fn=close_fn)
        if contents.strip():
            fail("identity_changed")
    final_inventory = {}
    count = 0
    try:
        with scandir_fn(AGENT_CGROUP_PATH) as entries:
            for entry in entries:
                count += 1
                if count > 128 or not isinstance(entry.name, str) or entry.name in final_inventory or entry.is_symlink() or entry.is_dir(follow_symlinks=False):
                    fail("identity_changed")
                item = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or item.st_nlink != 1 or item.st_mode & 0o022:
                    fail("identity_changed")
                final_inventory[entry.name] = (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink)
    except GuardError:
        raise
    except Exception:
        fail("identity_changed")
    if final_inventory != inventory:
        fail("identity_changed")
    for name in ("cgroup.procs", "cgroup.threads"):
        contents = read_agent_cgroup_member(os.path.join(AGENT_CGROUP_PATH, name), open_fn=open_fn, read_fn=read_fn, fstat_fn=fstat_fn, stat_fn=stat_fn, close_fn=close_fn)
        if contents.strip():
            fail("identity_changed")
    try:
        final_info = stat_fn(AGENT_CGROUP_PATH, follow_symlinks=False)
    except Exception:
        fail("identity_changed")
    if (stat.S_ISLNK(final_info.st_mode) or not stat.S_ISDIR(final_info.st_mode) or final_info.st_uid != 0 or
            final_info.st_mode & 0o022 or (final_info.st_dev, final_info.st_ino, final_info.st_mode, final_info.st_uid) !=
            (info.st_dev, info.st_ino, info.st_mode, info.st_uid)):
        fail("identity_changed")
    return "empty"


def check_paused_ct_identity(file_reader):
    context = validate_guardian_context()
    stable_tool("/usr/bin/ip")
    stable_tool("/usr/bin/systemctl")
    addresses_before = read_ct_addresses()
    if "10.0.0.58" not in addresses_before:
        fail("identity_changed")
    artifact_pins = (
        (AGENT_IMAGE_PATH, AGENT_IMAGE_PIN, 0o755, 0),
        (AGENT_UNIT_PATH, AGENT_UNIT_PIN, 0o644, 0),
        (AGENT_CONFIG_PATH, AGENT_CONFIG_PIN, 0o640, 989),
    )
    artifact_digests = []
    for path, (digest, size), mode, gid in artifact_pins:
        data = file_reader(path, digest, size, mode, gid)
        if not isinstance(data, bytes) or len(data) != size:
            fail("identity_changed")
        artifact_digests.append(data)
    agent_before = read_paused_agent_identity()
    cgroup_before = inspect_agent_cgroup()
    native_before = {unit: read_unit_identity(unit) for unit in CT_NATIVE_UNITS}
    addresses_after = read_ct_addresses()
    agent_after = read_paused_agent_identity()
    cgroup_after = inspect_agent_cgroup()
    native_after = {unit: read_unit_identity(unit) for unit in CT_NATIVE_UNITS}
    artifacts_after = []
    for path, (digest, size), mode, gid in artifact_pins:
        data = file_reader(path, digest, size, mode, gid)
        if not isinstance(data, bytes) or len(data) != size:
            fail("identity_changed")
        artifacts_after.append(data)
    if (addresses_after != addresses_before or agent_after != agent_before or cgroup_after != cgroup_before or
            native_after != native_before or artifacts_after != artifact_digests):
        fail("identity_changed")
    public_agent_unit = {key: agent_before[key] for key in ("LoadState", "ActiveState", "SubState", "MainPID", "InvocationID", "ExecMainStartTimestampMonotonic")}
    return {
        "role": "CT200", "phase": "agent_paused", "container_ip": "10.0.0.58",
        "net_namespace_matches_pid1": context["net_namespace_matches_pid1"],
        "agent": {"image": "pinned", "unit_artifact": "pinned", "config": "pinned", "unit": public_agent_unit,
                  "pending_job": False, "dropins_absent": True, "cgroup_state": cgroup_before},
        "native_units": native_before, "config_or_image_read": True,
    }


def check_fixed_identity(role, file_reader=stable_fixed_file, phase="active"):
    if phase not in ("active", "agent_paused") or (phase == "agent_paused" and role != "CT200"):
        fail("phase_invalid")
    if phase == "agent_paused":
        return check_paused_ct_identity(file_reader)
    context = validate_guardian_context()
    if role == "CT200":
        units = ["vram-governor-node-agent.service", "llama-server.service", "comfyui.service", "comfy-harness.service", "vram-governor-runtime-tunnel.service"]
        stable_tool("/usr/bin/ip")
        stable_tool("/usr/bin/systemctl")
        code, output = safe_child(["/usr/bin/ip", "-j", "address", "show"])
        if code != 0 or len(output) > 32768:
            fail("identity_changed")
        try:
            interfaces = json.loads(output.decode("ascii"))
            addresses = {entry.get("local") for link in interfaces if isinstance(link, dict) for info in link.get("addr_info", []) if isinstance(info, dict) for entry in [info]}
        except Exception:
            fail("identity_changed")
        if "10.0.0.58" not in addresses:
            fail("identity_changed")
        unit_values = {}
        for unit in units:
            unit_values[unit] = read_unit_identity(unit)
        return {"role": role, "container_ip": "10.0.0.58", "net_namespace_matches_pid1": context["net_namespace_matches_pid1"], "units": unit_values, "config_or_image_read": False}
    image_ok = False
    for digest, size in IMAGE_PINS.values():
        try:
            file_reader(IMAGE_PATH, digest, size, 0o755, None)
            image_ok = True
            break
        except GuardError:
            continue
    if not image_ok:
        fail("identity_changed")
    stable_tool("/usr/bin/ip")
    stable_tool("/usr/bin/systemctl")
    code, output = safe_child(["/usr/bin/ip", "-j", "address", "show"])
    if code != 0 or len(output) > 32768:
        fail("identity_changed")
    try:
        interfaces = json.loads(output.decode("ascii"))
        addresses = {info.get("local") for link in interfaces if isinstance(link, dict) for info in link.get("addr_info", []) if isinstance(info, dict)}
    except Exception:
        fail("identity_changed")
    if ROLES[role]["ip"] not in addresses:
        fail("identity_changed")
    file_reader(CONFIG_PATH, CONFIG_PIN[0], CONFIG_PIN[1], 0o640, 990)
    file_reader(CA_PATH, CA_PIN[0], CA_PIN[1], 0o640, 990)
    stable_tool("/usr/bin/systemctl")
    fields = read_unit_identity("vram-governor-controller.service")
    process = validate_live_controller(fields["MainPID"])
    if read_unit_identity("vram-governor-controller.service") != fields:
        fail("identity_changed")
    return {"role": role, "image": "pinned", "config_sha256": CONFIG_PIN[0], "ca_sha256": CA_PIN[0], "unit": fields, "process": process}


def read_unit_identity(unit):
    if unit not in {"vram-governor-controller.service", "vram-governor-node-agent.service", "llama-server.service", "comfyui.service", "comfy-harness.service", "vram-governor-runtime-tunnel.service"}:
        fail("identity_changed")
    keys = {"LoadState", "ActiveState", "SubState", "MainPID", "InvocationID", "ExecMainStartTimestampMonotonic"}
    code, output = safe_child(["/usr/bin/systemctl", "show", "--no-pager", "--property=LoadState,ActiveState,SubState,MainPID,InvocationID,ExecMainStartTimestampMonotonic", unit])
    if code != 0 or len(output) > 8192:
        fail("identity_changed")
    fields = {}
    try:
        lines = output.decode("ascii", "strict").splitlines()
    except Exception:
        fail("identity_changed")
    for line in lines:
        key, sep, value = line.partition("=")
        if not sep or key in fields or key not in keys:
            fail("identity_changed")
        fields[key] = value
    if set(fields) != keys or fields["LoadState"] != "loaded" or fields["ActiveState"] != "active" or fields["SubState"] != "running" or not fields["MainPID"].isdigit() or int(fields["MainPID"]) < 2 or not re.fullmatch(r"[a-f0-9]{32}", fields["InvocationID"]) or not fields["ExecMainStartTimestampMonotonic"].isdigit():
        fail("identity_changed")
    return fields


def validate_live_controller(pid_text):
    if not isinstance(pid_text, str) or not pid_text.isdigit() or int(pid_text) < 2:
        fail("identity_changed")
    proc_exe = "/proc/" + pid_text + "/exe"
    try:
        installed = os.stat(IMAGE_PATH, follow_symlinks=False)
        running = os.stat(proc_exe)
        if not stat.S_ISREG(installed.st_mode) or not stat.S_ISREG(running.st_mode) or (installed.st_dev, installed.st_ino) != (running.st_dev, running.st_ino) or os.readlink(proc_exe) != IMAGE_PATH:
            fail("identity_changed")
        fd = os.open("/proc/" + pid_text + "/cmdline", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            command = os.read(fd, 1024)
            if os.read(fd, 1) or command != IMAGE_PATH.encode("ascii") + b"\0-config\0" + CONFIG_PATH.encode("ascii") + b"\0":
                fail("identity_changed")
        finally:
            os.close(fd)
        with open("/proc/" + pid_text + "/cgroup", "rt", encoding="ascii") as stream:
            cgroup = stream.read(8193)
        if len(cgroup) > 8192 or "vram-governor-controller.service" not in cgroup:
            fail("identity_changed")
        return {"pid": int(pid_text), "executable_matches_installed": True, "fixed_config_argument": True, "service_cgroup": True}
    except GuardError:
        raise
    except Exception:
        fail("identity_changed")


def process_tcp_source_ports():
    found = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "rt", encoding="ascii") as stream:
                next(stream, None)
                for line in stream:
                    columns = line.split()
                    if len(columns) < 10 or ":" not in columns[1]:
                        fail("socket_inventory")
                    port = int(columns[1].rsplit(":", 1)[1], 16)
                    if port in SOURCE_PORTS:
                        found.add(port)
        except GuardError:
            raise
        except Exception:
            fail("socket_inventory")
    return found


def ephemeral_range(role, reader=open):
    try:
        raw = reader("/proc/sys/net/ipv4/ip_local_port_range", "rt", encoding="ascii").read(64)
        if not raw.endswith("\n"):
            fail("ephemeral_conflict")
        parts = raw.split()
        if len(parts) != 2 or not all(part.isdigit() for part in parts):
            fail("ephemeral_conflict")
        low, high = map(int, parts)
        protected = ROLES[role]["protected"]
        if low < 1024 or high > 65535 or low > high or any(low <= port <= high for port in SOURCE_PORTS) or any(low <= port <= high for port in protected):
            fail("ephemeral_conflict")
        return low, high
    except GuardError:
        raise
    except Exception:
        fail("ephemeral_conflict")


def parse_proc_tcp_rows(raw):
    if not isinstance(raw, str) or len(raw) > 4 * 1024 * 1024:
        fail("socket_inventory")
    rows = []
    lines = raw.splitlines()
    if not lines or not lines[0].lstrip().startswith("sl"):
        fail("socket_inventory")
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10 or ":" not in fields[1] or ":" not in fields[2] or not re.fullmatch(r"(?:[0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):[0-9A-Fa-f]{4}", fields[1]) or not re.fullmatch(r"(?:[0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):[0-9A-Fa-f]{4}", fields[2]) or not re.fullmatch(r"[0-9A-Fa-f]{2}", fields[3]):
            fail("socket_inventory")
        local_address = fields[1].rsplit(":", 1)[0].lower()
        remote_address = fields[2].rsplit(":", 1)[0].lower()
        local_port = int(fields[1].rsplit(":", 1)[1], 16)
        remote_port = int(fields[2].rsplit(":", 1)[1], 16)
        rows.append({"local_address": local_address, "remote_address": remote_address, "local_port": local_port, "remote_port": remote_port, "state": int(fields[3], 16), "inode": fields[9]})
    return rows


def retained_reverse_tuples(role, held):
    """Return only reverse server tuples backed by this session's exclusive validation FDs."""
    if held is None:
        return set()
    verify_held_sockets(held)
    allowed = set()
    for sock, source_port in zip(held, SOURCE_PORTS):
        try:
            local_ip, local_port = sock.getsockname()[:2]
            peer_ip, peer_port = sock.getpeername()[:2]
            local = ipaddress.ip_address(local_ip)
            peer = ipaddress.ip_address(peer_ip)
            if local != ipaddress.ip_address("127.0.0.1") or local_port != source_port:
                fail("socket_inventory")
            if role == "LB115":
                if peer != ipaddress.ip_address("127.0.0.1") or peer_port != 8443:
                    continue
            elif peer != ipaddress.ip_address("127.0.0.1") or peer_port not in (8080, 8188):
                continue
            peer_text = str(peer.ipv4_mapped) if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped is not None else str(peer)
            local_text = str(local.ipv4_mapped) if isinstance(local, ipaddress.IPv6Address) and local.ipv4_mapped is not None else str(local)
            allowed.add((peer_text, peer_port, local_text, source_port))
        except GuardError:
            raise
        except Exception:
            # An unconnected retained socket grants no tuple exception.
            continue
    return allowed


def process_protected_client_tuples(role, reader=open, held=None):
    protected = set(ROLES[role]["protected"])
    tuples = []
    all_rows = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with reader(path, "rt", encoding="ascii") as stream:
                rows = parse_proc_tcp_rows(stream.read(4 * 1024 * 1024 + 1))
        except GuardError:
            raise
        except Exception:
            fail("socket_inventory")
        all_rows.extend((path, row) for row in rows)
    reverse_allowed = retained_reverse_tuples(role, held)
    for path, row in all_rows:
        # LISTEN rows are not clients. procfs alone cannot distinguish an accepted external server
        # child from an outbound client explicitly bound to a protected source port. Only an exact
        # established reverse tuple backed by a retained guardian descriptor is exempt.
        if row["state"] == 0x0A or row["local_port"] not in protected or row["remote_port"] == 0:
            continue
        local_ip = proc_address_ip(path, row["local_address"])
        remote_ip = proc_address_ip(path, row["remote_address"])
        if row["state"] == 0x01 and (local_ip, row["local_port"], remote_ip, row["remote_port"]) in reverse_allowed:
            continue
        tuples.append((path, row["local_port"], row["remote_port"], row["state"]))
    if tuples:
        fail("socket_conflict")
    return ()


def proc_address_ip(path, value):
    try:
        raw = bytes.fromhex(value)
        if path.endswith("/tcp") and len(raw) == 4:
            return str(ipaddress.IPv4Address(raw[::-1]))
        if path.endswith("/tcp6") and len(raw) == 16:
            normalized = b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4))
            address = ipaddress.IPv6Address(normalized)
            return str(address.ipv4_mapped) if address.ipv4_mapped is not None else str(address)
    except Exception:
        pass
    return None


def is_loopback_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return address.is_loopback or address.is_unspecified or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None and (address.ipv4_mapped.is_loopback or address.ipv4_mapped.is_unspecified))
    except Exception:
        return True


def listening_port_inventory(reader=open):
    counts = {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with reader(path, "rt", encoding="ascii") as stream:
                rows = parse_proc_tcp_rows(stream.read(4 * 1024 * 1024 + 1))
        except GuardError:
            raise
        except Exception:
            fail("socket_inventory")
        for row in rows:
            if row["state"] == 0x0A:
                counts[row["local_port"]] = counts.get(row["local_port"], 0) + 1
    return counts


def acquire_lane_sockets(role, socket_factory=socket.socket, proc_reader=process_tcp_source_ports, range_reader=ephemeral_range, tuple_reader=process_protected_client_tuples):
    range_reader(role)
    tuple_reader(role)
    if proc_reader():
        fail("socket_conflict")
    held = []
    try:
        for port in SOURCE_PORTS:
            sock = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 0)
            sock.set_inheritable(False)
            sock.bind(("127.0.0.1", port))
            held.append(sock)
        if any(sock.getsockname() != ("127.0.0.1", port) or sock.get_inheritable() for sock, port in zip(held, SOURCE_PORTS)):
            fail("socket_inventory")
        return held
    except Exception:
        for sock in held:
            try:
                sock.close()
            except Exception:
                pass
        fail("socket_conflict")


def verify_held_sockets(held):
    if not isinstance(held, list) or len(held) != len(SOURCE_PORTS):
        fail("socket_inventory")
    descriptors = set()
    for sock, port in zip(held, SOURCE_PORTS):
        try:
            fd = sock.fileno()
            info = os.fstat(fd)
            if fd < 0 or fd in descriptors or not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or sock.getsockname() != ("127.0.0.1", port) or sock.get_inheritable() or sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0:
                fail("socket_inventory")
            descriptors.add(fd)
            if hasattr(socket, "SO_REUSEPORT") and sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) != 0:
                fail("socket_inventory")
        except GuardError:
            raise
        except Exception:
            fail("socket_inventory")


def trusted_directory(path, mode):
    try:
        info = os.stat(path, follow_symlinks=False)
    except Exception:
        fail("lock_custody")
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
        fail("lock_custody")
    return info


def acquire_lock(open_fn=os.open, flock_fn=fcntl.flock, create=True):
    trusted_directory("/run", 0o755)
    if create:
        try:
            os.mkdir(LOCK_DIR, 0o700)
        except FileExistsError:
            pass
        except Exception:
            fail("lock_custody")
    trusted_directory(LOCK_DIR, 0o700)
    flags = (os.O_CREAT if create else 0) | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = open_fn(LOCK_PATH, flags, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            os.close(fd)
            fail("lock_custody")
        named = os.stat(LOCK_PATH, follow_symlinks=False)
        if stat.S_ISLNK(named.st_mode) or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            os.close(fd)
            fail("lock_custody")
        flock_fn(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except GuardError:
        raise
    except FileNotFoundError:
        if not create:
            return None
        fail("lock_custody")
    except BlockingIOError:
        fail("lock_busy")
    except Exception:
        fail("lock_custody")


def _canonical_ruleset_bytes(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_OUTPUT:
        fail("nft_json_invalid")
    try:
        root = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_pairs, parse_constant=lambda _: fail("nft_json_invalid"))
    except GuardError:
        raise
    except Exception:
        fail("nft_json_invalid")
    if not isinstance(root, dict) or set(root) != {"nftables"} or not isinstance(root["nftables"], list) or len(root["nftables"]) > 16384:
        fail("nft_json_invalid")
    rows = root["nftables"]
    metainfo = [row.get("metainfo") for row in rows if isinstance(row, dict) and set(row) == {"metainfo"}]
    if len(metainfo) != 1 or not rows or rows[0].get("metainfo") is not metainfo[0] or not isinstance(metainfo[0], dict) or set(metainfo[0]) != {"version", "release_name", "json_schema_version"} or metainfo[0].get("version") != "1.0.9" or not isinstance(metainfo[0].get("release_name"), str) or type(metainfo[0].get("json_schema_version")) is not int or metainfo[0].get("json_schema_version") != 1:
        fail("nft_schema_unknown")
    return rows


def nft_ruleset():
    try:
        info = os.stat(NFT, follow_symlinks=False)
    except Exception:
        fail("nft_tool_custody")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
        fail("nft_tool_custody")
    stable_tool(NFT)
    code, version = safe_child([NFT, "--version"], timeout=5)
    if code != 0 or re.fullmatch(rb"nftables v1\.0\.9 \([^\r\n]{1,128}\)\n?", version) is None:
        fail("nft_schema_unknown")
    code, raw = safe_child([NFT, "-j", "-a", "list", "ruleset"])
    if code != 0:
        fail("nft_read_failed")
    return _canonical_ruleset_bytes(raw)


def ruleset_snapshot_and_owned(objects, role):
    target = ROLES[role]["table"]
    foreign = []
    owned = []
    if not isinstance(objects, list) or not objects or len(objects) > 16384 or not isinstance(objects[0], dict) or set(objects[0]) != {"metainfo"}:
        fail("nft_schema_unknown")
    for row in objects:
        if not isinstance(row, dict) or len(row) != 1:
            fail("nft_json_invalid")
        kind, value = next(iter(row.items()))
        if kind not in {"metainfo", "table", "chain", "rule", "set", "map", "element", "flowtable", "counter", "quota", "ct helper", "limit", "ct timeout", "ct expectation"} or not isinstance(value, dict):
            fail("nft_schema_unknown")
        if kind == "metainfo":
            if set(value) != {"version", "release_name", "json_schema_version"} or value["version"] != "1.0.9" or not isinstance(value["release_name"], str) or type(value["json_schema_version"]) is not int or value["json_schema_version"] != 1:
                fail("nft_schema_unknown")
            if row is not objects[0]:
                fail("nft_schema_unknown")
            foreign.append(row)
        else:
            validate_nft_object(kind, value)
        if kind != "metainfo" and value.get("family") == "inet" and (value.get("name") == target or value.get("table") == target):
            owned.append(row)
        elif kind != "metainfo":
            foreign.append(row)
    return foreign, owned


def validate_nft_object(kind, value):
    if kind == "table":
        allowed = {"family", "name", "handle", "comment", "flags"}
        if set(value) - allowed or not {"family", "name", "handle"} <= set(value) or not isinstance(value["family"], str) or not isinstance(value["name"], str) or not isinstance(value["handle"], int) or isinstance(value["handle"], bool) or value["handle"] <= 0 or ("comment" in value and not isinstance(value["comment"], str)) or ("flags" in value and not (isinstance(value["flags"], str) or isinstance(value["flags"], list))):
            fail("nft_schema_unknown")
    elif kind == "chain":
        allowed = {"family", "table", "name", "handle", "type", "hook", "prio", "policy", "dev", "newname", "comment"}
        if set(value) - allowed or not {"family", "table", "name", "handle"} <= set(value) or not isinstance(value["family"], str) or not isinstance(value["table"], str) or not isinstance(value["name"], str) or not isinstance(value["handle"], int) or isinstance(value["handle"], bool) or value["handle"] <= 0:
            fail("nft_schema_unknown")
        if "hook" in value and (not isinstance(value.get("hook"), str) or not isinstance(value.get("type"), str) or not isinstance(value.get("prio"), int) or isinstance(value.get("prio"), bool) or not isinstance(value.get("policy"), str)):
            fail("nft_schema_unknown")
    elif kind == "rule":
        allowed = {"family", "table", "chain", "expr", "handle", "index", "comment"}
        if set(value) - allowed or not {"family", "table", "chain", "expr", "handle"} <= set(value) or not isinstance(value["family"], str) or not isinstance(value["table"], str) or not isinstance(value["chain"], str) or not isinstance(value["expr"], list) or not value["expr"] or not isinstance(value["handle"], int) or isinstance(value["handle"], bool) or value["handle"] <= 0:
            fail("nft_schema_unknown")
        if "index" in value and (type(value["index"]) is not int or value["index"] < 0):
            fail("nft_schema_unknown")
    elif kind == "element":
        if set(value) != {"family", "table", "name", "elem"} or not all(isinstance(value.get(key), str) for key in ("family", "table", "name")):
            fail("nft_schema_unknown")
    else:
        # Strict common foreign-object identity; arbitrary structures and unknown keys are rejected.
        required = {"family", "table", "name", "handle"}
        if not required <= set(value) or set(value) - (required | {"type", "map", "policy", "flags", "elem", "timeout", "gc-interval", "size", "packets", "bytes", "used", "inv", "rate", "per", "burst", "unit", "protocol", "l3proto", "state", "value", "dport"}) or not all(isinstance(value.get(key), str) for key in ("family", "table", "name")) or not isinstance(value["handle"], int) or isinstance(value["handle"], bool) or value["handle"] <= 0:
            fail("nft_schema_unknown")
        for key in ("size", "packets", "bytes", "used"):
            if key in value and (type(value[key]) is not int or value[key] < 0):
                fail("nft_schema_unknown")
        if "inv" in value and type(value["inv"]) is not bool:
            fail("nft_schema_unknown")


def canonical_foreign_digest(objects, role):
    foreign, owned = ruleset_snapshot_and_owned(objects, role)
    if owned:
        fail("owned_table_present")
    return sha(canonical(foreign).encode("utf-8"))


def _expected_expression(role, nonce):
    batch = expected_batch(role, nonce).decode("ascii").splitlines()
    expected = {"input": [], "output": []}
    for line in batch[3:]:
        if not line.startswith("add rule "):
            continue
        parts = line.split()
        chain = parts[4]
        action = parts[-1]
        body = parts[5:-1]
        predicates = []
        i = 0
        while i < len(body):
            token = body[i]
            i += 1
            if token in ("iifname", "oifname"):
                predicates.append(("meta." + token, body[i].strip('"'))); i += 1
            elif token in ("meta", "ip", "tcp"):
                key = body[i]; val = body[i + 1]; i += 2
                if token == "meta":
                    key = "meta." + key
                else:
                    key = token + "." + key
                predicates.append((key, int(val) if val.isdigit() else val))
            else:
                fail("plan_invalid")
        expected[chain].append((chain, tuple(predicates), action))
    return expected


def normalize_rule_json(rule):
    if not isinstance(rule, dict) or set(rule) - {"family", "table", "chain", "expr", "handle", "index", "comment"} or not {"family", "table", "chain", "expr", "handle"} <= set(rule) or not isinstance(rule["expr"], list) or len(rule["expr"]) < 2 or not isinstance(rule["handle"], int) or isinstance(rule["handle"], bool) or rule["handle"] <= 0:
        fail("nft_schema_unknown")
    normalized = []
    for statement in rule["expr"][:-1]:
        if not isinstance(statement, dict) or set(statement) != {"match"} or not isinstance(statement["match"], dict) or set(statement["match"]) != {"op", "left", "right"} or statement["match"]["op"] != "==":
            fail("nft_schema_unknown")
        left = statement["match"]["left"]
        if not isinstance(left, dict) or len(left) != 1:
            fail("nft_schema_unknown")
        key, detail = next(iter(left.items()))
        if key == "meta" and isinstance(detail, dict) and set(detail) == {"key"} and detail["key"] in {"iifname", "oifname", "skuid"}:
            key = "meta." + detail["key"]
        elif key == "payload" and isinstance(detail, dict) and set(detail) == {"protocol", "field"} and detail["protocol"] in {"ip", "tcp"} and detail["field"] in {"saddr", "daddr", "sport", "dport"}:
            key = detail["protocol"] + "." + detail["field"]
        else:
            fail("nft_schema_unknown")
        right = statement["match"]["right"]
        if key == "meta.skuid" or key in {"tcp.sport", "tcp.dport"}:
            if type(right) is not int or right < 0:
                fail("nft_schema_unknown")
        elif key.startswith("ip.") or key in {"meta.iifname", "meta.oifname"}:
            if not isinstance(right, str):
                fail("nft_schema_unknown")
        normalized.append((key, right))
    final = rule["expr"][-1]
    if not isinstance(final, dict) or len(final) != 1 or next(iter(final)) not in {"accept", "drop"} or final[next(iter(final))] is not None:
        fail("nft_schema_unknown")
    if len({pair[0] for pair in normalized}) != len(normalized):
        fail("nft_schema_unknown")
    return rule["chain"], tuple(normalized), next(iter(final))


def inspect_owned_objects(owned, role, nonce):
    target = ROLES[role]["table"]
    tables = [row["table"] for row in owned if set(row) == {"table"} and row["table"].get("name") == target]
    chains = [row["chain"] for row in owned if set(row) == {"chain"}]
    rules = [row["rule"] for row in owned if set(row) == {"rule"}]
    if len(owned) != 1 + len(chains) + len(rules):
        fail("owned_table_mismatch")
    if len(tables) != 1:
        fail("owned_table_absent")
    table = tables[0]
    if set(table) != {"family", "name", "handle", "comment"} or table.get("family") != "inet" or table.get("name") != target or not isinstance(table.get("handle"), int) or isinstance(table.get("handle"), bool) or table["handle"] <= 0 or table.get("comment") != "vg-maintenance-owner-nonce-" + nonce:
        fail("owned_table_mismatch")
    if len(chains) != 2:
        fail("owned_table_mismatch")
    by_hook = {}
    for chain in chains:
        if set(chain) != {"family", "table", "name", "handle", "type", "hook", "prio", "policy"} or chain.get("family") != "inet" or chain.get("table") != target or chain.get("name") != chain.get("hook") or chain.get("type") != "filter" or chain.get("hook") not in ("input", "output") or chain.get("prio") != -150 or chain.get("policy") != "accept" or not isinstance(chain.get("handle"), int) or isinstance(chain.get("handle"), bool) or chain["handle"] <= 0 or chain["hook"] in by_hook:
            fail("owned_table_mismatch")
        by_hook[chain["hook"]] = chain
    if set(by_hook) != {"input", "output"}:
        fail("owned_table_mismatch")
    actual = {"input": [], "output": []}
    for rule in rules:
        normalized = normalize_rule_json(rule)
        if normalized[0] not in actual:
            fail("owned_table_mismatch")
        actual[normalized[0]].append(normalized)
    expected = _expected_expression(role, nonce)
    if actual != expected:
        fail("owned_table_mismatch")
    return {
        "table_handle": table["handle"], "chain_handles": {"input": by_hook["input"]["handle"], "output": by_hook["output"]["handle"]},
        "rule_handles": sorted(rule["handle"] for rule in rules), "ownership_nonce": nonce,
        "rules_sha256": sha(canonical(actual).encode("utf-8")),
    }


def fixed_preflight(role, nonce, held, phase="active"):
    if role not in ROLES:
        fail("role_invalid")
    if phase not in ("active", "agent_paused") or (phase == "agent_paused" and role != "CT200"):
        fail("phase_invalid")
    identity = check_fixed_identity(role) if phase == "active" else check_fixed_identity(role, phase=phase)
    ephemeral_range(role)
    process_protected_client_tuples(role, held=held)
    objects = nft_ruleset()
    foreign_digest = canonical_foreign_digest(objects, role)
    verify_held_sockets(held)
    listeners = listening_port_inventory()
    if phase == "agent_paused":
        identity_after = check_fixed_identity(role, phase=phase)
        if identity_after != identity:
            fail("identity_changed")
    return {"role": role, "nonce": nonce, "identity": identity, "foreign_ruleset_sha256": foreign_digest, "held_source_ports": list(SOURCE_PORTS), "source_sockets": "bound_exclusive_noninheritable", "protected_listener_counts": {str(port): listeners.get(port, 0) for port in ROLES[role]["protected"]}, "owned_table_absent": True, "applying": False, "diagnostics": "not_performed"}


def bounded_receipt_write(value, writer=None):
    data = (canonical(value) + "\n").encode("ascii")
    if len(data) > 8192:
        fail("receipt_custody")
    if writer is None:
        fail("receipt_custody")
    writer(data)
    return sha(data)


def receipt_path(nonce):
    if not isinstance(nonce, str) or re.fullmatch(r"[a-f0-9]{32}", nonce) is None:
        fail("receipt_custody")
    return os.path.join(RECEIPT_DIR, "maintenance-guardian-" + nonce + ".json")


def ensure_receipt_dir(create=False):
    try:
        parent = os.stat("/var/lib", follow_symlinks=False)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            fail("receipt_custody")
        if create:
            info = os.stat(RECEIPT_DIR, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                fail("receipt_custody")
    except GuardError:
        raise
    except Exception:
        fail("receipt_custody")


def create_receipt_fd(nonce, payload):
    ensure_receipt_dir(create=True)
    path = receipt_path(nonce)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        info = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            os.close(fd)
            fail("receipt_custody")
        write_receipt_fd(fd, path, payload)
        return fd
    except GuardError:
        raise
    except FileExistsError:
        fail("receipt_custody")
    except Exception:
        fail("receipt_custody")


def write_receipt_fd(fd, path, payload):
    data = (canonical(payload) + "\n").encode("ascii")
    if len(data) > 8192:
        fail("receipt_custody")
    info = os.fstat(fd)
    named = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
        fail("receipt_custody")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    offset = 0
    while offset < len(data):
        offset += os.write(fd, data[offset:])
    os.fsync(fd)
    parent_fd = os.open(RECEIPT_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return sha(data)


def _same_private_file(fd, path, mode, error_code, fs=os):
    try:
        info = fs.fstat(fd)
        named = fs.stat(path, follow_symlinks=False)
    except Exception:
        fail(error_code)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != mode or stat.S_ISLNK(named.st_mode) or
            not stat.S_ISREG(named.st_mode) or named.st_uid != 0 or named.st_nlink != 1 or
            stat.S_IMODE(named.st_mode) != mode or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)):
        fail(error_code)
    return info


def validate_retained_custody(state, role, nonce, held, fs=os):
    verify_held_sockets(held)
    check_fixed_identity(role)
    lock_fd = state.get("lock_fd")
    if lock_fd is None:
        fail("lock_custody")
    _same_private_file(lock_fd, LOCK_PATH, 0o600, "lock_custody", fs)
    receipt_fd = state.get("receipt_fd")
    receipt_file = state.get("receipt_path")
    expected = state.get("receipt")
    expected_hash = state.get("receipt_sha256")
    if receipt_fd is None or receipt_file != receipt_path(nonce) or not isinstance(expected, dict) or not isinstance(expected_hash, str):
        fail("receipt_custody")
    receipt_info = _same_private_file(receipt_fd, receipt_file, 0o600, "receipt_custody", fs)
    try:
        original_offset = fs.lseek(receipt_fd, 0, fs.SEEK_CUR)
        fs.lseek(receipt_fd, 0, fs.SEEK_SET)
        raw = bytearray()
        while len(raw) <= 8192:
            chunk = fs.read(receipt_fd, min(1024, 8193 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        fs.lseek(receipt_fd, original_offset, fs.SEEK_SET)
    except Exception:
        fail("receipt_custody")
    data = bytes(raw)
    canonical_data = (canonical(expected) + "\n").encode("ascii")
    if len(data) > 8192 or data != canonical_data or sha(data) != expected_hash or expected.get("schema") != "maintenance-guard-receipt-v1" or expected.get("role") != role or expected.get("nonce") != nonce or expected.get("install_state") != "verified":
        fail("receipt_custody")
    return receipt_info


def handle_action(request, held, state, hooks=None):
    hooks = hooks or {}
    role = request["role"]
    nonce = request["nonce"]
    operation = request["operation"]
    if state["role"] != role or state["nonce"] != nonce:
        fail("request_invalid")
    phase = state.get("phase", "active")
    requested_phase = request.get("phase", "active")
    if ("phase" in request and requested_phase != "agent_paused") or phase not in ("active", "agent_paused") or requested_phase != phase or (phase == "agent_paused" and (role != "CT200" or operation != "preflight")):
        fail("phase_invalid")
    if operation == "preflight":
        result = fixed_preflight(role, nonce, held) if phase == "active" else fixed_preflight(role, nonce, held, phase=phase)
        return {"ok": True, "result": result, "receipt_sha256": None}
    if operation == "get":
        planes = {
            "LB115": {"lb_current": (8443, "/healthz", 0), "lb_candidate": (8443, "/healthz", 1), "lb_rollback": (8443, "/healthz", 2)},
            "CT200": {"ct_node_agent": (8080, "/health", 0), "ct_comfy_queue": (8188, "/queue", 1)},
        }[role]
        if request["plane"] not in planes:
            fail("diagnostic_failed")
        port, path, index = planes[request["plane"]]
        used = state.setdefault("get_planes", set())
        if request["plane"] in used:
            fail("diagnostic_failed")
        result = get_fixed_json(held, port, path, index)
        used.add(request["plane"])
        return {"ok": True, "result": result, "receipt_sha256": state.get("receipt_sha256")}
    if operation == "inspect":
        try:
            check_fixed_identity(role)
            verify_held_sockets(held)
            (hooks.get("process_tuples") or process_protected_client_tuples)(role, held=held)
            objects = (hooks.get("ruleset") or nft_ruleset)()
            foreign, owned = ruleset_snapshot_and_owned(objects, role)
            if not owned:
                if state.get("installed") == "verified":
                    state["installed"] = "uncertain"
                    fail("owned_table_absent")
                return {"ok": True, "result": {"owned_table_absent": True, "foreign_ruleset_sha256": sha(canonical(foreign).encode("utf-8"))}, "receipt_sha256": None}
            result = inspect_owned_objects(owned, role, nonce)
            if state.get("installed") != "verified":
                fail("owned_table_present")
            if result != state.get("receipt", {}).get("owned"):
                fail("owned_table_mismatch")
            validate_retained_custody(state, role, nonce, held, hooks.get("custody_fs", os))
            if sha(canonical(foreign).encode("utf-8")) != state["receipt"].get("foreign_ruleset_sha256"):
                fail("foreign_rules_changed")
            return {"ok": True, "result": result, "receipt_sha256": state.get("receipt_sha256")}
        except GuardError:
            if state.get("installed") == "verified":
                state["installed"] = "uncertain"
            raise
    if operation == "install":
        expected = expected_batch(role, nonce)
        batch = request["transaction"].encode("ascii")
        if request["batch_bytes"] != len(expected) or request["batch_sha256"] != sha(expected) or batch != expected:
            fail("plan_invalid")
        if state.get("installed"):
            fail("install_uncertain")
        if state.get("lock_fd") is None:
            fail("lock_custody")
        _same_private_file(state["lock_fd"], LOCK_PATH, 0o600, "lock_custody", hooks.get("custody_fs", os))
        preflight = fixed_preflight(role, nonce, held) if phase == "active" else fixed_preflight(role, nonce, held, phase=phase)
        verify_held_sockets(held)
        if hooks.get("before_install"):
            hooks["before_install"](preflight)
        receipt = {"schema": "maintenance-guard-receipt-v1", "role": role, "nonce": nonce, "batch_sha256": sha(expected), "foreign_ruleset_sha256": preflight["foreign_ruleset_sha256"], "install_state": "attempting"}
        if hooks.get("receipt_writer") is not None:
            receipt_hash = bounded_receipt_write(receipt, writer=hooks.get("receipt_writer"))
            state["receipt_fd"] = hooks.get("receipt_fd")
            state["receipt_path"] = hooks.get("receipt_path", receipt_path(nonce))
        else:
            state["receipt_fd"] = create_receipt_fd(nonce, receipt)
            state["receipt_path"] = receipt_path(nonce)
            receipt_hash = sha((canonical(receipt) + "\n").encode("ascii"))
        state["receipt_sha256"] = receipt_hash
        state["installed"] = "attempting"
        runner = hooks.get("nft_apply")
        if runner is None:
            code, _ = safe_child([NFT, "-f", "-"], expected)
        else:
            code, _ = runner(expected)
        state["installed"] = "uncertain"
        if code != 0:
            fail("install_uncertain")
        post = (hooks.get("ruleset") or nft_ruleset)()
        foreign_after, owned_after = ruleset_snapshot_and_owned(post, role)
        if sha(canonical(foreign_after).encode("utf-8")) != preflight["foreign_ruleset_sha256"]:
            fail("foreign_rules_changed")
        inspected = inspect_owned_objects(owned_after, role, nonce)
        receipt = dict(receipt)
        receipt["install_state"] = "verified"
        receipt["owned"] = inspected
        try:
            if hooks.get("receipt_update") is not None:
                receipt_hash = bounded_receipt_write(receipt, writer=hooks.get("receipt_update"))
            else:
                receipt_hash = write_receipt_fd(state["receipt_fd"], state["receipt_path"], receipt)
        except Exception:
            state["installed"] = "uncertain"
            state.pop("receipt", None)
            fail("receipt_custody")
        state["receipt"] = receipt
        state["receipt_sha256"] = receipt_hash
        state["installed"] = "verified"
        return {"ok": True, "result": {"install_state": "verified", "owned": inspected, "foreign_ruleset_sha256": preflight["foreign_ruleset_sha256"]}, "receipt_sha256": receipt_hash}
    if operation == "release":
        verification = request["verification"]
        receipt = state.get("receipt")
        retained_hash = state.get("receipt_sha256")
        if state.get("installed") != "verified" or not isinstance(receipt, dict) or verification.get("schema") != "maintenance-guard-success-v1" or verification.get("nonce") != nonce or verification.get("disposition") != "successfully_verified" or verification.get("receipt_sha256") != retained_hash or receipt.get("install_state") != "verified":
            fail("release_not_verified")
        try:
            check_fixed_identity(role)
            verify_held_sockets(held)
            validate_retained_custody(state, role, nonce, held, hooks.get("custody_fs", os))
            ephemeral_range(role)
            (hooks.get("process_tuples") or process_protected_client_tuples)(role, held=held)
            objects = (hooks.get("ruleset") or nft_ruleset)()
            foreign, owned = ruleset_snapshot_and_owned(objects, role)
            inspected = inspect_owned_objects(owned, role, nonce)
            if inspected != receipt.get("owned") or sha(canonical(foreign).encode("utf-8")) != receipt.get("foreign_ruleset_sha256"):
                fail("release_not_verified")
        except GuardError:
            state["installed"] = "uncertain"
            raise
        state["installed"] = "release_attempting"
        delete = "delete table inet " + ROLES[role]["table"] + "\n"
        runner = hooks.get("nft_apply")
        if runner is None:
            code, _ = safe_child([NFT, "-f", "-"], delete.encode("ascii"))
        else:
            code, _ = runner(delete.encode("ascii"))
        if code != 0:
            fail("release_uncertain")
        after = (hooks.get("ruleset") or nft_ruleset)()
        foreign_after, owned_after = ruleset_snapshot_and_owned(after, role)
        if owned_after or sha(canonical(foreign_after).encode("utf-8")) != receipt.get("foreign_ruleset_sha256"):
            fail("release_uncertain")
        state["installed"] = "released"
        return {"ok": True, "result": {"release_state": "verified_absent", "prior_owned_handle": inspected["table_handle"]}, "receipt_sha256": state.get("receipt_sha256")}
    fail("request_invalid")


def validate_session_phase(role, request, phase):
    requested_phase = request.get("phase", "active")
    if ("phase" in request and requested_phase != "agent_paused") or phase not in ("active", "agent_paused") or requested_phase != phase or (phase == "agent_paused" and (role != "CT200" or request.get("operation") != "preflight")):
        fail("phase_invalid")


def get_fixed_json(held, port, path, source_index, timeout=5):
    if (port, path, source_index) not in {(8443, "/healthz", 0), (8443, "/healthz", 1), (8443, "/healthz", 2), (8080, "/health", 0), (8188, "/queue", 1)}:
        fail("diagnostic_failed")
    if source_index >= len(held) or held[source_index].getsockname() != ("127.0.0.1", SOURCE_PORTS[source_index]):
        fail("socket_inventory")
    sock = held[source_index]
    try:
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", port))
        if port == 8443:
            context = ssl.create_default_context(cafile=CA_PATH)
            sock = context.wrap_socket(sock, server_hostname=ROLES["LB115"]["ip"])
            sock.set_inheritable(False)
            held[source_index] = sock
        host = ROLES["LB115"]["ip"] if port == 8443 else "127.0.0.1"
        request = ("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n").encode("ascii")
        sock.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) <= 16384:
            chunk = sock.recv(4096)
            if not chunk:
                fail("diagnostic_failed")
            response.extend(chunk)
        split = response.find(b"\r\n\r\n")
        if split < 0:
            fail("diagnostic_failed")
        header = bytes(response[:split]).decode("ascii", "strict").split("\r\n")
        if not re.fullmatch(r"HTTP/1\.[01] [0-9]{3} .*", header[0]):
            fail("diagnostic_failed")
        status = int(header[0].split(" ", 2)[1])
        fields = {}
        for line in header[1:]:
            name, sep, value = line.partition(":")
            if not sep or name.lower() in fields:
                fail("diagnostic_failed")
            fields[name.lower()] = value.strip()
        if fields.get("connection", "").lower() == "close" or fields.get("transfer-encoding") or not fields.get("content-length", "").isdigit():
            fail("diagnostic_failed")
        body_size = int(fields["content-length"])
        if body_size > 65536:
            fail("diagnostic_failed")
        body = bytearray(response[split + 4:])
        while len(body) < body_size:
            chunk = sock.recv(min(4096, body_size - len(body)))
            if not chunk:
                fail("diagnostic_failed")
            body.extend(chunk)
        if len(body) != body_size or status not in (200, 401):
            fail("diagnostic_failed")
        try:
            parsed = json.loads(bytes(body).decode("utf-8"), object_pairs_hook=no_duplicate_pairs)
        except Exception:
            fail("diagnostic_failed")
        result = {"port": port, "path": path, "status": status, "body_bytes": body_size, "source_port": SOURCE_PORTS[source_index], "retained_fd": sock.fileno() >= 0}
        if port == 8188:
            if status != 200 or not isinstance(parsed, dict) or not isinstance(parsed.get("queue_running"), list) or not isinstance(parsed.get("queue_pending"), list):
                fail("diagnostic_failed")
            result["running_count"] = len(parsed["queue_running"])
            result["pending_count"] = len(parsed["queue_pending"])
        elif port == 8080 and path == "/health":
            if status != 200 or not isinstance(parsed, dict) or parsed.get("status") != "ok":
                fail("diagnostic_failed")
            result["reports_ok"] = True
        elif port == 8443:
            if status != 200 or not isinstance(parsed, dict) or parsed.get("status") != "ok":
                fail("diagnostic_failed")
            result["reports_ok"] = True
        return result
    except GuardError:
        raise
    except Exception:
        fail("diagnostic_failed")


def diagnostics(role, held):
    if role == "LB115":
        return [get_fixed_json(held, 8443, "/healthz", 0)]
    return [get_fixed_json(held, 8080, "/health", 0), get_fixed_json(held, 8188, "/queue", 1), {"port": 8190, "status": "diagnostic_unavailable", "reason": "no independently accepted endpoint"}]


def emit(value):
    data = (canonical(value) + "\n").encode("ascii")
    if len(data) > MAX_LINE:
        fail("request_invalid")
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def run_session(role, first_request, deadline_armed=False):
    lock_fd = None
    held = []
    phase = first_request.get("phase", "active")
    validate_session_phase(role, first_request, phase)
    state = {"role": role, "nonce": first_request["nonce"], "installed": False, "receipt_sha256": None, "phase": phase}
    if not hasattr(signal, "SIGALRM"):
        fail("deadline")
    if not deadline_armed:
        signal.alarm(SESSION_DEADLINE)
    try:
        held = acquire_lane_sockets(role)
        actions = 0
        request = first_request
        while request is not None:
            actions += 1
            if actions > MAX_ACTIONS:
                fail("action_limit")
            try:
                validate_session_phase(role, request, phase)
                if request["operation"] in ("install", "release") and lock_fd is None:
                    lock_fd = acquire_lock(create=True)
                    state["lock_fd"] = lock_fd
                result = handle_action(request, held, state)
                emit(result)
                if phase == "agent_paused":
                    return 0
            except GuardError as error:
                if phase == "agent_paused" and request["operation"] == "preflight":
                    emit({"ok": False, "code": error.code, "state": state.get("installed", False)})
                    return 1
                if error.code == "phase_invalid":
                    emit({"ok": False, "code": error.code, "state": state.get("installed", False)})
                    return 1
                if error.code == "deadline":
                    if state.get("installed") not in (False, "released"):
                        state["installed"] = "uncertain"
                    emit({"ok": False, "code": "deadline", "state": state.get("installed", False)})
                    return 1
                emit({"ok": False, "code": error.code, "state": state.get("installed", False)})
            raw = sys.stdin.buffer.readline(MAX_LINE + 1)
            if raw == b"":
                break
            request = parse_request(raw)
            if request["role"] != role or request["nonce"] != state["nonce"]:
                fail("request_invalid")
        if state.get("installed") not in (False, "released"):
            # On EOF the foreground guard retains its held lane sockets until the fixed deadline.
            time.sleep(max(0, SESSION_DEADLINE))
        return 0
    except DeadlineError:
        if state.get("installed") not in (False, "released"):
            state["installed"] = "uncertain"
        emit({"ok": False, "code": "deadline", "state": state.get("installed", False)})
        return 1
    finally:
        signal.alarm(0)
        # Unknown/uncertain objects are deliberately not removed. Only our own held descriptors close.
        for sock in held:
            try:
                sock.close()
            except Exception:
                pass
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except Exception:
                pass
        receipt_fd = state.get("receipt_fd")
        if receipt_fd is not None:
            try:
                os.close(receipt_fd)
            except Exception:
                pass


def _expired(_signum, _frame):
    raise DeadlineError()


def main():
    signal.signal(signal.SIGALRM, _expired)
    signal.alarm(SESSION_DEADLINE)
    try:
        raw = sys.stdin.buffer.readline(MAX_LINE + 1)
    except DeadlineError:
        emit({"ok": False, "code": "deadline", "state": "uncertain"})
        return 1
    request = parse_request(raw)
    return run_session(request["role"], request, deadline_armed=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DeadlineError:
        sys.stdout.write(canonical({"ok": False, "code": "deadline", "state": "uncertain"}) + "\n")
        sys.exit(1)
    except GuardError as error:
        sys.stdout.write(canonical({"ok": False, "code": error.code, "state": "uncertain"}) + "\n")
        sys.exit(1)
    except Exception:
        sys.stdout.write(canonical({"ok": False, "code": "request_invalid", "state": "uncertain"}) + "\n")
        sys.exit(1)
