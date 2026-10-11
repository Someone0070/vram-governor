#!/usr/bin/python3
"""Fixed CT200 isolated startup-test supervisor. Input is a pinned bounded frame."""

import base64
import ast
import errno
import hashlib
import json
import mmap
import os
import posixpath
import re
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import tarfile
import tempfile
import time
import zipfile
from types import FunctionType, SimpleNamespace

SCHEMA = "ct200-startup-request-v1"
RECEIPT_SCHEMA = "ct200-startup-run-v1"
CAPACITY_SCHEMA = "ct200-capacity-request-v1"
CAPACITY_RECEIPT_SCHEMA = "ct200-capacity-run-v1"
STAGED_ROOT = "/var/tmp/lb-verification-tools-s521mxgv"
GO_ARCHIVE_SHA256 = "6924efde5de86fe277676e929dc9917d466efa02fb934197bc2eba35d5680971"
GO_ARCHIVE_BYTES = 73645095
NODE_ARCHIVE_SHA256 = "9d942932535988091034dc94cc5f42b6dc8784d6366df3a36c4c9ccb3996f0c2"
NODE_ARCHIVE_BYTES = 54108748
NODE_BYTES = 120177224
NODE_SHA256 = "1abce2374a485bddae3c27b17a3e3143e2780232026e627c4fe74ddde3f380a1"
GO_TREE_MAX = 1800000000
ELF_STRTAB_MAX = 8 * 1024 * 1024  # Bounds the observed 7,753,645-byte Node table with limited headroom.
ZIP_MAX = 67108864
ZIP_ENTRY_MAX = 33554432
ZIP_TOTAL_MAX = 201326592
FILE_COUNT_MAX = 30000
SOURCE_COUNT_MAX = 4112
SOURCE_BYTES_MAX = 67108864
TRANSFER_MAX = 335544320
META_MAX = 8388608
BOOTSTRAP_CAPACITY_MODE = globals().get("_capacity_mode", False)
RUN_SECONDS = 450 if BOOTSTRAP_CAPACITY_MODE is True else 225
UNIT_SECONDS = 360 if BOOTSTRAP_CAPACITY_MODE is True else 180
CLEANUP_SECONDS = 12
CAPACITY_FREEZE_SHA256 = "438df45ee3397c7ba1845f5b03738cae86028d001ed5a97f4918e1372f2652f5"
CAPACITY_PINS = {
    "internal/workloads/manager.go": (411178, "e661094ed488140743780e413c1dbe42197ae2aab99ddb1b3bb08041c29fe358"),
    "internal/workloads/manager_test.go": (290449, "2b7db9a3ed001330ddafc777788dd0e766508be01f426270fb0d9f009c887c8a"),
    "internal/workloads/residency.go": (112173, "341f55bd6a4e2ee374b8d38562bd5aeab93af1166bdac84db39208afdc53522e"),
    "internal/api/node_commands.go": (79097, "20047d49a8628c65c71efa23c6b3c627279783ed545046a51851e8c5187eb550"),
    "internal/api/node_commands_test.go": (80334, "b77fec982aae8fc6595dbe05b1f3ed14fa38c570fd156478433493b5e5399bc2"),
    "internal/api/ws.go": (58722, "2a60e84306871a08e372c811d8e2edb82f24d33e94639de988b491be1ed10ead"),
    "internal/api/ws_test.go": (66923, "a2334022efa245687a128c024e0e010640db1b2d7b15421c18ddb95f0744eed3"),
    "scripts/verify-runtime-profile-projection.mjs": (185643, "a099d5e788a1461a78206700680b741075e35e9b701518e287721b1021fd0aa1"),
}
CAPACITY_PACKAGES = ("vram-governor/internal/api", "vram-governor/internal/workloads")
CAPACITY_OUTPUT = (b"STRICT UNIT: exact uncached package PASS=vram-governor/internal/api,vram-governor/internal/workloads\n"
                   b"STRICT UNIT: exact unique RUN/PASS inventory=82\n"
                   b"runtime profile projection unit controls passed\n")
UNIT_NAMES = (
    "vram-governor-node-agent.service", "llama-server.service", "comfyui.service",
    "comfy-harness.service", "vram-governor-runtime-tunnel.service",
)
OUTER_DEADLINE = globals().get("_deadline", time.monotonic() + (470 if BOOTSTRAP_CAPACITY_MODE is True else 235))
UNIT_FIELDS = ("Id", "LoadState", "ActiveState", "SubState", "MainPID", "InvocationID")
STARTUP_PINS = {
    "internal/nodeagent/checkpoint_launch_plan.go": (19291, "02ac5cdd48e417c6f8fe835914bad32130e3e6df7f61bf45b6e572e3f33d3983"),
    "internal/nodeagent/checkpoint_launch_plan_test.go": (6563, "e11d0e6339e8c7585740f709b4630a249e1b4cdc6d4232633c8339d7f1434498"),
    "internal/nodeagent/checkpoint_fixed_launcher.go": (16817, "648f71fd7efc2b4764cf90b36770969b2add94e84f5ad293bcbb66c8cf96a0a4"),
    "internal/nodeagent/checkpoint_fixed_launcher_test.go": (16192, "93b6fa83e55d8af21df706625a017471242d4899a1f2bce83100544100d00272"),
    "scripts/verify-checkpoint-startup-runtime.mjs": (13772, "8e9bfc7b17a960886b3b7e12382f6b35e179154dc4d1f4a0629d1fc7c9f7d28c"),
}
UNIT_PROPS = ",".join(UNIT_FIELDS)
MAX_RECEIPT = 4096
MAX_SERVICE_STDERR = 8192
FAILURE_STAGES = frozenset(("bootstrap", "request", "snapshot", "runtime", "isolation", "receipt"))
FAILURE_REASONS = frozenset((
    "deadline", "service_start", "service_activation", "service_output_bound", "service_stderr_bound", "unit_identity_changed",
    "unit_main_membership", "unit_pid", "unit_pid_identity", "unit_pid_gone", "unit_pid_reused", "service_result", "inner_probe", "inner_unit",
    "service_identity", "production_unit_changed", "service_cgroup_identity", "cleanup_observation",
    "scratch_cleanup", "systemd_properties", "rootfs_custody", "cgroup_limit", "cgroup_file", "cgroup_identity",
    "cgroup_main_pid", "cgroup_pid_membership", "cgroup", "cgroup_path", "unclassified",
))
SERVICE_DIAGNOSTICS = frozenset((
    "launcher", "permission", "node_syntax", "node_module", "probe", "probe_config", "probe_config_shape", "probe_facts_shape",
    "probe_credentials", "probe_privilege", "probe_capabilities", "probe_namespace", "probe_identity",
    "probe_limits", "probe_controls", "probe_bounded_read", "probe_file_custody", "probe_gpu_inventory",
    "probe_absence", "probe_runtime", "probe_status_field", "probe_status_ids", "probe_config_missing",
    "probe_guard_error", "probe_native_error", "control", "overflow", "unclassified",
))
PROBE_CONFIG_MARKER = b"CT200_PROBE_DIAGNOSTIC probe_config_missing\n"
PROBE_GUARD_MARKER = b"CT200_PROBE_DIAGNOSTIC probe_guard_error\n"
PROBE_NATIVE_MARKER = b"CT200_PROBE_DIAGNOSTIC probe_native_error\n"
PROBE_NATIVE_CODES = frozenset((
    "EACCES", "EADDRNOTAVAIL", "EBADF", "ECONNABORTED", "ECONNREFUSED", "ECONNRESET", "EEXIST",
    "EHOSTUNREACH", "EINVAL", "EIO", "EISDIR", "ELOOP", "EMFILE", "ENFILE", "ENETUNREACH", "ENOENT",
    "ENOMEM", "ENOSPC", "ENOTDIR", "ENOTEMPTY", "EPERM", "EROFS", "ETIMEDOUT", "EAFNOSUPPORT",
))
PROBE_NATIVE_SYSCALLS = frozenset((
    "open", "read", "fstat", "lstat", "readlink", "scandir", "readdir", "close", "write", "fsync", "unlink", "connect",
))
PROBE_NATIVE_ERRNO_VALUES = {
    code: -getattr(errno, code) for code in PROBE_NATIVE_CODES if hasattr(errno, code)
}
PROBE_OPEN_CALLS = {
    "/probe-config.json": ((("readRegular", 56), ("Module.probe", 126)),),
    "/proc/self/status": ((("readBounded", 51), ("Module.probe", 127)),),
    "/proof-input.txt": (
        (("readRegular", 56), ("Module.probe", 140)),
        (("Module.probe", 142),),
    ),
}


def probe_open_call_sequences(path):
    if path in PROBE_OPEN_CALLS:
        return PROBE_OPEN_CALLS[path]
    if re.fullmatch(r"/work/isolation-write-[a-f0-9]{32}", path):
        return ((("Module.probe", 148),),)
    return ()
PROBE_SOURCE_URL = "file:///source/scripts/ct200-verification/.probe.mjs"
PROBE_WRAPPER_URL = "file:///source/.ct200-wrapper.mjs"
PROBE_GUARD_DIAGNOSTICS = {
    ("validateConfig", 13): "probe_config_shape",
    ("Module.validateConfig", 13): "probe_config_shape",
    ("validateFacts", 23): "probe_facts_shape",
    ("validateFacts", 26): "probe_facts_shape",
    ("validateFacts", 28): "probe_facts_shape",
    ("validateFacts", 31): "probe_facts_shape",
    ("Module.validateFacts", 23): "probe_facts_shape",
    ("Module.validateFacts", 26): "probe_facts_shape",
    ("Module.validateFacts", 28): "probe_facts_shape",
    ("Module.validateFacts", 31): "probe_facts_shape",
    ("validateConfig", 16): "probe_config",
    ("validateConfig", 18): "probe_config",
    ("Module.validateConfig", 16): "probe_config",
    ("Module.validateConfig", 18): "probe_config",
    ("validateFacts", 24): "probe_credentials",
    ("validateFacts", 25): "probe_privilege",
    ("validateFacts", 27): "probe_capabilities",
    ("validateFacts", 29): "probe_namespace",
    ("validateFacts", 30): "probe_identity",
    ("validateFacts", 33): "probe_limits",
    ("validateFacts", 34): "probe_controls",
    ("Module.validateFacts", 24): "probe_credentials",
    ("Module.validateFacts", 25): "probe_privilege",
    ("Module.validateFacts", 27): "probe_capabilities",
    ("Module.validateFacts", 29): "probe_namespace",
    ("Module.validateFacts", 30): "probe_identity",
    ("Module.validateFacts", 33): "probe_limits",
    ("Module.validateFacts", 34): "probe_controls",
    ("readBoundedDescriptor", 38): "probe_bounded_read",
    ("readBoundedDescriptor", 43): "probe_bounded_read",
    ("readBoundedDescriptor", 47): "probe_bounded_read",
    ("readRegular", 59): "probe_file_custody",
    ("readRegular", 64): "probe_file_custody",
    ("readRegular", 65): "probe_file_custody",
    ("gpuDirectoryAbsent", 74): "probe_gpu_inventory",
    ("absent", 80): "probe_absence",
    ("probe", 125): "probe_runtime",
    ("Module.probe", 125): "probe_runtime",
    ("field", 130): "probe_status_field",
    ("ids", 133): "probe_status_ids",
}
PROBE_FRAME_LINES = {
    "object": frozenset((9,)), "validateConfig": frozenset((13, 16, 18)),
    "Module.validateConfig": frozenset((13, 16, 18)),
    "validateFacts": frozenset((23, 24, 25, 26, 27, 28, 29, 30, 31, 33, 34)),
    "Module.validateFacts": frozenset((23, 24, 25, 26, 27, 28, 29, 30, 31, 33, 34)),
    "readBoundedDescriptor": frozenset((38, 43, 47)), "readBounded": frozenset((52,)),
    "readRegular": frozenset((59, 64, 65)), "gpuDirectoryAbsent": frozenset((74,)), "absent": frozenset((80,)),
    "probe": frozenset((125, 126, 127, 133, 134, 135, 136, 138, 140, 142, 148, 149, 150, 151, 153, 155, 156, 157, 158, 159, 163, 164, 166)),
    "Module.probe": frozenset((125, 126, 127, 133, 134, 135, 136, 138, 140, 142, 148, 149, 150, 151, 153, 155, 156, 157, 158, 159, 163, 164, 166)),
    "field": frozenset((130,)), "ids": frozenset((133,)),
}
FAILURE_EXCEPTIONS = frozenset((
    "reject", "os_error", "file_not_found", "permission_error", "timeout", "subprocess_error", "value_error",
    "type_error", "key_error", "index_error", "attribute_error", "assertion_error", "unicode_error", "eof_error",
    "memory_error", "overflow_error", "recursion_error", "system_exit", "other",
))
FAILURE_FRAMES = frozenset((
    "main", "isolation", "validation", "request_validation", "material_stage", "source_validation", "tree_measure",
    "copy_tree", "copy_file", "elf_closure", "command", "systemd_properties", "unit_projection", "unit_capture",
    "cgroup_validation", "cgroup_read", "cgroup_path",
    "fixture_cleanup", "unit_cleanup", "unlocated",
))
MAX_FAILURE_LINE = 4096
MAX_FAILURE_TRACE_FRAMES = 64
SYSTEMD_VERSION_LINE = b"systemd 255 (255.4-1ubuntu8.17)"
STARTED = time.monotonic()
DEADLINE = min(STARTED + RUN_SECONDS, OUTER_DEADLINE - CLEANUP_SECONDS - 2)
REQUEST = globals().get("_request_meta")
READ_RAW = globals().get("_read_raw")
READ_EXTRA = globals().get("_read_extra")
SCRATCH = None
SCRATCH_ID = None
SCRATCH_FD = None
OUTSIDE_ROOT = None
OUTSIDE_ID = None
OUTSIDE_FILE_ID = None
OUTSIDE_SOCKET = None
SERVICE_NAME = None
SERVICE_LAUNCH_ATTEMPTED = False
SERVICE_CGROUP = None
SERVICE_CGROUP_PATH = None
SERVICE_CGROUP_ID = None
SERVICE_PIDS = set()
SERVICE_INVOCATION = None
SERVICE_MAIN_PID = None
SERVICE_MAIN_START = None
SERVICE_ROOTFS_ID = None
SERVICE_EXEC_ID = None
SERVICE_ARGV_BYTES = None
SERVICE_SETTLED = False
OUTSIDE_DATA = None
OUTSIDE_FILE = None
OUTSIDE_FILE_META = None
OUTSIDE_SETTLED = False
CURRENT_STAGE = "bootstrap"
OWNED_UNIT_STARTED = False
ACTIVE_CHILD = None
ACTIVE_LISTENER = None
SERVICE_DIAGNOSTIC = "unclassified"
CAPACITY_WRAPPER_FIXTURE = None


class Reject(Exception):
    pass


def need(condition, code="validation"):
    if not condition:
        raise Reject(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=False, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_sorted(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def ensure_time():
    if time.monotonic() >= DEADLINE:
        raise Reject("deadline")


def set_stage(value):
    global CURRENT_STAGE
    need(value in ("bootstrap", "request", "snapshot", "runtime", "isolation", "receipt"), "stage")
    CURRENT_STAGE = value


def alarm_handler(_signum, _frame):
    child = ACTIVE_CHILD
    if child is not None:
        try:
            child.kill()
        except OSError:
            pass
    raise Reject("deadline")


def exact_keys(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value or "\r" in value or "\n" in value or value.startswith("/"):
        return False
    parts = value.split("/")
    return all(part and part not in (".", "..") and len(part.encode("utf-8")) <= 255 for part in parts)


def valid_module_path(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._~+!-]+(?:/[A-Za-z0-9._~+!-]+)*", value) is not None and all(p not in (".", "..") for p in value.split("/"))


def valid_version(value):
    return isinstance(value, str) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", value) is not None


def escape_go(value):
    need(valid_module_path(value) or valid_version(value))
    return re.sub(r"[A-Z]", lambda match: "!" + match.group(0).lower(), value)


def parse_go_mod(raw):
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError:
        raise Reject("go_mod") from None
    requirements = []
    in_block = False
    seen_module = False
    seen_go = False
    for raw_line in re.split(r"\r?\n", text):
        trimmed = raw_line.strip()
        if not trimmed or trimmed.startswith("//"):
            continue
        comment = ""
        if "//" in raw_line:
            line_part, comment_part = raw_line.split("//", 1)
            line = line_part.strip()
            comment_text = comment_part.strip()
            comment = "// " + comment_text if comment_text else "//"
        else:
            line = trimmed
        if not line:
            continue
        if in_block:
            if line == ")":
                need(not comment or comment == "// indirect", "go_mod")
                in_block = False
                continue
            need(re.match(r"^(?:module|go|require|replace|exclude|toolchain|retract)(?:\s|$)", line) is None and "(" not in line and ")" not in line, "go_mod")
            need(not comment or comment == "// indirect", "go_mod")
            words = line.split()
            need(len(words) == 2 and valid_module_path(words[0]) and valid_version(words[1]), "go_mod")
            requirements.append((words[0], words[1]))
            continue
        if line.startswith("module "):
            match = re.fullmatch(r"module\s+([^\s()]+)", line)
            need(not seen_module and not seen_go and not requirements and match and valid_module_path(match.group(1)), "go_mod")
            seen_module = True
            continue
        if line.startswith("go "):
            match = re.fullmatch(r"go\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", line)
            need(seen_module and not seen_go and not requirements and match, "go_mod")
            seen_go = True
            continue
        if line == "require (":
            need(seen_module and seen_go, "go_mod")
            in_block = True
            continue
        if line.startswith("require "):
            need(seen_module and seen_go and (not comment or comment == "// indirect"), "go_mod")
            words = line[len("require "):].split()
            need(len(words) == 2 and valid_module_path(words[0]) and valid_version(words[1]), "go_mod")
            requirements.append((words[0], words[1]))
            continue
        raise Reject("go_mod")
    need(not in_block and seen_module and seen_go and requirements and len(requirements) <= 128, "go_mod")
    seen = set()
    for module, version in requirements:
        need(module not in seen, "go_mod")
        seen.add(module)
    return sorted(requirements)


def parse_go_sum(raw):
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError:
        raise Reject("go_sum") from None
    sums = {}
    for line in text.splitlines():
        if not line:
            continue
        match = re.fullmatch(r"([^\s]+)\s+(v[^\s]+)\s+(h1:[A-Za-z0-9+/]{43}=)", line)
        need(match is not None, "go_sum")
        key = (match.group(1), match.group(2))
        need(key not in sums, "go_sum")
        sums[key] = match.group(3)
    return sums


def hash1(entries):
    lines = []
    names = set()
    for name, content_hash in sorted(entries, key=lambda item: item[0].encode("utf-8")):
        path_name = name[:-1] if name.endswith("/") else name
        need(safe_relative(path_name) and name not in names, "module_zip")
        names.add(name)
        lines.append(content_hash.hex() + "  " + name + "\n")
    return "h1:" + base64.b64encode(hashlib.sha256("".join(lines).encode("utf-8")).digest()).decode("ascii")


def read_exact(size):
    need(callable(READ_RAW) and isinstance(size, int) and 0 <= size <= TRANSFER_MAX, "frame")
    data = READ_RAW(size)
    need(isinstance(data, bytes) and len(data) == size, "frame")
    return data


def validate_request(meta):
    capacity_mode = type(meta) is dict and meta.get("schema") == CAPACITY_SCHEMA
    keys = (("schema", "mode", "nonce", "manifestSha256", "sourceManifestSha256", "startupFreezeSha256", "capacityFreezeSha256",
             "sourceCount", "moduleCount", "totalBytes", "files") if capacity_mode else
            ("schema", "nonce", "manifestSha256", "sourceManifestSha256", "startupFreezeSha256", "sourceCount", "moduleCount", "totalBytes", "files"))
    need(exact_keys(meta, keys) and meta["schema"] == (CAPACITY_SCHEMA if capacity_mode else SCHEMA) and
         (not capacity_mode or (meta["mode"] == "capacity" and meta["capacityFreezeSha256"] == CAPACITY_FREEZE_SHA256)) and
         isinstance(meta["nonce"], str) and re.fullmatch(r"[a-f0-9]{32}", meta["nonce"]) is not None, "request")
    for key in ("manifestSha256", "sourceManifestSha256", "startupFreezeSha256"):
        need(isinstance(meta[key], str) and re.fullmatch(r"[a-f0-9]{64}", meta[key]), "request")
    need(isinstance(meta["files"], list) and 10 <= len(meta["files"]) <= FILE_COUNT_MAX and len(meta["files"]) == meta["sourceCount"] + 4 * meta["moduleCount"], "request")
    need(type(meta["sourceCount"]) is int and 1 < meta["sourceCount"] <= SOURCE_COUNT_MAX and type(meta["moduleCount"]) is int and 1 <= meta["moduleCount"] <= 128, "request")
    total = 0
    rows = []
    source_rows = []
    previous = ""
    paths = set()
    for item in meta["files"]:
        need(exact_keys(item, ("path", "bytes", "sha256")) and safe_relative(item.get("path")), "request")
        name = item["path"]
        need(name > previous and name not in paths and (name.startswith("source/") or name.startswith("modules/")), "request")
        if name == "source/scripts/verify-runtime-profile-projection.mjs":
            need(capacity_mode, "request")
        previous = name
        paths.add(name)
        need(type(item["bytes"]) is int and 0 <= item["bytes"] <= TRANSFER_MAX - total and isinstance(item["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", item["sha256"]), "request")
        total += item["bytes"]
        rows.append({"path": name, "bytes": item["bytes"], "sha256": item["sha256"]})
        if name.startswith("source/"):
            source_rows.append({"path": name[len("source/"):], "bytes": item["bytes"], "sha256": item["sha256"]})
    need(type(meta["totalBytes"]) is int and total == meta["totalBytes"] and total <= TRANSFER_MAX and sha256(canonical(rows)) == meta["manifestSha256"] and len(source_rows) == meta["sourceCount"] and sha256(canonical(source_rows)) == meta["sourceManifestSha256"], "request")
    source_total = sum(row["bytes"] for row in source_rows)
    need(source_total <= SOURCE_BYTES_MAX, "request")
    for item in meta["files"]:
        name = item["path"]
        if name.startswith("source/"):
            suffix = name[len("source/"):]
            limit = 2 * 1024 * 1024 if suffix == "go.mod" else 8 * 1024 * 1024 if suffix == "go.sum" else SOURCE_BYTES_MAX
            need(item["bytes"] <= limit, "request")
        else:
            suffix = name.rsplit(".", 1)[-1]
            limit = ZIP_MAX if suffix == "zip" else 8 * 1024 * 1024 if suffix == "mod" else 65536 if suffix == "info" else 128
            need(item["bytes"] <= limit, "request")
    if capacity_mode:
        source_by_path = {row["path"]: row for row in source_rows}
        need(all(name in source_by_path and source_by_path[name]["bytes"] == size and source_by_path[name]["sha256"] == digest
                 for name, (size, digest) in CAPACITY_PINS.items()), "capacity_pin")
    return total, source_rows


def safe_write(root, relative, size, expected_hash, mode=0o444):
    need(safe_relative(relative), "path")
    parts = relative.split("/")
    parent = root
    for part in parts[:-1]:
        parent = os.path.join(parent, part)
        try:
            os.mkdir(parent, 0o755)
        except FileExistsError:
            pass
        info = os.lstat(parent)
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022), "custody")
    target = os.path.join(root, *parts)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), mode)
    digest = hashlib.sha256()
    remaining = size
    try:
        while remaining:
            ensure_time()
            chunk = read_exact(min(65536, remaining))
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                count = os.write(fd, view)
                need(count > 0, "disk")
                view = view[count:]
            remaining -= len(chunk)
        os.fchmod(fd, mode)
        os.fsync(fd)
        opened = os.fstat(fd)
        named = os.lstat(target)
        need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_size == size and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino), "custody")
    finally:
        os.close(fd)
    need(digest.hexdigest() == expected_hash, "payload_hash")
    return target


def sha_file(path, max_bytes, require_root=True):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    total = 0
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= max_bytes and not (before.st_mode & 0o6022) and (not require_root or before.st_uid == 0), "file_custody")
        while True:
            ensure_time()
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            need(total <= max_bytes, "file_bound")
            digest.update(block)
        after = os.fstat(fd)
        named = os.lstat(path)
        for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"):
            need(getattr(before, key) == getattr(after, key) == getattr(named, key), "file_changed")
    finally:
        os.close(fd)
    return total, digest.hexdigest()


def read_small(path, max_bytes):
    size, digest = sha_file(path, max_bytes)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        chunks = []
        left = size
        while left:
            block = os.read(fd, min(65536, left))
            need(block, "file_read")
            chunks.append(block)
            left -= len(block)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    need(sha256(data) == digest, "file_changed")
    return data


def _kernel_entry_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid)


def _kernel_entry_valid(info, max_bytes, require_root, category):
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= max_bytes and
         type(info.st_uid) is int and info.st_uid >= 0 and type(info.st_gid) is int and info.st_gid >= 0 and
         not (info.st_mode & 0o6022) and (not require_root or info.st_uid == 0), category)


def _read_kernel_entry_once(path, max_bytes, require_root, category, _ops=None):
    if _ops is None:
        open_fn, fstat_fn, lstat_fn, read_fn, close_fn = os.open, os.fstat, os.lstat, os.read, os.close
    else:
        need(type(_ops) is dict and set(_ops) == {"open", "fstat", "lstat", "read", "close"}, "verify_fixture")
        open_fn, fstat_fn, lstat_fn, read_fn, close_fn = (_ops[key] for key in ("open", "fstat", "lstat", "read", "close"))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = None
    try:
        named_before = lstat_fn(path)
        _kernel_entry_valid(named_before, max_bytes, require_root, category)
        fd = open_fn(path, flags)
        opened = fstat_fn(fd)
        _kernel_entry_valid(opened, max_bytes, require_root, category)
        need(_kernel_entry_identity(opened) == _kernel_entry_identity(named_before), category)
        data = read_fn(fd, max_bytes + 1)
        need(isinstance(data, bytes) and len(data) <= max_bytes, category)
        after = fstat_fn(fd)
        named_after = lstat_fn(path)
        _kernel_entry_valid(after, max_bytes, require_root, category)
        _kernel_entry_valid(named_after, max_bytes, require_root, category)
        need(_kernel_entry_identity(opened) == _kernel_entry_identity(after) == _kernel_entry_identity(named_after), category)
        return data
    except Reject:
        raise
    except OSError as error:
        if category == "unit_pid" and error.errno == errno.ENOENT:
            raise Reject("unit_pid_gone") from None
        raise Reject(category) from None
    finally:
        if fd is not None:
            try:
                close_fn(fd)
            except OSError:
                raise Reject(category) from None


def _read_proc_stat(pid, _ops=None):
    need(type(pid) is int and 0 < pid < 4194304, "unit_pid")
    path = "/proc/%d/stat" % pid
    return _read_kernel_entry_once(path, 4096, False, "unit_pid", _ops)


def _parse_proc_stat_starttime(data, pid):
    need(type(pid) is int and 0 < pid < 4194304 and isinstance(data, bytes) and 0 < len(data) <= 4096 and
         data.endswith(b"\n") and b"\0" not in data, "unit_pid")
    prefix = (str(pid) + " (").encode("ascii")
    need(data.startswith(prefix), "unit_pid")
    close = data.rfind(b")")
    need(close >= len(prefix) - 1 and close + 2 < len(data) and data[close + 1:close + 2] == b" ", "unit_pid")
    tail = data[close + 2:-1]
    need(all(value < 128 for value in tail), "unit_pid")
    fields = tail.split()
    need(len(fields) >= 20 and fields[0] in (b"R", b"S", b"D", b"Z", b"T", b"t", b"X", b"x", b"K", b"W", b"P", b"I") and
         1 <= len(fields[19]) <= 20 and fields[19].isdigit(), "unit_pid")
    return int(fields[19])


def zip_hash(path, module, version):
    prefix = module + "@" + version + "/"
    rows = []
    seen = set()
    expanded = 0
    try:
        archive = zipfile.ZipFile(path, "r")
    except Exception:
        raise Reject("module_zip") from None
    with archive:
        infos = archive.infolist()
        need(0 < len(infos) <= 20000, "module_zip")
        for info in infos:
            ensure_time()
            name = info.filename
            directory = name.endswith("/")
            body = name[:-1] if directory else name
            need(safe_relative(body) and name.startswith(prefix) and len(name) > len(prefix) or name == prefix and directory, "module_zip")
            need("\\" not in name and len(name.encode("utf-8")) <= 4096 and not (info.flag_bits & 0x41) and
                 info.extract_version < 45 and b"\x01\x00" not in info.extra and
                 info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and name not in seen, "module_zip")
            seen.add(name)
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(unix_mode)
            need(file_type in (0, stat.S_IFDIR if directory else stat.S_IFREG) and info.file_size <= ZIP_ENTRY_MAX, "module_zip")
            if directory:
                need(info.file_size == 0, "module_zip")
            expanded += info.file_size
            need(expanded <= ZIP_TOTAL_MAX, "module_zip")
            content = hashlib.sha256()
            count = 0
            with archive.open(info, "r") as stream:
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    count += len(block)
                    need(count <= info.file_size and count <= ZIP_ENTRY_MAX, "module_zip")
                    content.update(block)
            need(count == info.file_size, "module_zip")
            rows.append((name, content.digest()))
    return hash1(rows)


def decode_ziphash(raw, expected):
    need(isinstance(raw, bytes) and isinstance(expected, str) and re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", expected) is not None and raw == (expected + "\n").encode("ascii"), "module_ziphash")
    return expected


def validate_module_info(raw, version):
    try:
        info = json.loads(raw.decode("utf-8", "strict"))
    except Exception:
        raise Reject("module_info") from None
    need(isinstance(info, dict) and set(info) in ({"Version", "Time"}, {"Version", "Time", "Origin"}) and
         info.get("Version") == version and isinstance(info.get("Time"), str) and
         re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", info["Time"]) is not None, "module_info")
    if "Origin" in info:
        origin = info["Origin"]
        required = {"VCS", "URL", "Hash"}
        optional = {"Ref", "Subdir"}
        need(isinstance(origin, dict) and required <= set(origin) and set(origin) <= required | optional and
             all(isinstance(value, str) and value.isascii() and 0 < len(value) <= 512 and not any(ord(c) < 32 or ord(c) == 127 for c in value) for value in origin.values()) and
             origin["VCS"] == "git" and re.match(r"^https?://[^\s]+$", origin["URL"]) is not None and
             re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", origin["Hash"]) is not None and
             ("Ref" not in origin or (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", origin["Ref"]) is not None and
                                       all(part not in (".", "..") for part in origin["Ref"].split("/")))) and
             ("Subdir" not in origin or safe_relative(origin["Subdir"])), "module_info_origin")
    return info


def verify_module_cache(root, requirements, sums):
    expected = set()
    for module, version in requirements:
        escaped = escape_go(module) + "/@v/" + escape_go(version)
        base = escaped
        for suffix in (".zip", ".mod", ".info", ".ziphash"):
            name = "modules/" + base + suffix
            expected.add(name)
        zip_hash_expected = sums.get((module, version))
        mod_hash_expected = sums.get((module, version + "/go.mod"))
        need(zip_hash_expected and mod_hash_expected, "go_sum")
        zip_path = os.path.join(root, "deps", "cache", "download", *base.split("/")) + ".zip"
        mod_path = os.path.join(root, "deps", "cache", "download", *base.split("/")) + ".mod"
        info_path = os.path.join(root, "deps", "cache", "download", *base.split("/")) + ".info"
        ziphash_path = os.path.join(root, "deps", "cache", "download", *base.split("/")) + ".ziphash"
        validate_module_info(read_small(info_path, 65536), version)
        mod = read_small(mod_path, 8 * 1024 * 1024)
        need(hash1([("go.mod", hashlib.sha256(mod).digest())]) == mod_hash_expected, "module_mod")
        stored_ziphash = decode_ziphash(read_small(ziphash_path, 128), zip_hash_expected)
        zip_size_before, zip_digest_before = sha_file(zip_path, ZIP_MAX)
        need(zip_size_before > 0, "module_zip")
        need(zip_hash(zip_path, module, version) == zip_hash_expected, "module_zip")
        need(sha_file(zip_path, ZIP_MAX) == (zip_size_before, zip_digest_before), "module_zip_changed")
    actual = set()
    module_root = os.path.join(root, "deps", "cache", "download")
    for base, dirs, files in os.walk(module_root, followlinks=False):
        for name in dirs:
            full = os.path.join(base, name)
            st = os.lstat(full)
            need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "module_cache")
        for name in files:
            full = os.path.join(base, name)
            st = os.lstat(full)
            need(stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode), "module_cache")
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            actual.add(relative.replace("deps/cache/download/", "modules/", 1))
    need(actual == expected, "module_cache")


def validate_source_tree(root, source_rows, mode="startup"):
    need(mode in ("startup", "capacity"), "source_inventory")
    capacity_mode = mode == "capacity"
    expected = set()
    for row in source_rows:
        name = row["path"]
        need(safe_relative(name), "source_path")
        if (name in ("go.mod", "go.sum") or name == "scripts/verify-checkpoint-startup-runtime.mjs" or
                (capacity_mode and name == "scripts/verify-runtime-profile-projection.mjs") or
                (name.startswith("internal/") and name.endswith(".go"))):
            expected.add(name)
        else:
            raise Reject("source_path")
    need(len(expected) == len(source_rows), "source_path")
    need("go.mod" in expected and "go.sum" in expected and "scripts/verify-checkpoint-startup-runtime.mjs" in expected, "source_inventory")
    for path, (size, digest) in STARTUP_PINS.items():
        row = next((item for item in source_rows if item["path"] == path), None)
        need(row is not None and row["bytes"] == size and row["sha256"] == digest, "startup_pin")
    if capacity_mode:
        for path, (size, digest) in CAPACITY_PINS.items():
            row = next((item for item in source_rows if item["path"] == path), None)
            need(row is not None and row["bytes"] == size and row["sha256"] == digest, "capacity_pin")
    internal = os.path.join(root, "source", "internal")
    actual = set()
    for base, dirs, files in os.walk(internal, followlinks=False):
        for name in dirs:
            st = os.lstat(os.path.join(base, name))
            need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "source_type")
        for name in files:
            full = os.path.join(base, name)
            st = os.lstat(full)
            need(stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode), "source_type")
            if name.endswith(".go"):
                actual.add(os.path.relpath(full, os.path.join(root, "source")).replace(os.sep, "/"))
    expected_internal = {name for name in expected if name.startswith("internal/") and name.endswith(".go")}
    need(actual == expected_internal, "source_inventory")
    for row in source_rows:
        bound = max((size for size, _ in STARTUP_PINS.values()), default=SOURCE_BYTES_MAX)
        size, digest = sha_file(os.path.join(root, "source", *row["path"].split("/")), max(bound, row["bytes"]))
        need(size == row["bytes"] and digest == row["sha256"], "source_changed")
    go_mod = read_small(os.path.join(root, "source", "go.mod"), 2 * 1024 * 1024)
    go_sum = read_small(os.path.join(root, "source", "go.sum"), 8 * 1024 * 1024)
    return parse_go_mod(go_mod), parse_go_sum(go_sum)


def stage_materials(root, meta, source_rows):
    os.mkdir(root, 0o700)
    os.chmod(root, 0o700)
    root_stat = os.lstat(root)
    need(stat.S_ISDIR(root_stat.st_mode) and not stat.S_ISLNK(root_stat.st_mode) and root_stat.st_uid == 0 and (root_stat.st_mode & 0o7777) == 0o700, "scratch_custody")
    for item in meta["files"]:
        relative = item["path"]
        if relative.startswith("source/"):
            target = os.path.join(root, "source", *relative[len("source/"):].split("/"))
        else:
            target = os.path.join(root, "deps", "cache", "download", *relative[len("modules/"):].split("/"))
        destination_root = os.path.commonpath((root, target))
        need(destination_root == root, "path")
        rel = os.path.relpath(target, root)
        mode = 0o444
        safe_write(root, rel, item["bytes"], item["sha256"], mode)
    mode = "capacity" if meta.get("mode") == "capacity" and meta.get("schema") == CAPACITY_SCHEMA else "startup"
    requirements, sums = validate_source_tree(root, source_rows, mode)
    verify_module_cache(root, requirements, sums)
    return requirements, sums


def tree_measure(root):
    rows = []
    modes = {}
    hashes = {}
    total = 0
    count = 0
    stack = [(root, "")]
    while stack:
        base, relative = stack.pop()
        dfd = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(dfd)
            names = sorted(os.listdir(dfd), key=lambda name: name.encode("utf-8"))
            for name in names:
                ensure_time()
                need(name not in (".", "..") and safe_relative(name), "tree_path")
                info = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                full_name = relative + "/" + name if relative else name
                count += 1
                need(count <= FILE_COUNT_MAX and not (info.st_mode & 0o6022) and info.st_uid == 0, "tree_bound")
                modes[full_name] = stat.S_IMODE(info.st_mode)
                if stat.S_ISDIR(info.st_mode):
                    rows.append((full_name, "D", b""))
                    hashes[full_name] = None
                    stack.append((os.path.join(base, name), full_name))
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd)
                    digest = hashlib.sha256()
                    try:
                        opened = os.fstat(fd)
                        need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_uid == 0 and opened.st_size == info.st_size and opened.st_ino == info.st_ino, "tree_changed")
                        while True:
                            block = os.read(fd, 65536)
                            if not block:
                                break
                            total += len(block)
                            need(total <= GO_TREE_MAX, "tree_bound")
                            digest.update(block)
                        after = os.fstat(fd)
                        named = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                        need(after.st_ino == opened.st_ino == named.st_ino and after.st_size == named.st_size == opened.st_size and after.st_mtime_ns == opened.st_mtime_ns and named.st_mtime_ns == opened.st_mtime_ns, "tree_changed")
                    finally:
                        os.close(fd)
                    rows.append((full_name, "F", digest.digest()))
                    hashes[full_name] = digest.hexdigest()
                else:
                    raise Reject("tree_type")
            after = os.fstat(dfd)
            need(after.st_ino == before.st_ino and after.st_mtime_ns == before.st_mtime_ns, "tree_changed")
        finally:
            os.close(dfd)
    digest = hashlib.sha256()
    for name, kind, content_hash in sorted(rows, key=lambda row: row[0].encode("utf-8")):
        digest.update(kind.encode("ascii") + b"\0" + name.encode("utf-8") + b"\0" + content_hash + b"\n")
    return count, total, digest.hexdigest(), modes, hashes


def archive_go_measure(filename):
    rows = []
    modes = {}
    hashes = {}
    seen = set()
    expanded = 0
    count = 0
    try:
        archive = tarfile.open(filename, mode="r|gz")
    except Exception:
        raise Reject("go_archive") from None
    with archive:
        for item in archive:
            ensure_time()
            parts = item.name.rstrip("/").split("/")
            need(parts and parts[0] == "go" and all(part not in ("", ".", "..") and "\\" not in part and len(part.encode("utf-8")) <= 255 for part in parts), "go_archive")
            if len(parts) == 1:
                need(item.isdir() and item.size == 0, "go_archive")
                continue
            relative = "/".join(parts[1:])
            need(relative not in seen and safe_relative(relative), "go_archive")
            seen.add(relative)
            count += 1
            need(count <= FILE_COUNT_MAX, "go_archive")
            if item.isdir():
                need(item.size == 0, "go_archive")
                rows.append((relative, "D", b""))
                modes[relative] = 0o755
                hashes[relative] = None
                continue
            need(item.isreg() and item.size >= 0, "go_archive")
            expanded += item.size
            need(expanded <= GO_TREE_MAX, "go_archive")
            stream = archive.extractfile(item)
            need(stream is not None, "go_archive")
            digest = hashlib.sha256()
            read = 0
            while True:
                block = stream.read(65536)
                if not block:
                    break
                read += len(block)
                need(read <= item.size and read <= GO_TREE_MAX, "go_archive")
                digest.update(block)
            need(read == item.size, "go_archive")
            rows.append((relative, "F", digest.digest()))
            modes[relative] = 0o755 if item.mode & 0o111 else 0o644
            hashes[relative] = digest.hexdigest()
    digest = hashlib.sha256()
    for name, kind, content_hash in sorted(rows, key=lambda row: row[0].encode("utf-8")):
        digest.update(kind.encode("ascii") + b"\0" + name.encode("utf-8") + b"\0" + content_hash + b"\n")
    need(rows, "go_archive")
    return len(rows), expanded, digest.hexdigest(), modes, hashes


def copy_file(source, destination, expected_sha=None, expected_size=None, force_mode=None):
    before = os.lstat(source)
    need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode) and before.st_nlink == 1 and before.st_uid == 0 and not (before.st_mode & 0o6022), "copy_source")
    if expected_size is not None:
        need(before.st_size == expected_size, "copy_size")
    parent = os.path.dirname(destination)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    parent_info = os.lstat(parent)
    need(stat.S_ISDIR(parent_info.st_mode) and not stat.S_ISLNK(parent_info.st_mode) and parent_info.st_uid == 0 and not (parent_info.st_mode & 0o022), "copy_destination")
    src = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    dst = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o644)
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(src)
        need(opened.st_ino == before.st_ino and opened.st_dev == before.st_dev and opened.st_size == before.st_size, "copy_source")
        while True:
            ensure_time()
            block = os.read(src, 65536)
            if not block:
                break
            total += len(block)
            need(total <= (expected_size if expected_size is not None else GO_TREE_MAX), "copy_bound")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(dst, view)
                need(written > 0, "copy_write")
                view = view[written:]
        mode = force_mode if force_mode is not None else (0o755 if before.st_mode & 0o111 else 0o644)
        os.fchmod(dst, mode)
        os.fsync(dst)
        after = os.fstat(src)
        named = os.lstat(source)
        need(after.st_ino == opened.st_ino == named.st_ino and after.st_size == opened.st_size == named.st_size and after.st_mtime_ns == opened.st_mtime_ns == named.st_mtime_ns, "copy_changed")
    finally:
        os.close(src)
        os.close(dst)
    actual = digest.hexdigest()
    need(expected_size is None or total == expected_size, "copy_size")
    need(expected_sha is None or actual == expected_sha, "copy_hash")
    return total, actual


def copy_tree(source, destination, expected_modes, expected_hashes=None):
    os.mkdir(destination, 0o755)
    stack = [(source, destination, "")]
    while stack:
        src_dir, dst_dir, rel = stack.pop()
        names = sorted(os.listdir(src_dir), key=lambda name: name.encode("utf-8"))
        for name in names:
            ensure_time()
            need(safe_relative(name), "tool_tree")
            src = os.path.join(src_dir, name)
            dst = os.path.join(dst_dir, name)
            item_rel = rel + "/" + name if rel else name
            info = os.lstat(src)
            need(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode) and not (info.st_mode & 0o6022), "tool_tree")
            if stat.S_ISDIR(info.st_mode):
                need(expected_modes.get(item_rel) == 0o755, "tool_tree")
                os.mkdir(dst, 0o755)
                stack.append((src, dst, item_rel))
            elif stat.S_ISREG(info.st_mode):
                expected_mode = expected_modes.get(item_rel)
                need(expected_mode in (0o444, 0o644, 0o755), "tool_tree")
                expected_hash = expected_hashes.get(item_rel) if expected_hashes is not None else None
                copy_file(src, dst, expected_sha=expected_hash, expected_size=info.st_size, force_mode=expected_mode)
            else:
                raise Reject("tool_tree")
    need(set(expected_modes) == {os.path.relpath(os.path.join(base, name), source).replace(os.sep, "/") for base, dirs, files in os.walk(source, followlinks=False) for name in dirs + files}, "tool_tree")


def pin_matches(size, digest, expected_size, expected_hash):
    return type(size) is int and size == expected_size and isinstance(digest, str) and digest == expected_hash and re.fullmatch(r"[a-f0-9]{64}", expected_hash) is not None


def read_pin(path, expected_size, expected_hash):
    size, digest = sha_file(path, expected_size)
    need(pin_matches(size, digest, expected_size, expected_hash), "tool_pin")
    return size


def parse_elf(path):
    size, _ = sha_file(path, GO_TREE_MAX)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        data = mmap.mmap(fd, size, access=mmap.ACCESS_READ)
        try:
            return _parse_elf_image(data)
        finally:
            data.close()
    finally:
        os.close(fd)


def _parse_elf_image(data):
    size = len(data) if isinstance(data, (bytes, mmap.mmap)) else -1
    need(64 <= size <= GO_TREE_MAX and data[:4] == b"\x7fELF" and data[4:6] == b"\x02\x01", "elf")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    need(phentsize == 56 and 0 < phnum <= 256 and phoff <= size and phentsize * phnum <= size - phoff, "elf")
    headers = []
    for index in range(phnum):
        row = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phentsize)
        headers.append(row)
    needed = []
    interpreter = None
    dynamic = None
    for row in headers:
        typ, _flags, offset, vaddr, _paddr, filesz, memsz, _align = row
        need(offset <= size and filesz <= size - offset, "elf")
        if typ == 1:
            need(memsz >= filesz and vaddr + filesz <= (1 << 64) - 1, "elf")
        if typ == 3:
            raw = bytes(data[offset:offset + filesz])
            need(raw.endswith(b"\0") and len(raw) <= 256 and b"\0" not in raw[:-1], "elf")
            interpreter = raw[:-1].decode("ascii", "strict")
        if typ == 2:
            need(dynamic is None and 16 <= filesz <= 1024 * 1024 and filesz % 16 == 0, "elf")
            dynamic = (offset, filesz)
    if dynamic is not None:
        dynoff, dynsize = dynamic
        entries = []
        string_addr = string_size = None
        terminated = False
        for relative in range(0, dynsize, 16):
            tag, value = struct.unpack_from("<qQ", data, dynoff + relative)
            if tag == 0:
                terminated = True
                for trailing in range(relative + 16, dynsize, 16):
                    trailing_tag, _trailing_value = struct.unpack_from("<qQ", data, dynoff + trailing)
                    need(trailing_tag == 0, "elf")
                break
            entries.append((tag, value))
            if tag == 5:
                need(string_addr is None, "elf")
                string_addr = value
            elif tag == 10:
                need(string_size is None, "elf")
                string_size = value
        need(terminated and ((string_addr is None) == (string_size is None)), "elf")
        has_needed = any(tag == 1 for tag, _ in entries)
        strings = None
        if has_needed or string_addr is not None:
            need(string_addr is not None and string_size is not None and 0 < string_size <= ELF_STRTAB_MAX, "elf")
            string_offsets = []
            for row in headers:
                if row[0] != 1:
                    continue
                segment_offset, segment_vaddr, segment_filesz = row[2], row[3], row[5]
                if string_addr < segment_vaddr:
                    continue
                delta = string_addr - segment_vaddr
                if delta <= segment_filesz and string_size <= segment_filesz - delta:
                    need(segment_offset <= size and delta <= size - segment_offset and string_size <= size - segment_offset - delta, "elf")
                    string_offsets.append(segment_offset + delta)
            need(len(string_offsets) == 1, "elf")
            string_off = string_offsets[0]
            strings = data[string_off:string_off + string_size]
        for tag, value in entries:
            if tag == 1:
                need(strings is not None and value < len(strings), "elf")
                end = strings.find(b"\0", value)
                need(end > value and end - value <= 255, "elf")
                name = bytes(strings[value:end]).decode("ascii", "strict")
                need(re.fullmatch(r"[A-Za-z0-9_.+-]+\.so(?:\.[A-Za-z0-9_.+-]+)*", name) is not None, "elf")
                needed.append(name)
    return interpreter, tuple(sorted(set(needed)))


def append_bounded_diagnostic(buffer, block, limit=MAX_SERVICE_STDERR):
    need(isinstance(buffer, bytearray) and isinstance(block, bytes) and type(limit) is int and limit >= 0, "diagnostic")
    remaining = max(0, limit - len(buffer))
    if remaining:
        buffer.extend(block[:remaining])
    return len(block) > remaining


def consume_service_pipe(fd, stream_kind, output, diagnostic, diagnostic_overflow):
    need(type(fd) is int and stream_kind in ("stdout", "stderr") and isinstance(output, bytearray) and
         isinstance(diagnostic, bytearray) and type(diagnostic_overflow) is bool, "diagnostic")
    block = os.read(fd, 8193 - len(output)) if stream_kind == "stdout" else os.read(fd, 8193)
    if not block:
        return False, diagnostic_overflow
    if stream_kind == "stdout":
        output.extend(block)
        need(len(output) <= 8192, "service_output_bound")
    else:
        diagnostic_overflow = append_bounded_diagnostic(diagnostic, block) or diagnostic_overflow
    return True, diagnostic_overflow


def capture_queued_service_stderr(selector, output, diagnostic, diagnostic_overflow):
    if diagnostic_overflow:
        return "overflow"
    deadline = min(time.monotonic() + 0.05, OUTER_DEADLINE)
    completed = False
    for _ in range(16):
        if time.monotonic() >= deadline:
            break
        ready = selector.select(0)
        stderr_ready = [key for key, _events in ready if key.data == "stderr"]
        if not stderr_ready:
            completed = True
            break
        for key in stderr_ready:
            pipe_open, diagnostic_overflow = consume_service_pipe(
                key.fd, "stderr", output, diagnostic, diagnostic_overflow)
            if not pipe_open:
                selector.unregister(key.fileobj)
            if diagnostic_overflow:
                break
        if diagnostic_overflow:
            break
    if not completed and not diagnostic_overflow:
        return "unclassified"
    return classify_service_stderr(bytes(diagnostic), diagnostic_overflow)


def refresh_service_diagnostic(selector, output, diagnostic, diagnostic_overflow):
    global SERVICE_DIAGNOSTIC
    try:
        SERVICE_DIAGNOSTIC = capture_queued_service_stderr(
            selector, output, diagnostic, diagnostic_overflow)
    except BaseException:
        SERVICE_DIAGNOSTIC = "unclassified"


def retain_service_stderr(data, _ops=None):
    # This is private bounded evidence only; a full buffer may be truncated and never proves completeness.
    need(type(data) is bytes and len(data) <= MAX_SERVICE_STDERR and SCRATCH_FD is not None and
         type(SCRATCH_ID) is tuple and len(SCRATCH_ID) == 2 and type(SCRATCH) is str, "scratch_custody")
    if _ops is None:
        open_fn, close_fn = os.open, os.close
        fstat_fn, lstat_fn, stat_at_fn = os.fstat, os.lstat, os.stat
        fchmod_fn, write_fn = os.fchmod, os.write
    else:
        need(type(_ops) is dict and set(_ops) == {
            "open", "close", "fstat", "lstat", "stat_at", "fchmod", "write"}, "verify_fixture")
        open_fn, close_fn = _ops["open"], _ops["close"]
        fstat_fn, lstat_fn, stat_at_fn = _ops["fstat"], _ops["lstat"], _ops["stat_at"]
        fchmod_fn, write_fn = _ops["fchmod"], _ops["write"]

    def check_scratch():
        held = fstat_fn(SCRATCH_FD)
        named = lstat_fn(SCRATCH)
        need(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(named.st_mode) and
             (held.st_dev, held.st_ino) == SCRATCH_ID == (named.st_dev, named.st_ino) and
             held.st_uid == named.st_uid == 0 and
             (held.st_mode & 0o7777) == (named.st_mode & 0o7777) == 0o700, "scratch_custody")

    def check_file(info, size):
        need(stat.S_ISREG(info.st_mode) and info.st_dev == SCRATCH_ID[0] and info.st_nlink == 1 and info.st_uid == 0 and
             (info.st_mode & 0o7777) == 0o600 and 0 <= info.st_size <= MAX_SERVICE_STDERR and
             (size is None or info.st_size == size), "stderr_custody")

    filename = "service-stderr.bin"
    check_scratch()
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = open_fn(filename, flags, 0o600, dir_fd=SCRATCH_FD)
    try:
        fchmod_fn(fd, 0o600)
        opened = fstat_fn(fd)
        named = stat_at_fn(filename, dir_fd=SCRATCH_FD, follow_symlinks=False)
        check_file(opened, 0)
        check_file(named, 0)
        need((opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino), "stderr_custody")
        offset = 0
        interrupted = 0
        while offset < len(data):
            try:
                written = write_fn(fd, memoryview(data)[offset:])
            except InterruptedError:
                interrupted += 1
                need(interrupted <= 16, "stderr_write")
                continue
            need(type(written) is int and 0 < written <= len(data) - offset, "stderr_write")
            offset += written
        opened = fstat_fn(fd)
        named = stat_at_fn(filename, dir_fd=SCRATCH_FD, follow_symlinks=False)
        check_file(opened, len(data))
        check_file(named, len(data))
        need((opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino), "stderr_custody")
        file_identity = (opened.st_dev, opened.st_ino)
        check_scratch()
    finally:
        close_fn(fd)
    named = stat_at_fn(filename, dir_fd=SCRATCH_FD, follow_symlinks=False)
    check_file(named, len(data))
    need((named.st_dev, named.st_ino) == file_identity, "stderr_custody")
    check_scratch()


def retain_service_stderr_best_effort(data, failed=True, retain_fn=None):
    if not failed:
        return False
    retain_fn = retain_service_stderr if retain_fn is None else retain_fn
    try:
        retain_fn(data)
        return True
    except BaseException:
        return False


def classify_probe_stderr(data):
    if type(data) is not bytes or not data or len(data) > MAX_SERVICE_STDERR or b"\0" in data or b"\r" in data:
        return "unclassified"
    try:
        text = data.decode("ascii", "strict")
    except UnicodeError:
        return "unclassified"
    if not text.endswith("\n"):
        return "unclassified"
    lines = text[:-1].split("\n")
    if len(lines) < 5 or len(lines) > 16 or any(len(line) > 512 for line in lines):
        return "unclassified"
    context_prefix = (
        PROBE_SOURCE_URL + ":6",
        "const fail = () => { throw new Error('isolation verification rejected'); };",
        " " * 27 + "^",
        "",
    )
    if tuple(lines[:4]) == context_prefix:
        stack_start = 4
    else:
        stack_start = 0
    if lines[stack_start] != "Error: isolation verification rejected" or lines[-1] != "Node.js v22.14.0":
        return "unclassified"
    frame_lines = lines[stack_start + 1:-1]
    if frame_lines and frame_lines[-1] == "":
        frame_lines.pop()
    if len(frame_lines) < 3 or len(frame_lines) > 6 or "" in frame_lines:
        return "unclassified"
    frame_re = re.compile(
        r"    at (?:(async) )?(?:([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*) \()?"
        r"(file:///source/scripts/ct200-verification/\.probe\.mjs|file:///source/\.ct200-wrapper\.mjs):"
        r"([1-9][0-9]{0,3}):([1-9][0-9]{0,3})\)?"
    )
    frames = []
    for frame_line in frame_lines:
        match = frame_re.fullmatch(frame_line)
        if match is None:
            return "unclassified"
        async_prefix, function_name, source_url, source_line, source_column = match.groups()
        line = int(source_line)
        column = int(source_column)
        if column > 512:
            return "unclassified"
        frames.append((bool(async_prefix), function_name, source_url, line, column))
    first = frames[0]
    last = frames[-1]
    if (first != (False, "fail", PROBE_SOURCE_URL, 6, 28) or last[2] != PROBE_WRAPPER_URL or last[3] != 11 or
            last[1] is not None):
        return "unclassified"
    probe_frames = frames[1:-1]
    if not probe_frames or any(source_url != PROBE_SOURCE_URL or function_name not in PROBE_FRAME_LINES or
                               line not in PROBE_FRAME_LINES[function_name]
                               for _async, function_name, source_url, line, _column in probe_frames):
        return "unclassified"
    _async, function_name, _source_url, line, _column = probe_frames[0]
    if function_name == "object":
        if len(probe_frames) < 2:
            return "unclassified"
        _async, owner, _source_url, owner_line, _column = probe_frames[1]
        return PROBE_GUARD_DIAGNOSTICS.get((owner, owner_line), "unclassified")
    return PROBE_GUARD_DIAGNOSTICS.get((function_name, line), "unclassified")


def classify_structured_probe_stderr(data):
    if type(data) is not bytes or not data or len(data) > MAX_SERVICE_STDERR or b"\0" in data or b"\r" in data:
        return None
    markers = (PROBE_CONFIG_MARKER, PROBE_GUARD_MARKER, PROBE_NATIVE_MARKER)
    matches = [marker for marker in markers if marker in data]
    if len(matches) != 1 or not data.startswith(matches[0]) or data.count(matches[0]) != 1:
        return None
    marker = matches[0]
    try:
        text = data.decode("ascii", "strict")
    except UnicodeError:
        return None
    if not text.endswith("\n"):
        return None
    lines = text[:-1].split("\n")
    if len(lines) < 5 or len(lines) > 32 or any(len(line) > 512 for line in lines):
        return None
    if lines[0] != marker.decode("ascii").rstrip("\n"):
        return None
    if lines[-1] != "Node.js v22.14.0" or lines.count("Node.js v22.14.0") != 1:
        return None
    if marker == PROBE_GUARD_MARKER:
        precise = classify_probe_stderr(data[len(marker):])
        return precise if precise != "unclassified" else None

    if lines[1:5] == ["node:fs:562", "  return binding.open(", "                 ^", ""]:
        error_index = 5
    else:
        error_index = 1
    if error_index >= len(lines):
        return None
    native_header = re.fullmatch(
        r"Error: ([A-Z][A-Z0-9]{1,15}): ([A-Za-z0-9 ._'-]{1,120}), open '([^'\n]{1,192})'",
        lines[error_index],
    )
    if native_header is None:
        return None
    code, message, header_path = native_header.groups()
    if code not in PROBE_NATIVE_CODES or code not in PROBE_NATIVE_ERRNO_VALUES:
        return None
    native_and_probe_lines = []
    frame_end = error_index + 1
    while frame_end < len(lines) and not lines[frame_end].endswith(" {"):
        native_and_probe_lines.append(lines[frame_end])
        frame_end += 1
    if frame_end >= len(lines) or not lines[frame_end].endswith(" {"):
        return None
    final_frame = lines[frame_end][:-2]
    if not re.fullmatch(
            r"    at (?:async )?file:///source/\.ct200-wrapper\.mjs:11:[1-9][0-9]{0,2}", final_frame):
        return None
    if not native_and_probe_lines or not re.fullmatch(
            r"    at (?:Object|Module)\.openSync \(node:fs:562:18\)", native_and_probe_lines[0]):
        return None
    probe_frame_lines = native_and_probe_lines[1:]
    parsed_probe_frames = []
    for frame_line in probe_frame_lines:
        frame_match = re.fullmatch(
            r"    at ([A-Za-z_$][A-Za-z0-9_$.]*) \(file:///source/scripts/ct200-verification/\.probe\.mjs:([1-9][0-9]{0,3}):([1-9][0-9]{0,2})\)",
            frame_line,
        )
        if frame_match is None:
            return None
        parsed_probe_frames.append((frame_match.group(1), int(frame_match.group(2))))
    if code != "ENOENT" or message.casefold() != "no such file or directory":
        if message.casefold() != os.strerror(-PROBE_NATIVE_ERRNO_VALUES[code]).casefold():
            return None
    property_lines = lines[frame_end + 1:-3]
    if len(lines) < frame_end + 5 or lines[-3:] != ["}", "", "Node.js v22.14.0"]:
        return None
    if len(property_lines) != 4:
        return None
    property_matches = (
        re.fullmatch(r"  errno: (-[1-9][0-9]{0,5}),", property_lines[0]),
        re.fullmatch(r"  code: '([A-Z][A-Z0-9]{1,15})',", property_lines[1]),
        re.fullmatch(r"  syscall: '([a-z]+)',", property_lines[2]),
        re.fullmatch(r"  path: '([^'\n]{1,192})'", property_lines[3]),
    )
    if any(match is None for match in property_matches):
        return None
    property_errno, property_code, property_syscall, property_path = (
        property_matches[0].group(1), property_matches[1].group(1),
        property_matches[2].group(1), property_matches[3].group(1),
    )
    if (int(property_errno) != PROBE_NATIVE_ERRNO_VALUES[code] or property_code != code or
            property_syscall != "open" or property_path != header_path):
        return None
    if tuple(parsed_probe_frames) not in probe_open_call_sequences(header_path):
        return None
    if marker == PROBE_CONFIG_MARKER:
        return "probe_config_missing" if code == "ENOENT" and header_path == "/probe-config.json" else None
    if code == "ENOENT" and header_path == "/probe-config.json":
        return None
    return "probe_native_error"


def classify_service_stderr(data, overflow=False):
    if type(data) is not bytes or len(data) > MAX_SERVICE_STDERR:
        return "unclassified"
    if overflow:
        return "overflow"
    if any(marker in data for marker in (b"Operation not permitted", b"Permission denied", b"Access denied")):
        return "permission"
    if b"SyntaxError:" in data:
        return "node_syntax"
    if any(marker in data for marker in (b"ERR_MODULE_NOT_FOUND", b"Cannot find package", b"Cannot find module")):
        return "node_module"
    if any(marker in data for marker in (PROBE_CONFIG_MARKER, PROBE_GUARD_MARKER, PROBE_NATIVE_MARKER)):
        structured = classify_structured_probe_stderr(data)
        if structured is not None:
            return structured
    if b"isolation verification rejected" in data or b"probe usage rejected" in data:
        return classify_probe_stderr(data)
    if any(marker in data for marker in (b"unshare:", b"setpriv:", b"Failed at step EXEC spawning")):
        return "launcher"
    if any(marker in data for marker in (
        b"exact unit oracle failed", b"output bound", b"cache manifest", b"cache bytes bound",
        b"unexpected cache directory", b"cache name", b"cache file custody", b"cache open custody",
        b"cache payload authentication", b"cache expansion bound", b"cache inventory mismatch",
    )):
        return "control"
    return "unclassified"


def failure_envelope(error, unit_state, fixture_state, scratch_state, diagnostic, exception_info=None):
    category = "controlled" if isinstance(error, Reject) else "internal"
    stage = CURRENT_STAGE if CURRENT_STAGE in FAILURE_STAGES else "unclassified"
    error_args = error.args if isinstance(error, Reject) else ()
    reason = error_args[0] if len(error_args) == 1 and type(error_args[0]) is str and error_args[0] in FAILURE_REASONS else "unclassified"
    if unit_state not in ("settled", "preserved"):
        unit_state = "unclassified"
    if fixture_state not in ("settled", "preserved"):
        fixture_state = "unclassified"
    if scratch_state not in ("retained", "absent"):
        scratch_state = "unclassified"
    if diagnostic not in SERVICE_DIAGNOSTICS:
        diagnostic = "unclassified"
    if exception_info is None:
        exception_info = failure_exception_info(error)
    if type(exception_info) is not tuple or len(exception_info) != 3:
        exception_info = ("other", "unlocated", 0)
    exception_type, frame, line = exception_info
    if type(exception_type) is not str or exception_type not in FAILURE_EXCEPTIONS:
        exception_type = "other"
    if type(frame) is not str or frame not in FAILURE_FRAMES:
        frame, line = "unlocated", 0
    if type(line) is not int or (frame == "unlocated" and line != 0) or (frame != "unlocated" and not (1 <= line <= MAX_FAILURE_LINE)):
        frame, line = "unlocated", 0
    return ("fixed startup supervisor failed stage=%s category=%s unit=%s fixture=%s scratch=%s reason=%s exception=%s frame=%s line=%d diagnostic=%s\n" %
            (stage, category, unit_state, fixture_state, scratch_state, reason, exception_type, frame, line, diagnostic)).encode("ascii")


def resolve_library(name):
    need(re.fullmatch(r"[A-Za-z0-9_.+-]+\.so(?:\.[A-Za-z0-9_.+-]+)*", name) is not None, "elf_library")
    for directory in ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64", "/usr/lib"):
        candidate = os.path.join(directory, name)
        try:
            resolved = os.path.realpath(candidate, strict=True)
            st = os.stat(resolved, follow_symlinks=False)
        except (OSError, TypeError):
            continue
        need(resolved.startswith("/lib/") or resolved.startswith("/usr/lib/") or resolved.startswith("/lib64/"), "elf_library")
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink >= 1 and not (st.st_mode & 0o6022), "elf_library")
        return resolved
    raise Reject("elf_library")


def copy_elf_closure(rootfs, binaries):
    queue = list(binaries)
    copied = set()
    root_prefix = os.path.realpath(rootfs).rstrip("/") + "/"
    while queue:
        source = queue.pop(0)
        in_root = source.startswith(root_prefix)
        need(in_root or source.startswith("/usr/bin/") or source.startswith("/lib/") or source.startswith("/usr/lib/") or source.startswith("/lib64/"), "elf_path")
        inspect_source = os.path.realpath(source) if not in_root else source
        interp, needed = parse_elf(inspect_source)
        if interp:
            need(interp == "/lib64/ld-linux-x86-64.so.2", "elf_interpreter")
            if interp not in copied:
                queue.append(interp)
        for name in needed:
            resolved = resolve_library(name)
            target = "/lib/x86_64-linux-gnu/" + name
            if target not in copied:
                copied.add(target)
                copy_file(resolved, os.path.join(rootfs, target.lstrip("/")), force_mode=0o755)
                queue.append(os.path.join(rootfs, target.lstrip("/")))
        if not in_root and source not in copied:
            copied.add(source)
            relative = source.lstrip("/")
            if source.startswith("/lib64/"):
                relative = "lib64/" + os.path.basename(source)
            copy_file(inspect_source, os.path.join(rootfs, relative), force_mode=0o755)


def command(argv, timeout=8, max_output=16384):
    ensure_time()
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=min(timeout, max(0.1, DEADLINE - time.monotonic())), check=False,
                                close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise Reject("system_observation") from None
    need(result.returncode == 0 and len(result.stdout) <= max_output, "system_observation")
    return result.stdout


def unit_projection():
    props = ",".join(UNIT_FIELDS)
    rows = []
    for name in UNIT_NAMES:
        raw = command(("/usr/bin/systemctl", "show", name, "--property=" + props), max_output=4096)
        lines = raw.decode("utf-8", "strict").splitlines()
        need(len(lines) == len(UNIT_FIELDS), "unit_projection")
        row = {}
        for line in lines:
            key, sep, value = line.partition("=")
            need(sep and key in UNIT_FIELDS and key not in row and len(value) <= 256 and "\0" not in value, "unit_projection")
            row[key] = value
        need(set(row) == set(UNIT_FIELDS) and row["Id"] == name and row["MainPID"].isdigit(), "unit_projection")
        row["MainPIDStartTime"] = proc_starttime(int(row["MainPID"]))
        rows.append(row)
    return sha256(canonical(rows))


def proc_starttime(pid):
    if pid == 0:
        return None
    return _parse_proc_stat_starttime(_read_proc_stat(pid), pid)


def parse_systemd_properties(raw, names):
    need(isinstance(raw, bytes) and len(raw) <= 2048, "systemd_properties")
    result = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        key, sep, value = line.partition("=")
        need(sep and key in names and key not in result and len(value) <= 512, "systemd_properties")
        result[key] = value
    need(set(result) == set(names), "systemd_properties")
    return result


def validate_systemd_version(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.endswith(b"\n") and b"\0" not in raw, "systemd_version")
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeError:
        raise Reject("systemd_version") from None
    first_line, separator, _rest = text.partition("\n")
    need(bool(separator) and first_line.encode("ascii") == SYSTEMD_VERSION_LINE, "systemd_version")
    return True


def systemd_properties(unit):
    names = ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState")
    raw = command(("/usr/bin/systemctl", "show", unit, "--property=" + ",".join(names)), max_output=2048)
    result = parse_systemd_properties(raw, names)
    need(result["MainPID"].isdigit() and result["ActiveState"] in ("activating", "active", "deactivating", "inactive", "failed") and
         result["LoadState"] in ("loaded", "not-found"), "systemd_properties")
    return result


def validate_unit_absent(fields, unit):
    need(re.fullmatch(r"ct200-startup-[a-f0-9]{32}\.service", unit) is not None and
         exact_keys(fields, ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState")) and
         all(isinstance(fields[key], str) for key in ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState")) and
         fields["LoadState"] == "not-found" and fields["ControlGroup"] == "" and fields["MainPID"] == "0" and
         fields["InvocationID"] == "" and fields["ActiveState"] in ("inactive", "failed"), "unit_preexisting")
    return True


def validate_active_unit(fields, unit):
    need(re.fullmatch(r"ct200-startup-[a-f0-9]{32}\.service", unit) is not None and
         exact_keys(fields, ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState")) and
         all(isinstance(fields[key], str) for key in ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState")) and
         fields["LoadState"] == "loaded" and fields["ControlGroup"] == "/system.slice/" + unit and
         isinstance(fields["MainPID"], str) and fields["MainPID"].isdigit() and int(fields["MainPID"]) > 0 and
         re.fullmatch(r"[a-f0-9]{32}", fields["InvocationID"]) is not None and fields["ActiveState"] == "active", "unit_identity")
    return True


def validate_controller_change(root_before, root_after, parent_before, parent_after, cpu_bound):
    need(cpu_bound is True, "controller_cpu_bound")
    def valid_pair(before, after):
        a = set(before.split())
        b = set(after.split())
        need(b >= a and b - a <= {"cpu"}, "controller_change")
    valid_pair(root_before, root_after)
    valid_pair(parent_before, parent_after)
    return True


def cgroup_path(relative, root="/sys/fs/cgroup", lstat=os.lstat):
    need(isinstance(relative, str) and re.fullmatch(r"/system\.slice/[A-Za-z0-9_.@:-]+\.service", relative), "cgroup_path")
    need(isinstance(root, str) and root.startswith("/") and not root.startswith("//") and posixpath.normpath(root) == root and "\x00" not in root, "cgroup_path")
    current = "/"
    for part in root.split("/")[1:]:
        if not part:
            continue
        current = posixpath.join(current, part)
        info = lstat(current)
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0, "cgroup_path")
    for part in relative.split("/")[1:]:
        current = posixpath.join(current, part)
        info = lstat(current)
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0, "cgroup_path")
    return current


def _read_cgroup_pids(cgroup, _ops=None):
    need(type(cgroup) is str and re.fullmatch(r"/sys/fs/cgroup/system\.slice/ct200-startup-[a-f0-9]{32}\.service", cgroup) is not None,
         "cgroup_processes")
    path = posixpath.join(cgroup, "cgroup.procs")
    raw = _read_kernel_entry_once(path, 65536, True, "cgroup_processes", _ops).decode("ascii", "strict")
    values = [line for line in raw.splitlines() if line]
    need(len(values) <= 128 and all(value.isdigit() and 0 < int(value) < 4194304 for value in values), "cgroup_processes")
    return {int(value) for value in values}


def read_pids(cgroup):
    return _read_cgroup_pids(cgroup)


def verify_cgroup(cgroup, unit, pids, expected_identity=None):
    expected = {"memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "100000 100000"}
    for name, value in expected.items():
        need(read_cgroup_value(cgroup, name) == value, "cgroup_limit")
        limit_path = os.path.join(cgroup, name)
        st = os.lstat(limit_path)
        need(stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_uid == 0, "cgroup_file")
    props = systemd_properties(unit)
    need(props["LoadState"] == "loaded" and re.fullmatch(r"[a-f0-9]{32}", props["InvocationID"]) is not None and
         props["ControlGroup"].startswith("/system.slice/") and cgroup_path(props["ControlGroup"]) == cgroup, "cgroup_identity")
    main_pid = int(props["MainPID"])
    need(main_pid in pids and pids and len(pids) <= 128, "cgroup_main_pid")
    if expected_identity is not None:
        need(expected_identity == (props["InvocationID"], main_pid, proc_starttime(main_pid)), "cgroup_identity")
    proc_cgroup = read_small("/proc/%d/cgroup" % main_pid, 4096).decode("ascii", "strict")
    need("0::" + props["ControlGroup"] + "\n" in proc_cgroup.splitlines(True), "cgroup_pid_membership")
    return props


def capacity_wrapper_source(startup_wrapper):
    need(type(startup_wrapper) is bytes, "capacity_wrapper")
    marker_literal = json.dumps(CAPACITY_OUTPUT.decode("ascii"), ensure_ascii=True).encode("ascii")
    package_literal = json.dumps(list(CAPACITY_PACKAGES), ensure_ascii=True).encode("ascii")
    replacements = (
        (br"const marker = 'checkpoint startup runtime unit controls passed\n';",
         b"const marker = " + marker_literal + b";"),
        (b"process.argv=[process.execPath,'/source/scripts/verify-checkpoint-startup-runtime.mjs','--unit'];\nprocess.exitCode=0;\n"
         b"await import(pathToFileURL('/source/scripts/verify-checkpoint-startup-runtime.mjs').href+'?run='+nonce);",
         b"process.argv=[process.execPath,'/source/scripts/verify-runtime-profile-projection.mjs','--unit'];\nprocess.exitCode=0;\n"
         b"process.chdir('/source');if(process.cwd()!=='/source')throw new Error('capacity verifier working directory');\n"
         b"await import(pathToFileURL('/source/scripts/verify-runtime-profile-projection.mjs').href+'?run='+nonce);"),
        (b"if(process.exitCode!==0||Buffer.concat(emitted).toString('utf8')!==marker)throw new Error('exact unit oracle failed');",
         b"if(process.exitCode!==0||Buffer.concat(emitted).toString('utf8')!==marker)throw new Error('exact capacity unit oracle failed');"),
        (br"process.stdout.write(JSON.stringify({schema:'ct200-startup-inner-v1',nonce,probe,probeReceiptSha256:digest(Buffer.from(canonical(probe))),unitOutputSha256:digest(Buffer.concat(emitted)),testCount:15})+'\nCT200_STARTUP_INNER_PASSED\n');",
         b"process.stdout.write(JSON.stringify({schema:'ct200-capacity-inner-v1',mode:'capacity',nonce,probe,probeReceiptSha256:digest(Buffer.from(canonical(probe))),capacityOutputSha256:digest(Buffer.concat(emitted)),testCount:82,packages:" + package_literal + b"})+'\\nCT200_CAPACITY_INNER_PASSED\\n');"),
    )
    result = startup_wrapper
    for before, after in replacements:
        need(result.count(before) == 1, "capacity_wrapper")
        result = result.replace(before, after, 1)
    need(b"process.chdir('/source');if(process.cwd()!=='/source')" in result and
         result.index(b"process.cwd()!=='/source'") < result.index(b"await import(pathToFileURL('/source/scripts/verify-runtime-profile-projection.mjs')"),
         "capacity_wrapper")
    return result


def internal_receipt(output, meta):
    capacity_mode = meta.get("mode") == "capacity" and meta.get("schema") == CAPACITY_SCHEMA
    terminal = b"\nCT200_CAPACITY_INNER_PASSED\n" if capacity_mode else b"\nCT200_STARTUP_INNER_PASSED\n"
    need(isinstance(output, bytes) and len(output) <= 8192 and output.endswith(terminal), "inner_receipt")
    lines = output.splitlines()
    need(len(lines) == 2, "inner_receipt")
    try:
        value = json.loads(lines[0].decode("ascii", "strict"))
    except Exception:
        raise Reject("inner_receipt") from None
    if capacity_mode:
        need(exact_keys(value, ("schema", "mode", "nonce", "probe", "probeReceiptSha256", "capacityOutputSha256", "testCount", "packages")) and
             value["schema"] == "ct200-capacity-inner-v1" and value["mode"] == "capacity" and value["nonce"] == meta["nonce"] and
             type(value["testCount"]) is int and value["testCount"] == 82 and value["packages"] == list(CAPACITY_PACKAGES) and
             isinstance(value["probeReceiptSha256"], str) and re.fullmatch(r"[a-f0-9]{64}", value["probeReceiptSha256"]) and
             isinstance(value["capacityOutputSha256"], str) and value["capacityOutputSha256"] == sha256(CAPACITY_OUTPUT), "inner_capacity_receipt")
        probe = value["probe"]
        need(exact_keys(probe, ("schema", "nonce", "inputSha256", "pid", "namespaces", "limits")) and
             probe["schema"] == "lb-isolation-receipt-v1" and probe["nonce"] == meta["nonce"] and type(probe["pid"]) is int and probe["pid"] == 1 and
             isinstance(probe["inputSha256"], str) and re.fullmatch(r"[a-f0-9]{64}", probe["inputSha256"]) and
             exact_keys(probe["namespaces"], ("pid", "mnt", "net")) and exact_keys(probe["limits"], ("memory.max", "memory.swap.max", "pids.max", "cpu.max")),
             "inner_probe")
        for key, expected in (("memory.max", "2147483648"), ("memory.swap.max", "0"), ("pids.max", "128"), ("cpu.max", "100000 100000")):
            need(probe["limits"][key] == expected, "inner_probe")
        for kind in ("pid", "mnt", "net"):
            need(isinstance(probe["namespaces"][kind], str) and re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", probe["namespaces"][kind]), "inner_probe")
        need(value["probeReceiptSha256"] == sha256(canonical_sorted(probe)), "inner_capacity_receipt_hash")
        return value
    need(exact_keys(value, ("schema", "nonce", "probe", "probeReceiptSha256", "unitOutputSha256", "testCount")) and
         value["schema"] == "ct200-startup-inner-v1" and isinstance(value["nonce"], str) and value["nonce"] == meta["nonce"] and
         type(value["testCount"]) is int and value["testCount"] == 15 and isinstance(value["probeReceiptSha256"], str) and
         isinstance(value["unitOutputSha256"], str) and re.fullmatch(r"[a-f0-9]{64}", value["probeReceiptSha256"]) and
         re.fullmatch(r"[a-f0-9]{64}", value["unitOutputSha256"]), "inner_receipt")
    probe = value["probe"]
    need(exact_keys(probe, ("schema", "nonce", "inputSha256", "pid", "namespaces", "limits")) and
         probe["schema"] == "lb-isolation-receipt-v1" and isinstance(probe["nonce"], str) and probe["nonce"] == meta["nonce"] and
         type(probe["pid"]) is int and probe["pid"] == 1 and isinstance(probe["inputSha256"], str) and
         re.fullmatch(r"[a-f0-9]{64}", probe["inputSha256"]) is not None, "inner_probe")
    need(exact_keys(probe["namespaces"], ("pid", "mnt", "net")) and exact_keys(probe["limits"], ("memory.max", "memory.swap.max", "pids.max", "cpu.max")), "inner_probe")
    for key, value_expected in (("memory.max", "2147483648"), ("memory.swap.max", "0"), ("pids.max", "128"), ("cpu.max", "100000 100000")):
        need(probe["limits"][key] == value_expected, "inner_probe")
    for kind in ("pid", "mnt", "net"):
        actual = probe["namespaces"][kind]
        need(isinstance(actual, str) and re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", actual), "inner_probe")
    need(value["probeReceiptSha256"] == sha256(canonical_sorted(probe)) and
         value["unitOutputSha256"] == sha256(b"checkpoint startup runtime unit controls passed\n"), "inner_receipt_hash")
    return value


def read_cgroup_value(cgroup, name):
    need(name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max"), "cgroup")
    path = os.path.join(cgroup, name)
    raw = read_small(path, 64)
    return raw.decode("ascii", "strict").strip()


def fixture_input(path, nonce):
    data = ("ct200 startup isolation proof " + nonce + "\n").encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o444)
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.fchmod(fd, 0o444)
    finally:
        os.close(fd)
    return data


def write_exact(path, data, mode=0o444):
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), mode)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            need(n > 0, "write")
            view = view[n:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_tmp_parent():
    for dirname in ("/", "/var", "/var/tmp"):
        info = os.lstat(dirname)
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0, "tmp_parent")
        if dirname == "/var/tmp":
            need((info.st_mode & 0o7777) == 0o1777, "tmp_parent")
        else:
            need(not (info.st_mode & 0o6022), "tmp_parent")


def verify_no_mounts_below(root):
    raw = read_small("/proc/self/mountinfo", 4 * 1024 * 1024).decode("utf-8", "strict")
    for line in raw.splitlines():
        fields = line.split()
        need(len(fields) >= 6, "mount_inventory")
        mount = fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
        need(mount != root and not mount.startswith(root.rstrip("/") + "/"), "scratch_mount")


def verify_owned_tree(root, device):
    count = 0
    stack = [root]
    while stack:
        base = stack.pop()
        parent = os.lstat(base)
        need(stat.S_ISDIR(parent.st_mode) and not stat.S_ISLNK(parent.st_mode) and parent.st_uid == 0 and parent.st_dev == device, "scratch_tree")
        for name in os.listdir(base):
            need(safe_relative(name), "scratch_tree")
            full = os.path.join(base, name)
            info = os.lstat(full)
            count += 1
            need(count <= 160000 and info.st_uid == 0 and info.st_dev == device and not stat.S_ISLNK(info.st_mode), "scratch_tree")
            if stat.S_ISDIR(info.st_mode):
                stack.append(full)
            else:
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "scratch_tree")


def verify_stage(root):
    for directory in ("/", "/var", "/var/tmp", STAGED_ROOT):
        info = os.lstat(directory)
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0, "tool_tree")
        if directory == STAGED_ROOT:
            need((info.st_mode & 0o7777) == 0o700, "tool_tree")
        elif directory == "/var/tmp":
            need((info.st_mode & 0o7777) == 0o1777, "tool_tree")
        else:
            need(not (info.st_mode & 0o6022), "tool_tree")
    go_dir = os.path.join(STAGED_ROOT, "go")
    node_file = os.path.join(STAGED_ROOT, "node")
    go_archive = os.path.join(STAGED_ROOT, ".go.archive")
    node_archive = os.path.join(STAGED_ROOT, ".node.archive")
    read_pin(go_archive, GO_ARCHIVE_BYTES, GO_ARCHIVE_SHA256)
    read_pin(node_archive, NODE_ARCHIVE_BYTES, NODE_ARCHIVE_SHA256)
    archive_measure = archive_go_measure(go_archive)
    actual_measure = tree_measure(go_dir)
    need(archive_measure[:3] == actual_measure[:3] and archive_measure[3:] == actual_measure[3:], "go_tree_auth")
    node_size, node_hash = sha_file(node_file, NODE_BYTES)
    need(node_size == NODE_BYTES and node_hash == NODE_SHA256, "node_pin")
    # Independently bind the staged Node binary to the sole matching archive member.
    matches = 0
    try:
        with tarfile.open(node_archive, "r:gz") as archive:
            for member in archive:
                ensure_time()
                parts = member.name.rstrip("/").split("/")
                need(parts and parts[0] == "node-v22.14.0-linux-x64", "node_archive")
                if parts == [parts[0], "bin", "node"]:
                    matches += 1
                    need(member.isreg() and member.size == NODE_BYTES, "node_archive")
                    stream = archive.extractfile(member)
                    need(stream is not None, "node_archive")
                    digest = hashlib.sha256()
                    count = 0
                    while True:
                        block = stream.read(65536)
                        if not block:
                            break
                        count += len(block)
                        need(count <= NODE_BYTES, "node_archive")
                        digest.update(block)
                    need(count == NODE_BYTES and digest.hexdigest() == NODE_SHA256, "node_archive")
    except (OSError, tarfile.TarError):
        raise Reject("node_archive") from None
    need(matches == 1, "node_archive")
    return go_dir, node_file, archive_measure[3], archive_measure[4]


def own_processes(cgroup):
    return read_pids(cgroup)


def process_cmdline(pid):
    path = "/proc/%d/cmdline" % pid
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 8192, "unit_process_identity")
        chunks = []
        total = 0
        while True:
            ensure_time()
            block = os.read(fd, 8193 - total)
            if not block:
                break
            total += len(block)
            need(total <= 8192, "unit_process_identity")
            chunks.append(block)
        after = os.fstat(fd)
        need(after.st_ino == before.st_ino and after.st_size == before.st_size, "unit_process_identity")
        return b"".join(chunks)
    finally:
        os.close(fd)


def service_process_matches(pid, start, rootfs_id, executable_id, argv_bytes):
    try:
        if proc_starttime(pid) != start:
            return False
        root = os.stat("/proc/%d/root" % pid)
        executable = os.stat("/proc/%d/exe" % pid)
        if (root.st_dev, root.st_ino) != rootfs_id or (executable.st_dev, executable.st_ino) != executable_id:
            return False
        if process_cmdline(pid) != argv_bytes or proc_starttime(pid) != start:
            return False
        return True
    except BaseException:
        return False


def confirm_gone_non_main_pid(pid, context, _ops=None):
    """Confirm a transient procfs ENOENT without weakening owned-unit identity."""
    if _ops is None:
        _ops = {
            "lstat_proc": os.lstat,
            "systemd_properties": systemd_properties,
            "cgroup_path": cgroup_path,
            "lstat_cgroup": os.lstat,
            "read_pids": read_pids,
            "proc_starttime": proc_starttime,
            "service_process_matches": service_process_matches,
        }
    if (type(_ops) is not dict or set(_ops) != {"lstat_proc", "systemd_properties", "cgroup_path", "lstat_cgroup",
                                                   "read_pids", "proc_starttime", "service_process_matches"} or
            type(context) is not dict or set(context) != {"unit", "fields", "cgroup", "cgroup_id", "main_pid", "main_start",
                                                           "rootfs_id", "executable_id", "argv_bytes"}):
        return False
    if type(pid) is not int or pid <= 0 or pid == context["main_pid"]:
        return False
    try:
        unit = context["unit"]
        expected_fields = context["fields"]
        cgroup = context["cgroup"]
        cgroup_id = context["cgroup_id"]
        main_pid = context["main_pid"]
        main_start = context["main_start"]
        if (type(expected_fields) is not dict or not exact_keys(expected_fields, ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState")) or
                type(cgroup_id) is not tuple or len(cgroup_id) != 2 or type(main_pid) is not int or
                type(main_start) is not int):
            return False
        proc_path = "/proc/%d" % pid
        for _ in range(2):
            try:
                _ops["lstat_proc"](proc_path)
            except OSError as error:
                if error.errno == errno.ENOENT:
                    continue
                return False
            return False
        first = _ops["systemd_properties"](unit)
        if first != expected_fields or not validate_active_unit(first, unit):
            return False
        if first["MainPID"] != str(main_pid) or _ops["cgroup_path"](first["ControlGroup"]) != cgroup:
            return False
        before = _ops["lstat_cgroup"](cgroup)
        if (not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_uid != 0 or
                (before.st_dev, before.st_ino) != cgroup_id):
            return False
        fresh_pids = _ops["read_pids"](cgroup)
        after = _ops["lstat_cgroup"](cgroup)
        if (type(fresh_pids) not in (set, frozenset) or len(fresh_pids) > 128 or
                any(type(item) is not int or item <= 0 for item in fresh_pids) or
                pid in fresh_pids or main_pid not in fresh_pids or
                not stat.S_ISDIR(after.st_mode) or stat.S_ISLNK(after.st_mode) or after.st_uid != 0 or
                (after.st_dev, after.st_ino) != cgroup_id):
            return False
        second = _ops["systemd_properties"](unit)
        if second != expected_fields or not validate_active_unit(second, unit):
            return False
        if (_ops["proc_starttime"](main_pid) != main_start or
                not _ops["service_process_matches"](main_pid, main_start, context["rootfs_id"],
                                                     context["executable_id"], context["argv_bytes"])):
            return False
        return True
    except BaseException:
        return False


def track_unit_pid(pid, main_pid, target, context, seen=None, _start=None, _confirm=None):
    start_reader = proc_starttime if _start is None else _start
    confirm = confirm_gone_non_main_pid if _confirm is None else _confirm
    try:
        start = start_reader(pid)
    except Reject as error:
        if type(error) is Reject and error.args == ("unit_pid_gone",) and pid != main_pid and confirm(pid, context):
            # This skips only the current observation; it neither acquires nor signals the PID,
            # and makes no claim that the numeric PID had no unobserved intermediate incarnation.
            return False
        raise
    record_unit_pid(pid, start, target, seen)
    return True


def record_unit_pid(pid, start, target, seen=None):
    need(type(start) is int, "unit_pid_identity")
    prior_target = target.get(pid)
    need(prior_target is None or prior_target == start, "unit_pid_reused")
    if seen is not None:
        prior = seen.get(pid)
        need(prior is None or prior == start, "unit_pid_reused")
        seen[pid] = start
    target[pid] = start
    return True


def main_pid_exit_candidate(main_pid, _lstat=None):
    lstat_proc = os.lstat if _lstat is None else _lstat
    if type(main_pid) is not int or not 0 < main_pid < 4194304 or not callable(lstat_proc):
        return False
    for _ in range(2):
        try:
            lstat_proc("/proc/%d" % main_pid)
            return False
        except OSError as error:
            if error.errno != errno.ENOENT:
                return False
    return True


def validate_main_exit_fields(fields, context):
    required = ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState")
    need(type(context) is dict and set(context) == {"unit", "cgroup", "cgroup_id", "invocation", "main_pid", "main_start"} and
         type(context["unit"]) is str and re.fullmatch(r"ct200-startup-[a-f0-9]{32}\.service", context["unit"]) is not None and
         type(context["cgroup"]) is str and
         type(context["cgroup_id"]) is tuple and len(context["cgroup_id"]) == 2 and
         type(context["invocation"]) is str and re.fullmatch(r"[a-f0-9]{32}", context["invocation"]) is not None and
         type(context["main_pid"]) is int and 0 < context["main_pid"] < 4194304 and
         type(context["main_start"]) is int and context["main_start"] > 0,
         "unit_pid_gone")
    need(type(fields) is dict and exact_keys(fields, required) and
         all(isinstance(fields[key], str) for key in required) and
         fields["LoadState"] == "loaded" and fields["ControlGroup"] == "/system.slice/" + context["unit"] and
         context["cgroup"] == "/sys/fs/cgroup" + fields["ControlGroup"] and
         fields["MainPID"] == "0" and fields["InvocationID"] == context["invocation"] and
         fields["ActiveState"] in ("deactivating", "inactive"), "unit_pid_gone")
    return True


def observe_main_exit_phase(fields, context, _ops=None):
    if _ops is None:
        _ops = {"owned_unit_settled": owned_unit_settled, "lstat_proc": os.lstat,
                "systemd_properties": systemd_properties, "cgroup_path": cgroup_path,
                "lstat_cgroup": os.lstat, "read_cgroup_value": read_cgroup_value, "read_pids": read_pids}
    required_ops = {"owned_unit_settled", "lstat_proc", "systemd_properties", "cgroup_path",
                    "lstat_cgroup", "read_cgroup_value", "read_pids"}
    need(type(_ops) is dict and set(_ops) == required_ops and all(callable(item) for item in _ops.values()) and
         type(context) is dict and set(context) == {"unit", "cgroup", "cgroup_id", "invocation", "main_pid", "main_start"},
         "unit_pid_gone")
    unit = context["unit"]
    if type(fields) is dict and fields.get("LoadState") == "not-found":
        validate_unit_absent(fields, unit)
        need(_ops["owned_unit_settled"](fields, unit), "unit_pid_gone")
        return None, frozenset()
    validate_main_exit_fields(fields, context)
    main_path = "/proc/%d" % context["main_pid"]
    for _ in range(2):
        try:
            _ops["lstat_proc"](main_path)
        except OSError as error:
            if error.errno == errno.ENOENT:
                continue
            raise Reject("unit_pid") from None
        raise Reject("unit_pid_gone")
    need(_ops["cgroup_path"](fields["ControlGroup"]) == context["cgroup"], "cgroup_identity")
    before = _ops["lstat_cgroup"](context["cgroup"])
    need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode) and before.st_uid == 0 and
         (before.st_dev, before.st_ino) == context["cgroup_id"], "cgroup_identity")
    expected_limits = {"memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "100000 100000"}
    for name, value in expected_limits.items():
        need(_ops["read_cgroup_value"](context["cgroup"], name) == value, "cgroup_limit")
    pids = _ops["read_pids"](context["cgroup"])
    need(type(pids) in (set, frozenset) and len(pids) <= 128 and
         all(type(pid) is int and 0 < pid < 4194304 for pid in pids) and context["main_pid"] not in pids,
         "cgroup_processes")
    after = _ops["lstat_cgroup"](context["cgroup"])
    need(stat.S_ISDIR(after.st_mode) and not stat.S_ISLNK(after.st_mode) and after.st_uid == 0 and
         (after.st_dev, after.st_ino) == context["cgroup_id"] == (before.st_dev, before.st_ino), "cgroup_identity")
    need(_ops["systemd_properties"](unit) == fields, "unit_identity_changed")
    return dict(fields), frozenset(pids)


def confirm_gone_non_main_after_main_exit(pid, context, known, _ops=None):
    if _ops is None:
        _ops = {"lstat_proc": os.lstat, "systemd_properties": systemd_properties,
                "cgroup_path": cgroup_path, "lstat_cgroup": os.lstat, "read_pids": read_pids}
    required_ops = {"lstat_proc", "systemd_properties", "cgroup_path", "lstat_cgroup", "read_pids"}
    if (type(_ops) is not dict or set(_ops) != required_ops or not all(callable(item) for item in _ops.values()) or
            type(context) is not dict or set(context) != {"unit", "fields", "cgroup", "cgroup_id", "invocation", "main_pid", "main_start", "accounted_pids"} or
            type(known) is not dict or type(pid) is not int or pid <= 0 or pid == context["main_pid"] or
            type(known.get(pid)) is not int or type(context["accounted_pids"]) not in (set, frozenset)):
        return False
    try:
        validate_main_exit_fields(context["fields"], {key: context[key] for key in ("unit", "cgroup", "cgroup_id", "invocation", "main_pid", "main_start")})
        for observed_pid in (pid, context["main_pid"]):
            for _ in range(2):
                try:
                    _ops["lstat_proc"]("/proc/%d" % observed_pid)
                    return False
                except OSError as error:
                    if error.errno != errno.ENOENT:
                        return False
        if _ops["systemd_properties"](context["unit"]) != context["fields"]:
            return False
        if _ops["cgroup_path"](context["fields"]["ControlGroup"]) != context["cgroup"]:
            return False
        before = _ops["lstat_cgroup"](context["cgroup"])
        if (not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_uid != 0 or
                (before.st_dev, before.st_ino) != context["cgroup_id"]):
            return False
        fresh = _ops["read_pids"](context["cgroup"])
        if (type(fresh) not in (set, frozenset) or len(fresh) > 128 or
                any(type(item) is not int or item <= 0 for item in fresh) or
                pid in fresh or context["main_pid"] in fresh or fresh != context["accounted_pids"] or
                not fresh.issubset(set(known))):
            return False
        after = _ops["lstat_cgroup"](context["cgroup"])
        if (not stat.S_ISDIR(after.st_mode) or stat.S_ISLNK(after.st_mode) or after.st_uid != 0 or
                (after.st_dev, after.st_ino) != context["cgroup_id"]):
            return False
        return _ops["systemd_properties"](context["unit"]) == context["fields"]
    except BaseException:
        return False


def account_main_exit_members(phase, context, known, seen, deferred_gone, _start=None, _confirm=None):
    start_reader = proc_starttime if _start is None else _start
    confirm = confirm_gone_non_main_after_main_exit if _confirm is None else _confirm
    need(type(phase) is tuple and len(phase) == 2 and type(deferred_gone) is set and
         type(known) is dict and type(seen) is dict and callable(start_reader) and callable(confirm), "unit_pid_gone")
    exit_fields, exit_pids = phase
    if exit_fields is None:
        need(phase == (None, frozenset()), "unit_pid_gone")
        return True
    need(type(exit_fields) is dict and type(exit_pids) is frozenset, "unit_pid_gone")
    member_context = {"unit": context["unit"], "fields": dict(exit_fields), "cgroup": context["cgroup"],
                      "cgroup_id": context["cgroup_id"], "invocation": context["invocation"],
                      "main_pid": context["main_pid"], "main_start": context["main_start"]}
    missing_members = sorted(deferred_gone)
    accounted_members = set()
    for pid in sorted(exit_pids):
        need(pid != context["main_pid"], "cgroup_processes")
        try:
            member_start = start_reader(pid)
        except Reject as error:
            if type(error) is not Reject or error.args != ("unit_pid_gone",) or pid not in known:
                raise
            if pid not in missing_members:
                missing_members.append(pid)
        else:
            record_unit_pid(pid, member_start, known, seen)
            accounted_members.add(pid)
    member_context["accounted_pids"] = frozenset(accounted_members)
    for pid in missing_members:
        need(confirm(pid, member_context, known), "unit_pid_gone")
    return True


def track_active_unit_members(ordered_pids, context, known, seen, deferred_gone, _track=None,
                              _start=None, _candidate=None):
    track = track_unit_pid if _track is None else _track
    start_reader = proc_starttime if _start is None else _start
    candidate = main_pid_exit_candidate if _candidate is None else _candidate
    need(type(ordered_pids) is list and type(context) is dict and type(known) is dict and type(seen) is dict and
         type(deferred_gone) is set and callable(track) and callable(start_reader) and callable(candidate), "unit_pid_gone")
    main_pid = context["main_pid"]
    for index, pid in enumerate(ordered_pids):
        try:
            track(pid, main_pid, known, context, seen)
        except Reject as error:
            main_candidate = (type(error) is Reject and error.args == ("unit_pid_gone",) and candidate(main_pid))
            if not main_candidate or (pid != main_pid and pid not in known):
                raise
            # ENOENT remains only a candidate; all suffix PIDs are accounted or deferred
            # for the exact later terminal-phase disappearance proof.
            if pid != main_pid:
                deferred_gone.add(pid)
            for pending_pid in ordered_pids[index + 1:]:
                try:
                    pending_start = start_reader(pending_pid)
                except Reject as pending_error:
                    if (type(pending_error) is not Reject or pending_error.args != ("unit_pid_gone",) or
                            pending_pid not in known):
                        raise
                    deferred_gone.add(pending_pid)
                else:
                    record_unit_pid(pending_pid, pending_start, known, seen)
            return True
    return False


def service_monitor_poll_step(child_running, pending, phase_proven, owned_started, now, next_check,
                              unit, context, known, seen, deferred_gone, _read=None, _observe=None,
                              _start=None, _confirm=None):
    read_properties = systemd_properties if _read is None else _read
    observe_phase = observe_main_exit_phase if _observe is None else _observe
    need(type(child_running) is bool and type(pending) is bool and type(phase_proven) is bool and
         type(owned_started) is bool and type(now) in (int, float) and type(next_check) in (int, float) and
         type(unit) is str and type(context) is dict and type(seen) is dict and
         type(deferred_gone) is set and callable(read_properties) and callable(observe_phase), "service_result")
    context_keys = {"unit", "cgroup", "cgroup_id", "invocation", "main_pid", "main_start"}
    if not owned_started:
        need(not pending and not phase_proven and type(known) is set and not known and not seen and
             not deferred_gone and set(context) == context_keys and context["unit"] == unit and
             all(context[key] is None for key in ("cgroup", "cgroup_id", "invocation", "main_pid", "main_start")),
             "service_result")
    else:
        need(type(known) is dict and set(context) == context_keys and context["unit"] == unit and
             re.fullmatch(r"ct200-startup-[a-f0-9]{32}\.service", unit) is not None and
             context["cgroup"] == "/sys/fs/cgroup/system.slice/" + unit and
             type(context["cgroup_id"]) is tuple and len(context["cgroup_id"]) == 2 and
             all(type(value) is int for value in context["cgroup_id"]) and
             type(context["invocation"]) is str and re.fullmatch(r"[a-f0-9]{32}", context["invocation"]) is not None and
             type(context["main_pid"]) is int and 0 < context["main_pid"] < 4194304 and
             type(context["main_start"]) is int and context["main_start"] > 0 and
             known.get(context["main_pid"]) == context["main_start"] and
             all(type(pid) is int and known.get(pid) == start for pid, start in seen.items()), "service_result")
    if not ((child_running or (pending and not phase_proven)) and now >= next_check):
        return False, None, False, pending, phase_proven, next_check
    props = read_properties(unit)
    if not owned_started:
        # Pre-capture observations can only continue activation; they cannot prove a terminal phase.
        return True, props, False, False, False, now + 0.25
    pending_now = pending or (owned_started and
                              (props.get("LoadState") == "not-found" or props.get("MainPID") == "0"))
    if not pending_now:
        return True, props, False, pending_now, phase_proven, now + 0.25
    phase = observe_phase(props, context)
    if props.get("LoadState") == "not-found":
        need(phase == (None, frozenset()), "unit_pid_gone")
    else:
        need(type(phase) is tuple and len(phase) == 2 and type(phase[0]) is dict and
             phase[0] == props and type(phase[1]) is frozenset, "unit_pid_gone")
    account_main_exit_members(phase, context, known, seen, deferred_gone, _start, _confirm)
    return True, props, True, pending_now, True, now + 0.25


def capture_owned_unit(unit, fields, pids, rootfs, service_argv):
    global OWNED_UNIT_STARTED, SERVICE_CGROUP, SERVICE_CGROUP_PATH, SERVICE_CGROUP_ID, SERVICE_PIDS, SERVICE_INVOCATION
    global SERVICE_MAIN_PID, SERVICE_MAIN_START, SERVICE_ROOTFS_ID, SERVICE_EXEC_ID, SERVICE_ARGV_BYTES
    validate_active_unit(fields, unit)
    cgroup = cgroup_path(fields["ControlGroup"])
    info = os.lstat(cgroup)
    need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0, "unit_cgroup_custody")
    main_pid = int(fields["MainPID"])
    need(main_pid in pids, "unit_main_membership")
    main_start = proc_starttime(main_pid)
    need(type(main_start) is int, "unit_main_identity")
    root_info = os.lstat(rootfs)
    exec_path = os.path.join(rootfs, "tools", "unshare")
    executable_info = os.lstat(exec_path)
    root_id = (root_info.st_dev, root_info.st_ino)
    executable_id = (executable_info.st_dev, executable_info.st_ino)
    argv_bytes = b"\x00".join(item.encode("utf-8") for item in service_argv) + b"\x00"
    need(stat.S_ISDIR(root_info.st_mode) and not stat.S_ISLNK(root_info.st_mode) and root_info.st_uid == 0 and stat.S_IMODE(root_info.st_mode) == 0o755 and
         stat.S_ISREG(executable_info.st_mode) and not stat.S_ISLNK(executable_info.st_mode) and executable_info.st_uid == 0 and executable_info.st_nlink == 1 and stat.S_IMODE(executable_info.st_mode) == 0o755 and
         service_process_matches(main_pid, main_start, root_id, executable_id, argv_bytes), "unit_process_identity")
    SERVICE_NAME = unit
    SERVICE_CGROUP = fields["ControlGroup"]
    SERVICE_CGROUP_PATH = cgroup
    SERVICE_CGROUP_ID = (info.st_dev, info.st_ino)
    SERVICE_INVOCATION = fields["InvocationID"]
    SERVICE_MAIN_PID = main_pid
    SERVICE_MAIN_START = main_start
    SERVICE_ROOTFS_ID = root_id
    SERVICE_EXEC_ID = executable_id
    SERVICE_ARGV_BYTES = argv_bytes
    SERVICE_PIDS = {}
    provisional_context = {"unit": unit, "fields": dict(fields), "cgroup": cgroup, "cgroup_id": SERVICE_CGROUP_ID,
                           "main_pid": main_pid, "main_start": main_start, "rootfs_id": root_id,
                           "executable_id": executable_id, "argv_bytes": argv_bytes}
    for pid in pids:
        track_unit_pid(pid, main_pid, SERVICE_PIDS, provisional_context)
    OWNED_UNIT_STARTED = True
    return cgroup, info


def same_owned_unit(fields, unit, path_exists=None, processes_gone=None, process_matches=None):
    required = ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState")
    if (not OWNED_UNIT_STARTED or unit != SERVICE_NAME or re.fullmatch(r"ct200-startup-[a-f0-9]{32}\.service", unit) is None or
            not exact_keys(fields, required) or any(not isinstance(fields[key], str) for key in required)):
        return False
    if fields.get("LoadState") == "not-found":
        exists = os.path.exists if path_exists is None else path_exists
        gone = owned_processes_gone if processes_gone is None else processes_gone
        if not isinstance(SERVICE_CGROUP_PATH, str):
            return False
        try:
            path_present = exists(SERVICE_CGROUP_PATH)
            processes_gone_value = gone()
        except BaseException:
            return False
        return (type(path_present) is bool and path_present is False and type(processes_gone_value) is bool and processes_gone_value is True and
                fields.get("ControlGroup") == "" and fields.get("MainPID") == "0" and fields.get("InvocationID") == "")
    if fields.get("LoadState") != "loaded" or fields.get("ControlGroup") != SERVICE_CGROUP or fields.get("InvocationID") != SERVICE_INVOCATION:
        return False
    try:
        cgroup = cgroup_path(fields["ControlGroup"])
        info = os.lstat(cgroup)
        if (info.st_dev, info.st_ino) != SERVICE_CGROUP_ID:
            return False
        pid = int(fields["MainPID"])
        if pid == 0:
            return True
        matches = service_process_matches if process_matches is None else process_matches
        return pid == SERVICE_MAIN_PID and matches(pid, SERVICE_MAIN_START, SERVICE_ROOTFS_ID, SERVICE_EXEC_ID, SERVICE_ARGV_BYTES)
    except BaseException:
        return False


def owned_unit_settled(fields, unit, cgroup_empty=False, processes_gone=None, path_exists=None):
    if not same_owned_unit(fields, unit, path_exists=path_exists, processes_gone=processes_gone):
        return False
    if fields.get("LoadState") == "not-found":
        return True
    gone = owned_processes_gone() if processes_gone is None else processes_gone()
    return fields.get("MainPID") == "0" and cgroup_empty is True and type(gone) is bool and gone is True


def same_tree_snapshot(actual, expected):
    return isinstance(actual, tuple) and isinstance(expected, tuple) and len(actual) == len(expected) == 5 and actual == expected


def cleanup_outside_fixture(lstat_fn=None, listdir_fn=None, read_fn=None, unlink_fn=None, rmdir_fn=None, exists_fn=None):
    global OUTSIDE_SETTLED
    OUTSIDE_SETTLED = False
    lstat_fn = os.lstat if lstat_fn is None else lstat_fn
    listdir_fn = os.listdir if listdir_fn is None else listdir_fn
    read_fn = read_small if read_fn is None else read_fn
    unlink_fn = os.unlink if unlink_fn is None else unlink_fn
    rmdir_fn = os.rmdir if rmdir_fn is None else rmdir_fn
    exists_fn = os.path.lexists if exists_fn is None else exists_fn
    if OUTSIDE_ROOT is None:
        OUTSIDE_SETTLED = True
        return True
    try:
        root_info = lstat_fn(OUTSIDE_ROOT)
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode) or (root_info.st_dev, root_info.st_ino) != OUTSIDE_ID or root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700:
            return False
        names = sorted(listdir_fn(OUTSIDE_ROOT))
        if OUTSIDE_FILE_ID is None:
            if names:
                return False
        else:
            if names != ["outside-control.txt"] or OUTSIDE_FILE is None or OUTSIDE_DATA is None:
                return False
            file_info = lstat_fn(OUTSIDE_FILE)
            metadata = tuple(getattr(file_info, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"))
            if (file_info.st_dev, file_info.st_ino) != OUTSIDE_FILE_ID or metadata != OUTSIDE_FILE_META or not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != 0 or file_info.st_nlink != 1:
                return False
            if read_fn(OUTSIDE_FILE, 4096) != OUTSIDE_DATA:
                return False
            unlink_fn(OUTSIDE_FILE)
        if listdir_fn(OUTSIDE_ROOT):
            return False
        rmdir_fn(OUTSIDE_ROOT)
        if exists_fn(OUTSIDE_ROOT):
            return False
        OUTSIDE_SETTLED = True
        return True
    except BaseException:
        return False


def cleanup_remaining(deadline, now=None):
    current = time.monotonic() if now is None else now
    need(type(deadline) in (int, float) and type(current) in (int, float), "cleanup_deadline")
    return max(0.0, deadline - current)


def validate_private_rootfs(rootfs, expected_identity, lstat_fn=None):
    lstat_fn = os.lstat if lstat_fn is None else lstat_fn
    need(type(expected_identity) is tuple and len(expected_identity) == 2 and
         all(type(value) is int and value >= 0 for value in expected_identity), "rootfs_custody")
    current = lstat_fn(rootfs)
    need(stat.S_ISDIR(current.st_mode) and not stat.S_ISLNK(current.st_mode) and current.st_uid == 0 and
         stat.S_IMODE(current.st_mode) == 0o755 and (current.st_dev, current.st_ino) == expected_identity,
         "rootfs_custody")
    run_path = os.path.join(rootfs, "run")
    try:
        run_info = lstat_fn(run_path)
    except FileNotFoundError as error:
        need(error.errno == errno.ENOENT, "rootfs_custody")
    else:
        need(stat.S_ISDIR(run_info.st_mode) and not stat.S_ISLNK(run_info.st_mode) and run_info.st_uid == 0 and
             not (run_info.st_mode & 0o022), "rootfs_custody")
    for relative in ("root", "home", "run/user"):
        path = os.path.join(rootfs, *relative.split("/"))
        try:
            lstat_fn(path)
        except FileNotFoundError as error:
            need(error.errno == errno.ENOENT, "rootfs_custody")
        else:
            raise Reject("rootfs_custody")
    return True


def fixed_service_properties(rootfs, unit, mode="startup"):
    need(mode in ("startup", "capacity"), "systemd_properties")
    runtime_seconds = 360 if mode == "capacity" else 180
    limit_binds = ["/sys/fs/cgroup/system.slice/" + unit + "/" + name + ":/.limits/" + name
                   for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max")]
    return [
        "Type=exec", "Restart=no", "RootDirectory=" + rootfs, "WorkingDirectory=/work",
        "PrivateMounts=yes", "PrivateNetwork=yes", "PrivateDevices=yes", "MountAPIVFS=no",
        "ProtectSystem=strict", "NoNewPrivileges=yes",
        "UnsetEnvironment=NODE_OPTIONS NODE_PATH NODE_V8_COVERAGE LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PYTHONHOME BASH_ENV ENV PERL5OPT RUBYOPT JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS",
        "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_SETPCAP",
        "MemoryMax=2147483648", "MemorySwapMax=0", "TasksMax=128", "CPUQuota=100%", "CPUQuotaPeriodSec=100ms",
        "RuntimeMaxSec=" + str(runtime_seconds), "TimeoutStopSec=5", "KillMode=control-group", "LimitNOFILE=4096",
        "TemporaryFileSystem=/work:rw,size=1G,mode=0700,uid=65534,gid=65534",
    ] + ["BindReadOnlyPaths=" + item for item in limit_binds]


def validate_fixed_service_properties(properties, rootfs, unit, mode="startup"):
    need(type(properties) is list and properties == fixed_service_properties(rootfs, unit, mode), "systemd_properties")
    return True


def run_isolated(root, requirements, probe_bytes, meta):
    global SERVICE_NAME, SERVICE_LAUNCH_ATTEMPTED, OWNED_UNIT_STARTED, ACTIVE_LISTENER, SERVICE_SETTLED
    global OUTSIDE_ROOT, OUTSIDE_ID, OUTSIDE_FILE, OUTSIDE_FILE_ID, OUTSIDE_DATA, OUTSIDE_FILE_META, OUTSIDE_SETTLED
    mode = "capacity" if meta.get("mode") == "capacity" and meta.get("schema") == CAPACITY_SCHEMA else "startup"
    nonce = meta["nonce"]
    rootfs = os.path.join(root, "rootfs")
    os.mkdir(rootfs, 0o755)
    os.chmod(rootfs, 0o755)
    rootfs_created = os.lstat(rootfs)
    rootfs_identity = (rootfs_created.st_dev, rootfs_created.st_ino)
    validate_private_rootfs(rootfs, rootfs_identity)
    material = os.path.join(root, "material")
    source = os.path.join(material, "source")
    source_rows = [{"path": item["path"][len("source/"):], "bytes": item["bytes"], "sha256": item["sha256"]}
                   for item in meta["files"] if item["path"].startswith("source/")]
    current_requirements, current_sums = validate_source_tree(material, source_rows, mode)
    need(current_requirements == requirements, "source_changed")
    verify_module_cache(material, current_requirements, current_sums)
    go_dir, node_file, go_modes, go_hashes = verify_stage(root)
    count, size, tree_hash, source_modes, source_hashes = tree_measure(source)
    need(count > 1 and size <= SOURCE_BYTES_MAX, "source_snapshot")
    deps_root = os.path.join(material, "deps")
    deps_count, deps_size, deps_hash, deps_modes, deps_hashes = tree_measure(deps_root)
    go_measure = tree_measure(go_dir)
    node_size, _node_hash = sha_file(node_file, NODE_BYTES)
    free = os.statvfs("/var/tmp").f_bavail * os.statvfs("/var/tmp").f_frsize
    need(free >= 2 * 1024 * 1024 * 1024 + size + deps_size + go_measure[1] + node_size, "disk_reserve")
    manifest_source_hashes = {row["path"]: row["sha256"] for row in source_rows}
    need({name: value for name, value in source_hashes.items() if value is not None} == manifest_source_hashes, "source_manifest_tree")
    copy_tree(source, os.path.join(rootfs, "source"), source_modes, manifest_source_hashes)
    copied_source_initial = tree_measure(os.path.join(rootfs, "source"))
    need(copied_source_initial[:3] == (count, size, tree_hash) and copied_source_initial[3:] == (source_modes, source_hashes), "source_copy_changed")
    validate_source_tree(rootfs, source_rows, mode)
    os.mkdir(os.path.join(rootfs, "tools"), 0o755)
    copy_tree(go_dir, os.path.join(rootfs, "tools", "go"), go_modes, go_hashes)
    copy_file(node_file, os.path.join(rootfs, "tools", "node", "bin", "node"), NODE_SHA256, NODE_BYTES, 0o755)
    # The runtime inventory pins these host launchers; validate bytes before any service unit is created.
    launchers = {
        "/usr/bin/unshare": (43624, "a23c8863860669003dc4660039fe642f5795c8c2195898ebc5d01afa1ac3d11c"),
        "/usr/bin/setpriv": (39304, "62ec0120791f3afcfb689fed52384ec2b0accc6e118a6b9a1d6fcfa7450aaf37"),
    }
    for path, (n, digest) in launchers.items():
        read_pin(path, n, digest)
    copy_file("/usr/bin/unshare", os.path.join(rootfs, "tools", "unshare"), launchers["/usr/bin/unshare"][1], launchers["/usr/bin/unshare"][0], 0o755)
    copy_file("/usr/bin/setpriv", os.path.join(rootfs, "tools", "setpriv"), launchers["/usr/bin/setpriv"][1], launchers["/usr/bin/setpriv"][0], 0o755)
    binaries = [os.path.join(rootfs, "tools", "unshare"), os.path.join(rootfs, "tools", "setpriv"),
                os.path.join(rootfs, "tools", "node", "bin", "node"), os.path.join(rootfs, "tools", "go", "bin", "go")]
    copy_elf_closure(rootfs, binaries)
    os.mkdir(os.path.join(rootfs, "work"), 0o755)
    for name in ("proc", "dev", "tmp"):
        os.mkdir(os.path.join(rootfs, name), 0o755)
    for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max"):
        write_exact(os.path.join(rootfs, ".limits", name), b"pending\n")
    proof = fixture_input(os.path.join(root, "proof-input.txt"), nonce)
    outside = os.path.join("/var/tmp", "lb-test-run-" + nonce)
    os.mkdir(outside, 0o700)
    outside_st = os.lstat(outside)
    outside_id = (outside_st.st_dev, outside_st.st_ino)
    outside_data = ("outside-control " + nonce + "\n").encode("ascii")
    outside_file = os.path.join(outside, "outside-control.txt")
    OUTSIDE_ROOT, OUTSIDE_ID, OUTSIDE_DATA, OUTSIDE_FILE, OUTSIDE_SETTLED = outside, outside_id, outside_data, outside_file, False
    write_exact(outside_file, outside_data, 0o600)
    outside_file_before = os.lstat(outside_file)
    OUTSIDE_FILE_ID = (outside_file_before.st_dev, outside_file_before.st_ino)
    OUTSIDE_FILE_META = tuple(getattr(outside_file_before, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(2)
    ACTIVE_LISTENER = listener
    port = listener.getsockname()[1]
    def prove_host_endpoint():
        try:
            client = socket.create_connection(("127.0.0.1", port), timeout=1)
            peer, _address = listener.accept()
            peer.settimeout(1)
            peer.sendall((nonce + "\n").encode("ascii"))
            response = client.recv(64)
            peer.close()
            client.close()
            need(response == (nonce + "\n").encode("ascii"), "outside_network_fixture")
        except (OSError, socket.timeout):
            raise Reject("outside_network_fixture") from None
    prove_host_endpoint()
    config = {
        "schema": "lb-isolation-config-v1", "nonce": nonce, "outsideRoot": outside,
        "outsidePort": port, "outsideNamespaces": {name: os.readlink("/proc/self/ns/" + name) for name in ("pid", "mnt", "net")},
        "inputSha256": sha256(proof),
    }
    write_exact(os.path.join(rootfs, "probe-config.json"), canonical(config))
    write_exact(os.path.join(rootfs, "proof-input.txt"), proof)
    write_exact(os.path.join(rootfs, "source", "scripts", "ct200-verification", ".probe.mjs"), probe_bytes)
    module_manifest = {
        "schema": "ct200-module-copy-v1",
        "files": [{"path": item["path"][len("modules/"):], "bytes": item["bytes"], "sha256": item["sha256"]}
                  for item in meta["files"] if item["path"].startswith("modules/")],
    }
    write_exact(os.path.join(rootfs, "module-manifest.json"), canonical(module_manifest))
    wrapper = b"""import fs from 'node:fs';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
const digest = b => crypto.createHash('sha256').update(b).digest('hex');
const canonical = v => Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const nonce = fs.readFileSync('/run-nonce','ascii').trim();
function safePathText(value){return typeof value==='string'&&!value.includes('\\\\')&&!/[\\r\\n\\0]/.test(value);}
for (const key of Object.keys(process.env)) delete process.env[key];
Object.assign(process.env,{PATH:'/tools/go/bin:/usr/bin:/bin',GOENV:'off',GOTOOLCHAIN:'local',GOPROXY:'off',GOSUMDB:'off',GOWORK:'off',GOFLAGS:'-mod=readonly',CGO_ENABLED:'0',GOMAXPROCS:'1',GOCACHE:'/work/gocache',GOMODCACHE:'/work/modcache',GOTMPDIR:'/work/tmp',TMPDIR:'/work/tmp',HOME:'/work/home',LANG:'C'});
const probeModule = await import(pathToFileURL('/source/scripts/ct200-verification/.probe.mjs').href);
const probe = await probeModule.probe().catch(reportProbeFailure);
function reportProbeFailure(error){try{if(error instanceof Error){let marker=null;if(error.code==='ENOENT'&&error.syscall==='open'&&error.path==='/probe-config.json')marker='CT200_PROBE_DIAGNOSTIC probe_config_missing\\n';else if(error.message==='isolation verification rejected'&&error.code===undefined&&error.syscall===undefined)marker='CT200_PROBE_DIAGNOSTIC probe_guard_error\\n';else if(['EACCES','EADDRNOTAVAIL','EBADF','ECONNABORTED','ECONNREFUSED','ECONNRESET','EEXIST','EHOSTUNREACH','EINVAL','EIO','EISDIR','ELOOP','EMFILE','ENFILE','ENETUNREACH','ENOENT','ENOMEM','ENOSPC','ENOTDIR','ENOTEMPTY','EPERM','EROFS','ETIMEDOUT','EAFNOSUPPORT'].includes(error.code)&&['open','read','fstat','lstat','readlink','scandir','readdir','close','write','fsync','unlink','connect'].includes(error.syscall))marker='CT200_PROBE_DIAGNOSTIC probe_native_error\\n';if(marker!==null){try{fs.writeSync(2,marker,null,'ascii');}catch{}}}}catch{}throw error;}
for(const dir of ['/work/gocache','/work/tmp','/work/home','/work/modcache'])fs.mkdirSync(dir,{recursive:true,mode:0o700});
function copyAuthenticatedCache(){
  const manifestStat=fs.lstatSync('/module-manifest.json');
  if(!manifestStat.isFile()||manifestStat.isSymbolicLink()||manifestStat.nlink!==1||manifestStat.uid!==0||manifestStat.size>8*1024*1024||(manifestStat.mode&0o022)!==0)throw new Error('cache manifest custody');
  const manifest=JSON.parse(fs.readFileSync('/module-manifest.json','utf8'));
  if(!manifest||manifest.schema!=='ct200-module-copy-v1'||Object.keys(manifest).sort().join(',')!=='files,schema'||!Array.isArray(manifest.files)||manifest.files.length<4||manifest.files.length>30000)throw new Error('cache manifest shape');
  const expected=new Map();let previous='';let totalExpected=0;
  for(const item of manifest.files){
    if(!item||Object.keys(item).sort().join(',')!=='bytes,path,sha256'||typeof item.path!=='string'||item.path<=previous||!safePathText(item.path)||item.path.split('/').some(p=>!p||p==='.'||p==='..')||!Number.isSafeInteger(item.bytes)||item.bytes<0||!/^[a-f0-9]{64}$/.test(item.sha256))throw new Error('cache manifest entry');
    previous=item.path;totalExpected+=item.bytes;if(totalExpected>201326592)throw new Error('cache bytes bound');expected.set(item.path,item);
  }
  const allowedDirs=new Set();for(const name of expected.keys()){let part='';const comps=name.split('/');for(let i=0;i<comps.length-1;i++){part=part?part+'/'+comps[i]:comps[i];allowedDirs.add(part);}}
  const source='/source/.authenticated-deps/cache/download',destination='/work/modcache/cache/download';
  fs.mkdirSync(destination,{recursive:true,mode:0o700});let actual=0,total=0;
  function walk(src,dst,prefix){
    const rootStat=fs.lstatSync(src);if(!rootStat.isDirectory()||rootStat.isSymbolicLink()||rootStat.uid!==0||(rootStat.mode&0o022)!==0)throw new Error('cache directory custody');
    for(const name of fs.readdirSync(src).sort()){
      if(!name||name==='.'||name==='..'||name.includes('/')||!safePathText(name))throw new Error('cache name');
      const sourcePath=src+'/'+name,destPath=dst+'/'+name,relative=prefix?prefix+'/'+name:name,st=fs.lstatSync(sourcePath);
      if(st.isDirectory()&&!st.isSymbolicLink()){
        if(!allowedDirs.has(relative))throw new Error('unexpected cache directory');
        fs.mkdirSync(destPath,{mode:0o700});walk(sourcePath,destPath,relative);continue;
      }
      const item=expected.get(relative);if(!item||!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.uid!==0||(st.mode&0o022)!==0||st.size!==item.bytes)throw new Error('cache file custody');
      const rfd=fs.openSync(sourcePath,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW),wfd=fs.openSync(destPath,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600),hash=crypto.createHash('sha256');
      try{const opened=fs.fstatSync(rfd);if(opened.dev!==st.dev||opened.ino!==st.ino||opened.size!==st.size||opened.nlink!==1)throw new Error('cache open custody');const b=Buffer.alloc(65536);let read=0;for(;;){const n=fs.readSync(rfd,b,0,b.length,null);if(!n)break;read+=n;total+=n;if(read>item.bytes||total>201326592)throw new Error('cache expansion bound');const chunk=b.subarray(0,n);hash.update(chunk);let off=0;while(off<n)off+=fs.writeSync(wfd,chunk,off,n-off);}const after=fs.fstatSync(rfd),named=fs.lstatSync(sourcePath);if(read!==item.bytes||hash.digest('hex')!==item.sha256||after.dev!==opened.dev||after.ino!==opened.ino||after.size!==opened.size||after.mtimeMs!==opened.mtimeMs||named.dev!==opened.dev||named.ino!==opened.ino||named.size!==opened.size||named.mtimeMs!==opened.mtimeMs)throw new Error('cache payload authentication');fs.fchmodSync(wfd,0o600);fs.fsyncSync(wfd);}finally{fs.closeSync(rfd);fs.closeSync(wfd);}expected.delete(relative);actual++;
      if(actual>30000)throw new Error('cache file count');
    }
  }
  walk(source,destination,'');if(expected.size!==0||total!==totalExpected)throw new Error('cache inventory mismatch');
}
copyAuthenticatedCache();
const marker = 'checkpoint startup runtime unit controls passed\\n';
const emitted=[]; let outputBytes=0; const original=process.stdout.write.bind(process.stdout);
process.stdout.write=(chunk,...args)=>{const b=Buffer.isBuffer(chunk)?chunk:Buffer.from(String(chunk));outputBytes+=b.length;if(outputBytes>8192)throw new Error('output bound');emitted.push(b);return true;};
process.argv=[process.execPath,'/source/scripts/verify-checkpoint-startup-runtime.mjs','--unit'];
process.exitCode=0;
await import(pathToFileURL('/source/scripts/verify-checkpoint-startup-runtime.mjs').href+'?run='+nonce);
process.stdout.write=original;
if(process.exitCode!==0||Buffer.concat(emitted).toString('utf8')!==marker)throw new Error('exact unit oracle failed');
process.stdout.write(JSON.stringify({schema:'ct200-startup-inner-v1',nonce,probe,probeReceiptSha256:digest(Buffer.from(canonical(probe))),unitOutputSha256:digest(Buffer.concat(emitted)),testCount:15})+'\\nCT200_STARTUP_INNER_PASSED\\n');
"""
    if mode == "capacity":
        wrapper = capacity_wrapper_source(wrapper)
    write_exact(os.path.join(rootfs, "source", ".ct200-wrapper.mjs"), wrapper)
    write_exact(os.path.join(rootfs, "run-nonce"), (nonce + "\n").encode("ascii"))
    copy_tree(deps_root, os.path.join(rootfs, "source", ".authenticated-deps"), deps_modes)
    dep_copy = tree_measure(os.path.join(rootfs, "source", ".authenticated-deps"))
    need(dep_copy[:3] == (deps_count, deps_size, deps_hash) and dep_copy[3:] == (deps_modes, deps_hashes) and
         tree_measure(deps_root)[:3] == (deps_count, deps_size, deps_hash), "module_copy_changed")
    need(tree_measure(source)[:3] == (count, size, tree_hash), "source_changed")
    validate_source_tree(rootfs, source_rows, mode)
    source_launch_measure = tree_measure(os.path.join(rootfs, "source"))
    copied_go = tree_measure(os.path.join(rootfs, "tools", "go"))
    need(copied_go[:3] == go_measure[:3] and copied_go[3:] == (go_modes, go_hashes), "go_copy_changed")
    read_pin(os.path.join(rootfs, "tools", "node", "bin", "node"), NODE_BYTES, NODE_SHA256)
    cgroup_parent_before = read_small("/sys/fs/cgroup/system.slice/cgroup.subtree_control", 4096)
    root_ctrl_before = read_small("/sys/fs/cgroup/cgroup.subtree_control", 4096)
    production_before = unit_projection()
    unit = "ct200-startup-" + nonce + ".service"
    props = fixed_service_properties(rootfs, unit, mode)
    validate_fixed_service_properties(props, rootfs, unit, mode)
    envs = {
        "PATH": "/tools/go/bin:/usr/bin:/bin", "GOENV": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off",
        "GOSUMDB": "off", "GOWORK": "off", "GOFLAGS": "-mod=readonly", "CGO_ENABLED": "0", "GOMAXPROCS": "1",
        "GOCACHE": "/work/gocache", "GOMODCACHE": "/work/modcache", "GOTMPDIR": "/work/tmp", "TMPDIR": "/work/tmp", "HOME": "/work/home", "LANG": "C",
    }
    argv = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=" + unit]
    argv += ["--property=" + value for value in props]
    argv += ["--property=Environment=" + key + "=" + value for key, value in sorted(envs.items())]
    service_argv = ["/tools/unshare", "--mount", "--pid", "--fork", "--kill-child", "--mount-proc=/proc", "--propagation", "private",
                    "/tools/setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
                    "--bounding-set=-all", "--no-new-privs", "/tools/node/bin/node", "/source/.ct200-wrapper.mjs"]
    argv += service_argv
    validate_source_tree(rootfs, source_rows, mode)
    need(same_tree_snapshot(tree_measure(os.path.join(rootfs, "source")), source_launch_measure), "source_launch_tree_changed")
    need(same_tree_snapshot(tree_measure(os.path.join(rootfs, "tools", "go")), go_measure), "go_launch_tree_changed")
    read_pin(os.path.join(rootfs, "tools", "node", "bin", "node"), NODE_BYTES, NODE_SHA256)
    for name, (n, digest) in launchers.items():
        read_pin(os.path.join(rootfs, "tools", name.rsplit("/", 1)[-1]), n, digest)
    SERVICE_NAME = unit
    validate_unit_absent(systemd_properties(unit), unit)
    ensure_time()
    validate_private_rootfs(rootfs, rootfs_identity)
    global ACTIVE_CHILD, SERVICE_DIAGNOSTIC
    try:
        SERVICE_LAUNCH_ATTEMPTED = True
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except OSError:
        raise Reject("service_start") from None
    ACTIVE_CHILD = child
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
    output = bytearray()
    service_stderr = bytearray()
    service_stderr_overflow = False
    seen_pids = {}
    observed_cgroup = None
    observed_invocation = None
    observed = False
    main_exit_pending = False
    main_exit_phase_proven = False
    deferred_gone_members = set()
    next_check = 0.0
    activation_deadline = time.monotonic() + 10
    try:
        while child.poll() is None or selector.get_map() or (main_exit_pending and not main_exit_phase_proven):
            ensure_time()
            for key, _ in selector.select(0.1):
                pipe_open, service_stderr_overflow = consume_service_pipe(
                    key.fd, key.data, output, service_stderr, service_stderr_overflow)
                if not pipe_open:
                    selector.unregister(key.fileobj)
            exit_context = {"unit": unit, "cgroup": SERVICE_CGROUP_PATH, "cgroup_id": SERVICE_CGROUP_ID,
                            "invocation": SERVICE_INVOCATION, "main_pid": SERVICE_MAIN_PID, "main_start": SERVICE_MAIN_START}
            poll_due, props_now, terminal_observed, main_exit_pending, main_exit_phase_proven, next_check = service_monitor_poll_step(
                child.poll() is None, main_exit_pending, main_exit_phase_proven, OWNED_UNIT_STARTED,
                time.monotonic(), next_check, unit, exit_context, SERVICE_PIDS, seen_pids, deferred_gone_members)
            if poll_due:
                if terminal_observed:
                    observed = True
                    continue
                if props_now["LoadState"] == "not-found" or props_now["ActiveState"] != "active" or props_now["MainPID"] == "0" or not props_now["ControlGroup"]:
                    need(time.monotonic() < activation_deadline, "service_activation")
                    continue
                validate_active_unit(props_now, unit)
                observed_cgroup = props_now["ControlGroup"]
                observed_invocation = props_now["InvocationID"]
                cgroup = cgroup_path(props_now["ControlGroup"])
                pids = read_pids(cgroup)
                if not OWNED_UNIT_STARTED:
                    cgroup, cg_info = capture_owned_unit(unit, props_now, pids, rootfs, service_argv)
                else:
                    cg_info = os.lstat(cgroup)
                    need(same_owned_unit(props_now, unit) and props_now["MainPID"] == str(SERVICE_MAIN_PID) and
                         cg_info.st_dev == SERVICE_CGROUP_ID[0] and cg_info.st_ino == SERVICE_CGROUP_ID[1], "unit_identity_changed")
                verify_cgroup(cgroup, unit, pids, (SERVICE_INVOCATION, SERVICE_MAIN_PID, SERVICE_MAIN_START))
                cg_after = os.lstat(cgroup)
                need(stat.S_ISDIR(cg_after.st_mode) and not stat.S_ISLNK(cg_after.st_mode) and cg_after.st_uid == 0 and
                     (cg_after.st_dev, cg_after.st_ino) == (cg_info.st_dev, cg_info.st_ino) == SERVICE_CGROUP_ID, "unit_cgroup_changed")
                current_context = {"unit": unit, "fields": dict(props_now), "cgroup": cgroup, "cgroup_id": SERVICE_CGROUP_ID,
                                   "main_pid": SERVICE_MAIN_PID, "main_start": SERVICE_MAIN_START,
                                   "rootfs_id": SERVICE_ROOTFS_ID, "executable_id": SERVICE_EXEC_ID,
                                   "argv_bytes": SERVICE_ARGV_BYTES}
                ordered_pids = [SERVICE_MAIN_PID] + sorted(pid for pid in pids if pid != SERVICE_MAIN_PID)
                if track_active_unit_members(ordered_pids, current_context, SERVICE_PIDS, seen_pids,
                                             deferred_gone_members):
                    main_exit_pending = True
                observed = True
        child.wait(timeout=2)
        SERVICE_DIAGNOSTIC = classify_service_stderr(bytes(service_stderr), service_stderr_overflow)
        need(not service_stderr_overflow, "service_stderr_bound")
    except BaseException:
        if child.poll() is None:
            try:
                child.kill()
                child.wait(timeout=2)
            except BaseException:
                pass
        refresh_service_diagnostic(selector, output, service_stderr, service_stderr_overflow)
        retain_service_stderr_best_effort(bytes(service_stderr))
        raise
    finally:
        ACTIVE_CHILD = None
        selector.close()
        if child.stdout:
            child.stdout.close()
        if child.stderr:
            child.stderr.close()
    stdout = bytes(output)
    if not observed or child.returncode != 0 or stdout is None or len(stdout) > 8192:
        retain_service_stderr_best_effort(bytes(service_stderr))
    need(observed and child.returncode == 0 and stdout is not None and len(stdout) <= 8192, "service_result")
    inner = internal_receipt(stdout, meta)
    production_after = unit_projection()
    need(production_before == production_after, "production_unit_changed")
    cgroup_parent_after = read_small("/sys/fs/cgroup/system.slice/cgroup.subtree_control", 4096)
    root_ctrl_after = read_small("/sys/fs/cgroup/cgroup.subtree_control", 4096)
    validate_controller_change(root_ctrl_before.decode("ascii", "strict"), root_ctrl_after.decode("ascii", "strict"),
                               cgroup_parent_before.decode("ascii", "strict"), cgroup_parent_after.decode("ascii", "strict"), True)
    # systemd --collect must leave no active service cgroup or PID namespace child.
    need(isinstance(observed_cgroup, str) and isinstance(observed_invocation, str), "service_identity")
    fields = systemd_properties(unit)
    if fields["LoadState"] == "loaded":
        need(fields["InvocationID"] == observed_invocation and fields["ControlGroup"] == observed_cgroup, "service_identity")
        final_cgroup = cgroup_path(observed_cgroup)
        final_cgroup_stat = os.lstat(final_cgroup)
        need((final_cgroup_stat.st_dev, final_cgroup_stat.st_ino) == SERVICE_CGROUP_ID, "service_cgroup_identity")
        empty = not read_pids(final_cgroup)
        need(owned_unit_settled(fields, unit, empty), "service_cgroup_not_empty")
    else:
        need(fields["LoadState"] == "not-found" and owned_unit_settled(fields, unit), "service_identity")
    for pid, original_start in seen_pids.items():
        current_start = proc_starttime(pid) if os.path.exists("/proc/%d" % pid) else None
        need(current_start != original_start, "service_pid_survived")
    SERVICE_SETTLED = True
    prove_host_endpoint()
    listener.close()
    ACTIVE_LISTENER = None
    source_now = tree_measure(source)
    need(source_now[:3] == (count, size, tree_hash), "source_changed")
    outside_current = os.lstat(outside)
    need((outside_current.st_dev, outside_current.st_ino) == outside_id and stat.S_ISDIR(outside_current.st_mode) and not stat.S_ISLNK(outside_current.st_mode), "fixture_custody")
    outside_bytes = read_small(outside_file, 4096)
    need(outside_bytes == outside_data, "fixture_control")
    outside_file_after = os.lstat(outside_file)
    after_meta = tuple(getattr(outside_file_after, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"))
    need(after_meta == OUTSIDE_FILE_META, "fixture_custody")
    need(cleanup_outside_fixture(), "fixture_cleanup")
    transaction = {
        "probeReceiptSha256": inner["probeReceiptSha256"],
        "testCount": inner["testCount"], "productionUnitsPreserved": True, "ownedEffectsSettled": SERVICE_SETTLED and OUTSIDE_SETTLED,
        "sourceTree": (count, size, tree_hash),
    }
    if mode == "capacity":
        transaction["capacityOutputSha256"] = inner["capacityOutputSha256"]
        transaction["packages"] = inner["packages"]
    else:
        transaction["unitOutputSha256"] = inner["unitOutputSha256"]
    return transaction


def main():
    global SCRATCH, SCRATCH_ID, SCRATCH_FD
    signal.signal(signal.SIGALRM, alarm_handler)
    set_stage("bootstrap")
    verify_tmp_parent()
    need(callable(READ_RAW) and callable(READ_EXTRA) and isinstance(REQUEST, dict) and isinstance(_probe_bytes, bytes), "frame")
    set_stage("request")
    total, source_rows = validate_request(REQUEST)
    capacity_mode = REQUEST.get("schema") == CAPACITY_SCHEMA and REQUEST.get("mode") == "capacity"
    need(type(BOOTSTRAP_CAPACITY_MODE) is bool and BOOTSTRAP_CAPACITY_MODE == capacity_mode, "request_mode")
    need(sha256(_probe_bytes) == "9de723c6fb1c98e40f693ad2ba1037dd3d7903cbe1843b79888a0aae8140daf9", "probe_pin")
    free_before = os.statvfs("/var/tmp").f_bavail * os.statvfs("/var/tmp").f_frsize
    need(free_before >= 2 * 1024 * 1024 * 1024 + total, "disk_reserve")
    root = tempfile.mkdtemp(prefix="lb-startup-", dir="/var/tmp")
    os.chmod(root, 0o700)
    root_st = os.lstat(root)
    need(stat.S_ISDIR(root_st.st_mode) and root_st.st_uid == 0 and (root_st.st_mode & 0o7777) == 0o700, "scratch")
    SCRATCH, SCRATCH_ID = root, (root_st.st_dev, root_st.st_ino)
    SCRATCH_FD = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    need((os.fstat(SCRATCH_FD).st_dev, os.fstat(SCRATCH_FD).st_ino) == SCRATCH_ID, "scratch")
    material = os.path.join(root, "material")
    set_stage("snapshot")
    requirements, sums = stage_materials(material, REQUEST, source_rows)
    need(READ_EXTRA() == b"", "frame_trailing")
    need(sha256(_probe_bytes) == "9de723c6fb1c98e40f693ad2ba1037dd3d7903cbe1843b79888a0aae8140daf9", "probe_pin")
    read_pin("/usr/bin/systemd-run", 68392, "dbc8b988a849d5c9d7ef2de7068a6f107021bc6c11e0d7864c73f373eef726a7")
    read_pin("/usr/bin/systemctl", 1501304, "e0d3d0e9444da1b2b58c792c3f5028b69f049b77d5ca17b3ec0d09f89117225b")
    validate_systemd_version(command(("/usr/bin/systemctl", "--version"), max_output=4096))
    set_stage("isolation")
    transaction = run_isolated(root, requirements, _probe_bytes, REQUEST)
    set_stage("receipt")
    if capacity_mode:
        receipt = {
            "schema": CAPACITY_RECEIPT_SCHEMA, "mode": "capacity", "status": "passed", "nonce": REQUEST["nonce"],
            "sourceManifestSha256": REQUEST["sourceManifestSha256"], "bundleManifestSha256": REQUEST["manifestSha256"],
            "startupFreezeSha256": REQUEST["startupFreezeSha256"], "capacityFreezeSha256": REQUEST["capacityFreezeSha256"],
            "probeReceiptSha256": transaction["probeReceiptSha256"], "capacityOutputSha256": transaction["capacityOutputSha256"],
            "testCount": transaction["testCount"], "packages": transaction["packages"],
            "productionUnitsPreserved": transaction["productionUnitsPreserved"], "ownedEffectsSettled": transaction["ownedEffectsSettled"],
        }
        raw = canonical(receipt) + b"\nCT200_CAPACITY_PASSED\n"
    else:
        receipt = {
            "schema": RECEIPT_SCHEMA, "status": "passed", "nonce": REQUEST["nonce"],
            "sourceManifestSha256": REQUEST["sourceManifestSha256"], "bundleManifestSha256": REQUEST["manifestSha256"],
            "startupFreezeSha256": REQUEST["startupFreezeSha256"],
            "probeReceiptSha256": transaction["probeReceiptSha256"], "unitOutputSha256": transaction["unitOutputSha256"],
            "testCount": transaction["testCount"], "productionUnitsPreserved": transaction["productionUnitsPreserved"],
            "ownedEffectsSettled": transaction["ownedEffectsSettled"],
        }
        raw = canonical(receipt) + b"\nCT200_STARTUP_PASSED\n"
    need(len(raw) <= MAX_RECEIPT, "receipt_bound")
    # Cleanup is restricted to the just-created scratch inode after the service is gone.
    held = os.fstat(SCRATCH_FD)
    named = os.lstat(root)
    need((held.st_dev, held.st_ino) == SCRATCH_ID == (named.st_dev, named.st_ino) and held.st_uid == named.st_uid == 0 and
         (held.st_mode & 0o7777) == (named.st_mode & 0o7777) == 0o700, "scratch_cleanup")
    verify_no_mounts_below(root)
    verify_owned_tree(root, held.st_dev)
    shutil.rmtree(root)
    need(not os.path.lexists(root), "scratch_cleanup")
    os.close(SCRATCH_FD)
    SCRATCH_FD = None
    view = memoryview(raw)
    while view:
        written = os.write(1, view)
        need(written > 0, "receipt_write")
        view = view[written:]


def failure_exception_info(error):
    exception_types = (
        (Reject, "reject"), (OSError, "os_error"), (FileNotFoundError, "file_not_found"),
        (PermissionError, "permission_error"), (TimeoutError, "timeout"),
        (subprocess.TimeoutExpired, "timeout"), (subprocess.SubprocessError, "subprocess_error"),
        (ValueError, "value_error"), (TypeError, "type_error"), (KeyError, "key_error"),
        (IndexError, "index_error"), (AttributeError, "attribute_error"), (AssertionError, "assertion_error"),
        (UnicodeError, "unicode_error"), (EOFError, "eof_error"), (MemoryError, "memory_error"),
        (OverflowError, "overflow_error"), (RecursionError, "recursion_error"), (SystemExit, "system_exit"),
    )
    exception_type = "other"
    if isinstance(error, BaseException):
        for exception_class, label in exception_types:
            if type(error) is exception_class:
                exception_type = label
                break
    frame_functions = (
        ("main", "main"), ("run_isolated", "isolation"),
        ("validate_request", "request_validation"), ("stage_materials", "material_stage"),
        ("validate_source_tree", "source_validation"), ("tree_measure", "tree_measure"),
        ("copy_tree", "copy_tree"), ("copy_file", "copy_file"), ("copy_elf_closure", "elf_closure"),
        ("command", "command"), ("systemd_properties", "systemd_properties"), ("parse_systemd_properties", "systemd_properties"),
        ("verify_cgroup", "cgroup_validation"), ("read_cgroup_value", "cgroup_read"), ("cgroup_path", "cgroup_path"),
        ("unit_projection", "unit_projection"), ("capture_owned_unit", "unit_capture"),
        ("cleanup_outside_fixture", "fixture_cleanup"), ("settle_owned_unit", "unit_cleanup"),
    )
    traceback_node = error.__traceback__ if isinstance(error, BaseException) else None
    traversed = 0
    deepest = None
    while traceback_node is not None and traversed < MAX_FAILURE_TRACE_FRAMES:
        code = traceback_node.tb_frame.f_code
        for function_name, label in frame_functions:
            function = globals().get(function_name)
            if isinstance(function, FunctionType) and function.__globals__ is globals() and function.__code__ is code:
                line = traceback_node.tb_lineno
                if type(line) is int and 1 <= line <= MAX_FAILURE_LINE:
                    deepest = (exception_type, label, line)
                    break
        traceback_node = traceback_node.tb_next
        traversed += 1
    if traceback_node is not None or deepest is None:
        return exception_type, "unlocated", 0
    return deepest


def emit_failure(error=None, exception_info=None):
    # Fixed categories only; never disclose exception text, paths, IDs, PIDs, or credentials.
    scratch_state = "retained" if SCRATCH is not None and os.path.lexists(SCRATCH) else "absent"
    unit_state = "settled" if SERVICE_SETTLED else "preserved"
    fixture_state = "settled" if OUTSIDE_SETTLED else "preserved"
    try:
        line = failure_envelope(error, unit_state, fixture_state, scratch_state, SERVICE_DIAGNOSTIC, exception_info)
        os.write(2, line)
    except OSError:
        pass


def cleanup_systemd_properties(unit, timeout):
    result = subprocess.run(("/usr/bin/systemctl", "show", unit, "--property=LoadState,ControlGroup,MainPID,InvocationID,ActiveState"),
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=max(0.05, timeout), check=False, close_fds=True,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 2048, "cleanup_observation")
    return parse_systemd_properties(result.stdout, ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState"))


def owned_processes_gone():
    for pid, start in SERVICE_PIDS.items():
        if os.path.exists("/proc/%d" % pid):
            try:
                current = proc_starttime(pid)
            except BaseException:
                if os.path.exists("/proc/%d" % pid):
                    return False
                continue
            if current == start:
                return False
    return True


def settle_owned_unit():
    global OWNED_UNIT_STARTED, ACTIVE_LISTENER, SERVICE_SETTLED, DEADLINE
    if ACTIVE_LISTENER is not None:
        try:
            ACTIVE_LISTENER.close()
        except OSError:
            pass
        ACTIVE_LISTENER = None
    now = time.monotonic()
    cleanup_deadline = min(now + CLEANUP_SECONDS, OUTER_DEADLINE - 2)
    signal.setitimer(signal.ITIMER_REAL, 0)
    if cleanup_deadline <= now:
        SERVICE_SETTLED = False
        return False
    DEADLINE = cleanup_deadline
    signal.setitimer(signal.ITIMER_REAL, cleanup_deadline - now)
    if SERVICE_NAME is None:
        SERVICE_SETTLED = True
    elif not SERVICE_LAUNCH_ATTEMPTED:
        try:
            validate_unit_absent(cleanup_systemd_properties(SERVICE_NAME, min(2.0, cleanup_remaining(DEADLINE))), SERVICE_NAME)
            SERVICE_SETTLED = True
        except BaseException:
            SERVICE_SETTLED = False
    else:
        try:
            fields = cleanup_systemd_properties(SERVICE_NAME, min(2.0, cleanup_remaining(DEADLINE)))
            if not OWNED_UNIT_STARTED:
                # Once launch was attempted without durable process/cgroup identity, even an absent
                # unit is ambiguous (it may have run and exited); preserve the fixture and scratch.
                SERVICE_SETTLED = False
            elif same_owned_unit(fields, SERVICE_NAME):
                if fields["LoadState"] == "loaded" and fields["MainPID"] != "0":
                    main_pid = int(fields["MainPID"])
                    if main_pid != SERVICE_MAIN_PID or proc_starttime(main_pid) != SERVICE_MAIN_START:
                        raise Reject("cleanup_identity")
                    cgroup = cgroup_path(fields["ControlGroup"])
                    info = os.lstat(cgroup)
                    if (info.st_dev, info.st_ino) != SERVICE_CGROUP_ID:
                        raise Reject("cleanup_identity")
                    stopped = subprocess.run(("/usr/bin/systemctl", "stop", SERVICE_NAME), stdin=subprocess.DEVNULL,
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                              timeout=min(5.0, cleanup_remaining(DEADLINE)), check=False,
                                              close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
                    if stopped.returncode != 0:
                        raise Reject("cleanup_stop")
                while cleanup_remaining(DEADLINE) > 0:
                    fields = cleanup_systemd_properties(SERVICE_NAME, min(1.0, cleanup_remaining(DEADLINE)))
                    if fields["LoadState"] == "not-found":
                        if owned_unit_settled(fields, SERVICE_NAME):
                            SERVICE_SETTLED = True
                            break
                        break
                    if not same_owned_unit(fields, SERVICE_NAME):
                        break
                    if fields["MainPID"] == "0":
                        cgroup = cgroup_path(fields["ControlGroup"])
                        info = os.lstat(cgroup)
                        if (info.st_dev, info.st_ino) != SERVICE_CGROUP_ID:
                            break
                        empty = not read_pids(cgroup)
                        if owned_unit_settled(fields, SERVICE_NAME, empty):
                            SERVICE_SETTLED = True
                            break
                    time.sleep(min(0.2, cleanup_remaining(DEADLINE)))
        except BaseException:
            SERVICE_SETTLED = False
    if SERVICE_SETTLED:
        OWNED_UNIT_STARTED = False
        cleanup_outside_fixture()
    signal.setitimer(signal.ITIMER_REAL, 0)
    return SERVICE_SETTLED and OUTSIDE_SETTLED


def verify_parser_fixtures():
    global CAPACITY_WRAPPER_FIXTURE
    global SERVICE_DIAGNOSTIC
    global SERVICE_NAME, SERVICE_CGROUP, SERVICE_CGROUP_PATH, SERVICE_CGROUP_ID, SERVICE_INVOCATION, SERVICE_MAIN_PID, SERVICE_MAIN_START, SERVICE_PIDS, OWNED_UNIT_STARTED
    global SERVICE_ROOTFS_ID, SERVICE_EXEC_ID, SERVICE_ARGV_BYTES, cgroup_path, proc_starttime, service_process_matches
    global OUTSIDE_ROOT, OUTSIDE_ID, OUTSIDE_DATA, OUTSIDE_FILE, OUTSIDE_FILE_ID, OUTSIDE_FILE_META, OUTSIDE_SETTLED
    need(NODE_ARCHIVE_BYTES == 54108748 and NODE_ARCHIVE_SHA256 == "9d942932535988091034dc94cc5f42b6dc8784d6366df3a36c4c9ccb3996f0c2", "verify_fixture")
    preowned_unit = "ct200-startup-" + "c" * 32 + ".service"
    preowned_context = {"unit": preowned_unit, "cgroup": None, "cgroup_id": None, "invocation": None,
                        "main_pid": None, "main_start": None}
    need(OWNED_UNIT_STARTED is False and type(SERVICE_PIDS) is set and not SERVICE_PIDS and
         SERVICE_CGROUP_PATH is None and SERVICE_CGROUP_ID is None and SERVICE_INVOCATION is None and
         SERVICE_MAIN_PID is None and SERVICE_MAIN_START is None and SERVICE_ROOTFS_ID is None and
         SERVICE_EXEC_ID is None and SERVICE_ARGV_BYTES is None, "verify_fixture")
    preowned_active = {"LoadState": "loaded", "ControlGroup": "/system.slice/" + preowned_unit,
                       "MainPID": "123", "InvocationID": "a" * 32, "ActiveState": "active"}
    preowned_observe_calls = []
    preowned_active_poll = service_monitor_poll_step(
        True, False, False, False, 0.0, 0.0, preowned_unit, preowned_context, SERVICE_PIDS, {}, set(),
        _read=lambda _unit: preowned_active,
        _observe=lambda *_args: preowned_observe_calls.append(True))
    need(preowned_active_poll == (True, preowned_active, False, False, False, 0.25) and
         not preowned_observe_calls and type(SERVICE_PIDS) is set and not SERVICE_PIDS and not OWNED_UNIT_STARTED,
         "verify_fixture")
    for activation_props in (
        {"LoadState": "not-found", "ControlGroup": "", "MainPID": "0", "InvocationID": "", "ActiveState": "inactive"},
        {**preowned_active, "MainPID": "0"},
    ):
        activation_poll = service_monitor_poll_step(
            True, False, False, False, 0.0, 0.0, preowned_unit, preowned_context, SERVICE_PIDS, {}, set(),
            _read=lambda _unit, value=activation_props: value,
            _observe=lambda *_args: preowned_observe_calls.append(True))
        need(activation_poll == (True, activation_props, False, False, False, 0.25) and
             not preowned_observe_calls, "verify_fixture")
    preowned_invalid = (
        {"pending": True}, {"phase_proven": True}, {"known": {123}}, {"known": {123: 456}},
        {"context": {**preowned_context, "main_pid": 123}},
        {"context": {**preowned_context, "cgroup": "/sys/fs/cgroup/system.slice/" + preowned_unit}},
    )
    for changes in preowned_invalid:
        args = {"pending": False, "phase_proven": False, "known": SERVICE_PIDS, "context": preowned_context}
        args.update(changes)
        rejected = False
        try:
            service_monitor_poll_step(True, args["pending"], args["phase_proven"], False, 0.0, 0.0,
                                      preowned_unit, args["context"], args["known"], {}, set(),
                                      _read=lambda _unit: preowned_active)
        except Reject as error:
            rejected = type(error) is Reject and error.args == ("service_result",)
        need(rejected, "verify_fixture")
    rejected = False
    try:
        service_monitor_poll_step(True, False, False, True, 0.0, 0.0, preowned_unit, preowned_context,
                                  SERVICE_PIDS, {}, set(), _read=lambda _unit: preowned_active)
    except Reject as error:
        rejected = type(error) is Reject and error.args == ("service_result",)
    need(rejected, "verify_fixture")

    # Exercise the real sole set-to-dict transition, then prove terminal eligibility
    # only from its captured identity and the actual terminal observer.
    capture_unit = "ct200-startup-" + "d" * 32 + ".service"
    capture_fields = {"LoadState": "loaded", "ControlGroup": "/system.slice/" + capture_unit,
                      "MainPID": "321", "InvocationID": "e" * 32, "ActiveState": "active"}
    capture_root = "/fixture/captured-root"
    capture_cgroup = "/sys/fs/cgroup" + capture_fields["ControlGroup"]
    capture_cgroup_info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=7, st_ino=11)
    capture_root_info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=7, st_ino=12)
    capture_exec_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_nlink=1, st_dev=7, st_ino=13)
    capture_exec_path = os.path.join(capture_root, "tools", "unshare")
    capture_stat = {capture_cgroup: capture_cgroup_info, capture_root: capture_root_info,
                    capture_exec_path: capture_exec_info}
    saved_capture_state = (SERVICE_NAME, SERVICE_CGROUP, SERVICE_CGROUP_PATH, SERVICE_CGROUP_ID, SERVICE_INVOCATION,
                           SERVICE_MAIN_PID, SERVICE_MAIN_START, SERVICE_ROOTFS_ID, SERVICE_EXEC_ID, SERVICE_ARGV_BYTES,
                           SERVICE_PIDS, OWNED_UNIT_STARTED, cgroup_path, proc_starttime, service_process_matches, os.lstat)
    try:
        SERVICE_NAME = SERVICE_CGROUP = SERVICE_CGROUP_PATH = SERVICE_CGROUP_ID = SERVICE_INVOCATION = None
        SERVICE_MAIN_PID = SERVICE_MAIN_START = SERVICE_ROOTFS_ID = SERVICE_EXEC_ID = SERVICE_ARGV_BYTES = None
        SERVICE_PIDS = set()
        OWNED_UNIT_STARTED = False
        cgroup_path = lambda relative: "/sys/fs/cgroup" + relative
        proc_starttime = lambda pid: 4567 if pid == 321 else (_ for _ in ()).throw(Reject("unit_pid_gone"))
        service_process_matches = lambda *_args: True
        os.lstat = lambda path: capture_stat[path]
        capture_owned_unit(capture_unit, capture_fields, {321}, capture_root, ["/fixture/tools/unshare"])
        need(OWNED_UNIT_STARTED is True and type(SERVICE_PIDS) is dict and SERVICE_PIDS == {321: 4567} and
             SERVICE_CGROUP_PATH == capture_cgroup and SERVICE_CGROUP_ID == (7, 11) and
             SERVICE_INVOCATION == capture_fields["InvocationID"] and SERVICE_MAIN_PID == 321 and
             SERVICE_MAIN_START == 4567, "verify_fixture")
        capture_context = {"unit": capture_unit, "cgroup": SERVICE_CGROUP_PATH, "cgroup_id": SERVICE_CGROUP_ID,
                           "invocation": SERVICE_INVOCATION, "main_pid": SERVICE_MAIN_PID,
                           "main_start": SERVICE_MAIN_START}
        capture_terminal_fields = {**capture_fields, "MainPID": "0", "ActiveState": "deactivating"}
        terminal_ops = {
            "owned_unit_settled": lambda _fields, _unit: True,
            "lstat_proc": lambda path: (_ for _ in ()).throw(OSError(errno.ENOENT, "fixture"))
                if path == "/proc/321" else (_ for _ in ()).throw(OSError(errno.EACCES, "fixture")),
            "systemd_properties": lambda _unit: dict(capture_terminal_fields),
            "cgroup_path": lambda relative: capture_cgroup if relative == capture_fields["ControlGroup"] else "/changed",
            "lstat_cgroup": lambda _path: capture_cgroup_info,
            "read_cgroup_value": lambda _path, name: {
                "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "100000 100000"}[name],
            "read_pids": lambda _path: set(),
        }
        capture_terminal_poll = service_monitor_poll_step(
            False, True, False, True, 0.25, 0.25, capture_unit, capture_context, SERVICE_PIDS, {}, set(),
            _read=lambda _unit: dict(capture_terminal_fields),
            _observe=lambda fields, context: observe_main_exit_phase(fields, context, terminal_ops))
        need(capture_terminal_poll == (True, capture_terminal_fields, True, True, True, 0.5), "verify_fixture")
        for changed_context in (
            {**capture_context, "cgroup": "/changed"},
            {**capture_context, "invocation": "f" * 32},
            {**capture_context, "main_pid": 654},
            {**capture_context, "main_start": 9999},
            {**capture_context, "cgroup_id": (7, 12)},
        ):
            rejected = False
            try:
                service_monitor_poll_step(False, True, False, True, 0.25, 0.25, capture_unit, changed_context,
                                          SERVICE_PIDS, {}, set(), _read=lambda _unit: dict(capture_terminal_fields),
                                          _observe=lambda fields, context: observe_main_exit_phase(fields, context, terminal_ops))
            except Reject as error:
                rejected = type(error) is Reject
            need(rejected, "verify_fixture")
    finally:
        (SERVICE_NAME, SERVICE_CGROUP, SERVICE_CGROUP_PATH, SERVICE_CGROUP_ID, SERVICE_INVOCATION,
         SERVICE_MAIN_PID, SERVICE_MAIN_START, SERVICE_ROOTFS_ID, SERVICE_EXEC_ID, SERVICE_ARGV_BYTES,
         SERVICE_PIDS, OWNED_UNIT_STARTED, cgroup_path, proc_starttime, service_process_matches, os.lstat) = saved_capture_state

    need(canonical_sorted({"z": 1, "a": 2}) == b'{"a":2,"z":1}', "verify_fixture")
    rootfs_fixture_path = "/fixed/private/rootfs"
    rootfs_fixture_identity = (77, 88)
    rootfs_fixture_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=77, st_ino=88)

    def rootfs_lstat_fixture(root_info=rootfs_fixture_stat, entries=None, blocked_path=None, blocked_error=None):
        entries = {} if entries is None else entries

        def fixture_lstat(path):
            if path == rootfs_fixture_path:
                return root_info
            if path == blocked_path:
                raise blocked_error
            if path in entries:
                return entries[path]
            raise FileNotFoundError(errno.ENOENT, "fixture absent", path)

        return fixture_lstat

    need(validate_private_rootfs(rootfs_fixture_path, rootfs_fixture_identity, rootfs_lstat_fixture()), "verify_fixture")
    rootfs_child = os.path.join(rootfs_fixture_path, "root")
    rootfs_run = os.path.join(rootfs_fixture_path, "run")
    rootfs_home_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=77, st_ino=89)
    rootfs_link_stat = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_dev=77, st_ino=90)
    rootfs_run_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=77, st_ino=91)
    need(validate_private_rootfs(rootfs_fixture_path, rootfs_fixture_identity,
                                 rootfs_lstat_fixture(entries={rootfs_run: rootfs_run_stat})), "verify_fixture")
    for root_info, entries in (
        (SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_dev=77, st_ino=88), {}),
        (SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1, st_dev=77, st_ino=88), {}),
        (SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0, st_dev=77, st_ino=88), {}),
        (SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=77, st_ino=99), {}),
        (rootfs_fixture_stat, {rootfs_child: rootfs_home_stat}),
        (rootfs_fixture_stat, {rootfs_child: rootfs_link_stat}),
        (rootfs_fixture_stat, {os.path.join(rootfs_fixture_path, "home"): rootfs_home_stat}),
        (rootfs_fixture_stat, {os.path.join(rootfs_fixture_path, "run"): rootfs_run_stat,
                               os.path.join(rootfs_fixture_path, "run", "user"): rootfs_home_stat}),
        (rootfs_fixture_stat, {os.path.join(rootfs_fixture_path, "run"): rootfs_run_stat,
                               os.path.join(rootfs_fixture_path, "run", "user"): rootfs_link_stat}),
        (rootfs_fixture_stat, {rootfs_run: rootfs_link_stat}),
        (rootfs_fixture_stat, {rootfs_run: SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0, st_dev=77, st_ino=91)}),
    ):
        rejected = False
        try:
            validate_private_rootfs(rootfs_fixture_path, rootfs_fixture_identity, rootfs_lstat_fixture(root_info, entries))
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    permission_rejected = False
    try:
        validate_private_rootfs(rootfs_fixture_path, rootfs_fixture_identity,
                                 rootfs_lstat_fixture(blocked_path=rootfs_child, blocked_error=PermissionError(errno.EACCES, "fixture denied", rootfs_child)))
    except PermissionError:
        permission_rejected = True
    need(permission_rejected, "verify_fixture")
    rootfs_fixture_unit = "ct200-startup-" + "a" * 32 + ".service"
    unit_capacity_properties = fixed_service_properties(rootfs_fixture_path, rootfs_fixture_unit, "capacity")
    need(unit_capacity_properties == fixed_service_properties(rootfs_fixture_path, rootfs_fixture_unit, "startup")[:17] +
         ["RuntimeMaxSec=360"] + fixed_service_properties(rootfs_fixture_path, rootfs_fixture_unit, "startup")[18:] and
         validate_fixed_service_properties(unit_capacity_properties, rootfs_fixture_path, rootfs_fixture_unit, "capacity"), "verify_fixture")
    for altered_mode in ("default", None, True):
        rejected_mode = False
        try:
            fixed_service_properties(rootfs_fixture_path, rootfs_fixture_unit, altered_mode)
        except Reject:
            rejected_mode = True
        need(rejected_mode, "verify_fixture")
    startup_unchanged = fixed_service_properties(rootfs_fixture_path, rootfs_fixture_unit)
    need(startup_unchanged[17] == "RuntimeMaxSec=180" and unit_capacity_properties[17] == "RuntimeMaxSec=360" and
         startup_unchanged[:17] == unit_capacity_properties[:17] and startup_unchanged[18:] == unit_capacity_properties[18:], "verify_fixture")
    expected_service_properties = [
        "Type=exec", "Restart=no", "RootDirectory=" + rootfs_fixture_path, "WorkingDirectory=/work",
        "PrivateMounts=yes", "PrivateNetwork=yes", "PrivateDevices=yes", "MountAPIVFS=no",
        "ProtectSystem=strict", "NoNewPrivileges=yes",
        "UnsetEnvironment=NODE_OPTIONS NODE_PATH NODE_V8_COVERAGE LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PYTHONHOME BASH_ENV ENV PERL5OPT RUBYOPT JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS",
        "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_SETPCAP",
        "MemoryMax=2147483648", "MemorySwapMax=0", "TasksMax=128", "CPUQuota=100%", "CPUQuotaPeriodSec=100ms",
        "RuntimeMaxSec=180", "TimeoutStopSec=5", "KillMode=control-group", "LimitNOFILE=4096",
        "TemporaryFileSystem=/work:rw,size=1G,mode=0700,uid=65534,gid=65534",
        "BindReadOnlyPaths=/sys/fs/cgroup/system.slice/" + rootfs_fixture_unit + "/memory.max:/.limits/memory.max",
        "BindReadOnlyPaths=/sys/fs/cgroup/system.slice/" + rootfs_fixture_unit + "/memory.swap.max:/.limits/memory.swap.max",
        "BindReadOnlyPaths=/sys/fs/cgroup/system.slice/" + rootfs_fixture_unit + "/pids.max:/.limits/pids.max",
        "BindReadOnlyPaths=/sys/fs/cgroup/system.slice/" + rootfs_fixture_unit + "/cpu.max:/.limits/cpu.max",
    ]
    need(fixed_service_properties(rootfs_fixture_path, rootfs_fixture_unit) == expected_service_properties and
         validate_fixed_service_properties(expected_service_properties, rootfs_fixture_path, rootfs_fixture_unit), "verify_fixture")
    for mutant in (expected_service_properties + ["ProtectHome=yes"],
                   expected_service_properties[:-4] + ["BindReadOnlyPaths=/sys/fs/cgroup:/cgroup"]):
        rejected = False
        try:
            validate_fixed_service_properties(mutant, rootfs_fixture_path, rootfs_fixture_unit)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    capacity_mutant = list(unit_capacity_properties)
    capacity_mutant[17] = "RuntimeMaxSec=180"
    rejected_capacity_mutant = False
    try:
        validate_fixed_service_properties(capacity_mutant, rootfs_fixture_path, rootfs_fixture_unit, "capacity")
    except Reject:
        rejected_capacity_mutant = True
    need(rejected_capacity_mutant, "verify_fixture")
    # Transform only the trusted production wrapper literal; this is static source inspection, not wrapper execution.
    production_tree = ast.parse(open(__file__, "rb").read())
    wrapper_literals = [node.value.value for node in ast.walk(production_tree)
                        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "wrapper" for target in node.targets)
                        and isinstance(node.value, ast.Constant) and isinstance(node.value.value, bytes)]
    need(len(wrapper_literals) == 1, "verify_fixture")
    capacity_wrapper = capacity_wrapper_source(wrapper_literals[0])
    CAPACITY_WRAPPER_FIXTURE = capacity_wrapper
    need(b"process.argv=[process.execPath,'/source/scripts/verify-runtime-profile-projection.mjs','--unit'];" in capacity_wrapper, "verify_fixture")
    need(b"process.chdir('/source');if(process.cwd()!=='/source');" not in capacity_wrapper and
         b"process.chdir('/source');if(process.cwd()!=='/source')throw new Error('capacity verifier working directory');" in capacity_wrapper, "verify_fixture")
    need(capacity_wrapper.index(b"process.cwd()!=='/source'") < capacity_wrapper.index(b"await import(pathToFileURL('/source/scripts/verify-runtime-profile-projection.mjs')"), "verify_fixture")
    need(b"CT200_CAPACITY_INNER_PASSED" in capacity_wrapper and b"verify-checkpoint-startup-runtime.mjs','--unit'" not in capacity_wrapper, "verify_fixture")
    rejected_argv_mutant = False
    try:
        capacity_wrapper_source(wrapper_literals[0].replace(b"verify-checkpoint-startup-runtime.mjs','--unit'", b"verify-checkpoint-startup-runtime.mjs','--source'", 1))
    except Reject:
        rejected_argv_mutant = True
    need(rejected_argv_mutant, "verify_fixture")
    capacity_nonce = "a" * 32
    capacity_request_files = [{"path": "source/" + name, "bytes": size, "sha256": digest}
                              for name, (size, digest) in CAPACITY_PINS.items()]
    capacity_request_files.extend((
        {"path": "modules/example.com/mod/@v/v1.0.0.info", "bytes": 2, "sha256": sha256(b"{}")},
        {"path": "modules/example.com/mod/@v/v1.0.0.mod", "bytes": 24, "sha256": sha256(b"module example.com/mod\n")},
        {"path": "modules/example.com/mod/@v/v1.0.0.zip", "bytes": 3, "sha256": sha256(b"zip")},
        {"path": "modules/example.com/mod/@v/v1.0.0.ziphash", "bytes": len(b"h1:EqbOt2cuTGyId7pp8AhTqIY7CSAiQyOQTkWYsau91oQ=\n"), "sha256": sha256(b"h1:EqbOt2cuTGyId7pp8AhTqIY7CSAiQyOQTkWYsau91oQ=\n")},
    ))
    capacity_request_files.sort(key=lambda row: row["path"])
    capacity_request_source_rows = [{"path": row["path"][len("source/"):], "bytes": row["bytes"], "sha256": row["sha256"]}
                                    for row in capacity_request_files if row["path"].startswith("source/")]
    capacity_request = {
        "schema": CAPACITY_SCHEMA, "mode": "capacity", "nonce": capacity_nonce,
        "manifestSha256": sha256(canonical(capacity_request_files)),
        "sourceManifestSha256": sha256(canonical(capacity_request_source_rows)),
        "startupFreezeSha256": "c" * 64, "capacityFreezeSha256": CAPACITY_FREEZE_SHA256,
        "sourceCount": len(capacity_request_source_rows), "moduleCount": 1,
        "totalBytes": sum(row["bytes"] for row in capacity_request_files), "files": capacity_request_files,
    }
    need(validate_request(capacity_request)[0] == capacity_request["totalBytes"], "verify_fixture")
    shared_capacity_pins = {name: pin for name, pin in CAPACITY_PINS.items()
                            if name != "scripts/verify-runtime-profile-projection.mjs"}
    default_request_files = [{"path": "source/" + name, "bytes": size, "sha256": digest}
                             for name, (size, digest) in shared_capacity_pins.items()]
    default_request_files.extend({"path": "source/" + name, "bytes": size, "sha256": digest}
                                 for name, (size, digest) in STARTUP_PINS.items())
    default_go_mod = b"module fixture\n\ngo 1.23.4\nrequire example.com/mod v1.0.0\n"
    default_request_files.extend((
        {"path": "source/go.mod", "bytes": len(default_go_mod), "sha256": sha256(default_go_mod)},
        {"path": "source/go.sum", "bytes": 0, "sha256": sha256(b"")},
        *(row for row in capacity_request_files if row["path"].startswith("modules/")),
    ))
    default_request_files.sort(key=lambda row: row["path"])
    default_request_source_rows = [{"path": row["path"][len("source/"):], "bytes": row["bytes"], "sha256": row["sha256"]}
                                   for row in default_request_files if row["path"].startswith("source/")]
    default_request = {
        "schema": SCHEMA, "nonce": capacity_nonce,
        "manifestSha256": sha256(canonical(default_request_files)),
        "sourceManifestSha256": sha256(canonical(default_request_source_rows)),
        "startupFreezeSha256": "c" * 64, "sourceCount": len(default_request_source_rows), "moduleCount": 1,
        "totalBytes": sum(row["bytes"] for row in default_request_files), "files": default_request_files,
    }
    need(validate_request(default_request)[0] == default_request["totalBytes"] and
         all("source/" + name in {row["path"] for row in default_request_files} for name in shared_capacity_pins),
         "verify_fixture")
    default_with_capacity_only_verifier = {**default_request, "files": [dict(row) for row in default_request_files]}
    default_with_capacity_only_verifier["files"].append({
        "path": "source/scripts/verify-runtime-profile-projection.mjs",
        "bytes": CAPACITY_PINS["scripts/verify-runtime-profile-projection.mjs"][0],
        "sha256": CAPACITY_PINS["scripts/verify-runtime-profile-projection.mjs"][1],
    })
    default_with_capacity_only_verifier["files"].sort(key=lambda row: row["path"])
    default_with_capacity_verifier_sources = [{"path": row["path"][len("source/"):], "bytes": row["bytes"], "sha256": row["sha256"]}
                                              for row in default_with_capacity_only_verifier["files"] if row["path"].startswith("source/")]
    default_with_capacity_only_verifier.update({
        "sourceCount": len(default_with_capacity_verifier_sources),
        "totalBytes": sum(row["bytes"] for row in default_with_capacity_only_verifier["files"]),
        "manifestSha256": sha256(canonical(default_with_capacity_only_verifier["files"])),
        "sourceManifestSha256": sha256(canonical(default_with_capacity_verifier_sources)),
    })
    rejected_capacity_only_verifier = False
    try:
        validate_request(default_with_capacity_only_verifier)
    except Reject:
        rejected_capacity_only_verifier = True
    need(rejected_capacity_only_verifier, "verify_fixture")
    default_with_mode = {**default_request, "mode": "capacity"}
    rejected_cross_mode = False
    try:
        validate_request(default_with_mode)
    except Reject:
        rejected_cross_mode = True
    need(rejected_cross_mode, "verify_fixture")
    for name in CAPACITY_PINS:
        mutant = {**capacity_request, "files": [dict(row) for row in capacity_request_files]}
        row = next(item for item in mutant["files"] if item["path"] == "source/" + name)
        row["sha256"] = "0" * 64
        source_rows = [{"path": item["path"][len("source/"):], "bytes": item["bytes"], "sha256": item["sha256"]}
                       for item in mutant["files"] if item["path"].startswith("source/")]
        mutant["manifestSha256"] = sha256(canonical(mutant["files"]))
        mutant["sourceManifestSha256"] = sha256(canonical(source_rows))
        rejected = False
        try:
            validate_request(mutant)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    for mutant in (
        {**capacity_request, "mode": "startup"},
        {**capacity_request, "capacityFreezeSha256": "0" * 64},
        {**capacity_request, "unexpected": True},
    ):
        rejected = False
        try:
            validate_request(mutant)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    capacity_probe = {
        "schema": "lb-isolation-receipt-v1", "nonce": capacity_nonce, "inputSha256": "b" * 64, "pid": 1,
        "namespaces": {"pid": "pid:[21]", "mnt": "mnt:[22]", "net": "net:[23]"},
        "limits": {"memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "100000 100000"},
    }
    capacity_meta = {"schema": CAPACITY_SCHEMA, "mode": "capacity", "nonce": capacity_nonce}
    capacity_inner = {
        "schema": "ct200-capacity-inner-v1", "mode": "capacity", "nonce": capacity_nonce, "probe": capacity_probe,
        "probeReceiptSha256": sha256(canonical_sorted(capacity_probe)), "capacityOutputSha256": sha256(CAPACITY_OUTPUT),
        "testCount": 82, "packages": list(CAPACITY_PACKAGES),
    }
    capacity_inner_bytes = canonical_sorted(capacity_inner) + b"\nCT200_CAPACITY_INNER_PASSED\n"
    need(internal_receipt(capacity_inner_bytes, capacity_meta) == capacity_inner, "verify_fixture")
    for mutate in (
        lambda value: value.update(schema="ct200-startup-inner-v1"),
        lambda value: value.update(mode="startup"),
        lambda value: value.update(testCount=15),
        lambda value: value.update(packages=list(reversed(CAPACITY_PACKAGES))),
        lambda value: value.update(capacityOutputSha256="0" * 64),
        lambda value: value.update(extra=True),
        lambda value: value.update(probeReceiptSha256="0" * 64),
    ):
        mutant = dict(capacity_inner)
        mutate(mutant)
        rejected = False
        try:
            internal_receipt(canonical_sorted(mutant) + b"\nCT200_CAPACITY_INNER_PASSED\n", capacity_meta)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    for wrong_mode_meta, terminal in (
        ({"schema": SCHEMA, "mode": "startup", "nonce": capacity_nonce}, b"\nCT200_STARTUP_INNER_PASSED\n"),
        ({"schema": CAPACITY_SCHEMA, "mode": "capacity", "nonce": capacity_nonce}, b"\nCT200_STARTUP_INNER_PASSED\n"),
    ):
        rejected = False
        try:
            internal_receipt(canonical_sorted(capacity_inner) + terminal, wrong_mode_meta)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    diagnostic_buffer = bytearray()
    need(not append_bounded_diagnostic(diagnostic_buffer, b"ab", 4) and diagnostic_buffer == b"ab", "verify_fixture")
    need(append_bounded_diagnostic(diagnostic_buffer, b"cdef", 4) and diagnostic_buffer == b"abcd", "verify_fixture")
    probe_config_stack = (
        PROBE_CONFIG_MARKER +
        b"node:fs:562\n  return binding.open(\n                 ^\n\n" +
        b"Error: ENOENT: no such file or directory, open '/probe-config.json'\n" +
        b"    at Object.openSync (node:fs:562:18)\n" +
        b"    at readRegular (file:///source/scripts/ct200-verification/.probe.mjs:56:17)\n" +
        b"    at Module.probe (file:///source/scripts/ct200-verification/.probe.mjs:126:43)\n" +
        b"    at async file:///source/.ct200-wrapper.mjs:11:15 {\n" +
        b"  errno: -2,\n  code: 'ENOENT',\n  syscall: 'open',\n  path: '/probe-config.json'\n}\n\nNode.js v22.14.0\n"
    )
    need(classify_structured_probe_stderr(probe_config_stack) == "probe_config_missing" and
         classify_service_stderr(probe_config_stack) == "probe_config_missing", "verify_fixture")
    for malformed_probe_config in (
        b"text before marker\n" + probe_config_stack,
        probe_config_stack + PROBE_CONFIG_MARKER,
        probe_config_stack.replace(b"Error: ENOENT:", b"TypeError: ENOENT:", 1),
        probe_config_stack.replace(b"Node.js v22.14.0", b"Node.js v24.13.0"),
        probe_config_stack.replace(b"\nNode.js v22.14.0\n", b"\nNode.js v22.14.0\nNode.js v22.14.0\n"),
        probe_config_stack.replace(b".ct200-wrapper.mjs:11:15", b".ct200-wrapper.mjs:12:15"),
        probe_config_stack.replace(b"Object.openSync (node:fs:562:18)", b"Object.openSync (node:fs:563:18)"),
        probe_config_stack.replace(b"node:fs:562\n", b"node:fs:563\n", 1),
        probe_config_stack.replace(b"errno: -2", b"errno: -13"),
        probe_config_stack.replace(b"code: 'ENOENT'", b"code: 'EACCES'"),
        probe_config_stack.replace(b"syscall: 'open'", b"syscall: 'read'"),
        probe_config_stack.replace(b"path: '/probe-config.json'", b"path: '/wrong-path'"),
        probe_config_stack.replace(b"readRegular (file:///source/scripts/ct200-verification/.probe.mjs:56:17)",
                                   b"readRegular (file:///source/scripts/ct200-verification/.probe.mjs:57:17)"),
        probe_config_stack.replace(b"  path: '/probe-config.json'\n}", b"  path: '/probe-config.json'\n  extra: 'x'\n}"),
        probe_config_stack.replace(b"  errno: -2,\n  code: 'ENOENT',", b"  code: 'ENOENT',\n  errno: -2,"),
        probe_config_stack.replace(b"  code: 'ENOENT',\n  syscall: 'open',", b"  code: 'ENOENT',\n  code: 'ENOENT',\n  syscall: 'open',"),
        probe_config_stack.replace(b"at async file:///source/.ct200-wrapper.mjs:11:15 {",
                                   b"at async file:///root/[eval1]:1:203 {"),
        probe_config_stack.replace(PROBE_CONFIG_MARKER, b"CT200_PROBE_DIAGNOSTIC probe_unknown\n"),
        probe_config_stack.replace(PROBE_CONFIG_MARKER, PROBE_CONFIG_MARKER + PROBE_CONFIG_MARKER),
        probe_config_stack.replace(b"\n", b"\r\n", 1),
        probe_config_stack + b"extra\n",
        probe_config_stack[:-1],
        probe_config_stack + b"\x00",
        probe_config_stack + b"\xff",
        probe_config_stack + b"x" * MAX_SERVICE_STDERR,
    ):
        need(classify_structured_probe_stderr(malformed_probe_config) is None, "verify_fixture")
    need(classify_service_stderr(probe_config_stack, True) == "overflow" and
         classify_service_stderr(b"Error: isolation verification rejected\n") == "unclassified", "verify_fixture")
    probe_stack = (
        PROBE_SOURCE_URL + ":6\nconst fail = () => { throw new Error('isolation verification rejected'); };\n" + " " * 27 + "^\n\n" +
        "Error: isolation verification rejected\n" +
        "    at fail (" + PROBE_SOURCE_URL + ":6:28)\n" +
        "    at validateFacts (" + PROBE_SOURCE_URL + ":33:68)\n" +
        "    at Module.probe (" + PROBE_SOURCE_URL + ":166:10)\n" +
        "    at async " + PROBE_WRAPPER_URL + ":11:15\n\nNode.js v22.14.0\n"
    ).encode("ascii")
    need(classify_probe_stderr(probe_stack) == "probe_limits" and classify_service_stderr(probe_stack) == "probe_limits", "verify_fixture")
    guard_stack = PROBE_GUARD_MARKER + probe_stack
    need(classify_structured_probe_stderr(guard_stack) == "probe_limits" and
         classify_service_stderr(guard_stack) == "probe_limits", "verify_fixture")
    early_guard_stack = guard_stack.replace(
        b"    at async " + PROBE_WRAPPER_URL.encode("ascii") + b":11:15",
        b"    at " + PROBE_WRAPPER_URL.encode("ascii") + b":11:9",
    )
    need(classify_probe_stderr(early_guard_stack[len(PROBE_GUARD_MARKER):]) == "probe_limits" and
         classify_structured_probe_stderr(early_guard_stack) == "probe_limits", "verify_fixture")
    unknown_guard_stack = guard_stack.replace(b"validateFacts (file:///source/scripts/ct200-verification/.probe.mjs:33:68)",
                                               b"validateFacts (file:///source/scripts/ct200-verification/.probe.mjs:99:68)")
    need(classify_structured_probe_stderr(unknown_guard_stack) is None and
         classify_service_stderr(unknown_guard_stack) == "unclassified", "verify_fixture")
    native_stack = (
        PROBE_NATIVE_MARKER +
        b"node:fs:562\n  return binding.open(\n                 ^\n\n" +
        b"Error: EACCES: permission denied, open '/proof-input.txt'\n" +
        b"    at Module.openSync (node:fs:562:18)\n" +
        b"    at readRegular (file:///source/scripts/ct200-verification/.probe.mjs:56:17)\n" +
        b"    at Module.probe (file:///source/scripts/ct200-verification/.probe.mjs:140:51)\n" +
        b"    at async file:///source/.ct200-wrapper.mjs:11:15 {\n" +
        b"  errno: -13,\n  code: 'EACCES',\n  syscall: 'open',\n  path: '/proof-input.txt'\n}\n\nNode.js v22.14.0\n"
    )
    need(classify_structured_probe_stderr(native_stack) == "probe_native_error" and
         classify_service_stderr(native_stack) == "probe_native_error", "verify_fixture")
    need(PROBE_OPEN_CALLS["/probe-config.json"] == ((("readRegular", 56), ("Module.probe", 126)),) and
         PROBE_OPEN_CALLS["/proc/self/status"] == ((("readBounded", 51), ("Module.probe", 127)),) and
         PROBE_OPEN_CALLS["/proof-input.txt"] == (
             (("readRegular", 56), ("Module.probe", 140)), (("Module.probe", 142),)) and
         all(probe_open_call_sequences(path) == () for path in
             ("/.limits/memory.max", "/.limits/memory.swap.max", "/.limits/pids.max", "/.limits/cpu.max")) and
         probe_open_call_sequences("/work/isolation-write-" + "a" * 32) == ((("Module.probe", 148),),) and
         probe_open_call_sequences("/root") == () and "rootUnavailable" not in PROBE_FRAME_LINES,
         "verify_fixture")
    native_without_context = native_stack.replace(
        b"node:fs:562\n  return binding.open(\n                 ^\n\n", b"", 1)
    need(classify_structured_probe_stderr(native_without_context) == "probe_native_error" and
         classify_service_stderr(native_without_context) == "probe_native_error", "verify_fixture")
    early_native_stack = (
        PROBE_NATIVE_MARKER +
        b"node:fs:562\n  return binding.open(\n                 ^\n\n" +
        b"Error: ENOENT: no such file or directory, open '/proc/self/status'\n" +
        b"    at Object.openSync (node:fs:562:18)\n" +
        b"    at readBounded (file:///source/scripts/ct200-verification/.probe.mjs:51:14)\n" +
        b"    at Module.probe (file:///source/scripts/ct200-verification/.probe.mjs:127:20)\n" +
        b"    at file:///source/.ct200-wrapper.mjs:11:9 {\n" +
        b"  errno: -2,\n  code: 'ENOENT',\n  syscall: 'open',\n  path: '/proc/self/status'\n}\n\nNode.js v22.14.0\n"
    )
    need(classify_structured_probe_stderr(early_native_stack) == "probe_native_error" and
         classify_service_stderr(early_native_stack) == "probe_native_error", "verify_fixture")
    for malformed_structured in (
        guard_stack.replace(b"isolation verification rejected", b"other rejection", 1),
        native_stack.replace(b"Error: EACCES:", b"Error: EXOTIC:", 1),
        native_stack.replace(b"node:fs:562:18", b"node:internal:562:18", 1),
        native_stack.replace(b".probe.mjs:140:51", b".probe.mjs:108:51"),
        native_stack.replace(b"'/proof-input.txt'", b"'/root'").replace(b"path: '/proof-input.txt'", b"path: '/root'"),
        native_stack.replace(b".ct200-wrapper.mjs:11:15", b".ct200-wrapper.mjs:12:15"),
        native_stack.replace(b".ct200-wrapper.mjs:11:15 {\n", b".ct200-wrapper.mjs:11:15 {\n    at extra (node:fs:562:18)\n"),
        early_native_stack.replace(b"at file:///source/.ct200-wrapper.mjs:11:9", b"at file:///root/[eval1]:11:9"),
        early_native_stack.replace(b"at file:///source/.ct200-wrapper.mjs:11:9", b"at file:///source/.ct200-wrapper.mjs:12:9"),
        native_stack + b"extra output\n",
        guard_stack + PROBE_GUARD_MARKER,
        native_stack + b"x" * MAX_SERVICE_STDERR,
    ):
        need(classify_structured_probe_stderr(malformed_structured) is None, "verify_fixture")
    object_stack = probe_stack.replace(
        b"    at validateFacts (" + PROBE_SOURCE_URL.encode("ascii") + b":33:68)",
        b"    at object (" + PROBE_SOURCE_URL.encode("ascii") + b":9:71)\n    at Module.validateFacts (" + PROBE_SOURCE_URL.encode("ascii") + b":26:3)"
    ).replace(b"    at Module.probe", b"    at Module.probe")
    need(classify_probe_stderr(object_stack) == "probe_facts_shape", "verify_fixture")
    for malformed_probe in (
        probe_stack.replace(PROBE_SOURCE_URL.encode("ascii"), b"file:///tmp/.probe.mjs"),
        probe_stack.replace(b".probe.mjs:166:10", b".probe.mjs:131:10"),
        probe_stack.replace(b"validateFacts (" + PROBE_SOURCE_URL.encode("ascii") + b":33:68)",
                            b"validateFacts (" + PROBE_SOURCE_URL.encode("ascii") + b":99:68)"),
        probe_stack.replace(b"    at Module.probe", b"    at arbitrary (" + PROBE_SOURCE_URL.encode("ascii") + b":166:10)\n    at Module.probe"),
        probe_stack.replace(b"Node.js v22.14.0", b"Node.js v24.13.0"),
        probe_stack + b"spoofed extra line\n",
        probe_stack + b"x" * MAX_SERVICE_STDERR,
    ):
        need(classify_probe_stderr(malformed_probe) == "unclassified", "verify_fixture")
    need(classify_service_stderr(b"Error: isolation verification rejected\n") == "unclassified", "verify_fixture")
    need(classify_service_stderr(b"unshare: unshare failed: Invalid argument\n") == "launcher" and
         classify_service_stderr(b"setpriv: setresuid failed: Operation not permitted\n") == "permission" and
         classify_service_stderr(b"SyntaxError: Unexpected token\n") == "node_syntax" and
         classify_service_stderr(b"Error [ERR_MODULE_NOT_FOUND]: Cannot find package\n") == "node_module" and
         classify_service_stderr(b"probe usage rejected\n") == "unclassified" and
         classify_service_stderr(b"Error: exact unit oracle failed\n") == "control" and
         classify_service_stderr(b"private unrecognized text\n") == "unclassified" and
         classify_service_stderr(b"ignored", True) == "overflow" and
         classify_service_stderr(b"x" * (MAX_SERVICE_STDERR + 1)) == "unclassified", "verify_fixture")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"receipt")
        os.close(write_fd)
        write_fd = None
        service_output = bytearray()
        service_diagnostic = bytearray()
        pipe_open, overflow = consume_service_pipe(read_fd, "stdout", service_output, service_diagnostic, False)
        need(pipe_open and not overflow and service_output == b"receipt" and not consume_service_pipe(
            read_fd, "stdout", service_output, service_diagnostic, overflow)[0], "verify_fixture")
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
    read_fd, write_fd = os.pipe()
    try:
        service_output = bytearray()
        service_diagnostic = bytearray()
        overflow = False
        for chunk in (b"x" * 4096, b"y" * 4096, b"z"):
            os.write(write_fd, chunk)
            pipe_open, overflow = consume_service_pipe(read_fd, "stderr", service_output, service_diagnostic, overflow)
            need(pipe_open, "verify_fixture")
        os.close(write_fd)
        write_fd = None
        need(len(service_diagnostic) == MAX_SERVICE_STDERR and overflow and
             not consume_service_pipe(read_fd, "stderr", service_output, service_diagnostic, overflow)[0] and
             classify_service_stderr(bytes(service_diagnostic), overflow) == "overflow", "verify_fixture")
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
    original_pipe_consumer = globals()["consume_service_pipe"]
    original_capture = globals()["capture_queued_service_stderr"]
    original_service_diagnostic = SERVICE_DIAGNOSTIC

    class ReadyDiagnosticSelector:
        def __init__(self, key):
            self.key = key
            self.ready = True
            self.timeouts = []
            self.unregistered = []

        def select(self, timeout):
            self.timeouts.append(timeout)
            if self.ready:
                self.ready = False
                return [(self.key, selectors.EVENT_READ)]
            return []

        def unregister(self, fileobj):
            self.unregistered.append(fileobj)

    fixture_key = SimpleNamespace(fd=71, data="stderr", fileobj="fixture-stderr")
    diagnostic_selector = ReadyDiagnosticSelector(fixture_key)
    diagnostic_output = bytearray()
    diagnostic_bytes = bytearray()
    diagnostic_reads = []

    def fixture_pipe_consumer(fd, stream_kind, output_buffer, diagnostic_buffer, overflow):
        need(fd == 71 and stream_kind == "stderr" and output_buffer is diagnostic_output and
             diagnostic_buffer is diagnostic_bytes, "verify_fixture")
        diagnostic_reads.append((fd, stream_kind))
        overflow = append_bounded_diagnostic(diagnostic_buffer, b"SyntaxError: fixture\n") or overflow
        return True, overflow

    try:
        globals()["consume_service_pipe"] = fixture_pipe_consumer
        need(capture_queued_service_stderr(diagnostic_selector, diagnostic_output, diagnostic_bytes, False) == "node_syntax" and
             diagnostic_bytes == b"SyntaxError: fixture\n" and diagnostic_reads == [(71, "stderr")] and
             diagnostic_selector.timeouts == [0, 0], "verify_fixture")

        overflow_selector = ReadyDiagnosticSelector(fixture_key)
        overflow_output = bytearray()
        overflow_bytes = bytearray()

        def fixture_overflow_consumer(fd, stream_kind, output_buffer, diagnostic_buffer, overflow):
            need(fd == 71 and stream_kind == "stderr", "verify_fixture")
            overflow = append_bounded_diagnostic(diagnostic_buffer, b"x" * (MAX_SERVICE_STDERR + 1)) or overflow
            return True, overflow

        globals()["consume_service_pipe"] = fixture_overflow_consumer
        need(capture_queued_service_stderr(overflow_selector, overflow_output, overflow_bytes, False) == "overflow" and
             len(overflow_bytes) == MAX_SERVICE_STDERR and overflow_selector.timeouts == [0], "verify_fixture")

        class ContinuouslyReadySelector:
            def __init__(self, key):
                self.key = key
                self.timeouts = []

            def select(self, timeout):
                self.timeouts.append(timeout)
                return [(self.key, selectors.EVENT_READ)]

            def unregister(self, _fileobj):
                raise Reject("unexpected_fixture_eof")

        bounded_selector = ContinuouslyReadySelector(fixture_key)
        bounded_output = bytearray()
        bounded_bytes = bytearray()

        def fixture_continuous_consumer(fd, stream_kind, output_buffer, diagnostic_buffer, overflow):
            need(fd == 71 and stream_kind == "stderr", "verify_fixture")
            overflow = append_bounded_diagnostic(diagnostic_buffer, b"x") or overflow
            return True, overflow

        globals()["consume_service_pipe"] = fixture_continuous_consumer
        need(capture_queued_service_stderr(bounded_selector, bounded_output, bounded_bytes, False) == "unclassified" and
             len(bounded_bytes) == 16 and bounded_selector.timeouts == [0] * 16, "verify_fixture")

        def capture_failure(*_args):
            raise RuntimeError("diagnostic capture fixture failure")

        globals()["capture_queued_service_stderr"] = capture_failure
        SERVICE_DIAGNOSTIC = "control"
        original_error = Reject("unit_main_membership")
        try:
            try:
                raise original_error
            except BaseException:
                refresh_service_diagnostic(diagnostic_selector, diagnostic_output, diagnostic_bytes, False)
                raise
        except Reject as caught_error:
            need(caught_error is original_error and SERVICE_DIAGNOSTIC == "unclassified", "verify_fixture")
    finally:
        globals()["consume_service_pipe"] = original_pipe_consumer
        globals()["capture_queued_service_stderr"] = original_capture
        SERVICE_DIAGNOSTIC = original_service_diagnostic

    saved_scratch = (SCRATCH, SCRATCH_ID, SCRATCH_FD)
    globals()["SCRATCH"], globals()["SCRATCH_ID"], globals()["SCRATCH_FD"] = ("/fixture/private-scratch", (77, 88), 701)

    def retention_fixture(kind="normal"):
        state = {"contents": bytearray(), "exists": False, "opened": False, "closed": [], "flags": None, "interrupted": False}

        def scratch_info():
            inode = 89 if kind == "scratch_custody" or (kind == "scratch_changed" and state["contents"]) else 88
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_dev=77, st_ino=inode, st_uid=0)

        def file_info():
            link_count = 2 if kind == "file_custody" else 1
            file_mode = stat.S_IFLNK | 0o777 if kind == "file_custody" else stat.S_IFREG | 0o600
            inode = 91 if kind == "replace_after_close" and state["closed"] else 90
            return SimpleNamespace(st_mode=file_mode, st_dev=77, st_ino=inode, st_nlink=link_count,
                                   st_uid=0, st_size=len(state["contents"]))

        def fixture_open(name, flags, mode, *, dir_fd):
            need(name == "service-stderr.bin" and dir_fd == 701 and mode == 0o600 and
                 flags == (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) |
                           getattr(os, "O_CLOEXEC", 0)), "verify_fixture")
            state["flags"] = flags
            if kind in ("collision", "symlink"):
                state["exists"] = True
                raise FileExistsError(errno.EEXIST, "fixture collision")
            state["exists"] = True
            state["opened"] = True
            return 702

        def fixture_close(fd):
            need(fd == 702, "verify_fixture")
            state["closed"].append(fd)
            if kind == "close_error":
                raise OSError(errno.EIO, "fixture close error")

        def fixture_fstat(fd):
            if fd == 701:
                return scratch_info()
            need(fd == 702, "verify_fixture")
            return file_info()

        def fixture_lstat(name):
            need(name == "/fixture/private-scratch", "verify_fixture")
            return scratch_info()

        def fixture_stat_at(name, *, dir_fd, follow_symlinks):
            need(name == "service-stderr.bin" and dir_fd == 701 and follow_symlinks is False, "verify_fixture")
            if not state["exists"]:
                raise FileNotFoundError(errno.ENOENT, "fixture absent")
            return file_info()

        def fixture_fchmod(fd, mode):
            need(fd == 702 and mode == 0o600, "verify_fixture")

        def fixture_write(fd, data):
            need(fd == 702, "verify_fixture")
            if kind == "diskfull":
                raise OSError(errno.ENOSPC, "fixture full")
            if kind == "eintr" and not state["interrupted"]:
                state["interrupted"] = True
                raise InterruptedError(errno.EINTR, "fixture interrupted")
            count = min(len(data), 13 if kind in ("short", "eintr") else len(data))
            state["contents"].extend(data[:count])
            return count

        ops = {"open": fixture_open, "close": fixture_close, "fstat": fixture_fstat, "lstat": fixture_lstat,
               "stat_at": fixture_stat_at, "fchmod": fixture_fchmod, "write": fixture_write}
        return state, ops

    try:
        for payload, kind in ((b"", "normal"), (bytes(range(256)) * 32, "short")):
            state, ops = retention_fixture(kind)
            need(retain_service_stderr(payload, ops) is None and bytes(state["contents"]) == payload and
                 state["closed"] == [702] and state["flags"] is not None, "verify_fixture")
        overflow_bytes = bytearray()
        overflowed = append_bounded_diagnostic(overflow_bytes, b"z" * (MAX_SERVICE_STDERR + 1))
        state, ops = retention_fixture()
        need(overflowed and len(overflow_bytes) == MAX_SERVICE_STDERR and
             retain_service_stderr(bytes(overflow_bytes), ops) is None and
             bytes(state["contents"]) == b"z" * MAX_SERVICE_STDERR and state["closed"] == [702], "verify_fixture")
        for kind in ("eintr",):
            state, ops = retention_fixture(kind)
            payload = b"binary\x00stderr" * 100
            need(retain_service_stderr(payload, ops) is None and bytes(state["contents"]) == payload and
                 state["interrupted"] and state["closed"] == [702], "verify_fixture")

        untouched = []
        need(not retain_service_stderr_best_effort(b"ignored", failed=False,
                                                   retain_fn=lambda data: untouched.append(data)) and not untouched,
             "verify_fixture")
        for kind in ("collision", "symlink", "file_custody", "scratch_custody", "scratch_changed",
                     "replace_after_close", "diskfull", "close_error"):
            state, ops = retention_fixture(kind)
            original_error = Reject("unit_main_membership")
            caught_error = None
            try:
                try:
                    raise original_error
                except BaseException:
                    retained = retain_service_stderr_best_effort(
                        b"private failure bytes", retain_fn=lambda data: retain_service_stderr(data, ops))
                    need(not retained, "verify_fixture")
                    raise
            except Reject as caught:
                caught_error = caught
            need(caught_error is original_error and
                 (not state["opened"] or state["closed"] == [702]), "verify_fixture")

        # Exercise both production decision shapes: exception-path retention and
        # normal child-failure retention before the service_result rejection.
        for hook in ("exception", "child_failure"):
            state, ops = retention_fixture()
            original_error = Reject("service_result")
            try:
                try:
                    if hook == "exception":
                        raise original_error
                    retain_service_stderr_best_effort(b"child stderr", retain_fn=lambda data: retain_service_stderr(data, ops))
                    raise original_error
                except BaseException:
                    if hook == "exception":
                        retain_service_stderr_best_effort(b"exception stderr", retain_fn=lambda data: retain_service_stderr(data, ops))
                    raise
            except Reject as caught:
                need(caught is original_error and state["closed"] == [702], "verify_fixture")
    finally:
        globals()["SCRATCH"], globals()["SCRATCH_ID"], globals()["SCRATCH_FD"] = saved_scratch

    located_error_obj = None
    try:
        parse_systemd_properties(b"invalid\n", ("LoadState",))
    except Reject as caught_error:
        located_error_obj = caught_error
        located_info = failure_exception_info(caught_error)
    need(located_info[0] == "reject" and located_info[1] == "systemd_properties" and
         located_info[2] == parse_systemd_properties.__code__.co_firstlineno + 5 and
         1 <= located_info[2] <= MAX_FAILURE_LINE, "verify_fixture")
    located_envelope = failure_envelope(located_error_obj, "preserved", "settled", "retained", "control", located_info)
    need(located_envelope.startswith(b"fixed startup supervisor failed stage=bootstrap category=controlled unit=preserved fixture=settled scratch=retained reason=systemd_properties exception=reject frame=systemd_properties line=") and
         located_envelope.endswith(b" diagnostic=control\n"), "verify_fixture")
    original_cgroup_reader = globals()["read_cgroup_value"]
    cgroup_error_obj = None
    try:
        globals()["read_cgroup_value"] = lambda _cgroup, _name: "wrong"
        try:
            verify_cgroup("/fixture/no-real-path", "fixed.service", set())
        except Reject as cgroup_error:
            cgroup_error_obj = cgroup_error
            cgroup_info = failure_exception_info(cgroup_error)
        else:
            need(False, "verify_fixture")
    finally:
        globals()["read_cgroup_value"] = original_cgroup_reader
    need(cgroup_info == ("reject", "cgroup_validation", verify_cgroup.__code__.co_firstlineno + 3), "verify_fixture")
    cgroup_envelope = failure_envelope(cgroup_error_obj, "preserved", "settled", "retained", "control", cgroup_info)
    need(b"reason=cgroup_limit exception=reject frame=cgroup_validation line=" in cgroup_envelope, "verify_fixture")

    # The earlier active verify_cgroup MainPID/start check must stay fail-closed:
    # disappearance before the later pending-candidate branch is not a terminal proof.
    cgroup_race_path = "/fixture/owned-cgroup"
    cgroup_race_unit = "ct200-startup-" + "2" * 32 + ".service"
    cgroup_race_fields = {"LoadState": "loaded", "ControlGroup": "/system.slice/" + cgroup_race_unit,
                          "MainPID": "321", "InvocationID": "3" * 32, "ActiveState": "active"}
    cgroup_race_stat = SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0)
    saved_cgroup_helpers = {name: globals()[name] for name in ("read_cgroup_value", "systemd_properties", "cgroup_path", "proc_starttime")}
    original_os_lstat = os.lstat
    try:
        globals()["read_cgroup_value"] = lambda _path, name: {
            "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "100000 100000"}[name]
        globals()["systemd_properties"] = lambda _unit: dict(cgroup_race_fields)
        globals()["cgroup_path"] = lambda relative: cgroup_race_path if relative == cgroup_race_fields["ControlGroup"] else "/changed"
        globals()["proc_starttime"] = lambda _pid: (_ for _ in ()).throw(Reject("unit_pid_gone"))
        os.lstat = lambda path: cgroup_race_stat if (
            os.path.normcase(os.path.dirname(path)) == os.path.normcase(os.path.normpath(cgroup_race_path)) and
            os.path.basename(path) in ("memory.max", "memory.swap.max", "pids.max", "cpu.max")
        ) else original_os_lstat(path)
        cgroup_main_race_rejected = False
        try:
            verify_cgroup(cgroup_race_path, cgroup_race_unit, {321},
                          (cgroup_race_fields["InvocationID"], 321, 4567))
        except Reject as error:
            cgroup_main_race_rejected = type(error) is Reject and error.args == ("unit_pid_gone",)
        need(cgroup_main_race_rejected, "verify_fixture")
    finally:
        os.lstat = original_os_lstat
        globals().update(saved_cgroup_helpers)

    for cgroup_reason in ("cgroup_limit", "cgroup_file", "cgroup_identity", "cgroup_main_pid", "cgroup_pid_membership",
                          "unit_main_membership", "unit_pid", "unit_pid_identity", "unit_pid_gone", "unit_pid_reused",
                          "cgroup", "cgroup_path"):
        need(b"reason=" + cgroup_reason.encode("ascii") in failure_envelope(Reject(cgroup_reason), "preserved", "settled", "retained", "control"), "verify_fixture")
    need(b"reason=unclassified" in failure_envelope(Reject("cgroup_unknown"), "preserved", "settled", "retained", "control"), "verify_fixture")
    try:
        read_cgroup_value("/not-accessed", "not-a-cgroup-file")
    except Reject as cgroup_read_error:
        cgroup_read_info = failure_exception_info(cgroup_read_error)
    need(cgroup_read_info == ("reject", "cgroup_read", read_cgroup_value.__code__.co_firstlineno + 1), "verify_fixture")
    try:
        cgroup_path("not-a-fixed-cgroup", root="/not-accessed", lstat=lambda _path: None)
    except Reject as cgroup_path_error:
        cgroup_path_info = failure_exception_info(cgroup_path_error)
    need(cgroup_path_info == ("reject", "cgroup_path", cgroup_path.__code__.co_firstlineno + 1), "verify_fixture")
    def deep_test_failure(depth):
        if depth:
            return deep_test_failure(depth - 1)
        need(False, "service_result")
    try:
        deep_test_failure(MAX_FAILURE_TRACE_FRAMES + 8)
    except Reject as deep_error:
        deep_info = failure_exception_info(deep_error)
    need(deep_info == ("reject", "unlocated", 0), "verify_fixture")
    try:
        raise RuntimeError("private/path" + "x" * 100000)
    except RuntimeError as unknown_error:
        unknown_info = failure_exception_info(unknown_error)
        unknown_envelope = failure_envelope(unknown_error, "preserved", "settled", "retained", "unknown", unknown_info)
    need(unknown_info == ("other", "unlocated", 0) and len(unknown_envelope) < 512 and
         b"private/path" not in unknown_envelope and b"unknown" not in unknown_envelope, "verify_fixture")
    try:
        raise ValueError("untrusted detail")
    except ValueError as known_error:
        known_info = failure_exception_info(known_error)
    need(known_info == ("value_error", "unlocated", 0), "verify_fixture")
    hostile_info = failure_envelope(Reject("service_result"), "preserved", "settled", "retained", "control",
                                    ("untrusted_class", "C:/private/path", MAX_FAILURE_LINE + 1))
    need(hostile_info.endswith(b"exception=other frame=unlocated line=0 diagnostic=control\n") and len(hostile_info) < 512, "verify_fixture")
    bare_envelope = failure_envelope(Reject("service_result"), "preserved", "settled", "retained", "control")
    need(bare_envelope == b"fixed startup supervisor failed stage=bootstrap category=controlled unit=preserved fixture=settled scratch=retained reason=service_result exception=reject frame=unlocated line=0 diagnostic=control\n" and
         b"private" not in failure_envelope(Reject("private/path"), "preserved", "settled", "retained", "unknown"), "verify_fixture")
    need(validate_systemd_version(SYSTEMD_VERSION_LINE + b"\n+PAM +AUDIT +APPARMOR\n"), "verify_fixture")
    for bad_version in (
        b"systemd 252 (252.4-1ubuntu8.17)\n",
        b"systemd 256 (256.4-1ubuntu8.17)\n",
        b"systemd 255 (255.4-1ubuntu8.16)\n",
        SYSTEMD_VERSION_LINE + b"\r\n",
        SYSTEMD_VERSION_LINE,
        "systemd 255 (255.4-1ubuntu8.17)\n",
        bytearray(SYSTEMD_VERSION_LINE + b"\n"),
        SYSTEMD_VERSION_LINE + b"\n" + b"x" * 4096,
    ):
        rejected = False
        try:
            validate_systemd_version(bad_version)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    def elf_fixture(string_size=96, needed_offset=1, segment_escape=False, duplicate_load=False,
                    bad_load_file_bound=False, tag_case="normal"):
        phnum = 3 if duplicate_load else 2
        dynoff = 64 + 56 * phnum
        table_off = (dynoff + 256 + 15) & ~15
        base = 0x400000
        table = bytearray(string_size)
        if string_size > 11:
            table[1:11] = b"libc.so.6\0"
        tags = [(5, base + table_off), (10, string_size), (1, needed_offset)]
        if tag_case == "duplicate_strtab":
            tags.insert(1, (5, base + table_off))
        elif tag_case == "duplicate_strsz":
            tags.insert(2, (10, string_size))
        elif tag_case == "missing_strtab":
            tags = tags[1:]
        elif tag_case == "missing_strsz":
            tags = [tags[0]] + tags[2:]
        if tag_case != "missing_null":
            tags.append((0, 0))
        if tag_case == "after_null":
            tags.append((1, needed_offset))
        dynamic_size = len(tags) * 16
        table_off = (dynoff + dynamic_size + 15) & ~15
        # Rebuild the address-dependent dynamic tag after sizing the table location.
        for index, (tag, value) in enumerate(tags):
            if tag == 5:
                tags[index] = (tag, base + table_off)
        image_size = table_off + string_size
        image = bytearray(image_size)
        ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        struct.pack_into("<16sHHIQQQIHHHHHH", image, 0, ident, 3, 62, 1, 0, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
        load_size = table_off + string_size - 1 if segment_escape else image_size
        if bad_load_file_bound:
            load_size = image_size + 1
        load = (1, 4, 0, base, 0, load_size, max(image_size, load_size), 0x1000)
        dynamic = (2, 4, dynoff, base + dynoff, 0, dynamic_size, dynamic_size, 8)
        rows = [load, dynamic]
        if duplicate_load:
            rows.append((1, 4, 0, base, 0, image_size, image_size, 0x1000))
        for index, row in enumerate(rows):
            struct.pack_into("<IIQQQQQQ", image, 64 + index * 56, *row)
        for index, (tag, value) in enumerate(tags):
            struct.pack_into("<qQ", image, dynoff + index * 16, tag, value)
        if string_size > 11:
            image[table_off:table_off + string_size] = table
        return bytes(image)

    large_elf = elf_fixture(string_size=7753645)
    need(_parse_elf_image(large_elf) == (None, ("libc.so.6",)), "verify_fixture")
    for malformed_elf in (
        elf_fixture(string_size=ELF_STRTAB_MAX + 1),
        elf_fixture(string_size=4096, segment_escape=True),
        elf_fixture(string_size=4096, duplicate_load=True),
        elf_fixture(string_size=4096, bad_load_file_bound=True),
        elf_fixture(string_size=4096, needed_offset=4096),
        elf_fixture(string_size=4096, needed_offset=4095),
        elf_fixture(string_size=4096, tag_case="duplicate_strtab"),
        elf_fixture(string_size=4096, tag_case="duplicate_strsz"),
        elf_fixture(string_size=4096, tag_case="missing_strtab"),
        elf_fixture(string_size=4096, tag_case="missing_strsz"),
        elf_fixture(string_size=4096, tag_case="missing_null"),
        elf_fixture(string_size=4096, tag_case="after_null"),
    ):
        rejected = False
        try:
            _parse_elf_image(malformed_elf)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    stat_pid = 321
    def proc_stat_fixture(pid=stat_pid, comm=b"worker ) (compiler)", state=b"S", start=b"4567", count=20, newline=True):
        fields = [state] + [b"1"] * 18 + [start]
        fields = fields[:count]
        return (str(pid).encode("ascii") + b" (" + comm + b") " + b" ".join(fields) + (b"\n" if newline else b""))
    valid_proc_stat = proc_stat_fixture()
    need(_parse_proc_stat_starttime(valid_proc_stat, stat_pid) == 4567, "verify_fixture")
    for malformed_stat, expected_pid in (
        (proc_stat_fixture(pid=stat_pid + 1), stat_pid),
        (proc_stat_fixture(newline=False), stat_pid),
        (proc_stat_fixture(start=b"bad"), stat_pid),
        (proc_stat_fixture(count=19), stat_pid),
        (proc_stat_fixture(state=b"?"), stat_pid),
        (proc_stat_fixture(start=b"1" * 21), stat_pid),
        (valid_proc_stat + b"x" * 4096, stat_pid),
    ):
        rejected = False
        try:
            _parse_proc_stat_starttime(malformed_stat, expected_pid)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    def unit_pid_reader_error(error):
        def fail_open(_path, _flags):
            raise error
        def fail_lstat(_path):
            raise error
        return {"open": fail_open, "fstat": lambda _fd: None, "lstat": fail_lstat,
                "read": lambda _fd, _amount: b"", "close": lambda _fd: None}
    for reader_error, expected_reason in ((OSError(errno.ENOENT, "gone"), "unit_pid_gone"),
                                          (OSError(errno.EACCES, "denied"), "unit_pid")):
        try:
            _read_proc_stat(stat_pid, unit_pid_reader_error(reader_error))
            need(False, "verify_fixture")
        except Reject as caught:
            need(caught.args == (expected_reason,), "verify_fixture")

    gone_unit = "ct200-startup-" + "1" * 32 + ".service"
    gone_fields = {"LoadState": "loaded", "ControlGroup": "/system.slice/" + gone_unit,
                   "MainPID": "321", "InvocationID": "2" * 32, "ActiveState": "active"}
    gone_cgroup = "/sys/fs/cgroup" + gone_fields["ControlGroup"]
    gone_context = {"unit": gone_unit, "fields": dict(gone_fields), "cgroup": gone_cgroup, "cgroup_id": (7, 11),
                    "main_pid": 321, "main_start": 4567, "rootfs_id": (9, 13), "executable_id": (9, 17),
                    "argv_bytes": b"/fixture/unshare\x00"}
    gone_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=7, st_ino=11)
    def gone_fixture(changes=None):
        changes = {} if changes is None else changes
        state = {"proc": 0, "properties": 0, "cgroup": 0}
        def lstat_proc(path):
            need(path == "/proc/654", "verify_fixture")
            state["proc"] += 1
            condition = changes.get("proc", "gone")
            if condition == "present":
                return gone_stat
            if condition == "second_present" and state["proc"] == 2:
                return gone_stat
            code = errno.EACCES if condition == "denied" or (condition == "second_denied" and state["proc"] == 2) else errno.ENOENT
            raise OSError(code, "fixture")
        def properties(unit):
            need(unit == gone_unit, "verify_fixture")
            state["properties"] += 1
            value = dict(gone_fields)
            if changes.get("properties") == "main" or (changes.get("properties") == "second_main" and state["properties"] == 2):
                value["MainPID"] = "322"
            if changes.get("properties") == "invocation":
                value["InvocationID"] = "3" * 32
            if changes.get("properties") == "inactive":
                value["ActiveState"] = "inactive"
            return value
        def stat_cgroup(path):
            need(path == gone_cgroup, "verify_fixture")
            state["cgroup"] += 1
            if changes.get("cgroup") == "swap" and state["cgroup"] == 2:
                return SimpleNamespace(st_mode=gone_stat.st_mode, st_uid=0, st_dev=7, st_ino=12)
            if changes.get("cgroup") == "mode":
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_dev=7, st_ino=11)
            if changes.get("cgroup") == "owner":
                return SimpleNamespace(st_mode=gone_stat.st_mode, st_uid=1000, st_dev=7, st_ino=11)
            return gone_stat
        def start(pid):
            need(pid == 321, "verify_fixture")
            return 4568 if changes.get("main_start") else 4567
        ops = {"lstat_proc": lstat_proc, "systemd_properties": properties,
               "cgroup_path": lambda relative: "/changed" if changes.get("path") else
                   gone_cgroup if relative == gone_fields["ControlGroup"] else "/changed",
               "lstat_cgroup": stat_cgroup,
               "read_pids": lambda path: ((lambda: (_ for _ in ()).throw(Reject("cgroup_processes")))() if changes.get("pids_error") else
                   changes.get("pids", {321}) if path == gone_cgroup else {321}),
               "proc_starttime": start,
               "service_process_matches": lambda pid, start_time, root, executable, argv:
                   pid == 321 and start_time == 4567 and root == (9, 13) and executable == (9, 17) and
                   argv == b"/fixture/unshare\x00" and not changes.get("main_matches", False)}
        return ops, state
    valid_gone_ops, valid_gone_state = gone_fixture()
    need(confirm_gone_non_main_pid(654, gone_context, valid_gone_ops) and valid_gone_state["proc"] == 2 and
         valid_gone_state["properties"] == 2, "verify_fixture")
    for gone_changes in (
        {"proc": "present"}, {"proc": "second_present"}, {"proc": "denied"}, {"proc": "second_denied"},
        {"properties": "main"}, {"properties": "second_main"}, {"properties": "invocation"}, {"properties": "inactive"},
        {"cgroup": "swap"}, {"cgroup": "mode"}, {"cgroup": "owner"}, {"pids": {321, 654}},
        {"pids": [321, "654"]}, {"pids_error": True}, {"path": True}, {"main_start": True}, {"main_matches": True},
    ):
        bad_ops, _bad_state = gone_fixture(gone_changes)
        need(not confirm_gone_non_main_pid(654, gone_context, bad_ops), "verify_fixture")
    for context_key, changed_value in (("rootfs_id", (9, 14)), ("executable_id", (9, 18)),
                                      ("argv_bytes", b"/fixture/other\x00"), ("cgroup_id", (7, 12))):
        changed_context = dict(gone_context)
        changed_context[context_key] = changed_value
        changed_ops, _changed_state = gone_fixture()
        need(not confirm_gone_non_main_pid(654, changed_context, changed_ops), "verify_fixture")
    main_gone_ops, _main_gone_state = gone_fixture()
    need(not confirm_gone_non_main_pid(321, gone_context, main_gone_ops), "verify_fixture")
    for seen in (None, {}):
        target = {}
        seen_before = None if seen is None else dict(seen)
        try:
            def exact_gone_start(_pid):
                raise Reject("unit_pid_gone")
            track_unit_pid(654, 321, target, gone_context, seen, exact_gone_start,
                           lambda pid, context: confirm_gone_non_main_pid(pid, context, gone_fixture()[0]))
        except Reject:
            need(False, "verify_fixture")
        need(target == {} and (seen is None or seen == seen_before), "verify_fixture")
    for known_in_target, known_in_seen in ((True, False), (False, True), (True, True)):
        target = {654: 4444} if known_in_target else {}
        seen = {654: 4444} if known_in_seen else None
        before_target = dict(target)
        before_seen = None if seen is None else dict(seen)
        confirms = []
        need(not track_unit_pid(654, 321, target, gone_context, seen,
                                lambda _pid: (_ for _ in ()).throw(Reject("unit_pid_gone")),
                                lambda _pid, _context: confirms.append(True) or True) and
             target == before_target and seen == before_seen and confirms == [True], "verify_fixture")

        original = Reject("unit_pid_gone")
        confirms = []
        try:
            track_unit_pid(654, 321, target, gone_context, seen,
                           lambda _pid: (_ for _ in ()).throw(original),
                           lambda _pid, _context: confirms.append(True) or False)
            need(False, "verify_fixture")
        except Reject as caught:
            need(caught is original, "verify_fixture")
        need(target == before_target and seen == before_seen and confirms == [True], "verify_fixture")
        for next_start, accepted in ((4444, True), (5555, False)):
            target_after = dict(before_target)
            seen_after = None if before_seen is None else dict(before_seen)
            try:
                result = track_unit_pid(654, 321, target_after, gone_context, seen_after,
                                        lambda _pid, value=next_start: value, lambda _pid, _context: False)
            except Reject as caught:
                need(not accepted and caught.args == ("unit_pid_reused",) and
                     target_after == before_target and seen_after == before_seen, "verify_fixture")
            else:
                need(accepted and result and target_after == {654: 4444} and
                     (seen_after is None if seen is None else seen_after == {654: 4444}), "verify_fixture")
    live_target = {}
    live_seen = {}
    need(track_unit_pid(654, 321, live_target, gone_context, live_seen, lambda _pid: 5555,
                        lambda _pid, _context: False) and live_target == {654: 5555} and live_seen == {654: 5555},
         "verify_fixture")
    original = Reject("unit_pid_gone")
    try:
        track_unit_pid(654, 321, {}, gone_context, {}, lambda _pid: (_ for _ in ()).throw(original),
                       lambda _pid, _context: False)
        need(False, "verify_fixture")
    except Reject as caught:
        need(caught is original, "verify_fixture")
    for non_gone in (Reject("unit_pid"), Reject("unit_pid_identity")):
        try:
            track_unit_pid(654, 321, {}, gone_context, {}, lambda _pid, error=non_gone: (_ for _ in ()).throw(error),
                           lambda _pid, _context: need(False, "verify_fixture"))
            need(False, "verify_fixture")
        except Reject as caught:
            need(caught is non_gone, "verify_fixture")
    main_pid_error = Reject("unit_pid_gone")
    try:
        track_unit_pid(321, 321, {}, gone_context, {}, lambda _pid: (_ for _ in ()).throw(main_pid_error),
                       lambda _pid, _context: need(False, "verify_fixture"))
        need(False, "verify_fixture")
    except Reject as caught:
        need(caught is main_pid_error, "verify_fixture")
    try:
        track_unit_pid(654, 321, {}, gone_context, {654: 4444}, lambda _pid: 5555,
                       lambda _pid, _context: False)
        need(False, "verify_fixture")
    except Reject as caught:
        need(caught.args == ("unit_pid_reused",), "verify_fixture")

    exit_unit = gone_unit
    exit_cgroup = gone_cgroup
    exit_fields = {"LoadState": "loaded", "ControlGroup": gone_fields["ControlGroup"], "MainPID": "0",
                   "InvocationID": gone_fields["InvocationID"], "ActiveState": "deactivating"}
    exit_context = {"unit": exit_unit, "cgroup": exit_cgroup, "cgroup_id": (7, 11),
                    "invocation": gone_fields["InvocationID"], "main_pid": 321, "main_start": 4567}
    exit_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=7, st_ino=11)

    def main_exit_fixture(changes=None):
        changes = {} if changes is None else changes
        state = {"proc": {}, "properties": 0, "cgroup": 0}
        fields = dict(exit_fields)
        if changes.get("main_pid") == "original":
            fields["MainPID"] = "321"
            fields["ActiveState"] = "active"
        elif changes.get("main_pid") == "zero_active":
            fields["ActiveState"] = "active"
        elif changes.get("main_pid") == "different":
            fields["MainPID"] = "322"
        if changes.get("invocation"):
            fields["InvocationID"] = "3" * 32
        if changes.get("path"):
            fields["ControlGroup"] = "/system.slice/other.service"

        def lstat_proc(path):
            state["proc"][path] = state["proc"].get(path, 0) + 1
            target = "/proc/321" if (changes.get("root_present") or changes.get("root_denied")) and path == "/proc/321" else "/proc/654"
            if path == target and changes.get("root_denied"):
                raise OSError(errno.EACCES, "fixture")
            if path == target and changes.get("root_present"):
                return gone_stat
            raise OSError(errno.ENOENT, "fixture")

        def properties(_unit):
            state["properties"] += 1
            if changes.get("properties_change"):
                changed = dict(fields)
                changed["InvocationID"] = "4" * 32
                return changed
            return dict(fields)

        def stat_cgroup(_path):
            state["cgroup"] += 1
            if changes.get("cgroup_swap") and state["cgroup"] == 2:
                return SimpleNamespace(st_mode=exit_stat.st_mode, st_uid=0, st_dev=7, st_ino=12)
            return exit_stat

        pids = changes.get("pids", {654, 655})
        ops = {"owned_unit_settled": lambda _fields, _unit: changes.get("settled", True),
               "lstat_proc": lstat_proc, "systemd_properties": properties,
               "cgroup_path": lambda relative: exit_cgroup if relative == exit_fields["ControlGroup"] and not changes.get("path") else "/changed",
               "lstat_cgroup": stat_cgroup,
               "read_cgroup_value": lambda _path, name: "999" if changes.get("bad_limit") and name == "cpu.max" else
                   {"memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "100000 100000"}[name],
               "read_pids": lambda _path: pids}
        return ops, state, fields

    valid_exit_ops, valid_exit_state, valid_exit_fields = main_exit_fixture()
    exit_sample = observe_main_exit_phase(valid_exit_fields, exit_context, valid_exit_ops)
    need(exit_sample == (exit_fields, frozenset({654, 655})) and valid_exit_state["proc"].get("/proc/321") == 2 and
         valid_exit_state["properties"] == 1 and valid_exit_state["cgroup"] == 2,
         "verify_fixture")
    # Model the default-15 fast-finish interleaving through the exact helper used by
    # run_isolated: main ENOENT creates a pending state, never a success decision.
    main_candidate_calls = []
    pending_from_main_enoent = main_pid_exit_candidate(
        321, lambda path: main_candidate_calls.append(path) or (_ for _ in ()).throw(OSError(errno.ENOENT, "fixture")))
    need(pending_from_main_enoent and exit_sample is not None and
         main_candidate_calls == ["/proc/321", "/proc/321"], "verify_fixture")
    need(not main_pid_exit_candidate(321, lambda _path: gone_stat) and
         not main_pid_exit_candidate(321, lambda _path: (_ for _ in ()).throw(OSError(errno.EACCES, "fixture"))) and
         not main_pid_exit_candidate(0, lambda _path: gone_stat), "verify_fixture")
    known_exit_pids = {321: 4567, 654: 4444, 655: 5555}
    monitor_gone_ops = {"lstat_proc": lambda _path: (_ for _ in ()).throw(OSError(errno.ENOENT, "fixture")),
                        "systemd_properties": lambda _unit: dict(exit_fields),
                        "cgroup_path": lambda relative: exit_cgroup if relative == exit_fields["ControlGroup"] else "/changed",
                        "lstat_cgroup": lambda _path: exit_stat, "read_pids": lambda _path: {654}}

    def monitor_confirm(pid, context, known):
        member_context = {**context, "fields": dict(exit_fields), "accounted_pids": frozenset({654})}
        return confirm_gone_non_main_after_main_exit(pid, member_context, known, monitor_gone_ops)

    # Exercise the production scheduling+terminal-proof composition: child exit happens
    # before the next poll, and only the due terminal observation can prove the phase.
    monitor_known = dict(known_exit_pids)
    monitor_seen = dict(known_exit_pids)
    monitor_deferred = set()
    monitor_read_calls = []
    monitor_properties = [dict(gone_fields), dict(valid_exit_fields)]

    def monitor_read(_unit):
        monitor_read_calls.append(_unit)
        return monitor_properties.pop(0)

    def monitor_start(pid):
        if pid == 655:
            raise Reject("unit_pid_gone")
        return {654: 4444}[pid]

    def monitor_track(pid, _main_pid, _known, _context, _seen):
        if pid == 321:
            raise Reject("unit_pid_gone")

    first_poll = service_monitor_poll_step(True, False, False, True, 0.0, 0.0, exit_unit, exit_context,
                                          monitor_known, monitor_seen, monitor_deferred, _read=monitor_read,
                                          _observe=lambda fields, context: observe_main_exit_phase(fields, context, valid_exit_ops),
                                          _start=monitor_start, _confirm=monitor_confirm)
    need(first_poll == (True, gone_fields, False, False, False, 0.25) and len(monitor_read_calls) == 1,
         "verify_fixture")
    pending_main = main_pid_exit_candidate(321, lambda _path: (_ for _ in ()).throw(OSError(errno.ENOENT, "fixture")))
    need(pending_main, "verify_fixture")
    active_members_pending = track_active_unit_members(
        [321, 654, 655], exit_context, monitor_known, monitor_seen, monitor_deferred,
        _track=monitor_track, _start=monitor_start, _candidate=lambda pid: pid == 321)
    need(active_members_pending and monitor_deferred == {655} and
         monitor_known == known_exit_pids and monitor_seen == known_exit_pids, "verify_fixture")
    terminal_ops, _terminal_state, terminal_fields = main_exit_fixture({"pids": {654}})
    between_polls = service_monitor_poll_step(False, True, False, True, 0.1, first_poll[5], exit_unit, exit_context,
                                               monitor_known, monitor_seen, monitor_deferred, _read=monitor_read,
                                               _observe=lambda fields, context: observe_main_exit_phase(fields, context, terminal_ops),
                                               _start=monitor_start, _confirm=monitor_confirm)
    need(between_polls == (False, None, False, True, False, 0.25) and len(monitor_read_calls) == 1,
         "verify_fixture")
    terminal_poll = service_monitor_poll_step(False, True, False, True, 0.25, between_polls[5], exit_unit, exit_context,
                                              monitor_known, monitor_seen, monitor_deferred, _read=monitor_read,
                                              _observe=lambda fields, context: observe_main_exit_phase(fields, context, terminal_ops),
                                              _start=monitor_start, _confirm=monitor_confirm)
    need(terminal_poll[0] and terminal_poll[2] and terminal_poll[3] and terminal_poll[4] and
         terminal_poll[1] == terminal_fields and monitor_read_calls == [exit_unit, exit_unit] and
         monitor_deferred == {655} and
         monitor_known == known_exit_pids and monitor_seen == known_exit_pids,
         "verify_fixture")

    changed_unit_rejected = False
    try:
        service_monitor_poll_step(False, True, False, True, 0.25, 0.25, exit_unit, exit_context,
                                  dict(known_exit_pids), dict(known_exit_pids), set(),
                                  _read=lambda _unit: {**exit_fields, "InvocationID": "f" * 32},
                                  _observe=lambda fields, context: observe_main_exit_phase(fields, context, valid_exit_ops),
                                  _start=monitor_start)
    except Reject:
        changed_unit_rejected = True
    need(changed_unit_rejected, "verify_fixture")
    changed_member_rejected = False
    try:
        service_monitor_poll_step(False, True, False, True, 0.25, 0.25, exit_unit, exit_context,
                                  dict(known_exit_pids), dict(known_exit_pids), set(),
                                  _read=lambda _unit: dict(exit_fields),
                                  _observe=lambda fields, context: observe_main_exit_phase(fields, context, valid_exit_ops),
                                  _start=lambda pid: {654: 9999, 655: 5555}[pid])
    except Reject as error:
        changed_member_rejected = type(error) is Reject and error.args == ("unit_pid_reused",)
    need(changed_member_rejected, "verify_fixture")
    omitted_terminal_proof_rejected = False
    try:
        service_monitor_poll_step(False, True, False, True, 0.25, 0.25, exit_unit, exit_context,
                                  dict(known_exit_pids), dict(known_exit_pids), set(),
                                  _read=lambda _unit: dict(exit_fields), _observe=lambda _fields, _context: None,
                                  _start=monitor_start)
    except Reject:
        omitted_terminal_proof_rejected = True
    need(omitted_terminal_proof_rejected, "verify_fixture")

    member_context = {**exit_context, "fields": dict(exit_fields), "accounted_pids": frozenset({655})}
    exit_gone_state = {"proc": {}, "properties": 0, "cgroup": 0}

    def exit_gone_proc(path):
        exit_gone_state["proc"][path] = exit_gone_state["proc"].get(path, 0) + 1
        raise OSError(errno.ENOENT, "fixture")

    exit_gone_ops = {"lstat_proc": exit_gone_proc, "systemd_properties": lambda _unit: dict(exit_fields),
                     "cgroup_path": lambda relative: exit_cgroup if relative == exit_fields["ControlGroup"] else "/changed",
                     "lstat_cgroup": lambda _path: exit_stat, "read_pids": lambda _path: {655}}
    need(confirm_gone_non_main_after_main_exit(654, member_context, known_exit_pids, exit_gone_ops) and
         exit_gone_state["proc"].get("/proc/654") == 2 and exit_gone_state["proc"].get("/proc/321") == 2,
         "verify_fixture")

    invalid_exit_fields = []
    for invalid_changes in ({"main_pid": "original"}, {"main_pid": "zero_active"}, {"main_pid": "different"},
                            {"invocation": True}, {"path": True}, {"root_present": True}, {"root_denied": True},
                            {"cgroup_swap": True}, {"bad_limit": True}, {"pids": {321, 654}}):
        invalid_ops, _invalid_state, invalid_fields = main_exit_fixture(invalid_changes)
        try:
            observe_main_exit_phase(invalid_fields, exit_context, invalid_ops)
        except Reject:
            pass
        else:
            invalid_exit_fields.append(invalid_changes)
    changed_props_ops, _changed_props_state, changed_props_fields = main_exit_fixture({"properties_change": True})
    try:
        observe_main_exit_phase(changed_props_fields, exit_context, changed_props_ops)
    except Reject:
        pass
    else:
        invalid_exit_fields.append({"properties_change": True})
    absent_fields = {"LoadState": "not-found", "ControlGroup": "", "MainPID": "0", "InvocationID": "", "ActiveState": "inactive"}
    absent_ops, _absent_state, _absent_fields = main_exit_fixture({"settled": False})
    try:
        observe_main_exit_phase(absent_fields, exit_context, absent_ops)
    except Reject:
        pass
    else:
        invalid_exit_fields.append({"not_found_without_owned_settlement": True})
    need(not invalid_exit_fields, "verify_fixture")

    invalid_exit_member = []
    for invalid_changes in ({"present": "/proc/654"}, {"present": "/proc/321"}, {"denied": "/proc/654"},
                            {"changed_properties": True}, {"cgroup_swap": True}, {"pids": {654}},
                            {"pids": {321, 655}}, {"pids": {999}}):
        member_state = {"proc": {}, "properties": 0, "cgroup": 0}

        def member_proc(path, selected=invalid_changes):
            member_state["proc"][path] = member_state["proc"].get(path, 0) + 1
            if selected.get("present") == path:
                return gone_stat
            if selected.get("denied") == path:
                raise OSError(errno.EACCES, "fixture")
            raise OSError(errno.ENOENT, "fixture")

        def member_properties(_unit, selected=invalid_changes):
            member_state["properties"] += 1
            if selected.get("changed_properties") and member_state["properties"] > 1:
                return {**exit_fields, "InvocationID": "4" * 32}
            return dict(exit_fields)

        def member_cgroup(_path, selected=invalid_changes):
            member_state["cgroup"] += 1
            if selected.get("cgroup_swap") and member_state["cgroup"] == 2:
                return SimpleNamespace(st_mode=exit_stat.st_mode, st_uid=0, st_dev=7, st_ino=12)
            return exit_stat

        member_ops = {"lstat_proc": member_proc, "systemd_properties": member_properties,
                      "cgroup_path": lambda relative: exit_cgroup if relative == exit_fields["ControlGroup"] else "/changed",
                      "lstat_cgroup": member_cgroup, "read_pids": lambda _path, selected=invalid_changes: selected.get("pids", {655})}
        if confirm_gone_non_main_after_main_exit(654, member_context, known_exit_pids, member_ops):
            invalid_exit_member.append(invalid_changes)
    need(confirm_gone_non_main_after_main_exit(654, member_context, {321: 4567, 655: 5555}, exit_gone_ops) is False and
         not invalid_exit_member, "verify_fixture")

    def reader_fixture(path, data, uid=0, gid=0, mode=None, nlink=1, opened_inode=None, named_after_inode=None, read_error=False):
        actual_mode = stat.S_IFREG | 0o444 if mode is None else mode
        def info(inode=41):
            return SimpleNamespace(st_dev=7, st_ino=inode, st_mode=actual_mode, st_nlink=nlink, st_uid=uid,
                                   st_gid=gid, st_size=0)
        named = [info(), info(info().st_ino if named_after_inode is None else named_after_inode)]
        opened = info(info().st_ino if opened_inode is None else opened_inode)
        calls = {"open": 0, "read": 0, "close": 0, "flags": None}
        def fake_open(name, flags):
            need(name == path, "verify_fixture")
            calls["open"] += 1
            calls["flags"] = flags
            return 55
        def fake_fstat(fd):
            need(fd == 55, "verify_fixture")
            return opened
        def fake_lstat(name):
            need(name == path, "verify_fixture")
            return named.pop(0)
        def fake_read(fd, amount):
            need(fd == 55 and amount == 65537 if path.endswith("cgroup.procs") else fd == 55 and amount == 4097, "verify_fixture")
            calls["read"] += 1
            if read_error:
                raise OSError("fixture read failure")
            return data if calls["read"] == 1 else b"999\n"
        def fake_close(fd):
            need(fd == 55, "verify_fixture")
            calls["close"] += 1
        return {"open": fake_open, "fstat": fake_fstat, "lstat": fake_lstat, "read": fake_read, "close": fake_close}, calls

    for owner in (0, 65534, 1000, 999):
        proc_ops, proc_calls = reader_fixture("/proc/%d/stat" % stat_pid, valid_proc_stat, uid=owner, gid=owner)
        need(_parse_proc_stat_starttime(_read_proc_stat(stat_pid, proc_ops), stat_pid) == 4567 and
             proc_calls == {"open": 1, "read": 1, "close": 1, "flags": os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)},
             "verify_fixture")
    invalid_reader_fixtures = (
        reader_fixture("/proc/%d/stat" % stat_pid, valid_proc_stat, nlink=2)[0],
        reader_fixture("/proc/%d/stat" % stat_pid, valid_proc_stat, mode=stat.S_IFIFO | 0o600)[0],
        reader_fixture("/proc/%d/stat" % stat_pid, valid_proc_stat, mode=stat.S_IFLNK | 0o777)[0],
        reader_fixture("/proc/%d/stat" % stat_pid, valid_proc_stat, uid=-1)[0],
        reader_fixture("/proc/%d/stat" % stat_pid, valid_proc_stat, opened_inode=42)[0],
        reader_fixture("/proc/%d/stat" % stat_pid, valid_proc_stat, named_after_inode=42)[0],
        reader_fixture("/proc/%d/stat" % stat_pid, b"x" * 4097)[0],
        reader_fixture("/proc/%d/stat" % stat_pid, valid_proc_stat, read_error=True)[0],
    )
    for proc_ops in invalid_reader_fixtures:
        rejected = False
        try:
            _read_proc_stat(stat_pid, proc_ops)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    service_cgroup = "/sys/fs/cgroup/system.slice/ct200-startup-" + "1" * 32 + ".service"
    cgroup_ops, cgroup_calls = reader_fixture(service_cgroup + "/cgroup.procs", b"321\n322\n")
    need(_read_cgroup_pids(service_cgroup, cgroup_ops) == {321, 322} and cgroup_calls["open"] == 1 and
         cgroup_calls["read"] == 1 and cgroup_calls["close"] == 1, "verify_fixture")
    for cgroup_ops in (
        reader_fixture(service_cgroup + "/cgroup.procs", b"321\n", uid=65534)[0],
        reader_fixture(service_cgroup + "/cgroup.procs", b"321\n", nlink=2)[0],
        reader_fixture(service_cgroup + "/cgroup.procs", b"321\n", opened_inode=42)[0],
    ):
        rejected = False
        try:
            _read_cgroup_pids(service_cgroup, cgroup_ops)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    known_ziphash = "h1:EqbOt2cuTGyId7pp8AhTqIY7CSAiQyOQTkWYsau91oQ="
    need(decode_ziphash((known_ziphash + "\n").encode("ascii"), known_ziphash) == known_ziphash, "verify_fixture")
    for bad_ziphash in (known_ziphash.encode("ascii"), (known_ziphash + "\n\n").encode("ascii"), b"h1:bad\n"):
        rejected = False
        try:
            decode_ziphash(bad_ziphash, known_ziphash)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    validate_module_info(b'{"Version":"v1.0.0","Time":"2024-01-02T03:04:05Z"}', "v1.0.0")
    validate_module_info(b'{"Version":"v1.0.0","Time":"2024-01-02T03:04:05Z","Origin":{"VCS":"git","URL":"https://example.invalid/repo","Hash":"' + b"a" * 40 + b'","Ref":"refs/tags/v1.0.0"}}', "v1.0.0")
    # Representative of the selected pgservicefile pseudo-version .info shape; Origin is descriptive metadata.
    validate_module_info(b'{"Version":"v0.0.0-20240606120523-5a60cdf6a761","Time":"2024-06-06T12:05:23Z","Origin":{"VCS":"git","URL":"https://github.com/jackc/pgservicefile","Hash":"5a60cdf6a7615a60cdf6a7615a60cdf6a7615a60"}}', "v0.0.0-20240606120523-5a60cdf6a761")
    for bad_info in (
        b'{"Version":"v1.0.0","Time":"2024-01-02T03:04:05Z","Origin":{"VCS":"git","URL":"https://example.invalid/repo","Hash":"' + b"a" * 40 + b'","Ref":"refs/tags/v1.0.0","Unexpected":"x"}}',
        b'{"Version":"v1.0.0","Time":"2024-01-02T03:04:05Z","Origin":[]}',
        b'{"Version":"v1.0.0","Time":"2024-01-02T03:04:05Z","Origin":{"VCS":"git","URL":"https://example.invalid/repo","Hash":"bad","Ref":"x"}}',
        b'{"Version":"v1.0.0","Time":"2024-01-02T03:04:05Z","Origin":{"VCS":"git","URL":"https://example.invalid/repo","Hash":"' + b"a" * 40 + b'","Ref":"refs/heads/../escape"}}',
        b'{"Version":"v1.0.0","Time":"2024-01-02T03:04:05Z","Origin":{"VCS":"git","URL":"https://example.invalid/repo","Hash":"' + b"a" * 40 + b'","Subdir":"../escape"}}',
        b'{"Version":"v1.0.0","Time":"2024-01-02T03:04:05Z","Origin":{"VCS":"git","URL":"https://example.invalid/repo","Hash":"' + b"a" * 40 + b'","Ref":7}}',
    ):
        rejected = False
        try:
            validate_module_info(bad_info, "v1.0.0")
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    fake_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
    fixture_cgroup = cgroup_path("/system.slice/ct200-startup-" + "1" * 32 + ".service", "/fixture/cgroup", lambda _path: fake_stat)
    need(fixture_cgroup == "/fixture/cgroup/system.slice/ct200-startup-" + "1" * 32 + ".service", "verify_fixture")
    for bad_cgroup in ("/system.slice/../evil.service", "/sys/fs/cgroup/system.slice/ct200-startup-" + "1" * 32 + ".service", "/system.slice/ct200-startup-" + "1" * 32 + ".service/child"):
        rejected = False
        try:
            cgroup_path(bad_cgroup, "/fixture/cgroup", lambda _path: fake_stat)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    unowned_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=65534)
    rejected = False
    try:
        cgroup_path("/system.slice/ct200-startup-" + "1" * 32 + ".service", "/fixture/cgroup", lambda _path: unowned_stat)
    except Reject:
        rejected = True
    need(rejected, "verify_fixture")
    unit = "ct200-startup-" + "1" * 32 + ".service"
    fields_raw = ("LoadState=not-found\nControlGroup=\nMainPID=0\nInvocationID=\nActiveState=inactive\n").encode("ascii")
    fields = parse_systemd_properties(fields_raw, ("LoadState", "ControlGroup", "MainPID", "InvocationID", "ActiveState"))
    need(validate_unit_absent(fields, unit), "verify_fixture")
    for altered in (
        dict(fields, LoadState="loaded"), dict(fields, ControlGroup="/system.slice/other.service"),
        dict(fields, MainPID="123"), dict(fields, InvocationID="a" * 32),
    ):
        rejected = False
        try:
            validate_unit_absent(altered, unit)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    active = {"LoadState": "loaded", "ControlGroup": "/system.slice/" + unit, "MainPID": "123", "InvocationID": "a" * 32, "ActiveState": "active"}
    need(validate_active_unit(active, unit), "verify_fixture")
    for altered in (dict(active, ControlGroup="/system.slice/ct200-startup-" + "2" * 32 + ".service"), dict(active, MainPID=True), dict(active, InvocationID="bad")):
        rejected = False
        try:
            validate_active_unit(altered, unit)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    old_unit, old_cgroup, old_cgroup_path, old_cgroup_id, old_invocation, old_main_pid, old_main_start, old_pids, old_owned = (
        SERVICE_NAME, SERVICE_CGROUP, SERVICE_CGROUP_PATH, SERVICE_CGROUP_ID, SERVICE_INVOCATION, SERVICE_MAIN_PID, SERVICE_MAIN_START, SERVICE_PIDS, OWNED_UNIT_STARTED)
    SERVICE_NAME, SERVICE_CGROUP, SERVICE_CGROUP_PATH, SERVICE_CGROUP_ID, SERVICE_INVOCATION, SERVICE_MAIN_PID, SERVICE_MAIN_START, SERVICE_PIDS, OWNED_UNIT_STARTED = (
        unit, "/system.slice/" + unit, "/fixture/cgroup/system.slice/" + unit, (1, 2), "a" * 32, 123, 456, {}, True)
    missing = {"LoadState": "not-found", "ControlGroup": "", "MainPID": "0", "InvocationID": "", "ActiveState": "inactive"}
    need(same_owned_unit(missing, unit, lambda _path: False, lambda: True), "verify_fixture")
    need(not same_owned_unit(missing, unit, lambda _path: True, lambda: True) and not same_owned_unit(missing, unit, lambda _path: False, lambda: False), "verify_fixture")
    need(owned_unit_settled(missing, unit, processes_gone=lambda: True, path_exists=lambda _path: False) and
         not owned_unit_settled(missing, unit, processes_gone=lambda: False, path_exists=lambda _path: False), "verify_fixture")
    replacement = dict(active, InvocationID="b" * 32)
    need(not same_owned_unit(replacement, unit), "verify_fixture")
    SERVICE_NAME, SERVICE_CGROUP, SERVICE_CGROUP_PATH, SERVICE_CGROUP_ID, SERVICE_INVOCATION, SERVICE_MAIN_PID, SERVICE_MAIN_START, SERVICE_PIDS, OWNED_UNIT_STARTED = (
        old_unit, old_cgroup, old_cgroup_path, old_cgroup_id, old_invocation, old_main_pid, old_main_start, old_pids, old_owned)
    need(validate_controller_change("memory pids", "memory pids cpu", "memory pids", "memory pids cpu", True), "verify_fixture")
    for values in (("memory pids", "memory pids io", "memory pids", "memory pids", True),
                   ("memory pids", "memory pids", "memory pids", "memory pids io", True),
                   ("memory pids", "memory pids cpu", "memory pids", "memory pids cpu", False)):
        rejected = False
        try:
            validate_controller_change(*values)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    snapshot = (2, 3, "a" * 64, {"file": 0o755}, {"file": "b" * 64})
    need(same_tree_snapshot(snapshot, snapshot) and not same_tree_snapshot(snapshot, (2, 3, "c" * 64, snapshot[3], snapshot[4])) and
         not same_tree_snapshot(snapshot, (2, 3, snapshot[2], {"file": 0o644}, snapshot[4])), "verify_fixture")
    need(pin_matches(NODE_ARCHIVE_BYTES, NODE_ARCHIVE_SHA256, 54108748, NODE_ARCHIVE_SHA256) and
         not pin_matches(100000000, NODE_ARCHIVE_SHA256, NODE_ARCHIVE_BYTES, NODE_ARCHIVE_SHA256) and
         not pin_matches(NODE_ARCHIVE_BYTES, "0" * 64, NODE_ARCHIVE_BYTES, NODE_ARCHIVE_SHA256), "verify_fixture")
    need(cleanup_remaining(10.0, 4.0) == 6.0 and cleanup_remaining(4.0, 10.0) == 0.0, "verify_fixture")
    old_outside = (OUTSIDE_ROOT, OUTSIDE_ID, OUTSIDE_DATA, OUTSIDE_FILE, OUTSIDE_FILE_ID, OUTSIDE_FILE_META, OUTSIDE_SETTLED)
    OUTSIDE_ROOT, OUTSIDE_ID, OUTSIDE_DATA, OUTSIDE_FILE, OUTSIDE_FILE_ID, OUTSIDE_SETTLED = (
        "/fixture/lb-test-run-" + "1" * 32, (1, 2), b"fixture-data\n", "/fixture/lb-test-run-" + "1" * 32 + "/outside-control.txt", (1, 3), False)
    fixture_root_stat = SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_mode=stat.S_IFDIR | 0o700)
    fixture_file_stat = SimpleNamespace(st_dev=1, st_ino=3, st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=0, st_gid=0,
                                        st_size=len(OUTSIDE_DATA), st_mtime_ns=10, st_ctime_ns=11)
    OUTSIDE_FILE_META = tuple(getattr(fixture_file_stat, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"))
    fixture_names = ["outside-control.txt"]
    fixture_exists = [True]
    fixture_unlinked = []
    def fixture_lstat(name):
        return fixture_root_stat if name == OUTSIDE_ROOT else fixture_file_stat
    def fixture_listdir(_name):
        return list(fixture_names)
    def fixture_unlink(name):
        fixture_unlinked.append(name)
        fixture_names.clear()
    def fixture_rmdir(_name):
        fixture_exists[0] = False
    need(cleanup_outside_fixture(fixture_lstat, fixture_listdir, lambda _name, _max: OUTSIDE_DATA, fixture_unlink,
                                 fixture_rmdir, lambda _name: fixture_exists[0]) and fixture_unlinked == [OUTSIDE_FILE], "verify_fixture")
    fixture_names[:] = ["outside-control.txt"]
    fixture_exists[0] = True
    fixture_unlinked.clear()
    changed_file_stat = SimpleNamespace(**dict(vars(fixture_file_stat), st_ino=99))
    def changed_lstat(name):
        return fixture_root_stat if name == OUTSIDE_ROOT else changed_file_stat
    need(not cleanup_outside_fixture(changed_lstat, fixture_listdir, lambda _name, _max: OUTSIDE_DATA, fixture_unlink,
                                     fixture_rmdir, lambda _name: fixture_exists[0]) and not fixture_unlinked, "verify_fixture")
    OUTSIDE_ROOT, OUTSIDE_ID, OUTSIDE_DATA, OUTSIDE_FILE, OUTSIDE_FILE_ID, OUTSIDE_FILE_META, OUTSIDE_SETTLED = old_outside

    # These are the actual fixed go.mod directive forms, including inline annotations.
    raw = ("module vram-governor\n\n"
           "go 1.23.4\n\n"
           "require (\n"
           "\tgithub.com/coder/websocket v1.8.15\n"
           "\tgithub.com/jackc/pgx/v5 v5.7.2\n"
           ")\n\n"
           "require (\n"
           "\tgithub.com/jackc/pgpassfile v1.0.0 // indirect\n"
           "\tgithub.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect\n"
           ")\n").encode("utf-8")
    parsed = parse_go_mod(raw)
    need(len(parsed) == 4 and parsed[0] == ("github.com/coder/websocket", "v1.8.15") and
         ("github.com/jackc/pgpassfile", "v1.0.0") in parsed and
         ("github.com/jackc/pgservicefile", "v0.0.0-20240606120523-5a60cdf6a761") in parsed, "verify_fixture")
    prefix_paths = (
        ("golang.org/x/sys", "v0.30.0"), ("golang.org/x/crypto", "v0.31.0"),
        ("gopkg.in/yaml.v3", "v3.0.1"), ("require.example/mod", "v1.2.3"),
        ("module.example/mod", "v1.2.3"), ("go.mod.example/mod", "v1.2.3"),
        ("replace.example/mod", "v1.2.3"), ("exclude.example/mod", "v1.2.3"),
        ("toolchain.example/mod", "v1.2.3"), ("retract.example/mod", "v1.2.3"),
    )
    prefix_lines = b"\n".join((module + " " + version).encode("ascii") for module, version in prefix_paths)
    prefix_mod = b"module fixture\ngo 1.23.4\nrequire (\n" + prefix_lines + b"\n)\nrequire golang.org/x/text v0.21.0 // indirect\n"
    need(parse_go_mod(prefix_mod) == sorted(list(prefix_paths) + [("golang.org/x/text", "v0.21.0")]), "verify_fixture")
    spaced_mod = b"module fixture\r\ngo 1.23.4\r\nrequire (\r\n\tgolang.org/x/sys\t v0.30.0\r\n)\r\n"
    need(parse_go_mod(spaced_mod) == [("golang.org/x/sys", "v0.30.0")], "verify_fixture")
    bad = (
        raw + b"replace example.com/x => example.com/y v1.0.0\n",
        b"module x\ngo 1.23.4\nrequire (\nrequire (\na v1.0.0\n)\n)\n",
        b"module x\ngo 1.23.4\nrequire (\nmodule other\n)\n",
        b"module x\ngo 1.23.4\nrequire (\ngo 1.23.4\n)\n",
        b"module x\ngo 1.23.4\nrequire (\nrequire other v1.0.0\n)\n",
        b"module x\ngo 1.23.4\nrequire (\nreplace old => new\n)\n",
        b"module x\ngo 1.23.4\nrequire (\nexclude other v1.0.0\n)\n",
        b"module x\ngo 1.23.4\nrequire (\ntoolchain go1.23.4\n)\n",
        b"module x\ngo 1.23.4\nrequire (\nretract [v1.0.0, v1.1.0]\n)\n",
        b"module x\ngo 1.23.4\rrequire a v1.0.0\r",
        b"module x\ngo 1.23.4\vrequire a v1.0.0\v",
        b"module x\ngo 1.23.4\nrequire a v1.0.0 trailing\n",
        b"module x\ngo 1.23.4\nrequire a v1.0.0 // indirect extra\n",
        b"module x\ngo 1.23.4\nrequire (\na v1.0.0\n) garbage\n",
        b"module x\ngo 1.23.4\nrequire a v1.0.0\nrequire a v1.0.0\n",
    )
    for fixture in bad:
        rejected = False
        try:
            parse_go_mod(fixture)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    need(escape_go("Example.com/M") == "!example.com/!m" and escape_go("v1.2.3") == "v1.2.3", "verify_fixture")
    known = hash1([
        ("Example.com/M@v1/empty/", hashlib.sha256(b"").digest()),
        ("Example.com/M@v1/z.txt", hashlib.sha256(b"z").digest()),
    ])
    need(known == "h1:EqbOt2cuTGyId7pp8AhTqIY7CSAiQyOQTkWYsau91oQ=", "verify_fixture")
    sums_raw = b"Example.com/M v1.0.0 h1:EqbOt2cuTGyId7pp8AhTqIY7CSAiQyOQTkWYsau91oQ=\n"
    need(parse_go_sum(sums_raw)[("Example.com/M", "v1.0.0")].startswith("h1:"), "verify_fixture")
    for fixture in (sums_raw + sums_raw, b"Example.com/M v1.0.0 h1:not-a-hash\n", b"bad\n"):
        rejected = False
        try:
            parse_go_sum(fixture)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    rows = []
    for name, content in (
        ("source/go.mod", b"module x\n"),
        ("source/go.sum", b""),
        ("source/scripts/verify-checkpoint-startup-runtime.mjs", b"source"),
        ("source/internal/nodeagent/example.go", b"package nodeagent\n"),
        ("source/internal/nodeagent/example_test.go", b"package nodeagent\n"),
        ("source/internal/nodeagent/second.go", b"package nodeagent\n"),
        ("modules/example.com/@v/v1.0.0.info", b"{}"),
        ("modules/example.com/@v/v1.0.0.mod", b"module example.com\n"),
        ("modules/example.com/@v/v1.0.0.zip", b"zip"),
        ("modules/example.com/@v/v1.0.0.ziphash", b"h1:invalid"),
    ):
        rows.append({"path": name, "bytes": len(content), "sha256": sha256(content)})
    rows.sort(key=lambda row: row["path"].encode("utf-8"))
    source_rows = [dict(row, path=row["path"][len("source/"):]) for row in rows if row["path"].startswith("source/")]
    test_request = {
        "schema": SCHEMA, "nonce": "0" * 32, "manifestSha256": sha256(canonical(rows)),
        "sourceManifestSha256": sha256(canonical(source_rows)), "startupFreezeSha256": "a" * 64,
        "sourceCount": 6, "moduleCount": 1, "totalBytes": sum(row["bytes"] for row in rows), "files": rows,
    }
    need(validate_request(test_request)[0] == test_request["totalBytes"], "verify_fixture")
    for mutate in (
        lambda obj: obj.update(totalBytes=obj["totalBytes"] + 1),
        lambda obj: obj.update(totalBytes=True),
        lambda obj: obj.update(moduleCount=True),
        lambda obj: obj.update(nonce=123),
        lambda obj: obj["files"][0].update(path="modules/../escape"),
        lambda obj: obj.update(manifestSha256="f" * 64),
    ):
        altered = json.loads(json.dumps(test_request))
        mutate(altered)
        rejected = False
        try:
            validate_request(altered)
        except Reject:
            rejected = True
        need(rejected, "verify_fixture")
    return True


if __name__ == "__main__" and len(os.sys.argv) == 2 and os.sys.argv[1] == "--verify":
    try:
        verify_parser_fixtures()
        os.write(1, ("startup receiver production parser fixtures passed nodeArchiveBytes=%d\nCAPACITY_WRAPPER_B64=%s\n" %
                     (NODE_ARCHIVE_BYTES, base64.b64encode(CAPACITY_WRAPPER_FIXTURE).decode("ascii"))).encode("ascii"))
    except BaseException:
        raise SystemExit(1)

if __name__ == "__main__" and not (len(os.sys.argv) == 2 and os.sys.argv[1] == "--verify"):
    if len(os.sys.argv) == 1 and "_request_meta" in globals():
        try:
            main()
        except BaseException as error:
            try:
                exception_info = failure_exception_info(error)
            except BaseException:
                exception_info = ("other", "unlocated", 0)
            try:
                settle_owned_unit()
            except BaseException:
                pass
            emit_failure(error, exception_info)
            raise SystemExit(1)
    else:
        raise SystemExit(2)
