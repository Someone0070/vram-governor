#!/usr/bin/env python3
"""Fixed-purpose private staging receiver for the controller hotfix.

This module deliberately has no install, activation, or cleanup operation.
The only production operations are ``stage`` and read-only ``inspect``.
"""
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from contextlib import ExitStack

PARENT = "/var/lib/vram-governor-controller-staging"
INSTALLED = "/usr/local/bin/vram-governor-controller"
CONFIG = "/etc/vram-governor/controller.yaml"
CA = "/etc/vram-governor/tls/controller.crt"
UNIT = "/etc/systemd/system/vram-governor-controller.service"
DROPIN = "/etc/systemd/system/vram-governor-controller.service.d"
REQUIRED_DROPIN = "artifact-store.conf"
STAGED_UNIT_NAME = "vram-governor-controller.service"
IMAGE_NAME = "vram-governor-controller-linux-amd64"
IMAGE_SHA256 = "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543"
IMAGE_BYTES = 12976280
ORIGINAL_SHA256 = "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c"
ORIGINAL_BYTES = 12976280
CONFIG_SHA256 = "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37"
CONFIG_BYTES = 6789
CA_SHA256 = "ddc7359a3f730b1817c7adff7ede84439bdf31cc56ff7cf658142473042c1944"
CA_BYTES = 1484
MANIFEST_SHA256 = "d94e61c723d62e6cdf675559298fb6dc3cf6311f7e24b28161f28f2c1ac53fe4"
MAX_FRAME = 64 * 1024
MAX_UNIT = 256 * 1024
MAX_DROPIN_TOTAL = 1024 * 1024
MAX_STAGE_BYTES = 256 * 1024 * 1024
MAX_STAGE_DIRS = 8
MAX_STAGE_ENTRIES = 1024
MAX_FILE_READ = 16 * 1024 * 1024
MAX_CHILD_OUTPUT = 64 * 1024
CHILD_TIMEOUT = 20
REMOTE_DEADLINE = 90
SUCCESS_LINE = b"configuration valid: /etc/vram-governor/controller.yaml\n"
FIXED_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root", "GODEBUG": ""}
ENV_DENY = re.compile(r"(?:^|_)(?:PATH|LANG|LC_ALL|LD_PRELOAD|LD_LIBRARY_PATH|GODEBUG|IFS|PYTHONPATH|BASH_ENV)(?:$|_)", re.I)


class StageError(Exception):
    """Safe, deliberately non-sensitive failure classification."""


def _fail(code):
    raise StageError(code)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_bytes(data, expected_hash, expected_size, code):
    if not isinstance(data, bytes) or len(data) != expected_size or _sha(data) != expected_hash:
        _fail(code)
    return data


def validate_command_line(cmdline):
    expected = INSTALLED.encode("ascii") + b"\0-config\0" + CONFIG.encode("ascii") + b"\0"
    if cmdline != expected:
        _fail("service_command")


def service_unchanged(before, after):
    if before != after:
        _fail("live_custody_changed")


def validate_stage_entries(actual_names, expected_names):
    if len(actual_names) > MAX_STAGE_ENTRIES or len(actual_names) != len(set(actual_names)) or set(actual_names) != set(expected_names):
        _fail("stage_entries_changed")


def validate_stage_capacity(existing_dirs, existing_bytes, reserve_dirs, reserve_bytes):
    if min(existing_dirs, existing_bytes, reserve_dirs, reserve_bytes) < 0 or existing_dirs + reserve_dirs > MAX_STAGE_DIRS or existing_bytes + reserve_bytes > MAX_STAGE_BYTES:
        _fail("stage_quota_reservation")


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_field")
        result[key] = value
    return result


def parse_request(line):
    if not isinstance(line, bytes) or len(line) > MAX_FRAME or not line.endswith(b"\n"):
        _fail("request_frame")
    try:
        value = json.loads(line[:-1].decode("ascii"), object_pairs_hook=_pairs_no_duplicates)
    except StageError:
        raise
    except Exception:
        _fail("request_json")
    if not isinstance(value, dict) or value.get("schema") != "controller-stage-request-v1":
        _fail("request_schema")
    op = value.get("operation")
    if op == "stage":
        allowed = {"schema", "operation", "nonce", "manifest_sha256", "image_sha256", "image_bytes"}
        if set(value) != allowed or value["manifest_sha256"] != MANIFEST_SHA256 or value["image_sha256"] != IMAGE_SHA256 or value["image_bytes"] != IMAGE_BYTES:
            _fail("request_identity")
        if not valid_nonce(value["nonce"]):
            _fail("request_nonce")
    elif op == "inspect":
        if set(value) != {"schema", "operation", "nonce"} or not valid_nonce(value.get("nonce")):
            _fail("request_inspect")
    else:
        _fail("request_operation")
    return value


def valid_nonce(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def extract_allowed_environment(raw, allowed_name="VRAM_NODE_COMMAND_SECRET"):
    if not isinstance(raw, bytes) or len(raw) > 1024 * 1024:
        _fail("service_environment_bound")
    selected = None
    for item in raw.rstrip(b"\0").split(b"\0"):
        if not item:
            continue
        key, sep, value = item.partition(b"=")
        if not sep or not re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]*", key):
            _fail("service_environment")
        if key.decode("ascii") == allowed_name:
            if selected is not None:
                _fail("service_environment_duplicate")
            selected = value
    if selected is None:
        _fail("secret_environment")
    return {allowed_name: selected}


def read_exact(stream, count, maximum):
    if not isinstance(count, int) or count < 0 or count > maximum:
        _fail("frame_bound")
    parts = []
    remaining = count
    while remaining:
        chunk = stream.read(min(65536, remaining))
        if not chunk:
            _fail("frame_truncated")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def read_frame(stream):
    line = stream.readline(MAX_FRAME + 1)
    request = parse_request(line)
    image = read_exact(stream, IMAGE_BYTES, IMAGE_BYTES) if request["operation"] == "stage" else b""
    if stream.read(1):
        _fail("frame_trailing")
    return request, image


def _lstat(path):
    try:
        return os.lstat(path)
    except OSError:
        _fail("path_missing")


def _same_file(a, b):
    return (a.st_dev, a.st_ino, a.st_mode, a.st_nlink, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (b.st_dev, b.st_ino, b.st_mode, b.st_nlink, b.st_size, b.st_mtime_ns, b.st_ctime_ns)


def trusted_path(path, expected_owner=0, allow_group_read=True, stat_reader=None):
    """Check every fixed ancestor and return stable metadata for a regular file."""
    if not os.path.isabs(path) or ".." in path.split(os.sep):
        _fail("path_shape")
    drive, tail = os.path.splitdrive(path)
    cursor = drive + os.sep if drive else os.sep
    lstat = stat_reader or _lstat
    for part in path.strip(os.sep).split(os.sep)[:-1]:
        cursor = os.path.join(cursor, part)
        info = lstat(cursor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_owner or info.st_mode & 0o022:
            _fail("ancestor_custody")
    info = lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner or info.st_nlink != 1 or info.st_mode & 0o022:
        _fail("file_custody")
    if not allow_group_read and info.st_mode & 0o070:
        _fail("file_mode")
    return info


def read_trusted(path, expected_hash, expected_size, maximum, stat_reader=None, fstat_reader=None):
    before = trusted_path(path, stat_reader=stat_reader)
    if before.st_size != expected_size or before.st_size > maximum:
        _fail("file_size")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        _fail("file_open")
    try:
        opened = fstat_reader(fd) if fstat_reader else os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_dev != before.st_dev or opened.st_ino != before.st_ino or opened.st_size != before.st_size:
            _fail("file_identity")
        chunks = []
        total = 0
        while total < expected_size:
            chunk = os.read(fd, min(65536, expected_size - total))
            if not chunk:
                _fail("file_short")
            chunks.append(chunk)
            total += len(chunk)
        if os.read(fd, 1):
            _fail("file_grew")
        after = fstat_reader(fd) if fstat_reader else os.fstat(fd)
        named = trusted_path(path, stat_reader=stat_reader)
        if not _same_file(before, after) or not _same_file(before, named):
            _fail("file_changed")
        data = b"".join(chunks)
        if expected_hash is not None and _sha(data) != expected_hash:
            _fail("file_digest")
        return data, fd, before
    except Exception:
        os.close(fd)
        raise


def _write_exclusive(directory, name, data, mode=0o600, hooks=None):
    if not name or "/" in name or name in (".", "..") or len(data) > MAX_FILE_READ:
        _fail("write_shape")
    path = os.path.join(directory, name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, mode)
    except OSError:
        _fail("write_create")
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            if hooks and hooks.get("write"):
                count = hooks["write"](fd, view[offset:])
            else:
                count = os.write(fd, view[offset:])
            if count <= 0:
                _fail("write_short")
            offset += count
        if hooks and hooks.get("fsync"):
            hooks["fsync"](fd)
        else:
            os.fsync(fd)
        info = os.fstat(fd)
        measured_mode = hooks["stat_mode"](info) if hooks and hooks.get("stat_mode") else stat.S_IMODE(info.st_mode)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != len(data) or measured_mode != mode:
            _fail("write_custody")
    except Exception:
        os.close(fd)
        raise
    os.close(fd)
    return path


def _sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _strict_systemctl(args, timeout=5):
    try:
        result = _bounded_child(["/usr/bin/systemctl"] + args, FIXED_ENV, timeout=timeout, output_limit=MAX_FRAME)
    except Exception:
        _fail("systemctl_unavailable")
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_FRAME:
        _fail("systemctl_status")
    return result.stdout


def service_identity():
    raw = _strict_systemctl(["show", "--property=MainPID,InvocationID,ActiveState,SubState", "vram-governor-controller.service"])
    properties = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in ("MainPID", "InvocationID", "ActiveState", "SubState") or key in properties:
            _fail("service_shape")
        properties[key] = value
    if set(properties) != {"MainPID", "InvocationID", "ActiveState", "SubState"}:
        _fail("service_shape")
    pid_text = properties["MainPID"]
    invocation = properties["InvocationID"]
    if not pid_text.isdigit() or int(pid_text) <= 1 or not re.fullmatch(r"[0-9a-f]{32}", invocation) or properties["ActiveState"] != "active" or properties["SubState"] != "running":
        _fail("service_state")
    pid = int(pid_text)
    proc = "/proc/" + pid_text
    try:
        status = os.stat(proc)
        exe = os.stat(proc + "/exe")
        with open(proc + "/cmdline", "rb") as stream:
            cmdline = stream.read(65537)
        with open(proc + "/environ", "rb") as stream:
            environ_raw = stream.read(1024 * 1024 + 1)
        with open(proc + "/stat", "rb") as stream:
            statline = stream.read(8192)
    except OSError:
        _fail("service_proc")
    if len(cmdline) > 65536 or len(environ_raw) > 1024 * 1024 or len(statline) > 8192:
        _fail("service_proc_bound")
    validate_command_line(cmdline)
    if exe.st_ino == 0:
        _fail("service_command")
    stat_fields = statline.rsplit(b")", 1)[-1].strip().split()
    if len(stat_fields) < 20:
        _fail("service_start")
    start_ticks = stat_fields[19].decode("ascii", "strict")
    environ_map = extract_allowed_environment(environ_raw)
    del environ_raw
    return {"pid": pid, "invocation": invocation, "start": start_ticks, "exe_dev": exe.st_dev, "exe_ino": exe.st_ino, "proc_dev": status.st_dev, "proc_ino": status.st_ino}, environ_map


def command_secret(config, environ_map):
    if len(config) != CONFIG_BYTES or _sha(config) != CONFIG_SHA256:
        _fail("config_identity")
    text = config.decode("utf-8", "strict")
    # Restrict extraction to the one reviewed, fixed YAML key and a simple scalar.
    lines = text.splitlines()
    auth_indent = None
    matches = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if re.fullmatch(r"auth:\s*(?:#.*)?", line.strip()):
            if auth_indent is not None:
                _fail("config_secret_key")
            auth_indent = indent
            continue
        if auth_indent is not None and indent <= auth_indent:
            auth_indent = None
        if auth_indent is not None:
            found = re.fullmatch(r"command_signing_secret_env:\s*['\"]?([A-Z][A-Z0-9_]{0,63})['\"]?\s*(?:#.*)?", line.strip())
            if found:
                matches.append(found.group(1))
    if len(matches) != 1:
        _fail("config_secret_key")
    name = matches[0]
    return name, validated_secret(name, environ_map)


def validated_secret(name, environ_map):
    if name != "VRAM_NODE_COMMAND_SECRET" or name in FIXED_ENV or ENV_DENY.search(name) or name not in environ_map:
        _fail("secret_environment")
    secret = environ_map[name]
    if not isinstance(secret, bytes) or len(secret) < 32 or len(secret) > 4096 or b"\0" in secret or b"\n" in secret:
        _fail("secret_value")
    return secret


def run_check_config(binary, secret_name, secret, runner=None, executable_fd=None):
    if not os.path.isabs(binary) or secret_name in FIXED_ENV or ENV_DENY.search(secret_name):
        _fail("check_config_arguments")
    child_env = dict(FIXED_ENV)
    child_env[secret_name] = secret.decode("utf-8", "strict")
    command = [binary, "-config", CONFIG, "-check-config"]
    try:
        if runner is None:
            result = _bounded_child(command, child_env, executable_fd=executable_fd)
        else:
            result = runner(command, child_env, CHILD_TIMEOUT, executable_fd)
    except StageError:
        raise
    except subprocess.TimeoutExpired:
        _fail("check_config_timeout")
    except Exception:
        _fail("check_config_spawn")
    if len(result.stdout) > MAX_CHILD_OUTPUT or len(result.stderr) > MAX_CHILD_OUTPUT:
        _fail("check_config_output_bound")
    if result.returncode != 0 or result.stdout != SUCCESS_LINE or result.stderr:
        _fail("check_config_rejected")
    return result.returncode


def _bounded_child(command, child_env, timeout=CHILD_TIMEOUT, output_limit=MAX_CHILD_OUTPUT, executable_fd=None):
    try:
        launch = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": child_env, "close_fds": True, "cwd": "/", "start_new_session": True}
        if executable_fd is not None:
            launch["executable"] = "/proc/self/fd/" + str(executable_fd)
            launch["pass_fds"] = (executable_fd,)
        child = subprocess.Popen(command, **launch)
    except Exception:
        _fail("check_config_spawn")
    selector = None
    completed = False
    try:
        selector = selectors.DefaultSelector()
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        names = {child.stdout.fileno(): "stdout", child.stderr.fileno(): "stderr"}
        for stream in (child.stdout, child.stderr):
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("check_config_timeout")
            events = selector.select(min(remaining, 0.25))
            for key, _ in events:
                fd = key.fileobj.fileno()
                chunk = os.read(fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer = buffers[names[fd]]
                if len(buffer) + len(chunk) > output_limit:
                    _fail("check_config_output_bound")
                buffer.extend(chunk)
        remaining = max(0, deadline - time.monotonic())
        try:
            code = child.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _fail("check_config_timeout")
        completed = True
        return subprocess.CompletedProcess(command, code, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    finally:
        if not completed and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except OSError:
                pass
        if child.poll() is None:
            try:
                child.wait(timeout=2)
            except Exception:
                pass
        if selector is not None:
            selector.close()
        for stream in (child.stdout, child.stderr):
            try:
                if not stream.closed:
                    stream.close()
            except Exception:
                pass


def _read_small(path, limit, owner=None):
    info = trusted_path(path, expected_owner=0 if owner is None else owner)
    if info.st_size > limit:
        _fail("snapshot_bound")
    data, fd, _ = read_trusted(path, None, info.st_size, limit)
    os.close(fd)
    return data


def _candidate_exec_handle(path, expected_hash=IMAGE_SHA256, expected_size=IMAGE_BYTES, reader=None, path_reader=None):
    read_file = reader or read_trusted
    stat_path = path_reader or trusted_path
    data, fd, before = read_file(path, expected_hash, expected_size, expected_size)
    try:
        validate_bytes(data, expected_hash, expected_size, "candidate_identity")
        if before.st_uid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o700:
            _fail("candidate_exec_custody")
        named = stat_path(path)
        if not _same_file(before, named):
            _fail("candidate_exec_changed")
        return fd, before
    except Exception:
        os.close(fd)
        raise


def _recheck_candidate_after_check(path, fd, before, expected_hash=IMAGE_SHA256, expected_size=IMAGE_BYTES, reader=None, path_reader=None, fstat_reader=None):
    read_file = reader or read_trusted
    stat_path = path_reader or trusted_path
    held = fstat_reader(fd) if fstat_reader else os.fstat(fd)
    named = stat_path(path)
    if not _same_file(before, held) or not _same_file(before, named):
        _fail("candidate_exec_changed")
    if stat.S_IMODE(held.st_mode) != 0o700 or held.st_nlink != 1 or held.st_uid != 0:
        _fail("candidate_exec_custody")
    data, reread_fd, reread_info = read_file(path, expected_hash, expected_size, expected_size)
    try:
        validate_bytes(data, expected_hash, expected_size, "candidate_exec_changed")
        if not _same_file(before, reread_info):
            _fail("candidate_exec_changed")
    finally:
        os.close(reread_fd)


def _checked_candidate_config(path, secret_name, secret, runner=None, reader=None, path_reader=None, fstat_reader=None, expected_hash=IMAGE_SHA256, expected_size=IMAGE_BYTES):
    fd, before = _candidate_exec_handle(path, expected_hash, expected_size, reader=reader, path_reader=path_reader)
    try:
        try:
            result = run_check_config(path, secret_name, secret, runner=runner, executable_fd=fd)
        finally:
            _recheck_candidate_after_check(path, fd, before, expected_hash, expected_size, reader=reader, path_reader=path_reader, fstat_reader=fstat_reader)
        return result
    finally:
        os.close(fd)


def _dropin_snapshot(fixture=None):
    path_map = fixture.get("path", lambda value: value) if fixture else (lambda value: value)
    stat_path = fixture.get("lstat", _lstat) if fixture else _lstat
    scan_path = fixture.get("scandir", os.scandir) if fixture else os.scandir
    trusted = fixture.get("trusted_path", trusted_path) if fixture else trusted_path
    read_small = fixture.get("read_small", _read_small) if fixture else _read_small
    dropin_dir = path_map(DROPIN)
    base = stat_path(dropin_dir)
    if not stat.S_ISDIR(base.st_mode) or base.st_uid != 0 or base.st_mode & 0o022:
        _fail("dropin_custody")
    before = base
    names = []
    with scan_path(dropin_dir) as iterator:
        for item in iterator:
            if len(names) >= 64:
                _fail("dropin_count")
            names.append(item.name)
    names.sort()
    if names != [REQUIRED_DROPIN]:
        _fail("dropin_inventory")
    snapshots = {}
    total = 0
    for name in names:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
            _fail("dropin_name")
        full = os.path.join(dropin_dir, name)
        info = trusted(full)
        if info.st_size > MAX_UNIT or total + info.st_size > MAX_DROPIN_TOTAL:
            _fail("dropin_bound")
        snapshots[name] = read_small(full, MAX_UNIT)
        total += len(snapshots[name])
    if not _same_file(before, stat_path(dropin_dir)):
        _fail("dropin_directory_changed")
    return snapshots


def _stage_usage(parent):
    dirs = 0
    total = 0
    entries_seen = 0
    stack = [parent]
    while stack:
        directory = stack.pop()
        before = os.lstat(directory)
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries_seen += 1
                if entries_seen > MAX_STAGE_ENTRIES:
                    _fail("stage_entry_quota")
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    _fail("stage_link")
                if stat.S_ISDIR(info.st_mode):
                    dirs += 1
                    if dirs > MAX_STAGE_DIRS:
                        _fail("stage_directory_quota")
                    stack.append(entry.path)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    total += info.st_size
                    if total > MAX_STAGE_BYTES:
                        _fail("stage_byte_quota")
                else:
                    _fail("stage_entry_type")
        after = os.lstat(directory)
        if not _same_file(before, after):
            _fail("stage_directory_changed")
    return dirs, total


def _private_parent(create=False):
    for ancestor in ("/var", "/var/lib"):
        item = _lstat(ancestor)
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
            _fail("staging_ancestor_custody")
    try:
        info = os.lstat(PARENT)
    except OSError:
        if not create:
            _fail("staging_parent_missing")
        parent = "/var/lib"
        ancestor = _lstat(parent)
        if not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_uid != 0 or ancestor.st_mode & 0o022:
            _fail("staging_ancestor_custody")
        try:
            os.mkdir(PARENT, 0o700)
        except OSError:
            _fail("staging_parent_create")
        _sync_directory(parent)
        info = os.lstat(PARENT)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700 or info.st_mode & 0o077:
        _fail("staging_parent_custody")
    return info


def _read_receipt(directory, read_small=None):
    raw = (read_small or _read_small)(os.path.join(directory, "receipt.json"), MAX_FRAME)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs_no_duplicates)
    except Exception:
        _fail("receipt_json")
    if not isinstance(value, dict) or value.get("activationApproved") is not False:
        _fail("receipt_shape")
    if (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii") != raw:
        _fail("receipt_canonical")
    return value


def _stage(request, candidate, hooks=None):
    with ExitStack() as cleanup:
        return _stage_owned(request, candidate, hooks, cleanup)


def _stage_owned(request, candidate, hooks, cleanup):
    validate_bytes(candidate, IMAGE_SHA256, IMAGE_BYTES, "candidate_identity")
    _private_parent(create=True)
    used_dirs, used_bytes = _stage_usage(PARENT)
    validate_stage_capacity(used_dirs, used_bytes, 1, IMAGE_BYTES * 2 + CONFIG_BYTES + MAX_UNIT + MAX_DROPIN_TOTAL + MAX_FRAME)
    original, original_fd, original_info = read_trusted(INSTALLED, ORIGINAL_SHA256, ORIGINAL_BYTES, ORIGINAL_BYTES)
    cleanup.callback(os.close, original_fd)
    if stat.S_IMODE(original_info.st_mode) != 0o755:
        _fail("installed_image_mode")
    before, live_env = service_identity()
    if (before["exe_dev"], before["exe_ino"]) != (original_info.st_dev, original_info.st_ino):
        _fail("running_image_identity")
    config, config_fd, config_info = read_trusted(CONFIG, CONFIG_SHA256, CONFIG_BYTES, CONFIG_BYTES)
    cleanup.callback(os.close, config_fd)
    ca, ca_fd, ca_info = read_trusted(CA, CA_SHA256, CA_BYTES, CA_BYTES)
    cleanup.callback(os.close, ca_fd)
    secret_name, secret = command_secret(config, live_env)
    unit = _read_small(UNIT, MAX_UNIT)
    dropins = _dropin_snapshot()
    stage_dir = os.path.join(PARENT, request["nonce"])
    try:
        os.mkdir(stage_dir, 0o700)
    except OSError:
        _fail("stage_directory_create")
    _sync_directory(PARENT)
    stage_identity = os.lstat(stage_dir)
    if not stat.S_ISDIR(stage_identity.st_mode) or stage_identity.st_uid != 0 or stat.S_IMODE(stage_identity.st_mode) != 0o700:
        _fail("stage_directory_custody")
    files = {"candidate.bin": candidate, "original.bin": original, "controller.yaml": config, STAGED_UNIT_NAME: unit}
    for name, data in files.items():
        _write_exclusive(stage_dir, name, data, mode=0o700 if name == "candidate.bin" else 0o600, hooks=hooks)
    for name, data in dropins.items():
        _write_exclusive(stage_dir, "dropin-" + name, data, hooks=hooks)
    for name in files:
        with open(os.path.join(stage_dir, name), "rb") as stream:
            if _sha(stream.read(MAX_FILE_READ + 1)) != _sha(files[name]):
                _fail("staged_file_digest")
    _sync_directory(stage_dir)
    check_config_exit = _checked_candidate_config(os.path.join(stage_dir, "candidate.bin"), secret_name, secret)
    after, after_env = service_identity()
    service_unchanged(before, after)
    if after_env.get(secret_name) != secret:
        _fail("live_custody_changed")
    if not _same_file(original_info, trusted_path(INSTALLED)) or not _same_file(config_info, trusted_path(CONFIG)) or not _same_file(ca_info, trusted_path(CA)):
        _fail("live_custody_changed")
    validate_bytes(_read_small(os.path.join(stage_dir, "candidate.bin"), IMAGE_BYTES), IMAGE_SHA256, IMAGE_BYTES, "stage_file_identity")
    validate_bytes(_read_small(os.path.join(stage_dir, "original.bin"), ORIGINAL_BYTES), ORIGINAL_SHA256, ORIGINAL_BYTES, "stage_file_identity")
    receipt = {"schema": "controller-stage-receipt-v1", "nonce": request["nonce"], "candidate_sha256": IMAGE_SHA256, "candidate_bytes": IMAGE_BYTES, "manifest_sha256": MANIFEST_SHA256, "original_sha256": ORIGINAL_SHA256, "original_bytes": ORIGINAL_BYTES, "config_sha256": CONFIG_SHA256, "config_bytes": CONFIG_BYTES, "ca_sha256": CA_SHA256, "ca_bytes": CA_BYTES, "unit_sha256": _sha(unit), "dropins": {name: {"sha256": _sha(data), "bytes": len(data)} for name, data in dropins.items()}, "pid": before["pid"], "invocation": before["invocation"], "start_ticks": before["start"], "process_dev": before["proc_dev"], "process_ino": before["proc_ino"], "image_dev": before["exe_dev"], "image_ino": before["exe_ino"], "check_config_exit": check_config_exit, "check_config_success": True, "activationApproved": False}
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    _write_exclusive(stage_dir, "receipt.json", encoded, hooks=hooks)
    _sync_directory(stage_dir)
    after_stage_identity = os.lstat(stage_dir)
    if not stat.S_ISDIR(after_stage_identity.st_mode) or (stage_identity.st_dev, stage_identity.st_ino, stage_identity.st_uid, stage_identity.st_mode) != (after_stage_identity.st_dev, after_stage_identity.st_ino, after_stage_identity.st_uid, after_stage_identity.st_mode):
        _fail("stage_directory_changed")
    _stage_usage(PARENT)
    if not _same_file(after_stage_identity, os.lstat(stage_dir)):
        _fail("stage_directory_changed")
    return receipt


def _inspect(nonce, fixture=None):
    if not valid_nonce(nonce):
        _fail("inspect_nonce")
    path_map = fixture.get("path", lambda value: value) if fixture else (lambda value: value)
    read_small = fixture.get("read_small", _read_small) if fixture else _read_small
    trusted = fixture.get("trusted_path", trusted_path) if fixture else trusted_path
    stat_path = fixture.get("lstat", _lstat) if fixture else _lstat
    scan_path = fixture.get("scandir", os.scandir) if fixture else os.scandir
    private_parent = fixture.get("private_parent", _private_parent) if fixture else _private_parent
    stage_usage = fixture.get("stage_usage", _stage_usage) if fixture else _stage_usage
    service = fixture.get("service_identity", service_identity) if fixture else service_identity
    hash_bytes = fixture.get("sha256", _sha) if fixture else _sha
    # Capture service custody before inspecting any staged or live files.
    live, _ = service()
    private_parent()
    parent_dir = path_map(PARENT)
    stage_usage(parent_dir)
    directory = os.path.join(parent_dir, nonce)
    info = stat_path(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        _fail("stage_directory_custody")
    receipt = _read_receipt(directory, read_small)
    if receipt.get("nonce") != nonce or receipt.get("candidate_sha256") != IMAGE_SHA256 or receipt.get("original_sha256") != ORIGINAL_SHA256 or receipt.get("activationApproved") is not False:
        _fail("receipt_identity")
    required_receipt = {"schema", "nonce", "candidate_sha256", "candidate_bytes", "manifest_sha256", "original_sha256", "original_bytes", "config_sha256", "config_bytes", "ca_sha256", "ca_bytes", "unit_sha256", "dropins", "pid", "invocation", "start_ticks", "process_dev", "process_ino", "image_dev", "image_ino", "check_config_exit", "check_config_success", "activationApproved"}
    if set(receipt) != required_receipt or receipt.get("schema") != "controller-stage-receipt-v1" or receipt.get("manifest_sha256") != MANIFEST_SHA256 or receipt.get("config_sha256") != CONFIG_SHA256 or receipt.get("ca_sha256") != CA_SHA256 or receipt.get("check_config_exit") != 0 or receipt.get("check_config_success") is not True:
        _fail("receipt_shape")
    if receipt.get("candidate_bytes") != IMAGE_BYTES or receipt.get("original_bytes") != ORIGINAL_BYTES or receipt.get("config_bytes") != CONFIG_BYTES or receipt.get("ca_bytes") != CA_BYTES or receipt.get("unit_sha256") is None or not valid_nonce(receipt.get("nonce")) or not isinstance(receipt.get("pid"), int) or receipt["pid"] <= 1 or not re.fullmatch(r"[0-9a-f]{32}", str(receipt.get("invocation", ""))) or not str(receipt.get("start_ticks", "")).isdigit():
        _fail("receipt_shape")
    for name, digest, length in (("candidate.bin", IMAGE_SHA256, IMAGE_BYTES), ("original.bin", ORIGINAL_SHA256, ORIGINAL_BYTES), ("controller.yaml", CONFIG_SHA256, CONFIG_BYTES)):
        full = os.path.join(directory, name)
        file_info = trusted(full)
        expected_mode = 0o700 if name == "candidate.bin" else 0o600
        if stat.S_IMODE(file_info.st_mode) != expected_mode:
            _fail("stage_file_mode")
        data = read_small(full, length)
        if len(data) != length or hash_bytes(data) != digest:
            _fail("stage_file_identity")
    if hash_bytes(read_small(os.path.join(directory, STAGED_UNIT_NAME), MAX_UNIT)) != receipt.get("unit_sha256"):
        _fail("stage_unit_identity")
    dropins = receipt.get("dropins")
    if not isinstance(dropins, dict) or set(dropins) != {REQUIRED_DROPIN}:
        _fail("receipt_dropins")
    expected_names = {"candidate.bin", "original.bin", "controller.yaml", STAGED_UNIT_NAME, "receipt.json"}
    for name, record in dropins.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) or not isinstance(record, dict) or set(record) != {"sha256", "bytes"} or not re.fullmatch(r"[a-f0-9]{64}", str(record.get("sha256", ""))) or not isinstance(record.get("bytes"), int) or record["bytes"] < 0 or record["bytes"] > MAX_UNIT:
            _fail("receipt_dropins")
        staged_name = "dropin-" + name
        expected_names.add(staged_name)
        staged = read_small(os.path.join(directory, staged_name), MAX_UNIT)
        if len(staged) != record["bytes"] or hash_bytes(staged) != record["sha256"]:
            _fail("stage_dropin_identity")
    current_dropins = _dropin_snapshot(fixture)
    if set(current_dropins) != set(dropins):
        _fail("inspect_dropin_inventory")
    for name, record in dropins.items():
        current = current_dropins[name]
        if len(current) != record["bytes"] or hash_bytes(current) != record["sha256"]:
            _fail("inspect_dropin_changed")
    directory_before = stat_path(directory)
    with scan_path(directory) as iterator:
        actual_names = []
        for entry in iterator:
            if len(actual_names) >= MAX_STAGE_ENTRIES:
                _fail("stage_entry_quota")
            actual_names.append(entry.name)
    validate_stage_entries(actual_names, expected_names)
    for name in actual_names:
        file_info = trusted(os.path.join(directory, name))
        required_mode = 0o700 if name == "candidate.bin" else 0o600
        if stat.S_IMODE(file_info.st_mode) != required_mode:
            _fail("stage_file_mode")
    directory_after = stat_path(directory)
    if not _same_file(directory_before, directory_after):
        _fail("stage_directory_changed")
    live_config = read_small(path_map(CONFIG), CONFIG_BYTES)
    live_ca = read_small(path_map(CA), CA_BYTES)
    live_unit = read_small(path_map(UNIT), MAX_UNIT)
    if hash_bytes(live_config) != CONFIG_SHA256 or hash_bytes(live_ca) != CA_SHA256 or hash_bytes(live_unit) != receipt.get("unit_sha256"):
        _fail("inspect_live_files")
    original_info = trusted(path_map(INSTALLED))
    if original_info.st_size != ORIGINAL_BYTES or stat.S_IMODE(original_info.st_mode) != 0o755 or (original_info.st_dev, original_info.st_ino) != (live["exe_dev"], live["exe_ino"]) or hash_bytes(read_small(path_map(INSTALLED), ORIGINAL_BYTES)) != ORIGINAL_SHA256:
        _fail("inspect_original_image")
    live_after, _ = service()
    service_unchanged(live, live_after)
    if live["pid"] != receipt.get("pid") or live["invocation"] != receipt.get("invocation") or live["start"] != receipt.get("start_ticks") or live["proc_dev"] != receipt.get("process_dev") or live["proc_ino"] != receipt.get("process_ino") or live["exe_dev"] != receipt.get("image_dev") or live["exe_ino"] != receipt.get("image_ino"):
        _fail("inspect_live_service")
    return receipt


def handle(request, image, hooks=None):
    """Test seam: hooks can inject only local write/fsync failures."""
    if request["operation"] == "stage":
        return _stage(request, image, hooks=hooks)
    if image:
        _fail("inspect_has_payload")
    return _inspect(request["nonce"])


def emit_safe(out, result=None, error=None):
    if error is not None:
        code = error.args[0] if isinstance(error, StageError) and error.args and error.args[0] in {"request_frame", "request_json", "duplicate_field", "request_schema", "request_identity", "request_nonce", "request_inspect", "request_operation", "frame_bound", "frame_truncated", "frame_trailing", "candidate_identity", "staging_parent_custody", "stage_directory_quota", "stage_byte_quota", "check_config_timeout", "check_config_rejected", "check_config_spawn", "inspect_live_service", "stage_file_identity", "live_custody_changed"} else "operation_failed"
        payload = {"ok": False, "code": code}
    else:
        payload = {"ok": True, "receipt": result}
    out.write((json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    out.flush()


def main():
    try:
        if os.name != "posix":
            _fail("unsupported_host")
        def deadline(_signum, _frame):
            _fail("remote_deadline")
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(REMOTE_DEADLINE)
        request, image = read_frame(sys.stdin.buffer)
        result = handle(request, image)
        emit_safe(sys.stdout.buffer, result=result)
    except Exception as exc:
        emit_safe(sys.stdout.buffer, error=exc)
        return 0
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
