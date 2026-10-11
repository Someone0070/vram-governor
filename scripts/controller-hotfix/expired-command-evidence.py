#!/usr/bin/env python3
"""Fixed, read-only evidence join for expired controller load_model commands.

This program reports historical cache linkage only. A cached node result is not
authoritative proof of present residency, installed source provenance, or
permission to restart/replay a command.
"""
import calendar
import datetime
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

WIRE_SCHEMA = "fixed-expired-command-evidence-v1"
MAX_WIRE = 65536
MAX_ROWS = 32
MAX_CACHE = 1024 * 1024
CONFIG_PATH = "/etc/vram-governor/node-agent.yaml"
CONFIG_BYTES = 1821
CONFIG_SHA256 = "af3d2a3fd50c61e9e0f19e4f50a6b15f31169cba028cc0dc5f5acdc34d610aa3"
UNIT_PATH = "/etc/systemd/system/vram-governor-node-agent.service"
UNIT_BYTES = 773
UNIT_SHA256 = "202db8608a6132d6e5dabdfeb232db531037ee6e5782fc1fdb1efc88704e71b6"
IMAGE_PATH = "/usr/local/bin/vram-governor-node-agent"
IMAGE_BYTES = 6586520
IMAGE_SHA256 = "116b7588ba359602a6ac547cab1d040ae19b0c8973332086ab8e8d70cfba2a85"
AGENT_PID = 315
STATE_PATH = "/var/lib/vram-governor/node-command-state.json"
NATIVE_UNITS = (
    "llama-server.service",
    "comfyui.service",
    "comfy-harness.service",
    "vram-governor-runtime-tunnel.service",
)
FIXED_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
ROW_KEYS = frozenset((
    "id", "node_id", "idempotency_key", "status", "command", "target_id", "model",
    "created_at", "expires_at", "sent_at", "last_sent_at", "completed_at",
    "body_id", "body_node_id", "body_idempotency_key", "body_status", "body_created_at",
    "body_expires_at", "body_sent_at", "body_last_sent_at", "body_completed_at",
    "args_type", "target_type", "model_type", "body_result_present",
))
COUNT_KEYS = (
    "selected", "matched_pairs", "missing", "mismatched", "malformed", "time_binding_unknown",
    "completed_before_expiry", "completed_at_expiry", "completed_after_expiry", "ok_true",
    "ok_false", "validation_refusal", "catalog_refusal", "lifecycle_unsupported", "unknown_failure",
    "outcome_unknown", "result_mismatch", "cache_invalid_entries",
)
FAILURE_CATEGORIES = {
    "node command signing is not configured": "validation_refusal",
    "command identity is required": "validation_refusal",
    "command is bound to a different node": "validation_refusal",
    "invalid command signature": "validation_refusal",
    "command expired": "validation_refusal",
    "command issue time is in the future": "validation_refusal",
    "target_id and model are required": "validation_refusal",
    "target is not an allowlisted local inference server": "catalog_refusal",
    "model is not allowlisted by router discovery": "catalog_refusal",
    "target runtime does not expose lifecycle control": "lifecycle_unsupported",
}


class EvidenceError(Exception):
    """Closed internal error code; messages and private observations are never emitted."""


def _fail(code):
    raise EvidenceError(code)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_json_key")
        result[key] = value
    return result


def _json_load(raw):
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                      parse_constant=lambda value: _fail("invalid_json_number"))


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _same_stat(first, second):
    keys = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(first, key) == getattr(second, key) for key in keys)


def _parent_owner_allowed(owner_uid, is_final_parent, process_uid=None):
    return owner_uid == 0 or (is_final_parent and process_uid is not None and owner_uid == process_uid)


def _parent_snapshot(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _safe_parents(path, process_uid=None):
    if not os.path.isabs(path) or ".." in path.split(os.sep):
        _fail("path_shape")
    cursor = os.sep
    parts = path.strip(os.sep).split(os.sep)[:-1]
    snapshots = []
    for index, part in enumerate(parts):
        cursor = os.path.join(cursor, part)
        info = os.lstat(cursor)
        owner_ok = _parent_owner_allowed(info.st_uid, index == len(parts) - 1, process_uid)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or not owner_ok or info.st_mode & 0o022:
            _fail("path_custody")
        snapshots.append((cursor, _parent_snapshot(info)))
    return tuple(snapshots)


def _open_beneath_nofollow(path):
    if (not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY") or
            os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd):
        _fail("path_custody")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(os.sep, flags)
    file_fd = None
    try:
        parent_parts = path.strip(os.sep).split(os.sep)[:-1]
        for part in parent_parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(os.path.basename(path), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
        return file_fd, directory_fd
    except Exception:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)
        raise


def _stable_file(path, maximum, exact_size=None, digest=None, mode=None, gid=None, uid=None, private=False, process_uid=None):
    if process_uid is not None and path != STATE_PATH:
        _fail("path_shape")
    parents_before = _safe_parents(path, process_uid)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        _fail("file_custody")
    if exact_size is not None and before.st_size != exact_size:
        _fail("file_size")
    if mode is not None and stat.S_IMODE(before.st_mode) != mode:
        _fail("file_mode")
    if gid is not None and before.st_gid != gid:
        _fail("file_group")
    if uid is not None and before.st_uid != uid:
        _fail("file_owner")
    if private and before.st_mode & 0o077:
        _fail("file_private_mode")
    fd, parent_fd = _open_beneath_nofollow(path)
    try:
        opened = os.fstat(fd)
        parent_opened = os.fstat(parent_fd)
        if (not parents_before or not stat.S_ISDIR(parent_opened.st_mode) or
                _parent_snapshot(parent_opened) != parents_before[-1][1] or
                not stat.S_ISREG(opened.st_mode) or not _same_stat(before, opened) or
                _safe_parents(path, process_uid) != parents_before):
            _fail("file_changed")
        chunks = []
        total = 0
        while total < before.st_size:
            block = os.read(fd, min(65536, before.st_size - total))
            if not block:
                _fail("file_short")
            chunks.append(block)
            total += len(block)
        if os.read(fd, 1):
            _fail("file_grew")
        after = os.fstat(fd)
        parent_after = os.fstat(parent_fd)
        named = os.stat(os.path.basename(path), dir_fd=parent_fd, follow_symlinks=False)
        named_path = os.lstat(path)
        if (_parent_snapshot(parent_after) != parents_before[-1][1] or
                not _same_stat(before, after) or not _same_stat(before, named) or not _same_stat(before, named_path) or
                _safe_parents(path, process_uid) != parents_before):
            _fail("file_changed")
        data = b"".join(chunks)
        if digest is not None and hashlib.sha256(data).hexdigest() != digest:
            _fail("file_identity")
        return data, before
    finally:
        close_failed = False
        for owned_fd in (fd, parent_fd):
            try:
                os.close(owned_fd)
            except Exception:
                close_failed = True
        if close_failed:
            _fail("file_cleanup")


def _parse_scalar(config, field):
    try:
        text = config.decode("utf-8", "strict")
    except Exception:
        _fail("config_encoding")
    found = []
    for line in text.splitlines():
        if line.startswith(field + ":"):
            found.append(line.split(":", 1)[1].split("#", 1)[0].strip())
    if len(found) != 1 or not found[0]:
        _fail("config_binding")
    value = found[0]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    if not value or len(value) > 512 or any(ord(char) < 0x20 for char in value):
        _fail("config_binding")
    return value


def _time_ns(value):
    if type(value) is not str or len(value) > 64:
        _fail("time_invalid")
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})", value)
    if match is None:
        _fail("time_invalid")
    whole, fraction, zone = match.groups()
    try:
        if zone != "Z":
            offset_hour = int(zone[1:3])
            offset_minute = int(zone[4:6])
            if offset_hour > 23 or offset_minute > 59:
                _fail("time_invalid")
        instant = datetime.datetime.fromisoformat(whole + ("+00:00" if zone == "Z" else zone))
        utc = instant.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        seconds = calendar.timegm(utc.timetuple())
    except Exception:
        _fail("time_invalid")
    nanos = int((fraction or "").ljust(9, "0") or "0")
    return seconds * 1000000000 + nanos


def _text(value, maximum, pattern=None):
    if type(value) is not str or not value or len(value) > maximum or any(ord(char) < 0x20 for char in value):
        return False
    return pattern is None or re.fullmatch(pattern, value) is not None


def _row_valid(row, configured_node):
    if type(row) is not dict or set(row) != ROW_KEYS:
        return False
    if not _text(row["id"], 40, r"cmd-[0-9a-f]{24}") or not _text(row["node_id"], 128, r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"):
        return False
    if not _text(row["idempotency_key"], 512) or row["node_id"] != configured_node:
        return False
    if row["status"] != "expired" or row["command"] != "load_model" or row["body_status"] != row["status"]:
        return False
    if row["body_id"] != row["id"] or row["body_node_id"] != row["node_id"] or row["body_idempotency_key"] != row["idempotency_key"]:
        return False
    if row["body_created_at"] is None or row["body_expires_at"] is None:
        return False
    if row["args_type"] != "object" or row["target_type"] != "string" or row["model_type"] != "string":
        return False
    if not _text(row["target_id"], 512) or not _text(row["model"], 512):
        return False
    if type(row["body_result_present"]) is not bool:
        return False
    try:
        # pgx/PostgreSQL timestamptz columns retain microseconds; body JSON
        # retains its full nanoseconds, so compare the known projection only.
        if _time_ns(row["created_at"]) != (_time_ns(row["body_created_at"]) // 1000) * 1000:
            return False
        if _time_ns(row["expires_at"]) != (_time_ns(row["body_expires_at"]) // 1000) * 1000:
            return False
        _time_ns(row["completed_at"])
        if row["sent_at"] is not None:
            _time_ns(row["sent_at"])
        if row["last_sent_at"] is not None:
            _time_ns(row["last_sent_at"])
        if row["body_sent_at"] is not None:
            _time_ns(row["body_sent_at"])
        if row["body_last_sent_at"] is not None:
            _time_ns(row["body_last_sent_at"])
        if row["body_completed_at"] is not None:
            _time_ns(row["body_completed_at"])
    except EvidenceError:
        return False
    return True


def _entry_valid(entry):
    if type(entry) is not dict or set(entry) - {"id", "node_id", "ok", "result", "error", "completed_at"}:
        return False
    if not {"id", "node_id", "ok", "completed_at"} <= set(entry):
        return False
    if not _text(entry["id"], 40, r"cmd-[0-9a-f]{24}") or not _text(entry["node_id"], 128, r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"):
        return False
    if type(entry["ok"]) is not bool or not _text(entry["completed_at"], 64):
        return False
    if "error" in entry and type(entry["error"]) is not str:
        return False
    if "result" in entry and entry["result"] is not None and type(entry["result"]) is not dict:
        return False
    return True


def _zero_counts(selected):
    value = {key: 0 for key in COUNT_KEYS}
    value["selected"] = selected
    return value


def match_cache_rows(rows, cache, configured_node):
    """Pure pair matcher. Returns counts only; no IDs, keys, payloads or hashes."""
    if type(rows) is not list or len(rows) > MAX_ROWS or type(cache) is not dict or type(configured_node) is not str:
        _fail("matcher_input")
    if len(cache) > 100000:
        _fail("cache_bound")
    counts = _zero_counts(len(rows))
    seen_ids = set()
    seen_keys = set()
    for row in rows:
        if not _row_valid(row, configured_node):
            counts["malformed"] += 1
            continue
        if row["id"] in seen_ids or row["idempotency_key"] in seen_keys:
            counts["mismatched"] += 1
            continue
        seen_ids.add(row["id"])
        seen_keys.add(row["idempotency_key"])
        if row["body_result_present"]:
            counts["outcome_unknown"] += 1
            continue
        id_copy = cache.get(row["id"])
        key_copy = cache.get("key:" + row["idempotency_key"])
        if id_copy is None and key_copy is None:
            counts["missing"] += 1
            continue
        if id_copy is None or key_copy is None:
            counts["missing"] += 1
            continue
        if not _entry_valid(id_copy) or not _entry_valid(key_copy):
            counts["malformed"] += 1
            continue
        try:
            same = _json_bytes(id_copy) == _json_bytes(key_copy)
        except Exception:
            same = False
        if not same or id_copy["id"] != row["id"] or key_copy["id"] != row["id"] or id_copy["node_id"] != row["node_id"] or key_copy["node_id"] != row["node_id"]:
            counts["mismatched"] += 1
            continue
        counts["matched_pairs"] += 1
        if id_copy["ok"]:
            counts["ok_true"] += 1
        else:
            counts["ok_false"] += 1
            error_text = id_copy.get("error")
            category = FAILURE_CATEGORIES.get(error_text) if type(error_text) is str else None
            counts[category or "unknown_failure"] += 1
        try:
            completion = _time_ns(id_copy["completed_at"])
            created = _time_ns(row["body_created_at"])
            sent_values = [row[key] for key in ("sent_at", "last_sent_at", "body_sent_at", "body_last_sent_at") if row[key] is not None]
            if not sent_values:
                counts["time_binding_unknown"] += 1
                continue
            sent_ns = [_time_ns(item) for item in sent_values]
            if completion < created or any(completion < sent for sent in sent_ns):
                counts["time_binding_unknown"] += 1
                continue
            expiry = _time_ns(row["body_expires_at"])
        except EvidenceError:
            counts["time_binding_unknown"] += 1
            continue
        if completion < expiry:
            counts["completed_before_expiry"] += 1
        elif completion == expiry:
            counts["completed_at_expiry"] += 1
        else:
            counts["completed_after_expiry"] += 1
        if not id_copy["ok"]:
            if "error" not in id_copy:
                counts["outcome_unknown"] += 1
            continue
        result = id_copy.get("result")
        if type(result) is not dict or not {"target_id", "model", "resident", "changed"} <= set(result):
            counts["outcome_unknown"] += 1
            continue
        if (type(result["target_id"]) is not str or type(result["model"]) is not str or
                result["target_id"] != row["target_id"] or result["model"] != row["model"] or
                type(result["resident"]) is not bool or result["resident"] is not True or
                type(result["changed"]) is not bool):
            counts["result_mismatch"] += 1
    counts["cache_invalid_entries"] = sum(1 for key, entry in cache.items()
                                           if type(key) is not str or
                                           not ((re.fullmatch(r"cmd-[0-9a-f]{24}", key) is not None) or
                                                (key.startswith("key:") and 4 <= len(key) <= 516)) or not _entry_valid(entry))
    return counts


def _read_limited(stream, maximum):
    chunks = []
    total = 0
    while total <= maximum:
        block = stream.read(min(4096, maximum + 1 - total))
        if not block:
            break
        chunks.append(block)
        total += len(block)
    if total > maximum:
        _fail("wire_bound")
    return b"".join(chunks)


def _emit(value, maximum=MAX_WIRE):
    raw = _json_bytes(value) + b"\n"
    if len(raw) > maximum:
        _fail("wire_bound")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def _parse_props(data):
    try:
        lines = data.decode("ascii", "strict").splitlines()
    except Exception:
        _fail("unit_observation")
    props = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if not sep or key not in {"MainPID", "InvocationID", "ActiveState", "SubState", "User"} or key in props or len(value) > 256:
            _fail("unit_observation")
        props[key] = value
    if set(props) != {"MainPID", "InvocationID", "ActiveState", "SubState", "User"}:
        _fail("unit_observation")
    if not props["MainPID"].isdigit() or (props["InvocationID"] and re.fullmatch(r"[0-9a-f]{32}", props["InvocationID"]) is None):
        _fail("unit_observation")
    return tuple(props[key] for key in ("MainPID", "InvocationID", "ActiveState", "SubState", "User"))


def _kill_group(child):
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
            _fail("unit_cleanup")


def _capture(argv, timeout=4, maximum=4096):
    child = None
    selector = None
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=FIXED_ENV, cwd="/", close_fds=True, start_new_session=True, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ, "out")
        selector.register(child.stderr, selectors.EVENT_READ, "err")
        captured = {"out": bytearray(), "err": bytearray()}
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("unit_timeout")
            for key, _ in selector.select(min(0.1, remaining)):
                block = os.read(key.fileobj.fileno(), min(1024, maximum + 1 - len(captured[key.data])))
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                captured[key.data].extend(block)
                if len(captured[key.data]) > maximum:
                    _fail("unit_output_bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("unit_timeout")
        code = child.wait(timeout=remaining)
        if code != 0 or captured["err"]:
            _fail("unit_observation")
        return bytes(captured["out"])
    except EvidenceError:
        raise
    except Exception:
        _fail("unit_observation")
    finally:
        if selector is not None:
            selector.close()
        if child is not None:
            if child.poll() is None:
                _kill_group(child)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass


def _system_units():
    values = []
    for unit in NATIVE_UNITS:
        raw = _capture(["/usr/bin/systemctl", "show", "--property=MainPID,InvocationID,ActiveState,SubState,User", unit])
        props = _parse_props(raw)
        if int(props[0]) <= 0 or props[1] == "" or props[2] != "active" or props[3] != "running":
            _fail("unit_observation")
        values.append((unit, props))
    return tuple(values)


def _agent_identity():
    try:
        if os.readlink("/proc/" + str(AGENT_PID) + "/exe") != IMAGE_PATH:
            _fail("agent_identity")
        with open("/proc/" + str(AGENT_PID) + "/cmdline", "rb", buffering=0) as stream:
            cmdline = stream.read(4097)
        expected = IMAGE_PATH.encode("ascii") + b"\0-config\0" + CONFIG_PATH.encode("ascii") + b"\0"
        if cmdline != expected:
            _fail("agent_identity")
        config, config_info = _stable_file(CONFIG_PATH, CONFIG_BYTES, CONFIG_BYTES, CONFIG_SHA256, mode=0o640, gid=989, uid=0)
        unit, unit_info = _stable_file(UNIT_PATH, UNIT_BYTES, UNIT_BYTES, UNIT_SHA256, mode=0o644, gid=0, uid=0)
        image, image_info = _stable_file(IMAGE_PATH, IMAGE_BYTES, IMAGE_BYTES, IMAGE_SHA256, mode=0o755, gid=0, uid=0)
        proc_info = os.stat("/proc/" + str(AGENT_PID))
        exe_info = os.stat("/proc/" + str(AGENT_PID) + "/exe")
        if (exe_info.st_dev, exe_info.st_ino) != (image_info.st_dev, image_info.st_ino):
            _fail("agent_identity")
        configured_node = _parse_scalar(config, "node_id")
        configured_state = _parse_scalar(config, "command_state_path")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", configured_node) is None or configured_state != STATE_PATH:
            _fail("config_binding")
        identity = (proc_info.st_dev, proc_info.st_ino, exe_info.st_dev, exe_info.st_ino,
                    config_info.st_dev, config_info.st_ino, config_info.st_mtime_ns, config_info.st_ctime_ns,
                    unit_info.st_dev, unit_info.st_ino, unit_info.st_mtime_ns, unit_info.st_ctime_ns,
                    image_info.st_dev, image_info.st_ino, image_info.st_mtime_ns, image_info.st_ctime_ns)
        return configured_node, identity
    except EvidenceError:
        raise
    except Exception:
        _fail("agent_identity")


def _read_cache():
    try:
        expected_uid = os.stat("/proc/" + str(AGENT_PID)).st_uid
    except Exception:
        _fail("agent_identity")
    raw, info = _stable_file(STATE_PATH, MAX_CACHE, uid=expected_uid, private=True, process_uid=expected_uid)
    try:
        cache = _json_load(raw)
    except Exception:
        _fail("cache_json")
    if type(cache) is not dict or any(key in cache for key in ("state", "payload", "data", "body", "results", "pending", "cached_results", "commands", "responses", "version", "checksum")):
        _fail("cache_schema")
    return cache, (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink,
                   info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _ct_input():
    raw = _read_limited(sys.stdin.buffer, MAX_WIRE)
    try:
        value = _json_load(raw)
    except Exception:
        _fail("wire_invalid")
    if type(value) is not dict or set(value) != {"schema", "nonce", "rows"} or value["schema"] != WIRE_SCHEMA:
        _fail("wire_invalid")
    if type(value["nonce"]) is not str or re.fullmatch(r"[a-f0-9]{32}", value["nonce"]) is None:
        _fail("wire_invalid")
    if type(value["rows"]) is not list or len(value["rows"]) > MAX_ROWS:
        _fail("wire_bound")
    return value


def _ct_main():
    nonce = None
    try:
        request = _ct_input()
        nonce = request["nonce"]
        node_before, agent_before = _agent_identity()
        units_before = _system_units()
        cache_before, cache_identity = _read_cache()
        counts = match_cache_rows(request["rows"], cache_before, node_before)
        cache_after, cache_identity_after = _read_cache()
        node_after, agent_after = _agent_identity()
        units_after = _system_units()
        if cache_identity_after != cache_identity or _json_bytes(cache_before) != _json_bytes(cache_after):
            _fail("cache_changed")
        if node_after != node_before or agent_after != agent_before or units_after != units_before:
            _fail("original_custody_changed")
        _emit({"schema": WIRE_SCHEMA, "nonce": nonce, "stage": "ok", "counts": counts,
               "cache_custody_unchanged": True, "original_custody_unchanged": True,
               "database_timestamp_precision_limited": True,
               "authoritative_outcome": False, "permission_to_restart": False,
               "command_history_changed": False})
        return 0
    except Exception as error:
        stage = "unknown"
        if isinstance(error, EvidenceError):
            codes = {
                "wire_bound": "protocol", "wire_invalid": "protocol", "duplicate_json_key": "protocol",
                "file_custody": "cache_custody", "file_changed": "cache_custody", "cache_json": "cache_malformed",
                "cache_schema": "cache_malformed", "cache_bound": "cache_malformed", "cache_changed": "cache_custody",
                "agent_identity": "original_custody", "unit_observation": "original_custody", "unit_timeout": "original_custody",
                "unit_output_bound": "original_custody", "unit_cleanup": "cleanup", "original_custody_changed": "original_custody",
                "config_binding": "original_custody", "config_encoding": "original_custody",
            }
            stage = codes.get(error.args[0] if len(error.args) == 1 else None, "unknown")
        try:
            _emit({"schema": WIRE_SCHEMA, "nonce": nonce, "stage": stage,
                   "authoritative_outcome": False, "permission_to_restart": False,
                   "command_history_changed": False})
        except Exception:
            pass
        return 1


def _lb_main(nonce):
    db = None
    phase = "original_custody"
    try:
        if type(nonce) is not str or re.fullmatch(r"[a-f0-9]{32}", nonce) is None:
            _fail("wire_invalid")
        original = _probe_service_and_config()
        phase = "readonly_connection"
        env = _connection_environment(_yaml_database_url(original["bytes"]))
        env["PGOPTIONS"] += " -c default_transaction_read_only=on"
        db = PsqlChannel(env)
        phase = "readonly_transaction"
        opened = db.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT pg_catalog.jsonb_build_object('read_only',pg_catalog.current_setting('transaction_read_only'))::text;", "transaction")
        if opened != {"read_only": "on"}:
            _fail("database_readonly")
        _validate_identity(db.query(IDENTITY_SQL, "identity"))
        if db.query(RESOLUTION_SQL, "resolution") != {"resolution_matches": True}:
            _fail("relation_shadowed")
        phase = "selected_projection"
        sql = """WITH expired AS (
 SELECT id,node_id,idempotency_key,status,created_at,expires_at,body
 FROM public.node_commands WHERE status='expired'
), load_rows AS (
 SELECT * FROM expired WHERE body->>'command'='load_model'
 ORDER BY expires_at,id LIMIT 33
)
SELECT pg_catalog.jsonb_build_object(
 'expired_total',(SELECT count(*) FROM expired),
 'unsupported_expired',(SELECT count(*) FROM expired WHERE body->>'command' IS DISTINCT FROM 'load_model'),
 'load_model_total',(SELECT count(*) FROM expired WHERE body->>'command'='load_model'),
 'rows',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
  'id',id,'node_id',node_id,'idempotency_key',idempotency_key,'status',status,
  'command',body->>'command','target_id',body->'args'->>'target_id','model',body->'args'->>'model',
  'created_at',created_at,'expires_at',expires_at,'sent_at',body->>'sent_at','last_sent_at',body->>'last_sent_at','completed_at',body->>'completed_at',
  'body_id',body->>'id','body_node_id',body->>'node_id','body_idempotency_key',body->>'idempotency_key','body_status',body->>'status',
  'body_created_at',body->>'created_at','body_expires_at',body->>'expires_at',
  'body_sent_at',body->>'sent_at','body_last_sent_at',body->>'last_sent_at','body_completed_at',body->>'completed_at',
  'args_type',pg_catalog.jsonb_typeof(body->'args'),
  'target_type',pg_catalog.jsonb_typeof(body->'args'->'target_id'),
  'model_type',pg_catalog.jsonb_typeof(body->'args'->'model'),
  'body_result_present',(body ? 'result' AND body->'result'<>'null'::jsonb)
 ) ORDER BY expires_at,id) FROM load_rows),'[]'::jsonb)
)::text;"""
        selected = db.query(sql, "snapshot")
        if type(selected) is not dict or set(selected) != {"expired_total", "unsupported_expired", "load_model_total", "rows"}:
            _fail("row_projection")
        for key in ("expired_total", "unsupported_expired", "load_model_total"):
            if type(selected[key]) is not int or selected[key] < 0 or selected[key] > 1000000000:
                _fail("row_projection")
        if selected["unsupported_expired"] != 0:
            _fail("unsupported_rows")
        if selected["expired_total"] != selected["load_model_total"]:
            _fail("row_projection")
        if selected["load_model_total"] > MAX_ROWS:
            _fail("too_many_rows")
        if type(selected["rows"]) is not list or len(selected["rows"]) != selected["load_model_total"]:
            _fail("row_projection")
        ids = set()
        idempotency = set()
        for row in selected["rows"]:
            if type(row) is not dict or set(row) != ROW_KEYS:
                _fail("row_projection")
            if type(row["id"]) is not str or type(row["idempotency_key"]) is not str:
                _fail("row_projection")
            if row["id"] in ids or row["idempotency_key"] in idempotency:
                _fail("row_projection")
            ids.add(row["id"])
            idempotency.add(row["idempotency_key"])
        phase = "readonly_rollback"
        if db.query("ROLLBACK; SELECT '{\"rollback\":true}'::jsonb::text;", "rollback") != {"rollback": True}:
            _fail("database_rollback")
        db.finish()
        db = None
        phase = "original_custody_after"
        if not _same_original(original, _probe_service_and_config()):
            _fail("original_identity_changed")
        _emit({"schema": WIRE_SCHEMA, "nonce": nonce, "stage": "ok", "expired_total": selected["expired_total"],
               "unsupported_expired": selected["unsupported_expired"], "load_model_total": selected["load_model_total"],
               "rows": selected["rows"], "read_only": True, "original_custody_unchanged": True,
               "database_timestamp_precision_limited": True,
               "authoritative_outcome": False, "permission_to_restart": False,
               "command_history_changed": False}, maximum=MAX_WIRE)
        return 0
    except Exception as error:
        if isinstance(error, EvidenceError):
            stage = {"unsupported_rows": "unsupported_rows", "too_many_rows": "too_many_rows", "row_projection": "row_projection",
                     "database_readonly": "database_readonly", "database_rollback": "database_rollback",
                     "relation_shadowed": "database_resolution"}.get(error.args[0] if len(error.args) == 1 else None, phase)
        else:
            stage = phase
        try:
            _emit({"schema": WIRE_SCHEMA, "nonce": nonce if type(nonce) is str else None, "stage": stage,
                   "authoritative_outcome": False, "permission_to_restart": False,
                   "command_history_changed": False})
        except Exception:
            pass
        return 1
    finally:
        if db is not None and not db.closed:
            db.abort()


if __name__ == "__main__":
    raise SystemExit(_ct_main())
