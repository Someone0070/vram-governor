#!/usr/bin/env python3
"""Fixed-purpose private managed-node capacity configuration repair."""
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
from contextlib import ExitStack

import yaml
import capacity_config_stage as stage

CONFIG_DIR = "/etc/vram-governor"
CONFIG = "/etc/vram-governor/controller.yaml"
CONFIG_LOCK = "/etc/vram-governor/.capacity-config.lock"
INSTALLED = "/usr/local/bin/vram-governor-controller"
CA = "/etc/vram-governor/tls/controller.crt"
BACKUP_PARENT = "/var/lib/vram-governor-controller-config-backups"
TARGET_ID = "cmp170-video-managed"
TARGET_GPU = "cmp170-node-gpu0"
TARGET_ENDPOINT = "http://127.0.0.1:9444"
TARGET_PROTOCOL = "managed_comfy_v1"
TARGET_RESERVE_MIB = 2048
CAPACITY_MIB = 10240
IMAGE_BYTES = 12976280
IMAGE_SHA256 = "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c"
CONFIG_BYTES = 6758
CONFIG_SHA256 = "22307f4535286ac56d6ee08b62b5febd8f2e1c6af6e525cbaa8a8b47852ddda0"
NEW_CONFIG_BYTES = 6789
NEW_CONFIG_SHA256 = "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37"
CA_BYTES = 1484
CA_SHA256 = "ddc7359a3f730b1817c7adff7ede84439bdf31cc56ff7cf658142473042c1944"
STAGE_SOURCE_BYTES = 37531
STAGE_SOURCE_SHA256 = "9284118f8c6f9723e09cc36219defd11a74710bf91685fcede84e6bf2d3af220"
MAX_BACKUP_BYTES = 2 * 1024 * 1024
MAX_BACKUP_DIRS = 8
MAX_BACKUP_ENTRIES = 512
MAX_REQUEST = 4096
MAX_RECEIPT = 16 * 1024
DEADLINE_SECONDS = 60
LOCK_TEXT = b"vram-governor capacity-config exclusive lock v1\n"
SUCCESS_CODES = {
    "request_frame", "request_json", "request_schema", "request_operation", "request_nonce",
    "request_fields", "deadline", "config_identity", "config_yaml", "target_missing",
    "target_ambiguous", "target_binding", "target_capacity_present", "config_transform",
    "path_custody", "file_custody", "file_size", "file_digest", "file_open", "file_identity",
    "file_changed", "service_identity", "service_changed", "image_identity", "ca_identity",
    "backup_parent", "backup_quota", "backup_exists", "backup_receipt", "backup_content",
    "backup_directory", "lock_exists", "lock_create", "config_changed", "temp_create",
    "temp_write", "temp_custody", "replace_failed", "post_replace_identity", "inspect_nonce",
    "inspect_missing", "inspect_service", "inspect_current", "inspect_original_service",
    "inspect_backup", "inspect_shape", "inspect_directory", "inspect_lock", "live_custody_changed", "operation_failed",
}


class ConfigError(Exception):
    """Safe allowlisted error code only."""


def fail(code):
    raise ConfigError(code if code in SUCCESS_CODES else "operation_failed")


def sha(data):
    return hashlib.sha256(data).hexdigest()


class UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            fail("config_yaml")
        result = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                fail("config_yaml")
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in result
            except TypeError:
                fail("config_yaml")
            if duplicate:
                fail("config_yaml")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def parse_yaml(data):
    try:
        text = data.decode("utf-8", "strict")
        value = yaml.load(text, Loader=UniqueSafeLoader)
        _reject_cycles(value)
        return value
    except ConfigError:
        raise
    except Exception:
        fail("config_yaml")


def _reject_cycles(value, active=None, done=None):
    active = set() if active is None else active
    done = set() if done is None else done
    if not isinstance(value, (dict, list)):
        return
    identity = id(value)
    if identity in active:
        fail("config_yaml")
    if identity in done:
        return
    active.add(identity)
    children = value.values() if isinstance(value, dict) else value
    for child in children:
        _reject_cycles(child, active, done)
    active.remove(identity)
    done.add(identity)


def _find_target(value, path=()):
    found = []
    if isinstance(value, dict):
        if value.get("id") == TARGET_ID:
            found.append((value, path))
        for key, child in value.items():
            found.extend(_find_target(child, path + (key,)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_find_target(child, path + (index,)))
    return found


def _mapping_matches_target(item):
    return (
        isinstance(item, dict)
        and item.get("id") == TARGET_ID
        and item.get("adapter") == "comfy"
        and item.get("runtime_protocol") == TARGET_PROTOCOL
        and item.get("endpoint") == TARGET_ENDPOINT
        and item.get("accelerator_id") == TARGET_GPU
        and item.get("enabled") is True
        and item.get("sharing_enabled") is True
        and item.get("vram_reserve_mb") == TARGET_RESERVE_MIB
    )


def _validate_target(document, allow_capacity=False):
    matches = _find_target(document)
    if len(matches) != 1:
        fail("target_missing" if not matches else "target_ambiguous")
    target, target_path = matches[0]
    if not _mapping_matches_target(target):
        fail("target_binding")
    for key in ("accelerator_vram_mb", "standalone_vram_mb"):
        if key in target and not (allow_capacity and key == "accelerator_vram_mb" and target[key] == CAPACITY_MIB):
            fail("target_capacity_present")
    if target_path != ("workloads", "targets", 0):
        fail("target_binding")
    sequence = document["workloads"]["targets"]
    if not isinstance(sequence, list) or len(sequence) != 2 or not isinstance(sequence[1], dict) or sequence[1].get("enabled") is not False:
        fail("target_binding")
    return target, target_path


def transform_config(original, expected_hash=CONFIG_SHA256, expected_size=CONFIG_BYTES, expected_new_hash=NEW_CONFIG_SHA256, expected_new_size=NEW_CONFIG_BYTES, fixture=False):
    if not isinstance(original, bytes) or len(original) != expected_size or sha(original) != expected_hash:
        fail("config_identity")
    if not fixture and (expected_hash != CONFIG_SHA256 or expected_size != CONFIG_BYTES or expected_new_hash != NEW_CONFIG_SHA256 or expected_new_size != NEW_CONFIG_BYTES):
        fail("config_identity")
    before = parse_yaml(original)
    target, _ = _validate_target(before)
    if not isinstance(target, dict) or "accelerator_vram_mb" in target or "standalone_vram_mb" in target:
        fail("target_capacity_present")
    try:
        text = original.decode("utf-8", "strict")
    except Exception:
        fail("config_yaml")
    lines = text.splitlines(keepends=True)
    if not lines or "".join(lines) != text or not text.endswith("\n") or "\r" in text:
        fail("config_transform")
    header = re.compile(r"^( *)- id: ['\"]?cmp170-video-managed['\"]?\n$")
    matches = [index for index, line in enumerate(lines) if header.fullmatch(line)]
    if len(matches) != 1:
        fail("target_ambiguous" if matches else "target_missing")
    start = matches[0]
    base_indent = len(lines[start]) - len(lines[start].lstrip(" "))
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= base_indent:
            end = index
            break
    sharing = re.compile(r"^( {4})sharing_enabled: true\n$")
    sharing_lines = [index for index in range(start + 1, end) if sharing.fullmatch(lines[index])]
    if len(sharing_lines) != 1:
        fail("target_binding")
    insert_at = sharing_lines[0]
    if any(re.fullmatch(r"\s*(?:accelerator_vram_mb|standalone_vram_mb)\s*:.*\n", lines[index]) for index in range(start + 1, end)):
        fail("target_capacity_present")
    changed = "".join(lines[:insert_at] + ["    accelerator_vram_mb: 10240\n"] + lines[insert_at:]).encode("utf-8")
    after = parse_yaml(changed)
    expected = parse_yaml(original)
    target_after, _ = _validate_target(after, allow_capacity=True)
    expected_target, _ = _validate_target(expected)
    expected_target["accelerator_vram_mb"] = CAPACITY_MIB
    if after != expected or target_after.get("accelerator_vram_mb") != CAPACITY_MIB:
        fail("config_transform")
    if len(changed) != expected_new_size or sha(changed) != expected_new_hash:
        fail("config_transform")
    if changed.count(b"    accelerator_vram_mb: 10240\n") != 1:
        fail("config_transform")
    return changed


def _lstat(path):
    try:
        return os.lstat(path)
    except OSError:
        fail("path_custody")


def _trusted_directory(path, exact_mode=None, expected_group=None):
    if not os.path.isabs(path) or ".." in path.split(os.sep):
        fail("path_custody")
    cursor = os.sep
    for part in path.strip(os.sep).split(os.sep):
        cursor = os.path.join(cursor, part)
        info = _lstat(cursor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            fail("path_custody")
    if exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode:
        fail("path_custody")
    if expected_group is not None and info.st_gid != expected_group:
        fail("path_custody")
    return info


def _read_fixed(path, digest, size):
    try:
        data, fd, info = stage.read_trusted(path, digest, size, size)
        return data, fd, info
    except stage.StageError as exc:
        fail("file_digest" if str(exc) in ("file_digest", "file_size") else "file_custody")


def _same(a, b):
    return stage._same_file(a, b)


def _same_directory(a, b):
    return stat.S_ISDIR(b.st_mode) and (a.st_dev, a.st_ino, a.st_uid, a.st_gid, stat.S_IMODE(a.st_mode)) == (b.st_dev, b.st_ino, b.st_uid, b.st_gid, stat.S_IMODE(b.st_mode))


def _service_snapshot():
    try:
        result = stage.service_identity()
    except stage.StageError:
        fail("service_identity")
    return result[0]


def _read_service_and_images(stack):
    image, image_fd, image_info = _read_fixed(INSTALLED, IMAGE_SHA256, IMAGE_BYTES)
    stack.callback(os.close, image_fd)
    if stat.S_IMODE(image_info.st_mode) != 0o755 or image_info.st_uid != 0:
        fail("image_identity")
    ca, ca_fd, ca_info = _read_fixed(CA, CA_SHA256, CA_BYTES)
    stack.callback(os.close, ca_fd)
    if len(ca) != CA_BYTES or sha(ca) != CA_SHA256 or ca_info.st_uid != 0:
        fail("ca_identity")
    service = _service_snapshot()
    if (service["exe_dev"], service["exe_ino"]) != (image_info.st_dev, image_info.st_ino):
        fail("image_identity")
    proc_fd = None
    try:
        proc_fd = os.open("/proc/{}/exe".format(service["pid"]), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        stack.callback(os.close, proc_fd)
        proc_info = os.fstat(proc_fd)
        if (proc_info.st_dev, proc_info.st_ino) != (image_info.st_dev, image_info.st_ino):
            fail("image_identity")
    except OSError:
        fail("image_identity")
    return service, image_info, ca_info


def _service_unchanged(before, image_info):
    try:
        after = _service_snapshot()
    except ConfigError:
        fail("service_changed")
    if after != before or (after["exe_dev"], after["exe_ino"]) != (image_info.st_dev, image_info.st_ino):
        fail("service_changed")


def _check_installed_and_ca(image_info, ca_info):
    if not _same(image_info, stage.trusted_path(INSTALLED)) or not _same(ca_info, stage.trusted_path(CA)):
        fail("live_custody_changed")


def _backup_usage(root):
    total = 0
    directories = 0
    entries = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        before = os.lstat(directory)
        if not stat.S_ISDIR(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o077:
            fail("backup_parent")
        with os.scandir(directory) as iterator:
            for item in iterator:
                entries += 1
                if entries > MAX_BACKUP_ENTRIES:
                    fail("backup_quota")
                info = item.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    fail("backup_parent")
                if stat.S_ISDIR(info.st_mode):
                    directories += 1
                    if directories > MAX_BACKUP_DIRS:
                        fail("backup_quota")
                    stack.append(item.path)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    total += info.st_size
                    if total > MAX_BACKUP_BYTES:
                        fail("backup_quota")
                else:
                    fail("backup_parent")
        if not _same(before, os.lstat(directory)):
            fail("backup_parent")
    return directories, total


def _backup_parent(create=False):
    _trusted_directory("/var/lib")
    try:
        info = os.lstat(BACKUP_PARENT)
    except OSError:
        if not create:
            fail("backup_parent")
        try:
            os.mkdir(BACKUP_PARENT, 0o700)
            fd = os.open("/var/lib", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            info = os.lstat(BACKUP_PARENT)
        except OSError:
            fail("backup_parent")
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        fail("backup_parent")
    return info


def _write_all_exclusive(directory, name, data, mode=0o600, hooks=None):
    """Exclusive file creation with test-only write/fsync seams."""
    fixed_name = name in ("old.yaml", "new.yaml", "receipt.json")
    nonce_temp = isinstance(name, str) and re.fullmatch(r"\.controller\.yaml\.capacity-[a-f0-9]{32}\.tmp", name) is not None
    if not (fixed_name or nonce_temp) or not isinstance(data, bytes) or len(data) > MAX_RECEIPT * 4:
        fail("temp_write")
    path = os.path.join(directory, name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, mode)
    except OSError:
        fail("backup_exists")
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            count = hooks["write"](fd, view[offset:]) if hooks and hooks.get("write") else os.write(fd, view[offset:])
            if count <= 0:
                fail("temp_write")
            offset += count
        if hooks and hooks.get("fsync"):
            hooks["fsync"](fd)
        else:
            os.fsync(fd)
        info = os.fstat(fd)
        measured_mode = hooks["mode"](info) if hooks and hooks.get("mode") else stat.S_IMODE(info.st_mode)
        measured_uid = hooks["uid"](info) if hooks and hooks.get("uid") else info.st_uid
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or measured_uid != 0 or measured_mode != mode or info.st_size != len(data):
            fail("temp_custody")
        named = os.lstat(path)
        if not _same(info, named):
            fail("temp_custody")
    except ConfigError:
        os.close(fd)
        raise
    except Exception:
        os.close(fd)
        fail("temp_write")
    os.close(fd)
    try:
        named = os.lstat(path)
    except OSError:
        fail("temp_custody")
    if not _same(info, named):
        fail("temp_custody")
    return path, named


def _acquire_lock(config_dir, nonce):
    _trusted_directory(config_dir, exact_mode=0o750, expected_group=990)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(CONFIG_LOCK, flags, 0o600)
    except FileExistsError:
        fail("lock_exists")
    except OSError:
        fail("lock_create")
    try:
        contents = memoryview(LOCK_TEXT + nonce.encode("ascii") + b"\n")
        offset = 0
        while offset < len(contents):
            count = os.write(fd, contents[offset:])
            if count <= 0:
                fail("lock_create")
            offset += count
        os.fsync(fd)
        info = os.fstat(fd)
        named = os.lstat(CONFIG_LOCK)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or not _same(info, named):
            fail("lock_create")
        return fd, info
    except Exception:
        os.close(fd)
        raise


def _release_owned_lock(fd, before, nonce):
    removed = False
    try:
        held = os.fstat(fd)
        named = os.lstat(CONFIG_LOCK)
        read_fd = os.open(CONFIG_LOCK, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            read_info = os.fstat(read_fd)
            content = os.read(read_fd, 256)
        finally:
            os.close(read_fd)
        expected = LOCK_TEXT + nonce.encode("ascii") + b"\n"
        if _same(before, held) and _same(before, named) and _same(before, read_info) and content == expected:
            os.unlink(CONFIG_LOCK)
            removed = True
            dfd = os.open(CONFIG_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    except OSError:
        removed = False
    finally:
        os.close(fd)
    return removed


def _canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _receipt_from(before, original_info, old_backup_info, new_config_info, new_bytes):
    return {
        "schema": "controller-capacity-config-receipt-v1",
        "nonce": before["nonce"],
        "old_sha256": CONFIG_SHA256,
        "old_bytes": CONFIG_BYTES,
        "new_sha256": sha(new_bytes),
        "new_bytes": len(new_bytes),
        "old_config_dev": original_info.st_dev,
        "old_config_ino": original_info.st_ino,
        "old_backup_dev": old_backup_info.st_dev,
        "old_backup_ino": old_backup_info.st_ino,
        "new_config_dev": new_config_info.st_dev,
        "new_config_ino": new_config_info.st_ino,
        "config_uid": original_info.st_uid,
        "config_gid": original_info.st_gid,
        "config_mode": stat.S_IMODE(original_info.st_mode),
        "pid": before["service"]["pid"],
        "invocation": before["service"]["invocation"],
        "start_ticks": before["service"]["start"],
        "process_dev": before["service"]["proc_dev"],
        "process_ino": before["service"]["proc_ino"],
        "image_dev": before["service"]["exe_dev"],
        "image_ino": before["service"]["exe_ino"],
        "activationApproved": False,
        "runtimeConfigReloaded": False,
    }


RECEIPT_KEYS = {
    "schema", "nonce", "old_sha256", "old_bytes", "new_sha256", "new_bytes", "old_config_dev", "old_config_ino",
    "old_backup_dev", "old_backup_ino", "new_config_dev", "new_config_ino",
    "config_uid", "config_gid", "config_mode", "pid", "invocation", "start_ticks", "process_dev", "process_ino",
    "image_dev", "image_ino", "activationApproved", "runtimeConfigReloaded",
}


def _read_receipt(raw):
    try:
        receipt = json.loads(raw.decode("ascii"), object_pairs_hook=stage._pairs_no_duplicates)
    except Exception:
        fail("backup_receipt")
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS or _canonical_json(receipt) != raw:
        fail("backup_receipt")
    if receipt.get("schema") != "controller-capacity-config-receipt-v1" or receipt.get("activationApproved") is not False or receipt.get("runtimeConfigReloaded") is not False:
        fail("backup_receipt")
    if receipt.get("old_sha256") != CONFIG_SHA256 or receipt.get("old_bytes") != CONFIG_BYTES or receipt.get("new_sha256") != NEW_CONFIG_SHA256 or receipt.get("new_bytes") != NEW_CONFIG_BYTES:
        fail("backup_receipt")
    if not stage.valid_nonce(receipt.get("nonce")) or not re.fullmatch(r"[0-9a-f]{32}", str(receipt.get("invocation", ""))) or not str(receipt.get("start_ticks", "")).isdigit():
        fail("backup_receipt")
    integer_fields = ("old_config_dev", "old_config_ino", "old_backup_dev", "old_backup_ino", "new_config_dev", "new_config_ino", "config_uid", "config_gid", "config_mode", "pid", "process_dev", "process_ino", "image_dev", "image_ino")
    if any(type(receipt.get(key)) is not int or receipt[key] < 0 for key in integer_fields) or receipt["pid"] <= 1 or receipt["config_uid"] != 0 or receipt["config_gid"] != 990 or receipt["config_mode"] != 0o640:
        fail("backup_receipt")
    return receipt


def _write_parent_sync(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _conditioned_replace(config_fd, original_info, old_bytes, temp_path, new_bytes, service, image_info, directory_info, applied, hooks=None, expected_old_hash=CONFIG_SHA256, expected_new_hash=NEW_CONFIG_SHA256, expected_old_size=CONFIG_BYTES, expected_new_size=NEW_CONFIG_BYTES, temp_fd=None):
    """Revalidate source, private temp and service immediately before atomic replace."""
    hooks = hooks or {}
    config_path = hooks.get("config_path", CONFIG)
    config_dir = hooks.get("config_dir", CONFIG_DIR)
    stat_path = hooks.get("stat_path", stage.trusted_path)
    read_file = hooks.get("read_file")
    service_check = hooks.get("service_check", _service_unchanged)
    sync_dir = hooks.get("sync_dir", _write_parent_sync)
    replace_file = hooks.get("replace", os.replace)
    fstat_file = hooks.get("fstat", os.fstat)
    held = fstat_file(config_fd)
    named = stat_path(config_path)
    if not _same(original_info, held) or not _same(original_info, named):
        fail("config_changed")
    if os.read(config_fd, 1):
        fail("config_changed")
    if read_file:
        current, current_info = read_file(config_path)
    else:
        current, current_fd, current_info = _read_fixed(config_path, expected_old_hash, expected_old_size)
        os.close(current_fd)
    if current != old_bytes or not _same(original_info, current_info):
        fail("config_changed")
    temp_info = stat_path(temp_path)
    if not stat.S_ISREG(temp_info.st_mode) or temp_info.st_nlink != 1 or temp_info.st_uid != 0 or temp_info.st_gid != 990 or stat.S_IMODE(temp_info.st_mode) != 0o640 or temp_info.st_size != expected_new_size:
        fail("temp_custody")
    if temp_fd is None or not _same(temp_info, fstat_file(temp_fd)):
        fail("temp_custody")
    if read_file:
        temp_data, temp_read_info = read_file(temp_path)
    else:
        temp_data, temp_read_fd, temp_read_info = _read_fixed(temp_path, expected_new_hash, expected_new_size)
        os.close(temp_read_fd)
    if temp_data != new_bytes or sha(temp_data) != expected_new_hash or not _same(temp_info, temp_read_info):
        fail("temp_custody")
    current_directory = hooks.get("directory_info", lambda: _trusted_directory(config_dir, exact_mode=0o750, expected_group=990))()
    if not _same(directory_info, current_directory):
        fail("path_custody")
    service_check(service, image_info)
    if not _same(original_info, fstat_file(config_fd)) or not _same(original_info, stat_path(config_path)):
        fail("config_changed")
    if not _same(temp_info, fstat_file(temp_fd)) or not _same(temp_info, stat_path(temp_path)):
        fail("temp_custody")
    try:
        applied["value"] = "unknown"
        replace_file(temp_path, config_path)
        applied["value"] = "confirmed"
        sync_dir(config_dir)
    except ConfigError:
        raise
    except OSError:
        fail("replace_failed" if applied["value"] == "unknown" else "post_replace_identity")
    if read_file:
        installed, installed_info = read_file(config_path)
    else:
        installed, installed_fd, installed_info = _read_fixed(config_path, expected_new_hash, expected_new_size)
        os.close(installed_fd)
    if installed != new_bytes or sha(installed) != expected_new_hash or installed_info.st_uid != 0 or installed_info.st_gid != 990 or stat.S_IMODE(installed_info.st_mode) != 0o640:
        fail("post_replace_identity")
    service_check(service, image_info)
    return installed_info


def _apply(nonce, hooks=None, fixture=None, applied_state=None):
    if not stage.valid_nonce(nonce):
        fail("request_nonce")
    applied = applied_state if applied_state is not None else {"value": "not_applied"}
    _trusted_directory("/etc/vram-governor", exact_mode=0o750, expected_group=990)
    lock_fd, lock_info = _acquire_lock(CONFIG_DIR, nonce)
    try:
        with ExitStack() as stack:
            service, image_info, ca_info = _read_service_and_images(stack)
            _check_installed_and_ca(image_info, ca_info)
            original, config_fd, original_info = _read_fixed(CONFIG, CONFIG_SHA256, CONFIG_BYTES)
            stack.callback(os.close, config_fd)
            if original_info.st_uid != 0 or original_info.st_gid != 990 or stat.S_IMODE(original_info.st_mode) != 0o640:
                fail("file_custody")
            config_directory_info = _trusted_directory(CONFIG_DIR, exact_mode=0o750, expected_group=990)
            new_config = transform_config(original, fixture=bool(fixture))
            _service_unchanged(service, image_info)
            _check_installed_and_ca(image_info, ca_info)
            current, check_fd, check_info = _read_fixed(CONFIG, CONFIG_SHA256, CONFIG_BYTES)
            try:
                if current != original or not _same(original_info, check_info):
                    fail("config_changed")
            finally:
                os.close(check_fd)
            parent_before = _backup_parent(create=True)
            used_dirs, used_bytes = _backup_usage(BACKUP_PARENT)
            needed = len(original) + len(new_config) + MAX_RECEIPT
            if used_dirs + 1 > MAX_BACKUP_DIRS or used_bytes + needed > MAX_BACKUP_BYTES:
                fail("backup_quota")
            backup_dir = os.path.join(BACKUP_PARENT, nonce)
            try:
                os.mkdir(backup_dir, 0o700)
            except OSError:
                fail("backup_exists")
            _write_parent_sync(BACKUP_PARENT)
            backup_info = os.lstat(backup_dir)
            if not stat.S_ISDIR(backup_info.st_mode) or backup_info.st_uid != 0 or stat.S_IMODE(backup_info.st_mode) != 0o700:
                fail("backup_directory")
            _, old_backup_info = _write_all_exclusive(backup_dir, "old.yaml", original, hooks=hooks)
            _, new_backup_info = _write_all_exclusive(backup_dir, "new.yaml", new_config, hooks=hooks)
            old_backup, old_backup_fd, old_backup_stat = _read_fixed(os.path.join(backup_dir, "old.yaml"), CONFIG_SHA256, CONFIG_BYTES)
            try:
                if old_backup != original or not _same(old_backup_info, old_backup_stat) or stat.S_IMODE(old_backup_stat.st_mode) != 0o600:
                    fail("backup_content")
            finally:
                os.close(old_backup_fd)
            new_backup, new_backup_fd, new_backup_stat = _read_fixed(os.path.join(backup_dir, "new.yaml"), NEW_CONFIG_SHA256, NEW_CONFIG_BYTES)
            try:
                if new_backup != new_config or not _same(new_backup_info, new_backup_stat) or stat.S_IMODE(new_backup_stat.st_mode) != 0o600:
                    fail("backup_content")
            finally:
                os.close(new_backup_fd)
            _write_parent_sync(backup_dir)
            temp_name = ".controller.yaml.capacity-{}.tmp".format(nonce)
            temp_path, _temp_created_info = _write_all_exclusive(CONFIG_DIR, temp_name, new_config, mode=0o600, hooks=hooks)
            config_directory_info = _trusted_directory(CONFIG_DIR, exact_mode=0o750, expected_group=990)
            temp_fd = os.open(temp_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            stack.callback(os.close, temp_fd)
            try:
                os.fchown(temp_fd, original_info.st_uid, original_info.st_gid)
                os.fchmod(temp_fd, stat.S_IMODE(original_info.st_mode))
                os.fsync(temp_fd)
                temp_open = os.fstat(temp_fd)
                if not stat.S_ISREG(temp_open.st_mode) or temp_open.st_nlink != 1 or temp_open.st_uid != 0 or temp_open.st_gid != 990 or stat.S_IMODE(temp_open.st_mode) != 0o640 or temp_open.st_size != NEW_CONFIG_BYTES:
                    fail("temp_custody")
                _conditioned_replace(config_fd, original_info, original, temp_path, new_config, service, image_info, config_directory_info, applied, temp_fd=temp_fd)
            except ConfigError:
                raise
            except OSError:
                fail("temp_write" if applied["value"] == "not_applied" else "post_replace_identity")
            current_new, new_fd, new_info = _read_fixed(CONFIG, NEW_CONFIG_SHA256, NEW_CONFIG_BYTES)
            try:
                if current_new != new_config or new_info.st_uid != 0 or new_info.st_gid != 990 or stat.S_IMODE(new_info.st_mode) != 0o640:
                    fail("post_replace_identity")
            finally:
                os.close(new_fd)
            _service_unchanged(service, image_info)
            _check_installed_and_ca(image_info, ca_info)
            receipt_source = {"nonce": nonce, "service": service}
            receipt = _receipt_from(receipt_source, original_info, old_backup_info, new_info, new_config)
            _write_all_exclusive(backup_dir, "receipt.json", _canonical_json(receipt), hooks=hooks)
            _write_parent_sync(backup_dir)
            _backup_usage(BACKUP_PARENT)
            if not _same_directory(parent_before, os.lstat(BACKUP_PARENT)) or not _same_directory(backup_info, os.lstat(backup_dir)):
                fail("backup_directory")
            return receipt, applied
    finally:
        if not _release_owned_lock(lock_fd, lock_info, nonce):
            fail("lock_exists")


def _inspect_owned(nonce, service_before, image_info, stack):
    if not stage.valid_nonce(nonce):
        fail("inspect_nonce")
    parent = _backup_parent(create=False)
    _backup_usage(BACKUP_PARENT)
    backup_dir = os.path.join(BACKUP_PARENT, nonce)
    try:
        directory_info = os.lstat(backup_dir)
    except OSError:
        fail("inspect_missing")
    if not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0 or stat.S_IMODE(directory_info.st_mode) != 0o700:
        fail("inspect_directory")
    try:
        names = []
        with os.scandir(backup_dir) as iterator:
            for entry in iterator:
                if len(names) >= 8:
                    fail("inspect_directory")
                names.append(entry.name)
    except OSError:
        fail("inspect_directory")
    if sorted(names) != ["new.yaml", "old.yaml", "receipt.json"]:
        fail("inspect_directory")
    receipt_path = os.path.join(backup_dir, "receipt.json")
    receipt_info = stage.trusted_path(receipt_path)
    if receipt_info.st_uid != 0 or receipt_info.st_nlink != 1 or stat.S_IMODE(receipt_info.st_mode) != 0o600:
        fail("inspect_backup")
    if receipt_info.st_size > MAX_RECEIPT:
        fail("inspect_backup")
    try:
        receipt_raw, receipt_fd, receipt_held = stage.read_trusted(receipt_path, None, receipt_info.st_size, MAX_RECEIPT)
    except stage.StageError:
        fail("inspect_backup")
    stack.callback(os.close, receipt_fd)
    if not _same(receipt_info, receipt_held):
        fail("inspect_backup")
    if not _same(receipt_info, stage.trusted_path(receipt_path)):
        fail("inspect_backup")
    receipt = _read_receipt(receipt_raw)
    if receipt["nonce"] != nonce:
        fail("inspect_nonce")
    old, old_fd, old_info = _read_fixed(os.path.join(backup_dir, "old.yaml"), CONFIG_SHA256, CONFIG_BYTES)
    stack.callback(os.close, old_fd)
    new, new_fd, new_info = _read_fixed(os.path.join(backup_dir, "new.yaml"), NEW_CONFIG_SHA256, NEW_CONFIG_BYTES)
    stack.callback(os.close, new_fd)
    for info in (old_info, new_info):
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            fail("inspect_backup")
    current, current_fd, current_info = _read_fixed(CONFIG, NEW_CONFIG_SHA256, NEW_CONFIG_BYTES)
    stack.callback(os.close, current_fd)
    if len(old) != CONFIG_BYTES or len(new) != NEW_CONFIG_BYTES or len(current) != NEW_CONFIG_BYTES or current != new or current_info.st_uid != 0 or current_info.st_gid != 990 or stat.S_IMODE(current_info.st_mode) != 0o640:
        fail("inspect_current")
    if receipt["old_backup_dev"] != old_info.st_dev or receipt["old_backup_ino"] != old_info.st_ino or receipt["new_config_dev"] != current_info.st_dev or receipt["new_config_ino"] != current_info.st_ino:
        fail("inspect_backup")
    if receipt["new_sha256"] != sha(new):
        fail("inspect_backup")
    if (receipt["pid"], receipt["invocation"], receipt["start_ticks"], receipt["process_dev"], receipt["process_ino"], receipt["image_dev"], receipt["image_ino"]) != (service_before["pid"], service_before["invocation"], service_before["start"], service_before["proc_dev"], service_before["proc_ino"], service_before["exe_dev"], service_before["exe_ino"]):
        fail("inspect_original_service")
    if not _same(directory_info, os.lstat(backup_dir)) or not _same(parent, os.lstat(BACKUP_PARENT)):
        fail("inspect_directory")
    try:
        os.lstat(CONFIG_LOCK)
    except FileNotFoundError:
        pass
    else:
        fail("inspect_lock")
    for path, held in ((receipt_path, receipt_held), (os.path.join(backup_dir, "old.yaml"), old_info), (os.path.join(backup_dir, "new.yaml"), new_info), (CONFIG, current_info)):
        if not _same(held, stage.trusted_path(path)):
            fail("inspect_backup" if path != CONFIG else "inspect_current")
    return receipt


def _inspect(nonce):
    if not stage.valid_nonce(nonce):
        fail("inspect_nonce")
    with ExitStack() as image_stack:
        service_before, image_info, ca_info = _read_service_and_images(image_stack)
        result = _inspect_owned(nonce, service_before, image_info, image_stack)
        current_service = _service_snapshot()
        if current_service != service_before or (current_service["exe_dev"], current_service["exe_ino"]) != (image_info.st_dev, image_info.st_ino):
            fail("inspect_service")
        _check_installed_and_ca(image_info, ca_info)
        return result


def _parse_request(line):
    if not isinstance(line, bytes) or len(line) > MAX_REQUEST or not line.endswith(b"\n"):
        fail("request_frame")
    try:
        value = json.loads(line[:-1].decode("ascii"), object_pairs_hook=stage._pairs_no_duplicates)
    except Exception:
        fail("request_json")
    if not isinstance(value, dict) or value.get("schema") != "controller-capacity-config-request-v1":
        fail("request_schema")
    if set(value) != {"schema", "operation", "nonce"} or value.get("operation") not in ("apply", "inspect"):
        fail("request_fields")
    if not stage.valid_nonce(value.get("nonce")):
        fail("request_nonce")
    return value


def _emit(stream, receipt=None, error=None, replacement="not_applied"):
    if error is not None:
        code = error.args[0] if isinstance(error, ConfigError) and error.args and error.args[0] in SUCCESS_CODES else "operation_failed"
        if replacement not in ("not_applied", "unknown", "confirmed"):
            replacement = "unknown"
        value = {"ok": False, "code": code, "replacement": replacement}
    else:
        value = {"ok": True, "receipt": receipt}
    stream.write(_canonical_json(value))
    stream.flush()


def _resolve_replacement_state(state, readback, expected_hash=NEW_CONFIG_SHA256, expected_size=NEW_CONFIG_BYTES):
    if state != "unknown":
        return state
    try:
        current = readback()
        if isinstance(current, bytes) and len(current) == expected_size and sha(current) == expected_hash:
            return "confirmed"
    except Exception:
        pass
    return "unknown"


def main():
    applied = {"value": "not_applied"}
    try:
        if os.name != "posix":
            fail("operation_failed")
        def deadline(_signum, _frame):
            fail("deadline")
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(DEADLINE_SECONDS)
        request = _parse_request(sys.stdin.buffer.readline(MAX_REQUEST + 1))
        if sys.stdin.buffer.read(1):
            fail("request_frame")
        if request["operation"] == "apply":
            receipt, applied = _apply(request["nonce"], applied_state=applied)
        else:
            receipt = _inspect(request["nonce"])
        _emit(sys.stdout.buffer, receipt=receipt)
        return 0
    except Exception as exc:
        if applied["value"] == "unknown" and "request" in locals() and request.get("operation") == "apply":
            def read_current_config():
                maybe_new, maybe_fd, _ = _read_fixed(CONFIG, NEW_CONFIG_SHA256, NEW_CONFIG_BYTES)
                try:
                    return maybe_new
                finally:
                    os.close(maybe_fd)
            applied["value"] = _resolve_replacement_state(applied["value"], read_current_config)
        _emit(sys.stdout.buffer, error=exc, replacement=applied["value"])
        return 0
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
