#!/usr/bin/python3
"""Fixed-route, authenticated, data-only tool staging receiver for CT200."""

import hashlib
import json
import os
import re
import signal
import socket
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

SCHEMA = "ct200-private-tools-v1"
GO_URL = "https://go.dev/dl/go1.23.4.linux-amd64.tar.gz"
GO_SHA256 = "6924efde5de86fe277676e929dc9917d466efa02fb934197bc2eba35d5680971"
GO_BYTES = 73645095
NODE_URL = "https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-x64.tar.gz"
NODE_SHA256 = "9d942932535988091034dc94cc5f42b6dc8784d6366df3a36c4c9ccb3996f0c2"
ARCHIVE_MAX_BYTES = 100000000
NODE_MAX_BYTES = 128 * 1024 * 1024
ARCHIVE_TOTAL_MAX = 180000000
EXPANDED_MAX_BYTES = 1800000000
ENTRY_MAX_COUNT = 100000
GLOBAL_SECONDS = 205
READ_TIMEOUT_SECONDS = 12
DISK_RESERVE_BYTES = 2 * 1024 * 1024 * 1024
ALLOWED_REDIRECT_HOSTS = frozenset(("go.dev", "dl.google.com", "nodejs.org"))
UNIT_NAMES = (
    "vram-governor-node-agent.service",
    "llama-server.service",
    "comfyui.service",
    "comfy-harness.service",
    "vram-governor-runtime-tunnel.service",
)
UNIT_FIELDS = ("Id", "LoadState", "ActiveState", "SubState", "MainPID", "InvocationID")
MAX_RECEIPT_BYTES = 3072
STARTED = time.monotonic()
DEADLINE = min(STARTED + GLOBAL_SECONDS, globals().get("_bootstrap_deadline", STARTED + GLOBAL_SECONDS))
SCRATCH = None
SCRATCH_FD = None
SCRATCH_ID = None


class StageError(Exception):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


def ensure_time():
    if time.monotonic() >= DEADLINE:
        raise StageError("deadline")


def canonical_hash(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def run_bounded(argv, timeout=8):
    ensure_time()
    remaining = DEADLINE - time.monotonic()
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=False, timeout=min(timeout, remaining), close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise StageError("observation") from None
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise StageError("observation")
    return result.stdout


def proc_starttime(pid):
    if pid == 0:
        return None
    if pid < 1 or pid > 4194304:
        raise StageError("observation")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open("/proc/%d/stat" % pid, flags)
        try:
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
    except OSError:
        raise StageError("observation") from None
    if len(raw) > 4096 or not raw.endswith(b"\n"):
        raise StageError("observation")
    # comm is parenthesized and can itself contain spaces or ')'; split after the final delimiter.
    close = raw.rfind(b")")
    if close < 0:
        raise StageError("observation")
    fields = raw[close + 2:].decode("ascii", "strict").split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise StageError("observation")
    return int(fields[19])


def unit_projection():
    projection = []
    props = ",".join(UNIT_FIELDS)
    for name in UNIT_NAMES:
        raw = run_bounded(("/usr/bin/systemctl", "show", name, "--property=" + props))
        try:
            lines = raw.decode("utf-8", "strict").splitlines()
        except UnicodeError:
            raise StageError("observation") from None
        if len(lines) != len(UNIT_FIELDS):
            raise StageError("observation")
        properties = {}
        for line in lines:
            key, sep, value = line.partition("=")
            if sep != "=" or key not in UNIT_FIELDS or key in properties or "\x00" in value or len(value) > 256:
                raise StageError("observation")
            properties[key] = value
        if set(properties) != set(UNIT_FIELDS):
            raise StageError("observation")
        values = [properties[key] for key in UNIT_FIELDS]
        if values[0] != name:
            raise StageError("observation")
        if not re.fullmatch(r"[0-9]+", values[4]):
            raise StageError("observation")
        pid = int(values[4])
        row = {key: value for key, value in zip(UNIT_FIELDS, values)}
        row["MainPIDStartTime"] = proc_starttime(pid)
        projection.append(row)
    return projection


def observe_units():
    return canonical_hash(unit_projection())


class AllowlistedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443) or parsed.hostname not in ALLOWED_REDIRECT_HOSTS:
            raise StageError("redirect")
        if not parsed.path.startswith("/") or parsed.fragment:
            raise StageError("redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, target, expected_hash, expected_size=None, max_size=ARCHIVE_MAX_BYTES):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_REDIRECT_HOSTS or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise StageError("url")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(), AllowlistedRedirect())
    digest = hashlib.sha256()
    total = 0
    timeout = min(READ_TIMEOUT_SECONDS, max(1, int(DEADLINE - time.monotonic())))
    try:
        response = opener.open(urllib.request.Request(url, headers={"User-Agent": "lb-ct200-verification-prep/1", "Accept-Encoding": "identity"}), timeout=timeout)
    except Exception:
        raise StageError("download") from None
    try:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname not in ALLOWED_REDIRECT_HOSTS or final.port not in (None, 443):
            raise StageError("redirect")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > max_size or (expected_size is not None and int(length) != expected_size)):
            raise StageError("download_size")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(target, flags, 0o600)
        try:
            while True:
                ensure_time()
                try:
                    chunk = response.read(65536)
                except (OSError, socket.timeout):
                    raise StageError("download_timeout") from None
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size or (expected_size is not None and total > expected_size):
                    raise StageError("download_size")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    n = os.write(fd, view)
                    if n <= 0:
                        raise StageError("disk")
                    view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        response.close()
    if expected_size is not None and total != expected_size:
        raise StageError("download_size")
    if digest.hexdigest() != expected_hash:
        raise StageError("download_hash")
    return total


def safe_parts(name, required_prefix):
    if not isinstance(name, str) or not name or "\\" in name or name.startswith("/") or "\x00" in name:
        raise StageError("archive_path")
    parts = name.split("/")
    if parts[-1] == "":
        parts.pop()
    if not parts or any(part in ("", ".", "..") or len(part.encode("utf-8")) > 255 for part in parts):
        raise StageError("archive_path")
    if parts[0] != required_prefix:
        raise StageError("archive_path")
    return parts


def mkdir_tree(root_fd, parts):
    current = os.dup(root_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o755, dir_fd=current)
            except FileExistsError:
                pass
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            nxt = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = nxt
        os.fchmod(current, 0o755)
    finally:
        os.close(current)


def open_parent(root_fd, parts):
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            nxt = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = nxt
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def extract_archive(archive_path, destination, mode, prefix, include_node=False):
    entries = 0
    expanded = 0
    selected_node = False
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    root_fd = os.open(destination, root_flags)
    try:
        try:
            archive = tarfile.open(archive_path, mode="r|gz")
        except (OSError, tarfile.TarError):
            raise StageError("archive") from None
        with archive:
            for item in archive:
                ensure_time()
                entries += 1
                if entries > ENTRY_MAX_COUNT:
                    raise StageError("archive_entries")
                parts = safe_parts(item.name, prefix)
                if item.isdir():
                    if item.size != 0:
                        raise StageError("archive_type")
                    if not include_node:
                        mkdir_tree(root_fd, parts)
                    continue
                if include_node and parts != [prefix, "bin", "node"]:
                    if not (item.isreg() or item.isdir() or item.issym() or item.islnk()):
                        raise StageError("archive_type")
                    if item.isreg():
                        if item.size < 0:
                            raise StageError("archive_type")
                        expanded += item.size
                        if expanded > EXPANDED_MAX_BYTES:
                            raise StageError("archive_expanded_bound")
                        stream = archive.extractfile(item)
                        if stream is None:
                            raise StageError("archive_data")
                        remaining = item.size
                        while remaining:
                            ensure_time()
                            block = stream.read(min(65536, remaining))
                            if not block:
                                raise StageError("archive_data")
                            remaining -= len(block)
                    continue
                if not item.isreg() or item.size < 0:
                    raise StageError("archive_type")
                expanded += item.size
                if expanded > EXPANDED_MAX_BYTES:
                    raise StageError("archive_expanded_bound")
                if include_node:
                    if selected_node or item.size > NODE_MAX_BYTES:
                        raise StageError("node_member")
                    out_parts = ["node"]
                else:
                    out_parts = parts
                parent_fd, basename = open_parent(root_fd, out_parts)
                try:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                    safe_mode = 0o755 if mode == 0o755 or (not include_node and item.mode & 0o111) else 0o644
                    fd = os.open(basename, flags, safe_mode, dir_fd=parent_fd)
                    stream = archive.extractfile(item)
                    if stream is None:
                        os.close(fd)
                        raise StageError("archive_data")
                    remaining = item.size
                    try:
                        while remaining:
                            ensure_time()
                            block = stream.read(min(65536, remaining))
                            if not block:
                                raise StageError("archive_data")
                            view = memoryview(block)
                            while view:
                                n = os.write(fd, view)
                                if n <= 0:
                                    raise StageError("disk")
                                view = view[n:]
                            remaining -= len(block)
                        os.fchmod(fd, safe_mode)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                finally:
                    os.close(parent_fd)
                if include_node:
                    selected_node = True
        if include_node and not selected_node:
            raise StageError("node_missing")
    finally:
        os.close(root_fd)
    return entries, expanded


def tree_measure(path):
    count = 0
    size = 0
    digest = hashlib.sha256()
    stack = [(path, "")]
    rows = []
    while stack:
        base, relative = stack.pop()
        with os.scandir(base) as entries:
            for entry in entries:
                count += 1
                if count > ENTRY_MAX_COUNT:
                    raise StageError("tree_bound")
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or (info.st_mode & 0o6022):
                    raise StageError("tree_mode")
                if stat.S_ISDIR(info.st_mode):
                    rows.append((relative + "/" + entry.name if relative else entry.name, "D", b""))
                    stack.append((entry.path, relative + "/" + entry.name if relative else entry.name))
                elif stat.S_ISREG(info.st_mode):
                    size += info.st_size
                    fd = os.open(entry.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
                    try:
                        opened = os.fstat(fd)
                        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size != info.st_size:
                            raise StageError("tree_changed")
                        content = hashlib.sha256()
                        while True:
                            ensure_time()
                            block = os.read(fd, 65536)
                            if not block:
                                break
                            content.update(block)
                    finally:
                        os.close(fd)
                    rows.append((relative + "/" + entry.name if relative else entry.name, "F", content.digest()))
                else:
                    raise StageError("tree_type")
                if size > EXPANDED_MAX_BYTES:
                    raise StageError("tree_bound")
    for name, kind, content_hash in sorted(rows, key=lambda row: row[0]):
        digest.update(kind.encode("ascii") + b"\0" + name.encode("utf-8") + b"\0" + content_hash + b"\n")
    return count, size, digest.hexdigest()


def verify_node_file(filename):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(filename, flags)
    except OSError:
        raise StageError("node_file") from None
    digest = hashlib.sha256()
    total = 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > NODE_MAX_BYTES or info.st_mode & 0o6022:
            raise StageError("node_file")
        while True:
            ensure_time()
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > NODE_MAX_BYTES:
                raise StageError("node_file")
            digest.update(block)
    finally:
        os.close(fd)
    return total, digest.hexdigest()


def emit_failure(category):
    # Only fixed categories and the newly-created scratch path cross the boundary.
    payload = {"status": "failed", "category": category, "path": SCRATCH}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) <= MAX_RECEIPT_BYTES:
        os.write(1, raw + b"\nCT200_TOOLS_FAILED\n")


def verify_tmp_parent():
    for dirname in ("/", "/var", "/var/tmp"):
        try:
            info = os.lstat(dirname)
        except OSError:
            raise StageError("scratch_custody") from None
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise StageError("scratch_custody")
        if dirname == "/var/tmp":
            if not (info.st_mode & stat.S_ISVTX) or not (info.st_mode & 0o002) or info.st_mode & 0o6000:
                raise StageError("scratch_custody")
        elif info.st_mode & 0o6022:
            raise StageError("scratch_custody")


def verify_scratch():
    if SCRATCH_FD is None or SCRATCH_ID is None:
        raise StageError("scratch_custody")
    try:
        held = os.fstat(SCRATCH_FD)
        named = os.lstat(SCRATCH)
    except OSError:
        raise StageError("scratch_custody") from None
    identity = (held.st_dev, held.st_ino)
    if identity != SCRATCH_ID or (named.st_dev, named.st_ino) != SCRATCH_ID or not stat.S_ISDIR(held.st_mode) or not stat.S_ISDIR(named.st_mode) or stat.S_ISLNK(named.st_mode) or held.st_uid != 0 or named.st_uid != 0 or (held.st_mode & 0o7777) != 0o700 or (named.st_mode & 0o7777) != 0o700:
        raise StageError("scratch_custody")


def alarm_expired(_signum, _frame):
    raise StageError("deadline")


def main():
    global SCRATCH, SCRATCH_FD, SCRATCH_ID
    signal.signal(signal.SIGALRM, alarm_expired)
    ensure_time()
    signal.setitimer(signal.ITIMER_REAL, max(0.1, DEADLINE - time.monotonic()))
    verify_tmp_parent()
    before_hash = observe_units()
    volume = os.statvfs("/var/tmp")
    free = volume.f_bavail * volume.f_frsize
    # Leave the requested reserve after allowing for compressed and expanded fixed payloads.
    if free < DISK_RESERVE_BYTES + ARCHIVE_TOTAL_MAX + EXPANDED_MAX_BYTES:
        raise StageError("disk_reserve")
    SCRATCH = tempfile.mkdtemp(prefix="lb-verification-tools-", dir="/var/tmp")
    os.chmod(SCRATCH, 0o700)
    scratch_stat = os.lstat(SCRATCH)
    if not stat.S_ISDIR(scratch_stat.st_mode) or stat.S_ISLNK(scratch_stat.st_mode) or scratch_stat.st_uid != 0 or scratch_stat.st_mode & 0o077:
        raise StageError("scratch_custody")
    SCRATCH_FD = os.open(SCRATCH, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    held_stat = os.fstat(SCRATCH_FD)
    SCRATCH_ID = (held_stat.st_dev, held_stat.st_ino)
    verify_scratch()
    go_archive = os.path.join(SCRATCH, ".go.archive")
    node_archive = os.path.join(SCRATCH, ".node.archive")
    verify_scratch()
    go_bytes = fetch(GO_URL, go_archive, GO_SHA256, expected_size=GO_BYTES)
    verify_scratch()
    node_bytes = fetch(NODE_URL, node_archive, NODE_SHA256)
    verify_scratch()
    if go_bytes + node_bytes > ARCHIVE_TOTAL_MAX:
        raise StageError("archive_total")
    go_dir = os.path.join(SCRATCH, "go")
    go_entries, _ = extract_archive(go_archive, SCRATCH, 0o644, "go")
    verify_scratch()
    node_dir = os.path.join(SCRATCH, ".node-extract")
    os.mkdir(node_dir, 0o700)
    node_entries, _ = extract_archive(node_archive, node_dir, 0o755, "node-v22.14.0-linux-x64", include_node=True)
    verify_scratch()
    node_target = os.path.join(SCRATCH, "node")
    os.rename(os.path.join(node_dir, "node"), node_target)
    os.rmdir(node_dir)
    verify_scratch()
    node_size, node_hash = verify_node_file(node_target)
    go_count, go_size, go_hash = tree_measure(go_dir)
    if go_count <= 0 or go_entries <= 0 or node_entries <= 0:
        raise StageError("archive_empty")
    after_hash = observe_units()
    verify_scratch()
    if before_hash != after_hash:
        raise StageError("units_changed")
    free_after = os.statvfs("/var/tmp").f_bavail * os.statvfs("/var/tmp").f_frsize
    if free_after < DISK_RESERVE_BYTES:
        raise StageError("disk_reserve")
    receipt = {
        "schema": SCHEMA,
        "status": "staged",
        "path": SCRATCH,
        "go_archive_sha256": GO_SHA256,
        "node_archive_sha256": NODE_SHA256,
        "go_tree_entries": go_count,
        "go_files_bytes": go_size,
        "go_tree_sha256": go_hash,
        "node_bytes": node_size,
        "node_file_sha256": node_hash,
        "units_before_sha256": before_hash,
        "units_after_sha256": after_hash,
        "downloaded_tools_executed": False,
        "production_units_unchanged": True,
    }
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > MAX_RECEIPT_BYTES:
        raise StageError("receipt_bound")
    os.write(1, raw + b"\nCT200_TOOLS_STAGED\n")


if __name__ == "__main__":
    try:
        main()
    except StageError as exc:
        emit_failure(exc.category)
        raise SystemExit(1)
    except BaseException:
        emit_failure("unknown")
        raise SystemExit(1)
