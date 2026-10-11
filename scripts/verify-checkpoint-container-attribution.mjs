import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const modes = ['--mode=authority', '--mode=kernel', '--mode=kernel-proxmox', '--mode=regressions', '--mode=source-only'];
const mode = process.argv[2];
if (process.argv.length !== 3 || !modes.includes(mode)) throw new Error(`usage: node scripts/verify-checkpoint-container-attribution.mjs ${modes.join('|')}`);
if (!['linux', 'win32'].includes(process.platform)) throw new Error(`unsupported verification host: ${process.platform}`);

const owned = [
  'internal/checkpointgpuobserver/protocol.go', 'internal/checkpointgpuobserver/protocol_test.go',
  'internal/checkpointgpuobserver/observer_linux.go', 'internal/checkpointgpuobserver/observer_linux_test.go',
  'internal/checkpointgpuobserver/observer_kernel_linux_test.go', 'internal/checkpointgpuobserver/observer_other.go',
  'internal/nodeagent/checkpoint_host_gpu_bridge.go', 'internal/nodeagent/checkpoint_host_gpu_bridge_linux.go',
  'internal/nodeagent/checkpoint_host_gpu_bridge_other.go', 'internal/nodeagent/checkpoint_host_gpu_bridge_test.go',
  'internal/nodeagent/checkpoint_host_gpu_bridge_linux_test.go', 'internal/nodeagent/checkpoint_device_binding_linux.go',
  'internal/nodeagent/checkpoint_device_binding_linux_test.go', 'internal/nodeagent/checkpoint_managed_binding_linux.go',
  'internal/nodeagent/checkpoint_managed_binding_linux_test.go',
];
const source = new Map(owned.map((name) => [name, readFileSync(path.join(root, name), 'utf8')]));
const protocol = source.get(owned[0]);
const host = source.get(owned[2]);
const bridge = source.get(owned[7]);
const startup = source.get(owned[11]);
const managed = source.get(owned[13]);
const fixture = source.get(owned[4]);
const observerCommand = readFileSync(path.join(root, 'cmd/checkpoint-gpu-observer/main_linux.go'), 'utf8');
const verifier = readFileSync(fileURLToPath(import.meta.url), 'utf8');
const expected = [
  'TestRequestCanonicalValidation', 'TestSignedResponseBindsNonceAndIncarnations',
  'TestResponseRejectsGPUAndNamespaceSubstitution', 'TestRepeatedNumericNSpidAcrossNamespacesIsValid',
  'TestEnvelopeRejectsDuplicateFieldsAndBadEncoding',
  'TestObserverConfigRequiresBothExactCallerRolesAndContainerAuthority', 'TestObserverPeerNeedsExecutableAndHostCgroupAuthority',
  'TestHostNSpidParserRetainsRepeatedIDsAcrossNamespaceLevels', 'TestGPUInventoryParserAndUniqueWorkerJoin',
  'TestCheckpointHostObserverFramingBoundsAndRoundTrip', 'TestCheckpointObserverFrameWriterHandlesShortWritesAndZeroProgress',
  'TestCheckpointObserverTrustPinDetectsContentAndPathSubstitution',
];

const proxmoxReceiver = String.raw`import hashlib, os, re, selectors, signal, stat, subprocess, sys, tempfile, time
EXPECTED_PIDNS = 4026531836
MAX_BINARY = 256 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
MAX_REMOTE_SECONDS = 175
NAME = "observer-kernel.test"
TEST = "TestCheckpointGPUObserverKernelNamespaceFixture"
ROOT = None

def fail(message):
    raise RuntimeError(str(message)[:1200])

def failure_tail(value):
    text = str(value)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    text = re.sub(r"(?<![A-Za-z0-9_])/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+", "[path]", text)
    return " ".join(text.split())[-700:]

def classify_fixture_failure(output, post_reap_confirmed=True, capture_succeeded=True, cleanup_confirmed=True):
    if not post_reap_confirmed or not cleanup_confirmed:
        return ("unavailable", "cleanup_uncertain")
    if not capture_succeeded:
        return ("unavailable", "capture_failed")
    if not isinstance(output, str) or len(output) > MAX_OUTPUT:
        return ("unavailable", "unsafe_or_oversized")
    anchors = [
        (100, "post_reap_pidfd", "readiness_rejected", "held fixture pidfd did not report clean post-reap readiness"),
        (100, "post_reap_pidfd", "live_process_present", "held pidfd still identifies a live or unreaped process"),
        (100, "post_reap_pidfd", "absence_record_invalid", "held pidfd info must contain exactly one original-process absence record"),
        (100, "worker_proc", "incarnation_present", "worker start ticks still identify the exited incarnation"),
        (100, "worker_proc", "pid_reused", "worker PID was reused before exited state could be confirmed"),
        (100, "worker_proc", "proc_uncertain", "cannot distinguish exited worker from an uncertain proc read"),
        (50, "systemd_unit", "launch_failed", "uniquely named local CPU namespace unit failed"),
        (50, "fixture_marker", "proof_marker_missing", "kernel fixture did not emit its proof marker"),
        (50, "fixture_marker", "marker_cardinality", "nested fixture output must contain exactly one"),
        (50, "nested_namespace", "isolation_marker_missing", "nested child did not prove namespace isolation"),
        (50, "observer_scenarios", "accept_failed", "observer scenario accept failed after"),
    ]
    found = []
    for priority, site, reason, anchor in anchors:
        count = output.count(anchor)
        if count > 1:
            return ("unavailable", "ambiguous")
        if count == 1:
            found.append((priority, site, reason))
    if not found:
        return ("unavailable", "unclassified")
    highest = max(item[0] for item in found)
    decisive = [item for item in found if item[0] == highest]
    if len(decisive) != 1:
        return ("unavailable", "ambiguous")
    return (decisive[0][1], decisive[0][2])

def capture_failure_stage(capture_error, cleanup_error, identity_stage, unit_error):
    if cleanup_error is not None:
        return "child_reap_unconfirmed"
    if identity_stage in ("fixture_identity_missing", "fixture_identity_duplicate", "fixture_identity_pid_mismatch"):
        return identity_stage
    if unit_error is not None:
        return "exact_unit_absence_unconfirmed"
    if capture_error is not None:
        return "capture_exception"
    return "unavailable"

def emit_failure_diagnostic(output, post_reap_confirmed=True, capture_succeeded=True, cleanup_confirmed=True, stage="unavailable"):
    site, reason = classify_fixture_failure(output, post_reap_confirmed, capture_succeeded, cleanup_confirmed)
    allowed_stages = {
        "capture_exception", "child_reap_unconfirmed", "fixture_identity_missing",
        "fixture_identity_duplicate", "fixture_identity_pid_mismatch", "exact_unit_absence_unconfirmed",
        "child_exit_nonzero", "postvalidation_hardware_claim", "postvalidation_marker_inventory",
        "postvalidation_server_reason_inventory", "postvalidation_unit_marker", "postvalidation_test_inventory",
        "postvalidation_runpass_inventory", "postvalidation_namespace_identity", "postvalidation_upload_pin",
        "postvalidation_uploaded_file_cleanup", "postvalidation_upload_root_state", "postvalidation_tmp_parent_state",
        "postvalidation_exact_root_cleanup", "postvalidation_success_output", "postvalidation_unknown", "unavailable",
    }
    if not isinstance(stage, str) or stage not in allowed_stages:
        stage, site, reason = "unavailable", "unavailable", "unclassified"
    elif stage == "unavailable":
        site, reason = "unavailable", "unclassified"
    marker = "REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=%s site=%s reason=%s\n" % (stage, site, reason)
    if len(marker.encode("ascii")) > 192:
        marker = "REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=unavailable site=unavailable reason=unclassified\n"
    sys.stderr.write(marker)
    sys.stderr.flush()

def initial_namespace():
    if os.geteuid() != 0 or os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
        fail("fixed host identity is not root Linux amd64")
    self_ns = os.stat("/proc/self/ns/pid").st_ino
    init_ns = os.stat("/proc/1/ns/pid").st_ino
    if self_ns != EXPECTED_PIDNS or init_ns != EXPECTED_PIDNS or self_ns != init_ns:
        fail("fixed host is not in the independently pinned initial PID namespace")

def regular_pin(st, dev, ino, size, mode):
    return stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and st.st_dev == dev and st.st_ino == ino and st.st_size == size and stat.S_IMODE(st.st_mode) == mode

def digest_fd(fd):
    h = hashlib.sha256()
    total = 0
    while True:
        block = os.pread(fd, 65536, total)
        if not block:
            break
        total += len(block)
        if total > MAX_BINARY:
            fail("held fixture executable exceeded its byte bound")
        h.update(block)
    return h.hexdigest(), total

def verify_upload_pins(binary_fd, binary_st):
    parent = os.fstat(tmp_fd)
    parent_path = os.stat("/tmp", follow_symlinks=False)
    root = os.fstat(upload_fd)
    root_path = os.stat(os.path.basename(ROOT), dir_fd=tmp_fd, follow_symlinks=False)
    held = os.fstat(binary_fd)
    path = os.stat(NAME, dir_fd=upload_fd, follow_symlinks=False)
    digest, size = digest_fd(binary_fd)
    if parent.st_dev != held_tmp_st.st_dev or parent.st_ino != held_tmp_st.st_ino or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) & 0o777 != 0o777 or not parent.st_mode & stat.S_ISVTX or parent_path.st_dev != held_tmp_st.st_dev or parent_path.st_ino != held_tmp_st.st_ino or parent_path.st_uid != 0 or stat.S_IMODE(parent_path.st_mode) & 0o777 != 0o777 or not parent_path.st_mode & stat.S_ISVTX:
        fail("held /tmp parent identity or permissions changed")
    if root.st_dev != held_upload_st.st_dev or root.st_ino != held_upload_st.st_ino or root.st_uid != 0 or stat.S_IMODE(root.st_mode) != 0o700 or root.st_nlink != 2 or root_path.st_dev != root.st_dev or root_path.st_ino != root.st_ino:
        fail("held private upload root identity changed")
    if not regular_pin(held, binary_st.st_dev, binary_st.st_ino, binary_st.st_size, 0o700) or not regular_pin(path, binary_st.st_dev, binary_st.st_ino, binary_st.st_size, 0o700) or digest != expected_sha or size != expected_size:
        fail("held uploaded executable inode, path, or digest changed")

def bounded_command(argv, timeout=8):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True, timeout=timeout, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root"}, check=False)
    output = result.stdout[:4097].decode("utf-8", "replace")
    if len(result.stdout) > 4096 or result.returncode != 0:
        fail("bounded exact-unit command failed: %s status=%s output=%s" % (argv[1:], result.returncode, output[-1200:]))
    return output.strip()

def confirm_exact_unit_absent(unit):
    if not re.fullmatch(r"checkpoint-gpu-observer-fixture-[0-9a-f]{24}\.service", unit):
        fail("fixture unit identity is malformed; exact-unit absence is unconfirmed")
    state = bounded_command(["/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit])
    if state != "not-found":
        fail("exact transient unit absence is unconfirmed; LoadState=" + state + "; no unit mutation attempted")

def capture_test(binary, binary_fd, binary_st):
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root", "TMPDIR": "/tmp", "CHECKPOINT_GPU_OBSERVER_FIXED_HOST": "1"}
    argv = [binary, "-test.run=^TestCheckpointGPUObserverKernelNamespaceFixture$", "-test.count=1", "-test.timeout=160s", "-test.v"]
    verify_upload_pins(binary_fd, binary_st)
    initial_namespace()
    proc = subprocess.Popen(argv, cwd="/tmp", env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True, start_new_session=True)
    captured = bytearray()
    capture_error = None
    status = None
    try:
        sys.stderr.write("REMOTE_TEST_PROCESS_IDENTITY: pid=%d upload=%s\n" % (proc.pid, ROOT))
        sys.stderr.flush()
        child_exe = os.stat("/proc/%d/exe" % proc.pid)
        child_ns = os.stat("/proc/%d/ns/pid" % proc.pid).st_ino
        if child_exe.st_dev != binary_st.st_dev or child_exe.st_ino != binary_st.st_ino or child_ns != EXPECTED_PIDNS:
            fail("test process executable or initial PID namespace did not match the held fixture")
        initial_namespace()
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + MAX_REMOTE_SECONDS
        while selector.get_map() or proc.poll() is None:
            left = deadline - time.monotonic()
            if left <= 0:
                fail("fixed-host kernel fixture exceeded its bounded 175-second receiver deadline")
            for key, _ in selector.select(min(left, 1.0)):
                block = os.read(key.fd, 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                captured.extend(block)
                if len(captured) > MAX_OUTPUT:
                    fail("fixed-host kernel fixture output exceeded its 2 MiB bound")
        status = proc.wait(timeout=2)
    except Exception as error:
        capture_error = error
    finally:
        cleanup_error = None
        try:
            if proc.poll() is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=3)
            else:
                proc.wait(timeout=2)
            if proc.poll() is None:
                fail("exact test child PID %d remains unreaped after bounded TERM/KILL" % proc.pid)
        except Exception as error:
            cleanup_error = error
        finally:
            if proc.stdout is not None:
                proc.stdout.close()
        output = captured.decode("utf-8", "replace")
        identity = re.findall(r"^KERNEL_FIXTURE_IDENTITY: pid=(\d+) unit=(checkpoint-gpu-observer-fixture-[0-9a-f]{24}\.service) root=(/tmp/checkpoint-gpu-observer-kernel-[A-Za-z0-9_-]+)$", output, re.M)
        if len(identity) == 0:
            identity_stage = "fixture_identity_missing"
        elif len(identity) > 1:
            identity_stage = "fixture_identity_duplicate"
        elif int(identity[0][0]) != proc.pid:
            identity_stage = "fixture_identity_pid_mismatch"
        else:
            identity_stage = None
        if identity_stage is not None:
            unit_error = "exact unit/PID identity was not observed exactly once before launch"
            unit = None
            fixture_root = "unconfirmed"
        else:
            unit = identity[0][1]
            fixture_root = identity[0][2]
            unit_error = None
        if unit is not None and cleanup_error is None:
            try:
                confirm_exact_unit_absent(unit)
            except Exception as error:
                unit_error = str(error)
        elif cleanup_error is not None:
            unit_error = "exact unit absence was not checked because test child reaping is unconfirmed"
        if capture_error is not None or cleanup_error is not None or unit_error is not None:
            failure_stage = capture_failure_stage(capture_error, cleanup_error, identity_stage, unit_error)
            emit_failure_diagnostic(output, post_reap_confirmed=(cleanup_error is None and unit_error is None), capture_succeeded=(capture_error is None), cleanup_confirmed=(cleanup_error is None and unit_error is None), stage=failure_stage)
            fail("fixture identity pid=%d unit=%s root=%s upload=%s; capture=%s; child-reap=%s; unit-absence=%s; captured-tail=%s" % (proc.pid, unit or "unconfirmed", fixture_root, ROOT, capture_error or "none", cleanup_error or "confirmed", unit_error or "confirmed", failure_tail(output)))
    output = captured.decode("utf-8", "replace")
    if status != 0:
        emit_failure_diagnostic(output, stage="child_exit_nonzero")
        fail("fixed-host kernel fixture exited %d; fixture identity pid=%d unit=%s root=%s upload=%s; bounded decisive output follows: %s" % (status, proc.pid, unit, fixture_root, ROOT, failure_tail(output)))
    failure_stage = "postvalidation_unknown"
    try:
        failure_stage = "postvalidation_hardware_claim"
        if re.search(r"FAKE_NVIDIA.*hardware|actual GPU measurement", output, re.I):
            fail("CPU fixture output contains an unsupported hardware-attribution claim")
        failure_stage = "postvalidation_marker_inventory"
        expected = ["NESTED_PID_MOUNT_CGROUP_FIXTURE_PASS", "NESTED_HOST_OBSERVER_SIGNED_JOIN_PASS_SYNTHETIC_ONLY", "KERNEL_FIXTURE_PUBLISHED_EXECUTABLE_CLEANUP_PASS", "KERNEL_FIXTURE_PRIVATE_ROOT_CLEANUP_PASS"]
        scenarios = ["positive", "wrong-peer", "wrong-container", "ambiguous-cgroup", "stale-start", "duplicate-gpu-row", "wrong-gpu-row", "wrong-namespace", "exited-worker"]
        expected.extend("FIXTURE_SCENARIO_PASS:" + name for name in scenarios)
        expected.extend("FIXTURE_SCENARIO_DENIED:" + name for name in scenarios if name != "positive")
        server_reason_names = ["wrong-peer", "wrong-container", "ambiguous-cgroup"]
        expected.extend("FIXTURE_SERVER_AUTH_DENIED:" + name for name in server_reason_names)
        for marker in expected:
            if output.count(marker) != 1:
                fail("fixed-host test marker count is not exactly one: " + marker)
        failure_stage = "postvalidation_server_reason_inventory"
        server_reason_events = re.findall(r"FIXTURE_SERVER_AUTH_DENIED:([^\r\n]*)", output)
        if server_reason_events != server_reason_names:
            fail("fixed-host server authorization-reason marker inventory is not exact")
        failure_stage = "postvalidation_unit_marker"
        unit_markers = re.findall(r"KERNEL_FIXTURE_UNIT_CLEANUP_PASS:(checkpoint-gpu-observer-fixture-[0-9a-f]{24}\.service)", output)
        if len(unit_markers) != 1:
            fail("exact transient CPU unit absence marker is missing or duplicated")
        failure_stage = "postvalidation_test_inventory"
        if re.search(r"^--- (?:SKIP|FAIL):", output, re.M):
            fail("fixed-host inventory contains an unexpected test, skip, or failure")
        failure_stage = "postvalidation_runpass_inventory"
        run_events = re.findall(r"^=== RUN[ \t]+(\S+)[ \t]*$", output, re.M)
        pass_events = re.findall(r"^--- PASS:[ \t]+(\S+)(?:[ \t]+\([^)]*\))?[ \t]*$", output, re.M)
        if run_events != [TEST] or pass_events != [TEST]:
            fail("fixed-host inventory did not contain exactly the selected RUN/PASS pair")
        failure_stage = "postvalidation_namespace_identity"
        initial_namespace()
        failure_stage = "postvalidation_upload_pin"
        verify_upload_pins(binary_fd, binary_st)
        failure_stage = "postvalidation_uploaded_file_cleanup"
        os.unlink(NAME, dir_fd=upload_fd)
        os.fsync(upload_fd)
        try:
            os.stat(NAME, dir_fd=upload_fd, follow_symlinks=False)
            fail("exact uploaded executable remains after unlink")
        except FileNotFoundError:
            pass
        failure_stage = "postvalidation_upload_root_state"
        if os.listdir(upload_fd):
            fail("private upload root contains unexpected entries")
        root_held_now = os.fstat(upload_fd)
        root_now = os.stat(os.path.basename(ROOT), dir_fd=tmp_fd, follow_symlinks=False)
        parent_held_now = os.fstat(tmp_fd)
        parent_now = os.stat("/tmp", follow_symlinks=False)
        failure_stage = "postvalidation_upload_root_state"
        if root_held_now.st_dev != held_upload_st.st_dev or root_held_now.st_ino != held_upload_st.st_ino or root_held_now.st_uid != 0 or stat.S_IMODE(root_held_now.st_mode) != 0o700 or root_held_now.st_nlink != 2 or root_now.st_dev != upload_root_st.st_dev or root_now.st_ino != upload_root_st.st_ino or root_now.st_uid != 0 or stat.S_IMODE(root_now.st_mode) != 0o700 or root_now.st_nlink != 2:
            fail("private upload root identity changed before cleanup")
        failure_stage = "postvalidation_tmp_parent_state"
        if parent_held_now.st_dev != held_tmp_st.st_dev or parent_held_now.st_ino != held_tmp_st.st_ino or parent_held_now.st_uid != 0 or stat.S_IMODE(parent_held_now.st_mode) & 0o777 != 0o777 or not parent_held_now.st_mode & stat.S_ISVTX or parent_now.st_dev != held_tmp_st.st_dev or parent_now.st_ino != held_tmp_st.st_ino or parent_now.st_uid != 0 or stat.S_IMODE(parent_now.st_mode) & 0o777 != 0o777 or not parent_now.st_mode & stat.S_ISVTX:
            fail("existing /tmp held parent identity or permissions changed before cleanup")
        failure_stage = "postvalidation_exact_root_cleanup"
        os.close(binary_fd)
        os.close(upload_fd)
        os.rmdir(os.path.basename(ROOT), dir_fd=tmp_fd)
        os.fsync(tmp_fd)
        try:
            os.stat(os.path.basename(ROOT), dir_fd=tmp_fd, follow_symlinks=False)
            fail("private upload root remains after exact cleanup")
        except FileNotFoundError:
            pass
        os.close(tmp_fd)
        failure_stage = "postvalidation_success_output"
        sys.stdout.write(output)
        sys.stdout.write("\nREMOTE_FIXED_KERNEL_UPLOAD_CLEANUP_PASS\n")
    except Exception as error:
        emit_failure_diagnostic(output, cleanup_confirmed=False, stage=failure_stage)
        fail("fixture identity pid=%d unit=%s root=%s upload=%s; post-run validation=%s; captured-tail=%s" % (proc.pid, unit, fixture_root, ROOT, error, failure_tail(output)))

try:
    initial_namespace()
    if len(sys.argv) != 3 or not sys.argv[1].isdigit() or not re.fullmatch(r"[0-9a-f]{64}", sys.argv[2]):
        fail("fixed receiver size or digest argument is malformed")
    expected_size = int(sys.argv[1])
    expected_sha = sys.argv[2]
    if expected_size <= 0 or expected_size > MAX_BINARY:
        fail("fixed receiver binary length is outside its bound")
    tmp_stat = os.stat("/tmp", follow_symlinks=False)
    if not stat.S_ISDIR(tmp_stat.st_mode) or tmp_stat.st_uid != 0 or stat.S_IMODE(tmp_stat.st_mode) & 0o777 != 0o777 or not tmp_stat.st_mode & stat.S_ISVTX:
        fail("existing /tmp is not root-owned, sticky, and searchable")
    tmp_fd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    held_tmp_st = os.fstat(tmp_fd)
    if held_tmp_st.st_dev != tmp_stat.st_dev or held_tmp_st.st_ino != tmp_stat.st_ino or held_tmp_st.st_uid != 0 or stat.S_IMODE(held_tmp_st.st_mode) & 0o777 != 0o777 or not held_tmp_st.st_mode & stat.S_ISVTX:
        fail("existing /tmp changed while acquiring its held parent descriptor")
    ROOT = tempfile.mkdtemp(prefix="checkpoint-gpu-observer-upload-", dir="/tmp")
    sys.stderr.write("EXACT_PRIVATE_UPLOAD_PATH: " + ROOT + "\n")
    sys.stderr.write("REMOTE_RECEIVER_IDENTITY: pid=%d upload=%s\n" % (os.getpid(), ROOT))
    sys.stderr.flush()
    upload_root_st = os.stat(ROOT, follow_symlinks=False)
    upload_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    held_upload_st = os.fstat(upload_fd)
    anchored_upload_st = os.stat(os.path.basename(ROOT), dir_fd=tmp_fd, follow_symlinks=False)
    if held_upload_st.st_dev != upload_root_st.st_dev or held_upload_st.st_ino != upload_root_st.st_ino or held_upload_st.st_dev != anchored_upload_st.st_dev or held_upload_st.st_ino != anchored_upload_st.st_ino or held_upload_st.st_uid != 0 or stat.S_IMODE(held_upload_st.st_mode) != 0o700 or held_upload_st.st_nlink != 2:
        fail("private upload directory held identity or permissions are invalid")
    write_fd = os.open(NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o700, dir_fd=upload_fd)
    os.fchmod(write_fd, 0o700)
    digest = hashlib.sha256()
    first = bytearray()
    remaining = expected_size
    while remaining:
        block = sys.stdin.buffer.read(min(65536, remaining))
        if not block:
            fail("bounded binary upload ended before its declared length")
        remaining -= len(block)
        digest.update(block)
        if len(first) < 20:
            first.extend(block[:20 - len(first)])
        view = memoryview(block)
        while view:
            written = os.write(write_fd, view)
            if written <= 0:
                fail("binary upload write made no forward progress")
            view = view[written:]
    if sys.stdin.buffer.read(1):
        fail("binary upload exceeded its declared length")
    if digest.hexdigest() != expected_sha or len(first) != 20 or bytes(first[:4]) != b"\x7fELF" or first[4] != 2 or first[5] != 1 or int.from_bytes(first[18:20], "little") != 62:
        fail("uploaded bytes are not the expected hashed ELF64 amd64 executable")
    os.fsync(write_fd)
    upload_file_st = os.fstat(write_fd)
    path_st = os.stat(NAME, dir_fd=upload_fd, follow_symlinks=False)
    if not regular_pin(upload_file_st, upload_file_st.st_dev, upload_file_st.st_ino, expected_size, 0o700) or not regular_pin(path_st, upload_file_st.st_dev, upload_file_st.st_ino, expected_size, 0o700):
        fail("uploaded file held descriptor/path metadata does not match exact private pin")
    os.close(write_fd)
    binary_fd = os.open(NAME, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=upload_fd)
    read_st = os.fstat(binary_fd)
    read_path_st = os.stat(NAME, dir_fd=upload_fd, follow_symlinks=False)
    read_digest, read_size = digest_fd(binary_fd)
    if not regular_pin(read_st, upload_file_st.st_dev, upload_file_st.st_ino, expected_size, 0o700) or not regular_pin(read_path_st, upload_file_st.st_dev, upload_file_st.st_ino, expected_size, 0o700) or read_digest != expected_sha or read_size != expected_size:
        fail("reopened uploaded executable does not match exact held read-only pin")
    initial_namespace()
    capture_test(os.path.join(ROOT, NAME), binary_fd, read_st)
except Exception as error:
    sys.stderr.write("REMOTE_FIXED_KERNEL_ERROR: " + str(error).replace("\n", " ")[:1600] + "\n")
    if ROOT:
        sys.stderr.write("PRESERVED_EXACT_UPLOAD_PATH: " + ROOT + "\n")
    sys.exit(1)
`;

function kernelPostReapStateAccepts(state) {
  if (!state || state.waitReaped !== true || state.waitSignal !== 'SIGKILL') return false;
  if (state.pollError || state.pollReady !== 1 || !Number.isInteger(state.pollEvents)) return false;
  const allowed = 0x001 | 0x010 | 0x040; // POLLIN, optional POLLHUP, POLLRDNORM.
  if ((state.pollEvents & 0x001) === 0 || (state.pollEvents & (0x008 | 0x020)) !== 0 || (state.pollEvents & ~allowed) !== 0) return false;
  if (state.fdinfoError || state.fdinfoPid !== -1 || state.procState !== 'absent') return false;
  return true;
}

function kernelPostReapStateControls() {
  const positive = { waitReaped: true, waitSignal: 'SIGKILL', pollReady: 1, pollEvents: 0x041, fdinfoPid: -1, procState: 'absent' };
  if (!kernelPostReapStateAccepts(positive) ||
      !kernelPostReapStateAccepts({ ...positive, pollEvents: 0x001 }) ||
      !kernelPostReapStateAccepts({ ...positive, pollEvents: 0x051 })) {
    throw new Error('post-reap predicate rejected the Linux pidfd-ready positive controls');
  }
  const negatives = [
    ['wait missing', { ...positive, waitReaped: false }],
    ['unexpected wait signal', { ...positive, waitSignal: 'SIGTERM' }],
    ['poll not ready', { ...positive, pollReady: 0 }],
    ['poll syscall error', { ...positive, pollError: true }],
    ['HUP without readable readiness', { ...positive, pollEvents: 0x010 }],
    ['poll error', { ...positive, pollEvents: 0x009 }],
    ['invalid descriptor', { ...positive, pollEvents: 0x021 }],
    ['unexpected poll flag', { ...positive, pollEvents: 0x003 }],
    ['live fdinfo target', { ...positive, fdinfoPid: 123 }],
    ['fdinfo read error', { ...positive, fdinfoError: true }],
    ['zombie remains in proc', { ...positive, procState: 'zombie' }],
    ['live process remains in proc', { ...positive, procState: 'live' }],
    ['PID was reused', { ...positive, procState: 'reused' }],
    ['proc read error', { ...positive, procState: 'error' }],
  ];
  for (const [name, state] of negatives) {
    if (kernelPostReapStateAccepts(state)) throw new Error(`post-reap predicate accepted ${name}`);
  }
}

function assertContract() {
  assert.match(verifier, /const sshEnvironment = Object\.fromEntries\(\['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'USERPROFILE', 'HOME', 'PROGRAMDATA'\]\.filter\(\(key\) => process\.env\[key\]\)\.map\(\(key\) => \[key, process\.env\[key\]\]\)\);/);
  const sshArgsSource = /const sshArgs = \[([\s\S]*?)\n    \];/.exec(verifier)?.[1];
  assert.ok(sshArgsSource, 'fixed-host SSH arguments must remain an explicit bounded array');
  assert.match(sshArgsSource, /'-F', 'none'[\s\S]*?'-oProxyCommand=none', '-oProxyJump=none', '-oClearAllForwardings=yes'/);
  assert.match(verifier, /run\(ssh, sshArgs, \{ environment: sshEnvironment,/);
  assert.match(proxmoxReceiver, /bytes\(first\[:4\]\) != b"\\x7fELF"/);
  assert.match(proxmoxReceiver, /checkpoint-gpu-observer-fixture-\[0-9a-f\]\{24\}\\\.service/);
  assert.match(proxmoxReceiver, /def verify_upload_pins\(binary_fd, binary_st\):/);
  assert.equal([...proxmoxReceiver.matchAll(/verify_upload_pins\(/g)].length, 3, 'every upload-pin check must receive its held descriptor and metadata explicitly');
  assert.match(proxmoxReceiver, /proc\.terminate\(\)[\s\S]*proc\.wait\(timeout=3\)[\s\S]*proc\.kill\(\)[\s\S]*proc\.wait\(timeout=3\)/);
  assert.match(proxmoxReceiver, /confirm_exact_unit_absent\(unit\)/);
  assert.doesNotMatch(proxmoxReceiver, /systemctl", "(?:stop|reset-failed)"/);
  assert.match(proxmoxReceiver, /REMOTE_TEST_PROCESS_IDENTITY/);
  assert.match(proxmoxReceiver, /def failure_tail\(value\):[\s\S]*return " ".join\(text\.split\(\)\)\[-700:\]/);
  assert.match(proxmoxReceiver, /REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=%s site=%s reason=%s/);
  assert.match(proxmoxReceiver, /len\(marker\.encode\("ascii"\)\) > 192/);
  assert.match(proxmoxReceiver, /def capture_failure_stage\(capture_error, cleanup_error, identity_stage, unit_error\):/);
  assert.match(proxmoxReceiver, /fixture_identity_missing[\s\S]*fixture_identity_duplicate[\s\S]*fixture_identity_pid_mismatch/);
  assert.equal([...proxmoxReceiver.matchAll(/failure_tail\(output\)/g)].length, 3, 'every captured Go failure must use the bounded sanitized diagnostic tail');
  assert.match(proxmoxReceiver, /MAX_REMOTE_SECONDS = 175/);
  assert.match(proxmoxReceiver, /status = proc\.wait\(timeout=2\)/);
  assert.match(proxmoxReceiver, /confirm_exact_unit_absent\(unit\)/);
  assert.match(proxmoxReceiver, /if status != 0:\n        emit_failure_diagnostic\(output, stage="child_exit_nonzero"\)\n        fail\("fixed-host kernel fixture exited/);
  assert.equal([...proxmoxReceiver.matchAll(/^\s+emit_failure_diagnostic\(output/gm)].length, 3, 'each post-reap receiver failure path emits one diagnostic marker');
  assert.doesNotMatch(proxmoxReceiver, /output\[-60000:\]/);
  assert.match(proxmoxReceiver, /captured-tail=/);
  assert.match(proxmoxReceiver, /PRESERVED_EXACT_UPLOAD_PATH/);
  assert.match(proxmoxReceiver, /re\.findall\(r"\^=== RUN\[ \\t\]/);
  assert.match(proxmoxReceiver, /re\.findall\(r"\^--- PASS:\[ \\t\]/);
  for (const anchor of [
    'held fixture pidfd did not report clean post-reap readiness',
    'held pidfd still identifies a live or unreaped process',
    'held pidfd info must contain exactly one original-process absence record',
    'worker start ticks still identify the exited incarnation',
    'worker PID was reused before exited state could be confirmed',
    'cannot distinguish exited worker from an uncertain proc read',
    'uniquely named local CPU namespace unit failed',
    'kernel fixture did not emit its proof marker',
    'nested fixture output must contain exactly one',
    'nested child did not prove namespace isolation',
    'observer scenario accept failed after',
  ]) {
    if (!fixture.includes(anchor)) throw new Error(`receiver diagnostic assertion anchor is not source-derived: ${anchor}`);
  }
  for (const pair of ['post_reap_pidfd:readiness_rejected', 'worker_proc:pid_reused', 'systemd_unit:launch_failed', 'unavailable:ambiguous', 'unavailable:cleanup_uncertain']) {
    if (!proxmoxReceiver.includes(pair.split(':')[0]) || !proxmoxReceiver.includes(pair.split(':')[1]) || !verifier.includes(`'${pair}'`)) {
      throw new Error(`receiver/host diagnostic closed enum is not aligned: ${pair}`);
    }
  }
  assert.match(verifier, /REMOTE_FAILURE_DIAGNOSTIC_STAGE_PAIRS = Object\.freeze\(/);
  assert.match(verifier, /child_exit_nonzero: \[\s*'post_reap_pidfd:readiness_rejected',[\s\S]*?'observer_scenarios:accept_failed',[\s\S]*?'unavailable:ambiguous', 'unavailable:unclassified', 'unavailable:unsafe_or_oversized',\s*\],/);
  assert.match(verifier, /stage=\(\[a-z_\]\+\) site=\(\[a-z_\]\+\) reason=\(\[a-z_\]\+\)/);
  assert.match(verifier, /failure_stage=\$\{stage\} failure_diagnostic=\$\{site\}:\$\{reason\}[\s\S]*\.slice\(0, 640\)/);
  assert.match(protocol, /ed25519\.Verify\(publicKey/);
  assert.match(protocol, /response\.Peer\.Namespace != response\.Init\.Namespace/);
  assert.match(protocol, /NSpid/);
  assert.match(host, /ensureInitialPIDNamespace\(\)/);
  assert.match(host, /exec\.CommandContext\(ctx, observerSMIPath, args\.\.\.\)/);
  assert.match(host, /SO_PEERCRED uid does not match the held process owner/);
  assert.match(host, /Unix peer uid, executable, cgroup, and role do not match the fixed allowlist/);
  assert.match(host, /credentials, socketErr = unix\.GetsockoptUcred\(int\(fd\), unix\.SOL_SOCKET, unix\.SO_PEERCRED\)/);
  assert.match(host, /if peer\.uid != credentials\.Uid/);
  assert.match(host, /selectObserverPeerContainer\(peer, authority, config\.Containers\)/);
  assert.match(host, /if matches != 1/);
  assert.match(host, /fixed-supervisor.*UID != 0/s);
  assert.match(host, /verifyRootPinnedSnapshot\(ObserverKeyPath/);
  assert.match(bridge, /rand\.Read\(nonce\)/);
  assert.match(bridge, /verifyCheckpointHostGPUResponseForRole\(responseBytes, publicKey, request, expectedRole/);
  assert.match(bridge, /func verifyCheckpointHostGPUResponseForRole\([\s\S]*?checkpointgpuobserver\.VerifyResponse\(raw, publicKey, request, nowUnixNS\)[\s\S]*?validateCheckpointHostGPUResponseRole\(response\.Role, expectedRole\)/);
  assert.match(bridge, /pin\.recheck\(\)/);
  assert.match(bridge, /parentDeadline\.Before\(deadline\)/);
  assert.match(startup, /namespaceRoute:\s*checkpointWorkerUsesNestedPIDNamespace/);
  assert.match(startup, /nestedAttribution:\s*observeCheckpointHostGPUAttribution/);
  assert.match(startup, /if nested \{[\s\S]*nestedAttribution[\s\S]*return checkpointOffloadEvidence/);
  assert.match(startup, /source\.pidNamespace\(bounded, pid\)/);
  assert.match(managed, /namespaceRoute:\s*checkpointWorkerUsesNestedPIDNamespace/);
  assert.match(managed, /nestedFootprint:\s*observeNestedManagedCheckpointFootprint/);
  assert.match(managed, /if nested \{[\s\S]*nestedFootprint[\s\S]*else \{[\s\S]*source\.footprint/);
  assert.match(fixture, /\/\/go:build linux && checkpoint_container_kernel/);
  assert.match(fixture, /verifyMountPropagationPrivateBeforeProcMount\(\)/);
  assert.match(fixture, /systemd-run/);
  assert.match(fixture, /Cloneflags:[\s\S]*CLONE_NEWUSER[\s\S]*CLONE_NEWPID[\s\S]*CLONE_NEWNS[\s\S]*CLONE_NEWCGROUP/);
  assert.match(fixture, /inventory := observerGPUInventorySource\s*\{/);
  assert.match(fixture, /handleObserverConnectionUsing\(callCtx, connection, scenario\.config, private, nil, inventory\)/);
  assert.match(fixture, /responseBytes, headerBytesRead, err := readFixtureFrame\(connection, MaxResponseBytes\)/);
  assert.match(fixture, /earlyAuthReject := scenario == "wrong-peer" \|\| scenario == "wrong-container" \|\| scenario == "ambiguous-cgroup"/);
  assert.match(fixture, /cleanEOF := headerBytesRead == 0 && errors\.Is\(err, io\.EOF\)/);
  assert.match(fixture, /resetBeforeFrame := earlyAuthReject && headerBytesRead == 0 && errors\.Is\(err, syscall\.ECONNRESET\)/);
  assert.match(fixture, /headerBytesRead, err := io\.ReadFull\(reader, header\[:\]\)/);
  assert.match(fixture, /return nil, headerBytesRead, err/);
  const reasonText = 'Unix peer uid, executable, cgroup, and role do not match the fixed allowlist';
  const serverReasonGuard = 'if results.accepted[index].callErr == nil || results.accepted[index].callErr.Error() != expectedReason {';
  const serverReasonMarker = 't.Log("FIXTURE_SERVER_AUTH_DENIED:" + scenario.name)';
  const serverReasonBindingInvariant = candidate => {
    const guardIndex = candidate.indexOf(serverReasonGuard);
    const markerIndex = candidate.indexOf(serverReasonMarker);
    return candidate.includes(`kernelFixtureFixedAllowlistDenialReason = "${reasonText}"`) &&
      /func kernelFixtureExpectedServerReason\(scenario string\) string \{[\s\S]*case "wrong-peer", "wrong-container", "ambiguous-cgroup":[\s\S]*return kernelFixtureFixedAllowlistDenialReason/.test(candidate) &&
      guardIndex >= 0 && markerIndex > guardIndex;
  };
  if (!serverReasonBindingInvariant(fixture) ||
      serverReasonBindingInvariant(fixture.replace(reasonText, 'different authorization failure')) ||
      serverReasonBindingInvariant(fixture.replace(serverReasonGuard, 'if false && results.accepted[index].callErr.Error() != expectedReason {'))) {
    throw new Error('early-auth server reason must be exact, bound to each named case before its independent marker');
  }
  assert.match(proxmoxReceiver, /server_reason_names = \["wrong-peer", "wrong-container", "ambiguous-cgroup"\]/);
  assert.match(proxmoxReceiver, /expected\.extend\("FIXTURE_SERVER_AUTH_DENIED:" \+ name for name in server_reason_names\)/);
  assert.match(proxmoxReceiver, /server_reason_events = re\.findall\(r"FIXTURE_SERVER_AUTH_DENIED:\(\[\^\\r\\n\]\*\)", output\)/);
  assert.match(proxmoxReceiver, /if server_reason_events != server_reason_names:/);
  assert.match(verifier, /if\(!fixedHostServerReasonInventory\(output\)\)/);
  const sourceSection = (sourceText, startPattern, endPattern, label) => {
    const starts = [...sourceText.matchAll(startPattern)];
    if (starts.length !== 1) throw new Error(`${label} source declaration is missing or ambiguous`);
    const start = starts[0].index;
    const ends = [...sourceText.matchAll(endPattern)].filter(match => match.index > start);
    if (ends.length !== 1) throw new Error(`${label} source boundary is missing or ambiguous`);
    return sourceText.slice(start, ends[0].index);
  };
  kernelPostReapStateControls();
  const fixturePollRDNORMDeclaration = 'const fixturePollRDNORM int16 = 0x0040';
  const reusedPIDFatalCall = 't.Fatalf("worker PID was reused before exited state could be confirmed: previous=%d current=%d", workerStart, currentWorkerStart)';
  const kernelExitProofFailures = candidate => {
    const testBody = sourceSection(candidate, /^func runCheckpointGPUObserverNestedPID1\(t \*testing\.T\) \{$/gm, /^func runCheckpointGPUObserverFixtureClient\(/gm, 'nested PID1 worker lifecycle');
    const pidfdExited = sourceSection(candidate, /^func observerFixturePIDFDExited\(fd int\) error \{$/gm, /^func verifyKernelFixturePID1ProcessState\(/gm, 'post-reap pidfd predicate');
    const processState = sourceSection(candidate, /^func verifyKernelFixturePID1ProcessState\(/gm, /^func kernelFixtureNamespaceAt\(/gm, 'kernel process-state predicate');
    const reusedPIDBranch = /^\tif currentWorkerStart, err := processStart\(workerPath, workerPID\); err == nil \{([\s\S]*?)^\t\} else if err != nil && !os\.IsNotExist\(err\) \{/m.exec(processState)?.[1] ?? '';
    const failures = [];
    const killAt = testBody.lastIndexOf('if err := worker.Process.Kill(); err != nil');
    const waitAt = testBody.indexOf('if err := <-workerDone; err == nil {', killAt);
    const sigkillAt = testBody.indexOf('status.Signal() != syscall.SIGKILL', waitAt);
    const postReapAt = testBody.indexOf('verifyKernelFixturePID1ProcessState(t, selfNamespaceFD, initNSFD, workerNSFD, initPIDFD, workerPIDFD, pidNamespace, initStart, workerPID, workerStart, false)', sigkillAt);
    if (killAt < 0 || waitAt < killAt || sigkillAt < waitAt || postReapAt < sigkillAt ||
        !testBody.includes('errors.As(err, &exitErr)') || !testBody.includes('exitErr.Sys().(syscall.WaitStatus)')) failures.push('actual SIGKILL wait/reap proof missing or unordered');
    if (!pidfdExited.includes('ready != 1') || !pidfdExited.includes('revents&unix.POLLIN == 0') ||
        !pidfdExited.includes('revents&(unix.POLLERR|unix.POLLNVAL) != 0') ||
        !pidfdExited.includes('revents&^(unix.POLLIN|unix.POLLHUP|fixturePollRDNORM) != 0') ||
        pidfdExited.split(fixturePollRDNORMDeclaration).length !== 2 ||
        !pidfdExited.includes('// POLLRDNORM is 0x0040 per Linux v6.8 include/uapi/asm-generic/poll.h:') ||
        !pidfdExited.includes('https://raw.githubusercontent.com/torvalds/linux/v6.8/include/uapi/asm-generic/poll.h') ||
        !pidfdExited.includes('// x/sys/unix v0.30.0 does not export POLLRDNORM.') ||
        pidfdExited.includes('revents&unix.POLLHUP == 0')) failures.push('held pidfd readiness/event predicate weakened or HUP required');
    if (!pidfdExited.includes('filepath.Join("/proc/self/fdinfo", strconv.Itoa(fd))') ||
        !pidfdExited.includes('io.LimitReader(file, (4<<10)+1)') || !pidfdExited.includes('len(info) > 4<<10') ||
        !pidfdExited.includes('fields[0] != "Pid:"') || !pidfdExited.includes('fields[1] != "-1"') ||
        !pidfdExited.includes('pidLines != 1')) failures.push('bounded held-fdinfo original-process absence proof missing');
    if (!processState.includes('namespaceFromFD(fd)') || !processState.includes('requireKernelFixtureNamespaceType(namespace, unix.CLONE_NEWPID)') ||
        !processState.includes('observerFixturePIDFDAlive(initPIDFD)') || !processState.includes('currentInitStart != initStart') ||
        !processState.includes('observerFixturePIDFDExited(workerPIDFD)') || !processState.includes('processStart(workerPath, workerPID)') ||
        !processState.includes('currentWorkerStart == workerStart') || !processState.includes('worker PID was reused') ||
        !processState.includes('!os.IsNotExist(err)')) failures.push('existing namespace/start/proc absence and reuse guards missing');
    if (!reusedPIDBranch || reusedPIDBranch.split(reusedPIDFatalCall).length !== 2) failures.push('reused-PID branch must directly reject the present PID with its exact fatal call');
    return failures;
  };
  const kernelExitSourceMutants = [
    ['missing expected SIGKILL', fixture.replace('status.Signal() != syscall.SIGKILL {\n\t\t\tt.Fatalf("worker exited unexpectedly after explicit kill:', 'false {\n\t\t\tt.Fatalf("worker exited unexpectedly after explicit kill:')],
    ['unbounded fdinfo read', fixture.replace('io.LimitReader(file, (4<<10)+1)', 'io.LimitReader(file, 1<<20)')],
    ['missing fdinfo -1 absence', fixture.replace('fields[1] != "-1"', 'false')],
    ['missing proc error guard', fixture.replace('} else if err != nil && !os.IsNotExist(err) {\n\t\tt.Fatalf("cannot distinguish exited worker', '} else if false {\n\t\tt.Fatalf("cannot distinguish exited worker')],
    ['altered POLLRDNORM constant', fixture.replace(fixturePollRDNORMDeclaration, 'const fixturePollRDNORM int16 = 0x0041')],
    ['reused PID message without fatal rejection', fixture.replace(reusedPIDFatalCall, reusedPIDFatalCall.replace('t.Fatalf(', '_ = fmt.Sprintf('))],
  ];
  if (kernelExitProofFailures(fixture).length || kernelExitSourceMutants.some(([, mutant]) => !kernelExitProofFailures(mutant).length)) {
    throw new Error('post-reap kernel source controls accepted a missing wait, fdinfo, proc, or namespace proof');
  }
  const kernelOracleSource = sourceSection(verifier, /^function runKernel\(\) \{$/gm, /^function shellQuote\(value\) \{/gm, 'local kernel oracle');
  const reasonInventorySource = sourceSection(verifier, /^function fixedHostServerReasonInventory\(output\) \{$/gm, /^function fixedHostServerReasonControls\(\) \{$/gm, 'server reason inventory');
  const remoteReasonInventoryInvariant = candidate =>
    candidate.includes('server_reason_names = ["wrong-peer", "wrong-container", "ambiguous-cgroup"]') &&
    candidate.includes('expected.extend("FIXTURE_SERVER_AUTH_DENIED:" + name for name in server_reason_names)') &&
    candidate.includes('if server_reason_events != server_reason_names:');
  const localReasonInventoryInvariant = candidate =>
    candidate.includes('if(!fixedHostServerReasonInventory(output))') &&
    candidate.includes("JSON.stringify(observed) === JSON.stringify(['wrong-peer', 'wrong-container', 'ambiguous-cgroup'])");
  if (!remoteReasonInventoryInvariant(proxmoxReceiver) ||
      remoteReasonInventoryInvariant(proxmoxReceiver.replace('expected.extend("FIXTURE_SERVER_AUTH_DENIED:" + name for name in server_reason_names)', 'expected.extend([])')) ||
      !localReasonInventoryInvariant(`${kernelOracleSource}\n${reasonInventorySource}`) ||
      localReasonInventoryInvariant(`${kernelOracleSource.replace('if(!fixedHostServerReasonInventory(output))', 'if(true)')}\n${reasonInventorySource}`)) {
    throw new Error('fixed-host and local oracles must refute missing, wrong, duplicate, and unexpected server-reason markers');
  }
  assert.match(fixture, /requireKernelFixtureInitialHostNamespace\(\)/);
  assert.match(fixture, /KERNEL_FIXTURE_IDENTITY: pid=%d unit=%s root=%s/);
  assert.match(fixture, /publishKernelFixtureExecutable\(binary, root, rootInfo\)/);
  assert.match(fixture, /removePublishedKernelFixtureExecutable\(root, publishedPath, rootInfo, publishedPin\)/);
  assert.match(fixture, /kernelFixtureFixedHostEnv/);
  assert.match(host, /observerPeerCredentials[\s\S]*authorizeObserverPeer/);
  assert.doesNotMatch(fixture, /unix\.Unshare\(/);
  assert.doesNotMatch(fixture, /--user/);
  assert.match(observerCommand, /RunFixedService\(\)/);
  assert.doesNotMatch(observerCommand, /flag\.|os\.Args|os\.Getenv/);
}

function fixedHostTranscriptAccepts(output) {
  if (/^--- (?:SKIP|FAIL):/m.test(output)) return false;
  const runs = [...output.matchAll(/^=== RUN[ \t]+(\S+)[ \t]*$/gm)].map((match) => match[1]);
  const passes = [...output.matchAll(/^--- PASS:[ \t]+(\S+)(?:[ \t]+\([^)]*\))?[ \t]*$/gm)].map((match) => match[1]);
  return runs.length === 1 && runs[0] === 'TestCheckpointGPUObserverKernelNamespaceFixture' && passes.length === 1 && passes[0] === 'TestCheckpointGPUObserverKernelNamespaceFixture';
}

function fixedHostTranscriptControls() {
  const name = 'TestCheckpointGPUObserverKernelNamespaceFixture';
  const positive = `=== RUN   ${name}\n--- PASS: ${name} (0.01s)\n`;
  if (!fixedHostTranscriptAccepts(positive)) throw new Error('fixed-host transcript parser rejected its positive control');
  const controls = [
    positive + `=== RUN   ${name}\n`,
    positive + `--- PASS: ${name} (0.01s)\n`,
    positive + '=== RUN   TestUnreviewed\n',
    positive + `--- SKIP: ${name} (0.00s)\n`,
    positive + `--- FAIL: ${name} (0.00s)\n`,
    positive.replace('=== RUN   ', '=== RUN : '),
  ];
  if (controls.some(fixedHostTranscriptAccepts)) throw new Error('fixed-host transcript parser accepted a duplicate, unexpected, skip, fail, or malformed negative control');
}

function fixedHostServerReasonInventory(output) {
  const observed = [...output.matchAll(/FIXTURE_SERVER_AUTH_DENIED:([^\r\n]*)/g)].map(match => match[1]);
  return JSON.stringify(observed) === JSON.stringify(['wrong-peer', 'wrong-container', 'ambiguous-cgroup']);
}

function fixedHostServerReasonControls() {
  const accepted = ['wrong-peer', 'wrong-container', 'ambiguous-cgroup']
    .map(name => `FIXTURE_SERVER_AUTH_DENIED:${name}`).join('\n');
  if (!fixedHostServerReasonInventory(accepted)) throw new Error('server authorization-reason inventory rejected its positive control');
  const controls = [
    accepted.replace('FIXTURE_SERVER_AUTH_DENIED:wrong-container\n', ''),
    accepted + '\nFIXTURE_SERVER_AUTH_DENIED:wrong-peer',
    accepted.replace('FIXTURE_SERVER_AUTH_DENIED:ambiguous-cgroup', 'FIXTURE_SERVER_AUTH_DENIED:wrong-reason'),
    accepted.split('\n').reverse().join('\n'),
  ];
  if (controls.some(fixedHostServerReasonInventory)) throw new Error('server authorization-reason inventory accepted missing, duplicate, wrong, or reordered markers');
}

function nestedServerReasonForwardingControls() {
  const sourceSection = (sourceText, startPattern, endPattern, label) => {
    const starts = [...sourceText.matchAll(startPattern)];
    if (starts.length !== 1) throw new Error(`${label} source declaration is missing or ambiguous`);
    const start = starts[0].index;
    const ends = [...sourceText.matchAll(endPattern)].filter(match => match.index > start);
    if (ends.length !== 1) throw new Error(`${label} source boundary is missing or ambiguous`);
    return sourceText.slice(start, ends[0].index);
  };
  const parser = sourceSection(fixture,
    /^func kernelFixtureNestedServerDenialMarkers\(output string\) \(\[\]string, bool\) \{$/gm,
    /^func runCheckpointGPUObserverSystemdFixture\(t \*testing\.T\) \{$/gm,
    'nested server-denial marker parser');
  const outer = sourceSection(fixture,
    /^func runCheckpointGPUObserverSystemdFixture\(t \*testing\.T\) \{$/gm,
    /^func runCheckpointGPUObserverNestedNamespaceChild\(t \*testing\.T\) \{$/gm,
    'outer systemd fixture forwarding');
  const prefix = /^\tconst prefix = "([A-Z_]+:)"$/m.exec(parser)?.[1] ?? '';
  const expectedSuffixes = [...parser.matchAll(/prefix \+ "([a-z-]+)"/g)].map(match => match[1]);
  const expectedMarkers = expectedSuffixes.map(suffix => `${prefix}${suffix}`);
  const parserInvariant = candidate =>
    candidate.includes('strings.Split(output, "\\n")') &&
    candidate.includes('strings.Index(line, prefix)') &&
    candidate.includes('if len(observed) >= len(expected)') &&
    candidate.includes('strings.TrimSuffix(line[markerStart:], "\\r")') &&
    candidate.includes('observed = append(observed, marker)') &&
    candidate.includes('if len(observed) != len(expected)') &&
    candidate.includes('if marker != expected[index]') &&
    candidate.includes('return observed, true') &&
    candidate.split('return nil, false').length === 4;
  const forwardInvariant = candidate => {
    const systemdRun = candidate.indexOf('output, err := runObserverFixtureCommand(ctx, "/usr/bin/systemd-run", args, nil)');
    const systemdRunFailure = candidate.indexOf('if err != nil {', systemdRun);
    const parserCall = candidate.indexOf('serverReasonMarkers, validServerReasonMarkers := kernelFixtureNestedServerDenialMarkers(output)');
    const proofMarkerCheck = candidate.indexOf('if !strings.Contains(output, "NESTED_PID_MOUNT_CGROUP_FIXTURE_PASS")');
    const validationGuard = candidate.indexOf('if !validServerReasonMarkers {');
    const validationFailure = candidate.indexOf('t.Fatal("nested server-denial marker inventory is missing, duplicated, reordered, or unexpected")');
    const forwardingLoop = candidate.indexOf('for _, marker := range serverReasonMarkers {');
    const forwardingLog = candidate.indexOf('t.Log(marker)', forwardingLoop);
    return systemdRun >= 0 && systemdRunFailure > systemdRun &&
      proofMarkerCheck > systemdRunFailure && parserCall > proofMarkerCheck &&
      validationGuard > parserCall && validationFailure > validationGuard &&
      forwardingLoop > validationFailure && forwardingLog > forwardingLoop &&
      candidate.split('serverReasonMarkers, validServerReasonMarkers := kernelFixtureNestedServerDenialMarkers(output)').length === 2 &&
      candidate.split('for _, marker := range serverReasonMarkers {').length === 2 &&
      candidate.split('t.Log(marker)').length === 3;
  };
  const sourceContract = candidate => {
    const parserStart = candidate.indexOf('func kernelFixtureNestedServerDenialMarkers(output string) ([]string, bool) {');
    const parserEnd = candidate.indexOf('\nfunc runCheckpointGPUObserverSystemdFixture(t *testing.T) {', parserStart);
    const outerStart = parserEnd;
    const outerEnd = candidate.indexOf('\nfunc runCheckpointGPUObserverNestedNamespaceChild(t *testing.T) {', outerStart);
    if (parserStart < 0 || parserEnd < 0 || outerEnd < 0) return false;
    const parserSource = candidate.slice(parserStart, parserEnd);
    const outerSource = candidate.slice(outerStart, outerEnd);
    return parserInvariant(parserSource) && expectedMarkers.join('|') === [
      'FIXTURE_SERVER_AUTH_DENIED:wrong-peer',
      'FIXTURE_SERVER_AUTH_DENIED:wrong-container',
      'FIXTURE_SERVER_AUTH_DENIED:ambiguous-cgroup',
    ].join('|') && forwardInvariant(outerSource);
  };
  if (!sourceContract(fixture)) throw new Error('nested denial marker parser/forwarder does not validate exact observed events before forwarding');

  const parseCapturedEvents = output => {
    const observed = [];
    for (const line of output.split('\n')) {
      const markerStart = line.indexOf(prefix);
      if (markerStart < 0) continue;
      if (observed.length >= expectedMarkers.length) return null;
      observed.push(line.slice(markerStart).replace(/\r$/, ''));
    }
    if (observed.length !== expectedMarkers.length) return null;
    for (let index = 0; index < observed.length; index += 1) if (observed[index] !== expectedMarkers[index]) return null;
    return observed;
  };
  const captured = [
    '=== RUN   TestCheckpointGPUObserverKernelNamespaceFixture',
    `    ${expectedMarkers[0]}`,
    '    FIXTURE_SCENARIO_PASS:wrong-peer',
    `    ${expectedMarkers[1]}`,
    `    ${expectedMarkers[2]}`,
    '--- PASS: TestCheckpointGPUObserverKernelNamespaceFixture (0.00s)',
  ].join('\n');
  const observed = parseCapturedEvents(captured);
  const forwarded = observed === null ? null : observed.slice();
  if (JSON.stringify(observed) !== JSON.stringify(expectedMarkers) || JSON.stringify(forwarded) !== JSON.stringify(observed)) {
    throw new Error('bounded extracted nested parser/forward control did not preserve the exact observed marker events once');
  }
  const malformedCaptured = [
    captured.replace(`${expectedMarkers[1]}\n`, ''),
    captured.replace(`${expectedMarkers[1]}\n`, `${expectedMarkers[1]}\n    ${expectedMarkers[1]}\n`),
    captured.replace(`${expectedMarkers[0]}\n    FIXTURE_SCENARIO_PASS:wrong-peer\n    ${expectedMarkers[1]}`, `${expectedMarkers[1]}\n    FIXTURE_SCENARIO_PASS:wrong-peer\n    ${expectedMarkers[0]}`),
    captured.replace(expectedMarkers[1], `${prefix}wrong-host`),
    `${captured}\n    ${prefix}unexpected`,
  ];
  if (malformedCaptured.some(output => parseCapturedEvents(output) !== null)) {
    throw new Error('bounded extracted nested parser accepted missing, duplicate, reordered, wrong-name, or unexpected events');
  }

  const validation = 'if !validServerReasonMarkers {\n\t\tt.Fatal("nested server-denial marker inventory is missing, duplicated, reordered, or unexpected")\n\t}';
  const forwardLoop = '\tfor _, marker := range serverReasonMarkers {\n\t\tt.Log(marker)\n\t}';
  const skippedValidation = fixture.replace(validation, 'if false && !validServerReasonMarkers {\n\t\tt.Fatal("nested server-denial marker inventory is missing, duplicated, reordered, or unexpected")\n\t}');
  const skippedForward = fixture.replace(forwardLoop, '');
  const forwardBeforeValidation = fixture.replace(`${validation}\n`, '').replace(`${forwardLoop}\n`, `${forwardLoop}\n${validation}\n`);
  const fabricatedForward = fixture.replace('for _, marker := range serverReasonMarkers {', 'for _, marker := range expectedMarkers {');
  const missingCountProof = fixture.replace('if len(observed) != len(expected) {', 'if false {');
  const missingOrderProof = fixture.replace('if marker != expected[index] {', 'if false {');
  const parserFailureAccepts = fixture.replaceAll('return nil, false', 'return observed, true');
  if ([skippedValidation, skippedForward, forwardBeforeValidation, fabricatedForward, missingCountProof, missingOrderProof, parserFailureAccepts].some(sourceContract)) {
    throw new Error('nested marker forwarding source mutant bypassed validation, observed-only forwarding, or order checks');
  }
}

function failureDiagnosticControls() {
  const decisive = 'K/V tensor geometry and global/per-sequence capacity assertion failed';
  const noisy = `${'old output '.repeat(300)}${decisive}`;
  const bounded = sanitizeFailureTail(noisy);
  if (bounded.length > 760 || !bounded.includes(decisive)) throw new Error('fixed-host failure tail did not retain its bounded decisive assertion');
  const sanitized = sanitizeFailureTail(`failure at /tmp/private-root/upload.bin\u0001: ${decisive}`);
  if (sanitized.includes('/tmp/private-root/upload.bin') || !sanitized.includes('[path]') || !sanitized.includes('K/V') || !sanitized.includes('global/per-sequence')) {
    throw new Error('fixed-host failure tail did not redact paths while preserving assertion wording and control safety');
  }

  const receiverDiagnosticFunctions = () => {
    const section = (name, next) => {
      const start = proxmoxReceiver.indexOf(`def ${name}(`);
      const end = proxmoxReceiver.indexOf(`\ndef ${next}(`, start);
      if (start < 0 || end < 0 || proxmoxReceiver.indexOf(`def ${name}(`, start + 1) >= 0) throw new Error(`receiver diagnostic function ${name} is not uniquely extractable`);
      return proxmoxReceiver.slice(start, end);
    };
    return [
      section('classify_fixture_failure', 'capture_failure_stage'),
      section('capture_failure_stage', 'emit_failure_diagnostic'),
      section('emit_failure_diagnostic', 'initial_namespace'),
      section('failure_tail', 'classify_fixture_failure'),
    ];
  };
  const receiverDiagnosticPropagationPresent = (candidate) => {
    const captureStart = candidate.indexOf('def capture_test(');
    const captureEnd = candidate.indexOf('\ntry:\n    initial_namespace()', captureStart);
    if (captureStart < 0 || captureEnd < 0) return false;
    const body = candidate.slice(captureStart, captureEnd);
    const captureFailure = 'failure_stage = capture_failure_stage(capture_error, cleanup_error, identity_stage, unit_error)\n            emit_failure_diagnostic(output, post_reap_confirmed=(cleanup_error is None and unit_error is None), capture_succeeded=(capture_error is None), cleanup_confirmed=(cleanup_error is None and unit_error is None), stage=failure_stage)';
    const statusFailure = 'if status != 0:\n        emit_failure_diagnostic(output, stage="child_exit_nonzero")\n        fail("fixed-host kernel fixture exited';
    const validationFailure = 'except Exception as error:\n        emit_failure_diagnostic(output, cleanup_confirmed=False, stage=failure_stage)\n        fail("fixture identity pid=%d unit=%s root=%s upload=%s; post-run validation=';
    const identityStages = ['fixture_identity_missing', 'fixture_identity_duplicate', 'fixture_identity_pid_mismatch'];
    const stageAssignments = ['postvalidation_marker_inventory', 'postvalidation_server_reason_inventory', 'postvalidation_unit_marker', 'postvalidation_test_inventory', 'postvalidation_runpass_inventory', 'postvalidation_namespace_identity', 'postvalidation_upload_pin', 'postvalidation_uploaded_file_cleanup', 'postvalidation_upload_root_state', 'postvalidation_tmp_parent_state', 'postvalidation_exact_root_cleanup'];
    return body.includes(captureFailure) && body.includes(statusFailure) && body.includes(validationFailure) &&
      body.includes('if len(identity) == 0:') && identityStages.every(stage => candidate.includes(`identity_stage = "${stage}"`)) &&
      stageAssignments.every(stage => body.includes(`failure_stage = "${stage}"`)) && body.includes('failure_stage = "postvalidation_unknown"') &&
      body.indexOf(captureFailure) > body.indexOf('confirm_exact_unit_absent(unit)') &&
      body.indexOf(statusFailure) > body.indexOf('confirm_exact_unit_absent(unit)');
  };
  const hostDiagnosticPropagationPresent = (candidate) => {
    const reducerStart = candidate.lastIndexOf('function fixedHostFailureDiagnostic(output) {');
    const reducerEnd = candidate.indexOf('\nfunction fixedHostFailureDetails', reducerStart);
    const detailsStart = candidate.lastIndexOf('function fixedHostFailureDetails(output, pid) {');
    const detailsEnd = candidate.indexOf('\nfunction inventoryFailures(', detailsStart);
    if (reducerStart < 0 || reducerEnd < 0 || detailsStart < 0 || detailsEnd < 0) return false;
    const reducer = candidate.slice(reducerStart, reducerEnd);
    const details = candidate.slice(detailsStart, detailsEnd);
    return details.includes('fixedHostFailureDiagnostic(output)') && details.includes('failure_stage=${stage} failure_diagnostic=${site}:${reason}') &&
      details.includes('.slice(0, 640)') && reducer.includes('stagePairs?.includes(pair) && REMOTE_FAILURE_DIAGNOSTIC_PAIRS.has(pair)') &&
      candidate.includes('REMOTE_FAILURE_DIAGNOSTIC_STAGE_PAIRS') && candidate.includes("Buffer.byteLength(lines[0], 'utf8') > 192");
  };
  if (!receiverDiagnosticPropagationPresent(proxmoxReceiver) || !hostDiagnosticPropagationPresent(verifier)) {
    throw new Error('failure diagnostics must propagate from post-reap receiver failures through the host reducer');
  }
  const missingCaptureStagePropagation = proxmoxReceiver.replace('stage=failure_stage)', ')');
  if (receiverDiagnosticPropagationPresent(missingCaptureStagePropagation)) throw new Error('receiver propagation mutant removed capture failure stage');
  const missingStatusStagePropagation = proxmoxReceiver.replace('emit_failure_diagnostic(output, stage="child_exit_nonzero")', 'emit_failure_diagnostic(output)');
  if (receiverDiagnosticPropagationPresent(missingStatusStagePropagation)) throw new Error('receiver propagation mutant removed nonzero-exit stage');
  const missingPostvalidationStagePropagation = proxmoxReceiver.replace('cleanup_confirmed=False, stage=failure_stage)', 'cleanup_confirmed=False)');
  if (receiverDiagnosticPropagationPresent(missingPostvalidationStagePropagation)) throw new Error('receiver propagation mutant removed postvalidation stage');
  const missingNamedStage = proxmoxReceiver.replace('failure_stage = "postvalidation_marker_inventory"', 'failure_stage = "postvalidation_unknown"');
  if (receiverDiagnosticPropagationPresent(missingNamedStage)) throw new Error('receiver propagation mutant removed named marker-validation stage');
  const hostDetailsStart = verifier.lastIndexOf('function fixedHostFailureDetails(output, pid) {');
  const hostDetailsEnd = verifier.indexOf('\nfunction inventoryFailures(', hostDetailsStart);
  const hostDetailsSource = verifier.slice(hostDetailsStart, hostDetailsEnd);
  const hostDetailsWithoutStage = hostDetailsSource.replace('failure_stage=${stage} failure_diagnostic=${site}:${reason}', 'failure_diagnostic=${site}:${reason} failure_stage=${stage}');
  const missingHostStageFirst = verifier.slice(0, hostDetailsStart) + hostDetailsWithoutStage + verifier.slice(hostDetailsEnd);
  if (hostDiagnosticPropagationPresent(missingHostStageFirst)) throw new Error('host propagation mutant moved the stage behind identity/tail output');
  const stagePairCheckAt = verifier.lastIndexOf('stagePairs?.includes(pair)');
  const missingHostStageAllowlist = verifier.slice(0, stagePairCheckAt) + 'true' + verifier.slice(stagePairCheckAt + 'stagePairs?.includes(pair)'.length);
  if (hostDiagnosticPropagationPresent(missingHostStageAllowlist)) throw new Error('host propagation mutant bypassed the atomic stage/pair allowlist');

  const extractHostDiagnosticParser = (source) => {
    const declarations = [...source.matchAll(/^const REMOTE_FAILURE_DIAGNOSTIC_PREFIX =/gm)];
    const parserStart = declarations[0]?.index ?? -1;
    const parserEnd = source.indexOf('\nfunction fixedHostFailureDetails(', parserStart);
    if (declarations.length !== 1 || parserStart < 0 || parserEnd < 0) {
      throw new Error('host failure parser source boundary is missing or ambiguous');
    }
    const isolated = source.slice(parserStart, parserEnd);
    return new Function('Buffer', `${isolated}\nreturn fixedHostFailureDiagnostic;`)(Buffer);
  };
  const extractedHostParser = extractHostDiagnosticParser(verifier);
  const diagnosticMarker = (stage, pair) => `REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=${stage} site=${pair.split(':')[0]} reason=${pair.split(':')[1]}`;
  const impossibleChildExitPairs = ['unavailable:cleanup_uncertain', 'unavailable:capture_failed'];
  const reachableChildExitPairs = [
    'post_reap_pidfd:readiness_rejected', 'post_reap_pidfd:live_process_present', 'post_reap_pidfd:absence_record_invalid',
    'worker_proc:incarnation_present', 'worker_proc:pid_reused', 'worker_proc:proc_uncertain',
    'systemd_unit:launch_failed', 'fixture_marker:proof_marker_missing', 'fixture_marker:marker_cardinality',
    'nested_namespace:isolation_marker_missing', 'observer_scenarios:accept_failed',
    'unavailable:ambiguous', 'unavailable:unclassified', 'unavailable:unsafe_or_oversized',
  ];
  const childExitParserContract = (parser) =>
    reachableChildExitPairs.every(pair => parser(diagnosticMarker('child_exit_nonzero', pair)) === `child_exit_nonzero:${pair}`) &&
    impossibleChildExitPairs.every(pair => parser(diagnosticMarker('child_exit_nonzero', pair)) === 'unavailable:unavailable:unavailable');
  if (!childExitParserContract(extractedHostParser)) throw new Error('extracted host parser violated the reachable child-exit stage/pair contract');
  const childExitMapStarts = [...verifier.matchAll(/^  child_exit_nonzero: \[$/gm)];
  const childExitMapStart = childExitMapStarts[0]?.index ?? -1;
  const childExitMapEnd = verifier.indexOf('\n  ],', childExitMapStart);
  if (childExitMapStarts.length !== 1 || childExitMapStart < 0 || childExitMapEnd < 0) {
    throw new Error('child-exit stage mapping source boundary is missing or ambiguous');
  }
  const broadChildExitMapping = verifier.slice(0, childExitMapStart) +
    '  child_exit_nonzero: [...REMOTE_FAILURE_DIAGNOSTIC_PAIRS],' + verifier.slice(childExitMapEnd + '\n  ],'.length);
  const broadHostParser = extractHostDiagnosticParser(broadChildExitMapping);
  if (childExitParserContract(broadHostParser) || !impossibleChildExitPairs.every(pair => broadHostParser(diagnosticMarker('child_exit_nonzero', pair)) === `child_exit_nonzero:${pair}`)) {
    throw new Error('child-exit allowlist broadening mutant was not decisively detected by the extracted parser controls');
  }

  const [classifierSource, stageSource, emitterSource, tailSource] = receiverDiagnosticFunctions();
  const pythonProgram = [
    'import io, json, re, sys',
    'MAX_OUTPUT = 2 * 1024 * 1024',
    tailSource,
    classifierSource,
    stageSource,
    emitterSource,
    'for case in json.load(sys.stdin):',
    '    sys.stderr = io.StringIO()',
    '    stage = capture_failure_stage(case.get("capture_error"), case.get("cleanup_error"), case.get("identity_stage"), case.get("unit_error")) if case.get("derive_stage") else case["stage"]',
    '    emit_failure_diagnostic(case["output"], case["post_reap_confirmed"], case["capture_succeeded"], case["cleanup_confirmed"], stage)',
    '    marker = sys.stderr.getvalue()',
    '    emitted_stage = marker.split(" stage=", 1)[1].split(" ", 1)[0]',
    '    print(json.dumps({"marker": marker, "tail": failure_tail(case["output"]), "stage": emitted_stage}, separators=(",", ":")))',
  ].join('\n');
  const earlyCause = 'worker PID was reused before exited state could be confirmed';
  const earlyOutput = `${earlyCause}\n${'later fixture cleanup noise '.repeat(90)}`;
  const postvalidationStages = [
    'postvalidation_hardware_claim', 'postvalidation_marker_inventory', 'postvalidation_server_reason_inventory',
    'postvalidation_unit_marker', 'postvalidation_test_inventory', 'postvalidation_runpass_inventory',
    'postvalidation_namespace_identity', 'postvalidation_upload_pin', 'postvalidation_uploaded_file_cleanup',
    'postvalidation_upload_root_state', 'postvalidation_tmp_parent_state', 'postvalidation_exact_root_cleanup',
    'postvalidation_success_output', 'postvalidation_unknown',
  ];
  const cases = [
    { name: 'early-cause', output: earlyOutput, stage: 'child_exit_nonzero', post_reap_confirmed: true, capture_succeeded: true, cleanup_confirmed: true, expectedStage: 'child_exit_nonzero', expected: 'worker_proc:pid_reused' },
    { name: 'helper-only', output: 'bounded nested PID namespace child failed: exit status 1', stage: 'child_exit_nonzero', post_reap_confirmed: true, capture_succeeded: true, cleanup_confirmed: true, expectedStage: 'child_exit_nonzero', expected: 'unavailable:unclassified' },
    { name: 'ambiguous-causes', output: 'held fixture pidfd did not report clean post-reap readiness\nworker PID was reused before exited state could be confirmed', stage: 'child_exit_nonzero', post_reap_confirmed: true, capture_succeeded: true, cleanup_confirmed: true, expectedStage: 'child_exit_nonzero', expected: 'unavailable:ambiguous' },
    { name: 'duplicate-cause', output: `${earlyCause}\n${earlyCause}`, stage: 'child_exit_nonzero', post_reap_confirmed: true, capture_succeeded: true, cleanup_confirmed: true, expectedStage: 'child_exit_nonzero', expected: 'unavailable:ambiguous' },
    { name: 'unknown-private', output: 'failure at /tmp/private/request-secret.bin with arbitrary assertion text', stage: 'child_exit_nonzero', post_reap_confirmed: true, capture_succeeded: true, cleanup_confirmed: true, expectedStage: 'child_exit_nonzero', expected: 'unavailable:unclassified' },
    { name: 'oversized', output: 'x'.repeat((2 * 1024 * 1024) + 1), stage: 'child_exit_nonzero', post_reap_confirmed: true, capture_succeeded: true, cleanup_confirmed: true, expectedStage: 'child_exit_nonzero', expected: 'unavailable:unsafe_or_oversized' },
    { name: 'capture-exception', output: earlyCause, derive_stage: true, capture_error: 'sentinel', cleanup_error: null, identity_stage: null, unit_error: null, post_reap_confirmed: true, capture_succeeded: false, cleanup_confirmed: true, expectedStage: 'capture_exception', expected: 'unavailable:capture_failed' },
    { name: 'child-reap-unconfirmed', output: earlyCause, derive_stage: true, capture_error: null, cleanup_error: 'sentinel', identity_stage: null, unit_error: 'sentinel', post_reap_confirmed: false, capture_succeeded: true, cleanup_confirmed: false, expectedStage: 'child_reap_unconfirmed', expected: 'unavailable:cleanup_uncertain' },
    { name: 'identity-missing', output: earlyCause, derive_stage: true, capture_error: null, cleanup_error: null, identity_stage: 'fixture_identity_missing', unit_error: 'sentinel', post_reap_confirmed: false, capture_succeeded: true, cleanup_confirmed: false, expectedStage: 'fixture_identity_missing', expected: 'unavailable:cleanup_uncertain' },
    { name: 'identity-duplicate', output: earlyCause, derive_stage: true, capture_error: null, cleanup_error: null, identity_stage: 'fixture_identity_duplicate', unit_error: 'sentinel', post_reap_confirmed: false, capture_succeeded: true, cleanup_confirmed: false, expectedStage: 'fixture_identity_duplicate', expected: 'unavailable:cleanup_uncertain' },
    { name: 'identity-pid-mismatch', output: earlyCause, derive_stage: true, capture_error: null, cleanup_error: null, identity_stage: 'fixture_identity_pid_mismatch', unit_error: 'sentinel', post_reap_confirmed: false, capture_succeeded: true, cleanup_confirmed: false, expectedStage: 'fixture_identity_pid_mismatch', expected: 'unavailable:cleanup_uncertain' },
    { name: 'exact-unit-absence-unconfirmed', output: earlyCause, derive_stage: true, capture_error: null, cleanup_error: null, identity_stage: null, unit_error: 'sentinel', post_reap_confirmed: false, capture_succeeded: true, cleanup_confirmed: false, expectedStage: 'exact_unit_absence_unconfirmed', expected: 'unavailable:cleanup_uncertain' },
    { name: 'identity-before-unit-stage', output: earlyCause, derive_stage: true, capture_error: 'sentinel', cleanup_error: null, identity_stage: 'fixture_identity_missing', unit_error: 'sentinel', post_reap_confirmed: false, capture_succeeded: false, cleanup_confirmed: false, expectedStage: 'fixture_identity_missing', expected: 'unavailable:cleanup_uncertain' },
    { name: 'unknown-stage', output: earlyCause, stage: '../private\npath', post_reap_confirmed: true, capture_succeeded: true, cleanup_confirmed: true, expectedStage: 'unavailable', expected: 'unavailable:unclassified' },
    ...postvalidationStages.map(stage => ({ name: stage, output: 'postvalidation failed', stage, post_reap_confirmed: true, capture_succeeded: true, cleanup_confirmed: false, expectedStage: stage, expected: 'unavailable:cleanup_uncertain' })),
  ];
  const python = spawnSync('python', ['-I', '-B', '-c', pythonProgram], {
    cwd: root, windowsHide: true, encoding: 'utf8', timeout: 5000, maxBuffer: 64 * 1024,
    input: JSON.stringify(cases.map(({ name, ...testCase }) => testCase)),
  });
  if (python.error || python.status !== 0 || python.stderr !== '') throw new Error('bounded local receiver-classifier fixture process failed');
  const classified = python.stdout.trimEnd().split('\n').map((line) => JSON.parse(line));
  if (classified.length !== cases.length) throw new Error('receiver classifier emitted an unexpected fixture count');
  for (const [index, testCase] of cases.entries()) {
    const { marker, tail, stage } = classified[index];
    const expectedParts = testCase.expected.split(':');
    const expectedMarker = `REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=${testCase.expectedStage} site=${expectedParts[0]} reason=${expectedParts[1]}\n`;
    if (stage !== testCase.expectedStage || marker !== expectedMarker || Buffer.byteLength(marker, 'utf8') > 192 || marker.includes('/tmp') || marker.includes('secret') || marker.includes('request') || /[\r\n\x00-\x1f]/.test(marker.slice(0, -1))) {
      throw new Error(`receiver classifier did not emit one bounded closed marker for ${testCase.name}`);
    }
    if (testCase.name === 'early-cause' && (tail.includes(earlyCause) || tail.length > 700)) throw new Error('receiver tail fixture did not displace the early cause beyond its 700-character bound');
    const hostOutput = `${marker}${'later host cleanup noise '.repeat(90)}\nREMOTE_FIXED_KERNEL_ERROR: bounded failure\n`;
    const hostDetails = fixedHostFailureDetails(hostOutput, undefined);
    if (!hostDetails.startsWith(`failure_stage=${testCase.expectedStage} failure_diagnostic=${testCase.expected}`) || Buffer.byteLength(hostDetails, 'utf8') > 640 || hostDetails.includes('/tmp/private/request-secret.bin')) {
      throw new Error(`host reducer did not preserve the receiver closed reason for ${testCase.name}`);
    }
    if (testCase.name === 'early-cause' && (sanitizeFailureTail(hostOutput).includes(REMOTE_FAILURE_DIAGNOSTIC_PREFIX) || !hostDetails.startsWith('failure_stage=child_exit_nonzero failure_diagnostic=worker_proc:pid_reused'))) {
      throw new Error('host tail fixture did not displace the early marker while keeping the stage and reduced pair first');
    }
  }
  const malformedMarkers = [
    '',
    'REMOTE_FIXED_KERNEL_DIAGNOSTIC site=post_reap_pidfd reason=readiness_rejected extra=/tmp/private.bin',
    'REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=unknown site=unknown reason=unknown',
    'REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=child_exit_nonzero site=post_reap_pidfd reason=pid_reused',
    'REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=postvalidation_marker_inventory site=worker_proc reason=pid_reused',
    `${classified[0].marker}${classified[0].marker}`,
    `REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=child_exit_nonzero site=post_reap_pidfd reason=readiness_rejected /tmp/request-secret\n`,
    `REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=${'a'.repeat(200)} site=unavailable reason=unclassified`,
  ];
  for (const raw of malformedMarkers) {
    if (fixedHostFailureDiagnostic(raw) !== 'unavailable:unavailable:unavailable') throw new Error('host reducer accepted a missing, ambiguous, malformed, unsafe, or wrong-stage marker');
    const details = fixedHostFailureDetails(raw, undefined);
    if (!details.startsWith('failure_stage=unavailable failure_diagnostic=unavailable:unavailable') || Buffer.byteLength(details, 'utf8') > 640 || details.includes('/tmp/request-secret')) throw new Error('host failure summary exposed unsafe marker content or placed stage after tail details');
  }
}

const deadline = Date.now() + 1_170_000;
function remaining() { const ms = deadline - Date.now(); if (ms <= 0) throw new Error('container attribution verifier exceeded shared 1170-second budget'); return ms; }
const env = { ...process.env, GOCACHE: path.join(root, '.unlazy/fleet-residency-v2/tmp/gocache-container-attribution') };
function run(program, args, { environment = env, maximum = 8 * 1024 * 1024, input, timeout, description, failureDetails } = {}) {
  const result = spawnSync(program, args, { cwd: root, env: environment, encoding: 'utf8', timeout: Math.min(timeout ?? remaining(), remaining()), maxBuffer: maximum, windowsHide: true, ...(input === undefined ? {} : { input }) });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  const label = description ?? `${program} ${args.join(' ')}`;
  const details = failureDetails ? failureDetails(output, result.pid) : '';
  const identityPrefix = details ? `${details}\n` : '';
  if (result.error) throw new Error(`${identityPrefix}${label} subprocess failed: ${sanitizeFailureTail(result.error.message)}\n${sanitizeFailureTail(output)}`);
  if (result.status !== 0) throw new Error(`${identityPrefix}${label} exited ${result.status ?? 'without status'}\n${sanitizeFailureTail(output)}`);
  return output;
}
function sanitizeFailureTail(value) {
  const text = String(value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .replace(/(?<![A-Za-z0-9_])(?:[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]*|\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+)/g, '[path]')
    .replace(/\s+/g, ' ')
    .trim();
  return text.slice(-760);
}
const REMOTE_FAILURE_DIAGNOSTIC_PREFIX = 'REMOTE_FIXED_KERNEL_DIAGNOSTIC';
const REMOTE_FAILURE_DIAGNOSTIC_PAIRS = new Set([
  'post_reap_pidfd:readiness_rejected', 'post_reap_pidfd:live_process_present', 'post_reap_pidfd:absence_record_invalid',
  'worker_proc:incarnation_present', 'worker_proc:pid_reused', 'worker_proc:proc_uncertain',
  'systemd_unit:launch_failed', 'fixture_marker:proof_marker_missing', 'fixture_marker:marker_cardinality',
  'nested_namespace:isolation_marker_missing', 'observer_scenarios:accept_failed',
  'unavailable:ambiguous', 'unavailable:unclassified', 'unavailable:capture_failed',
  'unavailable:cleanup_uncertain', 'unavailable:unsafe_or_oversized',
]);
const REMOTE_FAILURE_DIAGNOSTIC_STAGE_PAIRS = Object.freeze({
  capture_exception: ['unavailable:capture_failed'],
  child_reap_unconfirmed: ['unavailable:cleanup_uncertain'],
  fixture_identity_missing: ['unavailable:cleanup_uncertain'],
  fixture_identity_duplicate: ['unavailable:cleanup_uncertain'],
  fixture_identity_pid_mismatch: ['unavailable:cleanup_uncertain'],
  exact_unit_absence_unconfirmed: ['unavailable:cleanup_uncertain'],
  child_exit_nonzero: [
    'post_reap_pidfd:readiness_rejected', 'post_reap_pidfd:live_process_present', 'post_reap_pidfd:absence_record_invalid',
    'worker_proc:incarnation_present', 'worker_proc:pid_reused', 'worker_proc:proc_uncertain',
    'systemd_unit:launch_failed', 'fixture_marker:proof_marker_missing', 'fixture_marker:marker_cardinality',
    'nested_namespace:isolation_marker_missing', 'observer_scenarios:accept_failed',
    'unavailable:ambiguous', 'unavailable:unclassified', 'unavailable:unsafe_or_oversized',
  ],
  postvalidation_hardware_claim: ['unavailable:cleanup_uncertain'],
  postvalidation_marker_inventory: ['unavailable:cleanup_uncertain'],
  postvalidation_server_reason_inventory: ['unavailable:cleanup_uncertain'],
  postvalidation_unit_marker: ['unavailable:cleanup_uncertain'],
  postvalidation_test_inventory: ['unavailable:cleanup_uncertain'],
  postvalidation_runpass_inventory: ['unavailable:cleanup_uncertain'],
  postvalidation_namespace_identity: ['unavailable:cleanup_uncertain'],
  postvalidation_upload_pin: ['unavailable:cleanup_uncertain'],
  postvalidation_uploaded_file_cleanup: ['unavailable:cleanup_uncertain'],
  postvalidation_upload_root_state: ['unavailable:cleanup_uncertain'],
  postvalidation_tmp_parent_state: ['unavailable:cleanup_uncertain'],
  postvalidation_exact_root_cleanup: ['unavailable:cleanup_uncertain'],
  postvalidation_success_output: ['unavailable:cleanup_uncertain'],
  postvalidation_unknown: ['unavailable:cleanup_uncertain'],
  unavailable: ['unavailable:unclassified'],
});
function fixedHostFailureDiagnostic(output) {
  if (typeof output !== 'string' || output.split(REMOTE_FAILURE_DIAGNOSTIC_PREFIX).length !== 2) return 'unavailable:unavailable:unavailable';
  const lines = output.split(/\r?\n/).filter((line) => line.includes(REMOTE_FAILURE_DIAGNOSTIC_PREFIX));
  if (lines.length !== 1 || Buffer.byteLength(lines[0], 'utf8') > 192) return 'unavailable:unavailable:unavailable';
  const match = /^REMOTE_FIXED_KERNEL_DIAGNOSTIC stage=([a-z_]+) site=([a-z_]+) reason=([a-z_]+)$/.exec(lines[0]);
  if (!match) return 'unavailable:unavailable:unavailable';
  const [, stage, site, reason] = match;
  const pair = `${site}:${reason}`;
  const stagePairs = Object.hasOwn(REMOTE_FAILURE_DIAGNOSTIC_STAGE_PAIRS, stage) ? REMOTE_FAILURE_DIAGNOSTIC_STAGE_PAIRS[stage] : null;
  return stagePairs?.includes(pair) && REMOTE_FAILURE_DIAGNOSTIC_PAIRS.has(pair) ? `${stage}:${pair}` : 'unavailable:unavailable:unavailable';
}
function fixedHostFailureDetails(output, pid) {
  const first = (pattern) => pattern.exec(output);
  const uploadMatch = first(/^(?:EXACT_PRIVATE_UPLOAD_PATH|PRESERVED_EXACT_UPLOAD_PATH): (\/tmp\/checkpoint-gpu-observer-upload-[A-Za-z0-9_-]+)$/m);
  const receiverMatch = first(/^REMOTE_RECEIVER_IDENTITY: pid=(\d+) upload=(\/tmp\/checkpoint-gpu-observer-upload-[A-Za-z0-9_-]+)$/m);
  const testMatch = first(/^REMOTE_TEST_PROCESS_IDENTITY: pid=(\d+) upload=(\/tmp\/checkpoint-gpu-observer-upload-[A-Za-z0-9_-]+)$/m);
  const fixtureMatch = first(/(?:^KERNEL_FIXTURE_IDENTITY: |fixture identity )pid=(\d+) unit=(checkpoint-gpu-observer-fixture-[0-9a-f]{24}\.service) root=(\/tmp\/checkpoint-gpu-observer-kernel-[A-Za-z0-9_-]+)/m);
  const identity = `fixed-host identity ssh_pid=${Number.isInteger(pid) ? pid : 'unknown'} upload=${uploadMatch?.[1] ?? receiverMatch?.[2] ?? testMatch?.[2] ?? 'unknown'} receiver_pid=${receiverMatch?.[1] ?? 'unknown'} test_pid=${testMatch?.[1] ?? fixtureMatch?.[1] ?? 'unknown'} unit=${fixtureMatch?.[2] ?? 'unknown'} fixture_root=${fixtureMatch?.[3] ?? 'unknown'}`;
  const [stage, site, reason] = fixedHostFailureDiagnostic(output).split(':');
  return `failure_stage=${stage} failure_diagnostic=${site}:${reason} ${identity}`.slice(0, 640);
}
function inventoryFailures(events, names) {
	const records = new Map(names.map((name) => [name, []]));
	const failures = [];
	for (const event of events) {
		if (!event.Test || !['run', 'pass', 'skip', 'fail'].includes(event.Action)) continue;
		if (!records.has(event.Test)) { failures.push(`unexpected ${event.Action} ${event.Test}`); continue; }
		records.get(event.Test).push(event.Action);
	}
	for (const [name, sequence] of records) if (sequence.join(',') !== 'run,pass') failures.push(`${name}=${sequence.join(',') || 'absent'}`);
	return failures;
}
function goInventory(output, names, label) {
  const observed = new Map();
  for (const line of output.split(/\r?\n/)) {
    if (!line) continue;
    const event = JSON.parse(line);
    if (!event.Test || !['run', 'pass', 'skip', 'fail'].includes(event.Action)) continue;
    if (!names.includes(event.Test)) throw new Error(`${label} emitted unexpected test event ${event.Action} ${event.Test}`);
    const list = observed.get(event.Test) ?? []; list.push(event.Action); observed.set(event.Test, list);
  }
  for (const name of names) if (observed.get(name)?.join(',') !== 'run,pass') throw new Error(`${label} expected exactly RUN,PASS ${name}; saw ${observed.get(name)?.join(',') ?? 'none'}`);
  if (observed.size !== names.length) throw new Error(`${label} inventory had missing or unexpected names`);
}
function inventoryParserControls() {
	const names = ['positive']; const good = [{ Test: 'positive', Action: 'run' }, { Test: 'positive', Action: 'pass' }];
	if (inventoryFailures(good, names).length) throw new Error('inventory parser rejected positive control');
	const controls = [
		['missing RUN', []], ['duplicate RUN', [...good, good[0]]], ['duplicate PASS', [...good, good[1]]],
		['SKIP', [good[0], { Test: 'positive', Action: 'skip' }]], ['FAIL', [good[0], { Test: 'positive', Action: 'fail' }]],
		['unexpected', [...good, { Test: 'unreviewed', Action: 'run' }]], ['missing PASS', [good[0]]],
	];
	for (const [name, events] of controls) if (!inventoryFailures(events, names).length) throw new Error(`inventory parser accepted ${name} negative control`);
}
const protocolTops = ['TestRequestCanonicalValidation','TestSignedResponseBindsNonceAndIncarnations','TestResponseRejectsGPUAndNamespaceSubstitution','TestRepeatedNumericNSpidAcrossNamespacesIsValid','TestEnvelopeRejectsDuplicateFieldsAndBadEncoding'];
const protocolInventory = [...protocolTops,'TestRequestCanonicalValidation/duplicate','TestRequestCanonicalValidation/case_variant','TestRequestCanonicalValidation/unknown','TestRequestCanonicalValidation/null','TestRequestCanonicalValidation/whitespace',...['multiple_row_identity','wrong_GPU_UUID','namespace_device','namespace_inode','namespace_type','init_chain','empty_cgroup'].map((n)=>`TestResponseRejectsGPUAndNamespaceSubstitution/${n}`)];
const linuxObserverTops = ['TestObserverNamespaceTypeFromHeldCurrentPIDDescriptor','TestObserverConfigRequiresBothExactCallerRolesAndContainerAuthority','TestObserverPeerNeedsExecutableAndHostCgroupAuthority','TestObserverPeerContainerSelectionRequiresUniqueOverlap','TestHostNSpidParserRetainsRepeatedIDsAcrossNamespaceLevels','TestGPUInventoryParserAndUniqueWorkerJoin'];
const linuxObserverInventory = [...linuxObserverTops,...['local_observer_wrong_UID','duplicate_local_observer_role','local_observer_executable_swap','node_agent_changed_to_root_only'].map((n)=>`TestObserverConfigRequiresBothExactCallerRolesAndContainerAuthority/${n}`),...['uid','executable','executable_path','cgroup'].map((n)=>`TestObserverPeerNeedsExecutableAndHostCgroupAuthority/${n}`),...['node_agent','fixed_supervisor','local_observer'].flatMap((role)=>[`TestObserverPeerContainerSelectionRequiresUniqueOverlap/${role}`,...['single_match','disjoint_sibling','overlap_rejected'].map((scenario)=>`TestObserverPeerContainerSelectionRequiresUniqueOverlap/${role}/${scenario}`)]),...['absent','duplicate','wrong_GPU'].map((n)=>`TestGPUInventoryParserAndUniqueWorkerJoin/${n}`)];
const linuxNodeTops = ['TestCheckpointBridgeNamespaceTypeFromHeldCurrentPIDDescriptor','TestCheckpointHostObserverFramingBoundsAndRoundTrip','TestCheckpointObserverFrameWriterHandlesShortWritesAndZeroProgress','TestCheckpointObserverTrustPinDetectsContentAndPathSubstitution','TestCheckpointObserverPeerJoinRejectsStaleLocalIncarnation','TestCheckpointChildPlacementNestedObserverAndNoFallback','TestCheckpointManagedBindingNestedObserverRouteAndNoFallback'];
const linuxNodeInventory = [...linuxNodeTops,...['namespace','peer_PID','start_ticks','boot_ID','UID','executable'].map((n)=>`TestCheckpointObserverPeerJoinRejectsStaleLocalIncarnation/${n}`)];
const nodePortableTops = ['TestCheckpointHostGPUObservationRequiresExactPinnedPhysicalPlacement','TestCheckpointHostGPUObservationBindsPlannedPCIBus'];
const nodePortableInventory = [...nodePortableTops,...['missing_bytes','wrong_response_bytes','wrong_process_UUID','wrong_plan_UUID','missing_PCI'].map((n)=>`TestCheckpointHostGPUObservationRequiresExactPinnedPhysicalPlacement/${n}`)];
function parsedJSONEvents(output,label){const events=[];for(const [index,line] of output.split(/\r?\n/).entries()){if(!line.trim())continue;let event;try{event=JSON.parse(line)}catch{throw new Error(`${label} malformed Go JSON event line ${index+1}`)};if(event.Test&&['run','pass','skip','fail'].includes(event.Action))events.push(event)}return events}
function parsedVerboseEvents(output,label){const events=[];for(const line of output.split(/\r?\n/)){let match=/^=== RUN\s+(\S+)\s*$/.exec(line.trimStart());if(match){events.push({Test:match[1],Action:'run'});continue}match=/^--- (PASS|SKIP|FAIL):\s+(\S+?)(?:\s+\([^)]*\))?\s*$/.exec(line.trimStart());if(match)events.push({Test:match[2],Action:match[1].toLowerCase()})}if(events.length===0)throw new Error(`${label} produced no Go test transcript events`);return events}
function checkEvents(events,names,label){const failures=inventoryFailures(events,names);if(failures.length)throw new Error(`${label} inventory failed: ${failures.join('; ')}`)}
function testPattern(tops){return `^(${tops.join('|')})$`}
function runGoJSON(packagePath,tops,names,label){const output=run('go',['test','-json',packagePath,'-run',testPattern(tops),'-count=1','-timeout=60s']);checkEvents(parsedJSONEvents(output,label),names,label)}
function runWindowsLinuxBinary(packagePath,tops,names,label,temp){const binary=path.join(temp,`${path.basename(packagePath)}-linux.test`);run('go',['test','-c','-o',binary,packagePath],{environment:{...env,GOOS:'linux',GOARCH:'amd64',CGO_ENABLED:'0'}});const linux=windowsPathToWsl(binary);run('wsl.exe',['-d','Ubuntu','--exec','chmod','+x',linux]);const output=run('wsl.exe',['-d','Ubuntu','--exec',linux,`-test.run=${testPattern(tops)}`,'-test.count=1','-test.timeout=60s','-test.v']);checkEvents(parsedVerboseEvents(output,label),names,label)}
function runAuthority(){
  const temp=mkdtempSync(path.join(tmpdir(),'checkpoint-container-authority-'));
  try{
    if(process.platform==='linux'){
      runGoJSON('./internal/checkpointgpuobserver',[...protocolTops,...linuxObserverTops],[...protocolInventory,...linuxObserverInventory],'Linux observer authority');
      runGoJSON('./internal/nodeagent',[...nodePortableTops,...linuxNodeTops],[...nodePortableInventory,...linuxNodeInventory],'Linux node adapter authority');
    } else {
      runGoJSON('./internal/checkpointgpuobserver',protocolTops,protocolInventory,'portable protocol authority');
      runGoJSON('./internal/nodeagent',nodePortableTops,nodePortableInventory,'portable node adapter authority');
      runWindowsLinuxBinary('./internal/checkpointgpuobserver',[...protocolTops,...linuxObserverTops],[...protocolInventory,...linuxObserverInventory],'WSL observer authority',temp);
      runWindowsLinuxBinary('./internal/nodeagent',linuxNodeTops,linuxNodeInventory,'WSL node adapter authority',temp);
    }
    inventoryParserControls();
  } finally { rmSync(temp,{recursive:true,force:true}); }
}
function windowsPathToWsl(value) {
  const parsed = path.win32.parse(value); const drive = parsed.root.match(/^([A-Za-z]):\\$/)?.[1];
  if (!drive) throw new Error(`cannot map Linux test binary to WSL: ${value}`);
  return `/mnt/${drive.toLowerCase()}/${value.slice(parsed.root.length).split(/[\\/]+/).filter(Boolean).join('/')}`;
}
function runKernel() {
  const temp = mkdtempSync(path.join(tmpdir(), 'checkpoint-container-kernel-'));
  try {
    const binary = path.join(temp, 'observer-linux.test');
    run('go', ['test', '-c', '-tags=checkpoint_container_kernel', '-o', binary, './internal/checkpointgpuobserver'], {
      environment: { ...env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' },
    });
    let output;
    if (process.platform === 'linux') output = run(binary, ['-test.run=^TestCheckpointGPUObserverKernelNamespaceFixture$', '-test.count=1', '-test.timeout=160s', '-test.v']);
    else {
      const linux = windowsPathToWsl(binary);
      run('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--exec', 'chmod', '+x', linux]);
      output = run('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--exec', linux, '-test.run=^TestCheckpointGPUObserverKernelNamespaceFixture$', '-test.count=1', '-test.timeout=160s', '-test.v']);
    }
    if (!output.includes('NESTED_PID_MOUNT_CGROUP_FIXTURE_PASS')) throw new Error('kernel fixture did not emit its positive CPU namespace marker');
    if (!output.includes('NESTED_HOST_OBSERVER_SIGNED_JOIN_PASS_SYNTHETIC_ONLY')) throw new Error('kernel fixture did not prove signed host join mechanics with explicit synthetic-only labeling');
    if (/FAKE_NVIDIA.*hardware|actual GPU measurement/i.test(output)) throw new Error('CPU kernel fixture claimed hardware attribution');
    const scenarioNames=['positive','wrong-peer','wrong-container','ambiguous-cgroup','stale-start','duplicate-gpu-row','wrong-gpu-row','wrong-namespace','exited-worker'];
    for(const name of scenarioNames){const marker=`FIXTURE_SCENARIO_PASS:${name}`;if(output.split(marker).length!==2)throw new Error(`kernel helper inventory expected exactly one ${marker}`)}
    const denialNames=scenarioNames.filter((name)=>name!=='positive');
    for(const name of denialNames){const marker=`FIXTURE_SCENARIO_DENIED:${name}`;if(output.split(marker).length!==2)throw new Error(`kernel helper inventory expected exactly one ${marker}`)}
    if(!fixedHostServerReasonInventory(output))throw new Error('kernel helper did not emit the exact ordered server authorization-reason inventory');
    const events=parsedVerboseEvents(output,'kernel fixture outer/systemd transcript');checkEvents(events,['TestCheckpointGPUObserverKernelNamespaceFixture'],'kernel fixture outer/systemd transcript');
  } finally { rmSync(temp, { recursive: true, force: true }); }
}
function shellQuote(value) { return `'${value.replaceAll("'", `'"'"'`)}'`; }
function runKernelProxmox() {
  if (process.platform !== 'win32') throw new Error('kernel-proxmox mode is Windows-host-only and has no fallback');
  const ssh = 'C:/Windows/System32/OpenSSH/ssh.exe';
  const identity = 'C:/Users/Sasha/.ssh/cmp170_proxmox';
  const knownHosts = 'C:/Users/Sasha/.ssh/known_hosts';
  const goBin = 'C:/Users/Sasha/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.4.windows-amd64/bin';
  const go = `${goBin}/go.exe`;
  for (const [label, file] of [['OpenSSH client', ssh], ['fixed Proxmox identity', identity], ['strict known-hosts file', knownHosts], ['cached Go 1.23.4 toolchain', go]]) {
    let info;
    try { info = lstatSync(file); } catch { throw new Error(`${label} is unavailable at its fixed path`); }
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${label} is not a regular fixed-path file`);
  }
  const temp = mkdtempSync(path.join(tmpdir(), 'checkpoint-container-fixed-host-'));
  try {
    const binaryPath = path.join(temp, 'observer-linux.test');
    run(go, ['test', '-c', '-tags=checkpoint_container_kernel', '-o', binaryPath, './internal/checkpointgpuobserver'], {
      environment: { ...env, PATH: `${goBin};${env.PATH ?? ''}`, GOTOOLCHAIN: 'local', GOOS: 'linux', GOARCH: 'amd64', GOAMD64: 'v1', CGO_ENABLED: '0', GOFLAGS: '' },
    });
    const binaryInfo = lstatSync(binaryPath);
    if (!binaryInfo.isFile() || binaryInfo.isSymbolicLink() || binaryInfo.size <= 0 || binaryInfo.size > 256 * 1024 * 1024) throw new Error('compiled fixed-host self-test executable is not a bounded regular file');
    const executable = readFileSync(binaryPath);
    if (executable.length !== binaryInfo.size || executable.length < 20 || executable.subarray(0, 4).toString('hex') !== '7f454c46' || executable[4] !== 2 || executable[5] !== 1 || executable.readUInt16LE(18) !== 62) throw new Error('compiled fixed-host test executable is not ELF64 amd64');
    const digest = createHash('sha256').update(executable).digest('hex');
    const remoteCommand = `/usr/bin/python3 -c ${shellQuote(proxmoxReceiver)} ${executable.length} ${digest}`;
    const sshArgs = [
      '-F', 'none', '-T', '-oBatchMode=yes', '-oPreferredAuthentications=publickey', '-oPasswordAuthentication=no', '-oKbdInteractiveAuthentication=no',
      '-oStrictHostKeyChecking=yes', `-oUserKnownHostsFile=${knownHosts}`, '-oGlobalKnownHostsFile=none',
      '-oControlPath=none', '-oKnownHostsCommand=none',
      '-oIdentitiesOnly=yes', '-oIdentityAgent=none', '-i', identity, '-p', '22', '-oHostName=10.0.0.3',
      '-oProxyCommand=none', '-oProxyJump=none', '-oClearAllForwardings=yes', '-oForwardAgent=no',
      '-oPermitLocalCommand=no', '-oRequestTTY=no', '-oControlMaster=no', '-oConnectTimeout=10',
      '-oServerAliveInterval=10', '-oServerAliveCountMax=2', 'root@10.0.0.3', remoteCommand,
    ];
    const sshEnvironment = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'USERPROFILE', 'HOME', 'PROGRAMDATA'].filter((key) => process.env[key]).map((key) => [key, process.env[key]]));
    const output = run(ssh, sshArgs, { environment: sshEnvironment, input: executable, maximum: 3 * 1024 * 1024, timeout: 195_000, description: 'fixed-host SSH receiver', failureDetails: fixedHostFailureDetails });
    try {
      const successMarker = 'REMOTE_FIXED_KERNEL_UPLOAD_CLEANUP_PASS';
      if (output.split(successMarker).length !== 2) throw new Error('fixed-host receiver did not confirm exact uploaded-file and private-directory cleanup');
      if (!output.includes('KERNEL_FIXTURE_PRIVATE_ROOT_CLEANUP_PASS') || !output.includes('NESTED_HOST_OBSERVER_SIGNED_JOIN_PASS_SYNTHETIC_ONLY')) throw new Error('fixed-host kernel proof or exact nested fixture cleanup marker is absent');
    } catch (error) {
      throw new Error(`${fixedHostFailureDetails(output, undefined)}\n${error.message}`);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
}
function runRegressions() {
  run(process.execPath, ['scripts/verify-checkpoint-one-card-placement.mjs', '--regressions']);
  run(process.execPath, ['scripts/verify-checkpoint-managed-binding.mjs', '--faults']);
  runMutants();
}
function runMutants() {
  const temp = mkdtempSync(path.join(tmpdir(), 'checkpoint-container-mutants-'));
  try {
    const cases = [
      { name: 'signature', packagePath:'./internal/checkpointgpuobserver', file: 'internal/checkpointgpuobserver/protocol.go', needle: 'if !ed25519.Verify(publicKey, signed, signature) {', replacement: 'if false && !ed25519.Verify(publicKey, signed, signature) {', test: 'TestSignedResponseBindsNonceAndIncarnations', marker: 'response signed by an unpinned key was accepted' },
      { name: 'peer-namespace', packagePath:'./internal/nodeagent', file:'internal/nodeagent/checkpoint_host_gpu_bridge_linux.go', needle:'response.Peer.Namespace != self.namespace', replacement:'false && response.Peer.Namespace != self.namespace', test:'TestCheckpointObserverPeerJoinRejectsStaleLocalIncarnation/namespace', marker:'signed peer substitution was accepted' },
      { name: 'peer-incarnation', packagePath:'./internal/nodeagent', file:'internal/nodeagent/checkpoint_host_gpu_bridge_linux.go', needle:'response.Peer.StartTicks != self.start', replacement:'false && response.Peer.StartTicks != self.start', test:'TestCheckpointObserverPeerJoinRejectsStaleLocalIncarnation/start_ticks', marker:'signed peer substitution was accepted' },
      { name: 'gpu-join', packagePath:'./internal/checkpointgpuobserver', file:'internal/checkpointgpuobserver/observer_linux.go', needle:'if row.UUID != expectedUUID {', replacement:'if false && row.UUID != expectedUUID {', test:'TestGPUInventoryParserAndUniqueWorkerJoin/wrong_GPU', marker:'absent, duplicate, or wrong-GPU worker row was accepted' },
      { name: 'ambiguous-peer-container', packagePath:'./internal/checkpointgpuobserver', file:'internal/checkpointgpuobserver/observer_linux.go', needle:'if matches != 1 {', replacement:'if false && matches != 1 {', test:'TestObserverPeerContainerSelectionRequiresUniqueOverlap/node_agent/overlap_rejected', marker:'overlapping root container authorities were accepted' },
      { name: 'startup-route', packagePath:'./internal/nodeagent', file: 'internal/nodeagent/checkpoint_device_binding_linux.go', needle: 'if nested {', replacement: 'if false && nested {', test: 'TestCheckpointChildPlacementNestedObserverAndNoFallback', marker: 'nested attribution did not use only the host bridge' },
    ];
    for (const testCase of cases) {
      const original = readFileSync(path.join(root, testCase.file), 'utf8');
      if (original.split(testCase.needle).length !== 2) throw new Error(`${testCase.name} mutant anchor is not unique`);
      const mutated = original.replace(testCase.needle, testCase.replacement);
      const mutatedFile = path.join(temp, `${testCase.name}.go`); const overlay = path.join(temp, `${testCase.name}.overlay.json`);
      writeFileSync(mutatedFile, mutated); writeFileSync(overlay, JSON.stringify({ Replace: { [path.join(root, testCase.file)]: mutatedFile } }));
      let program='go';let args;
      if(process.platform==='linux') args=['test',`-overlay=${overlay}`,testCase.packagePath,'-run',`^${testCase.test}$`,'-count=1','-timeout=60s','-v'];
      else {
        const binary=path.join(temp,`${testCase.name}.test`);
        run('go',['test','-c',`-overlay=${overlay}`,'-o',binary,testCase.packagePath],{environment:{...env,GOOS:'linux',GOARCH:'amd64',CGO_ENABLED:'0'}});
        program='wsl.exe';const linux=windowsPathToWsl(binary);run('wsl.exe',['-d','Ubuntu','--exec','chmod','+x',linux]);args=['-d','Ubuntu','--exec',linux,`-test.run=${testCase.test}`,'-test.count=1','-test.timeout=60s','-test.v'];
      }
      const result = spawnSync(program, args, { cwd: root, env, encoding: 'utf8', timeout: remaining(), maxBuffer: 4 * 1024 * 1024, windowsHide: true });
      const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
      if (result.error) throw result.error;
      const expectedStatus=process.platform==='linux'?1:1;
      if (result.status !== expectedStatus || !output.includes(testCase.marker) || /panic:|fatal error:|test timed out/i.test(output)) throw new Error(`${testCase.name} implementation mutant did not hit its decisive assertion\n${output.slice(-5000)}`);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
}

assertContract();
inventoryParserControls();
fixedHostTranscriptControls();
failureDiagnosticControls();
nestedServerReasonForwardingControls();
fixedHostServerReasonControls();
if (mode === '--mode=source-only') { console.log('checkpoint container attribution source-only verification passed'); }
else if (mode === '--mode=authority') { runAuthority(); console.log('checkpoint container attribution authority verification passed'); }
else if (mode === '--mode=kernel') { runKernel(); console.log('checkpoint container attribution kernel verification passed'); }
else if (mode === '--mode=kernel-proxmox') { runKernelProxmox(); console.log('checkpoint container attribution kernel verification passed'); }
else { runRegressions(); console.log('checkpoint container attribution regression verification passed'); }
