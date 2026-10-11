#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

const CPU_WSL_TIMEOUT_MS = 1_050_000;
const CPU_PREFLIGHT_BUDGET_MS = 30_000;
const CPU_PREFLIGHT_CALL_TIMEOUT_MS = 10_000;
const CPU_MAIN_MIN_REMAINING_MS = 900_000;
const cpuStartedAt = performance.now();
const preflightDeadline = cpuStartedAt + CPU_PREFLIGHT_BUDGET_MS;
const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const patch = path.join(repo, 'patches/llama.cpp/62acc89c26c66076cb72e049f307fbe93b8b9750/0001-checkpoint-compat-descriptor.patch');
const builder = path.join(here, 'build-cpu-fixture.sh');
const generator = path.join(here, 'make-tiny-llama-gguf.py');
const mode = process.argv[2] === '--controls' ? 'controls' : 'cpu';
const limit = 1024 * 1024;
const FAILURE_SUMMARY_MAX_CHARS = 240;
const CLEANUP_UNCERTAIN_MARKER = 'cleanup uncertain; preserving private workspace';

function formatFailureSummary({ status, error, stdout = '', stderr = '' }) {
  const clean = value => String(value)
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\u202a-\u202e\u2066-\u2069\ufeff]/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, ' ')
    .replace(/(^|[\s"'(=])(?:[A-Za-z]:[\\/]|\/)[^\s"'<>),;]*/g, '$1[path]')
    .replace(/\s+/g, ' ').trim();
  const lines = value => String(value).slice(-65536).split(/\r?\n/).map(line => clean(line));
  const pythonCause = value => lines(value).filter(line => /^(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:Error|Exception|Interrupt|Exit)|SystemExit):/i.test(line)).at(-1);
  const otherCause = value => lines(value).filter(line => /^(?:error:|fatal error:|checkpoint backend descriptor:)/i.test(line)).at(-1);
  const selectedCause = pythonCause(stderr) || pythonCause(stdout) || otherCause(stderr) || otherCause(stdout);
  const cause = selectedCause?.replace(/cleanup uncertain;\s*preserving private workspace\b/i, '').replace(/[;,\s]+$/, '');
  const uncertainCleanup = /cleanup uncertain;\s*preserving private workspace\b/i.test(`${String(stderr).slice(-65536)}\n${String(stdout).slice(-65536)}`);
  const cleanupSuffix = uncertainCleanup ? `; ${CLEANUP_UNCERTAIN_MARKER}` : '';
  const prefixLimit = FAILURE_SUMMARY_MAX_CHARS - cleanupSuffix.length;
  const primary = error
    ? (/timed?\s*out|ETIMEDOUT/i.test(error.message ?? '') ? 'timed out' : `process error: ${clean(error.message).slice(0, 100)}`)
    : status == null ? 'process status unavailable' : `exit ${status}`;
  const prefix = error || status == null ? `${primary}${cause ? `; ${cause}` : ''}` : cause ? `${cause} (exit ${status})` : primary;
  return `${prefix.slice(0, prefixLimit)}${cleanupSuffix}`;
}

function failureOutcome({ status, error }) {
  if (error) return /timed?\s*out|ETIMEDOUT/i.test(error.message ?? '') ? 'timeout' : 'spawn error';
  return status == null ? 'unknown status' : `exit ${status}`;
}

function verifyFailureSummaryControls() {
  const noise = `build-output-${'x'.repeat(4096)}\n`;
  const decisive = formatFailureSummary({ status: 1, stdout: noise, stderr: `Traceback (most recent call last):\nRuntimeError: initialized slot capacity mismatch\u202e\u001b` });
  if (!decisive.startsWith('RuntimeError: initialized slot capacity mismatch') || decisive.length > FAILURE_SUMMARY_MAX_CHARS || /[\u202a-\u202e\u2066-\u2069\u0000-\u001f\u007f-\u009f]/.test(decisive)) {
    throw new Error('bounded failure summary did not frontload a sanitized decisive cause');
  }
  const generic = formatFailureSummary({ status: 1, stdout: noise, stderr: 'unclassified child failure' });
  const uncertain = 'fixture cleanup uncertain; preserving private workspace /home/fixture/private-cache';
  const longCause = formatFailureSummary({ status: 1, stderr: `RuntimeError: ${'K/V global/per-sequence capacity '.repeat(24)} /home/fixture/private-cache\n${uncertain}` });
  const timeout = formatFailureSummary({ status: null, error: Object.assign(new Error('spawnSync timed out'), { code: 'ETIMEDOUT' }), stderr: `RuntimeError: stale output\n${uncertain}` });
  if (generic !== 'exit 1' || !timeout.startsWith('timed out') || !timeout.includes(CLEANUP_UNCERTAIN_MARKER) ||
      longCause.length !== FAILURE_SUMMARY_MAX_CHARS || !longCause.includes(CLEANUP_UNCERTAIN_MARKER) ||
      !longCause.includes('K/V') || !longCause.includes('global/per-sequence') || longCause.includes('/home/fixture')) {
    throw new Error('generic failure, bounded-cause, path, or timeout/cleanup summary control changed');
  }
}

verifyFailureSummaryControls();

function preflightRemainingMs() {
  const remaining = Math.floor(preflightDeadline - performance.now());
  if (remaining <= 0) throw new Error('cumulative WSL preflight budget exhausted before fixture launch');
  return remaining;
}

function call(args, input) {
  const remaining = preflightRemainingMs();
  const timeout = Math.min(CPU_PREFLIGHT_CALL_TIMEOUT_MS, remaining);
  const result = spawnSync('wsl.exe', args, { input, encoding: 'utf8', timeout: timeout, maxBuffer: limit, windowsHide: true });
  if (result.error || result.status !== 0) {
    const summary = formatFailureSummary({ status: result.status, error: result.error, stdout: result.stdout, stderr: result.stderr });
    throw new Error(`WSL invocation ${failureOutcome(result)}: ${summary}`);
  }
  return result.stdout.trim();
}

function wslPath(value) {
  return call(['-d', 'Ubuntu', '--exec', 'wslpath', '-u', value]);
}

const uid = call(['-d', 'Ubuntu', '--exec', 'id', '-u']);
if (uid !== '1000') throw new Error(`WSL fixture UID mismatch: ${uid}`);
const patchWsl = wslPath(patch);
const builderWsl = wslPath(builder);
const generatorWsl = wslPath(generator);

function shellQuote(value) {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

const namespaceBootstrap = String.raw`import json
import fcntl
import os
import pathlib
import select
import subprocess
import sys
import time

supervisor_pidfd, original_parent_pidfd, work_fd, report_fd = map(int, sys.argv[1:5])
work = pathlib.Path(sys.argv[5])
outer_namespaces = json.loads(sys.argv[6])
builder, patch_file, generator, mode = sys.argv[7:11]
script = sys.stdin.buffer.read(48 * 1024 + 1)
if len(script) > 48 * 1024:
    raise SystemExit('inner fixture script exceeded its bound')
if os.getpid() != 1 or os.getuid() != 1000 or os.getgid() != 1000:
    raise SystemExit('private namespace bootstrap principal/PID1 mismatch')
uid_rows = [line.split() for line in pathlib.Path('/proc/self/uid_map').read_text().splitlines() if line.split()]
gid_rows = [line.split() for line in pathlib.Path('/proc/self/gid_map').read_text().splitlines() if line.split()]
if uid_rows != [['1000', '1000', '1']] or gid_rows != [['1000', '1000', '1']]:
    raise SystemExit('private namespace mapping is not the exact one-entry WSL UID/GID mapping')
for name, expected in outer_namespaces.items():
    if os.readlink('/proc/self/ns/' + name) == expected:
        raise SystemExit('requested private namespace was not created: ' + name)
mountinfo = pathlib.Path('/proc/self/mountinfo').read_text()
if ' - proc proc ' not in mountinfo or any(' shared:' in line for line in mountinfo.splitlines()):
    raise SystemExit('private procfs or mount propagation isolation was not established')
root_stat = os.fstat(work_fd)
path_stat = os.stat(work, follow_symlinks=False)
if (root_stat.st_dev, root_stat.st_ino, root_stat.st_uid, root_stat.st_gid) != (path_stat.st_dev, path_stat.st_ino, 1000, 1000) or not pathlib.Path(work).is_dir():
    raise SystemExit('private workspace held-root identity changed before build')
watch = select.poll()
watch.register(supervisor_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
watch.register(original_parent_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
if watch.poll(0):
    raise SystemExit('original supervisor/parent was already gone before fixture launch')
child_env = os.environ.copy()
child_env['CHECKPOINT_CLEANUP_REPORT_FD'] = str(report_fd)
script_fd = os.memfd_create('checkpoint-fixture-inner-script', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
try:
    offset = 0
    while offset < len(script):
        count = os.write(script_fd, script[offset:])
        if count <= 0:
            raise RuntimeError('short write of bounded inner fixture script')
        offset += count
    fcntl.fcntl(script_fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    os.lseek(script_fd, 0, os.SEEK_SET)
    child = subprocess.Popen(['/bin/bash', '--noprofile', '--norc', '-s', '--', builder, patch_file, generator, mode], stdin=script_fd, env=child_env, pass_fds=(report_fd,))
finally:
    os.close(script_fd)
try:
    while child.poll() is None:
        if watch.poll(100):
            # Exiting PID 1 makes the kernel terminate every process in this private PID namespace.
            os._exit(92)
        time.sleep(0.05)
    status = child.wait()
except BaseException:
    # PID1 exits on any loss of control rather than leaving its descendants detached.
    raise
if status:
    raise SystemExit(status)
`;

const supervisor = String.raw`import ctypes
import array
import fcntl
import errno
import json
import os
import pathlib
import select
import signal
import socket
import stat
import subprocess
import sys
import time

work = pathlib.Path(sys.argv[1])
work_fd = int(sys.argv[2])
builder, patch_file, generator, mode = sys.argv[3:7]
expected_parent_pid, expected_parent_start = map(int, sys.argv[7:9])
outer_uid, outer_gid = os.getuid(), os.getgid()
if (outer_uid, outer_gid) != (1000, 1000):
    raise SystemExit('WSL fixture must run as exact UID/GID 1000')
if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
    raise SystemExit('Linux pidfd supervision is unavailable; refusing to start a build')
root_stat = os.fstat(work_fd)
path_stat = os.stat(work, follow_symlinks=False)
if not pathlib.Path(work).is_absolute() or (root_stat.st_dev, root_stat.st_ino, root_stat.st_uid, root_stat.st_gid) != (path_stat.st_dev, path_stat.st_ino, outer_uid, outer_gid) or not pathlib.Path(work).is_dir():
    raise SystemExit('private workspace descriptor/path identity mismatch')
def proc_start(pid):
    raw = pathlib.Path('/proc', str(pid), 'stat').read_text()
    tail = raw[raw.rfind(')') + 2:].split()
    return int(tail[19])

if os.getppid() != expected_parent_pid or proc_start(expected_parent_pid) != expected_parent_start:
    raise SystemExit('original WSL shell identity is absent; refusing adopted-parent fallback')
parent_pidfd = os.pidfd_open(expected_parent_pid, 0)
if os.getppid() != expected_parent_pid or proc_start(expected_parent_pid) != expected_parent_start:
    os.close(parent_pidfd)
    raise SystemExit('original WSL shell identity changed while pinning its pidfd')
supervisor_pidfd = os.pidfd_open(os.getpid(), 0)
libc = ctypes.CDLL(None, use_errno=True)
PR_SET_PDEATHSIG = 1
if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != expected_parent_pid or proc_start(expected_parent_pid) != expected_parent_start:
    raise SystemExit('could not establish a race-checked parent-death link')
outer_namespaces = {name: os.readlink('/proc/self/ns/' + name) for name in ('user', 'mnt', 'pid')}
script = sys.stdin.buffer.read(48 * 1024 + 1)
if len(script) > 48 * 1024:
    raise SystemExit('fixture script exceeded its bound')
bootstrap = ${JSON.stringify(namespaceBootstrap)}
def namespace_command(watched_parent_fd, report_fd, fixture_mode):
    return ['unshare', '--user', '--map-current-user', '--mount', '--propagation', 'private', '--pid', '--fork', '--kill-child=KILL', '--mount-proc', 'python3', '-c', bootstrap,
            str(supervisor_pidfd), str(watched_parent_fd), str(work_fd), str(report_fd), str(work), json.dumps(outer_namespaces), builder, patch_file, generator, fixture_mode]

def launch_namespace(script_bytes, watched_parent_fd, fixture_mode):
    if len(script_bytes) > 48 * 1024:
        raise RuntimeError('namespace fixture script exceeded its bound')
    launch_parent_pid = os.getpid()
    def pdeathsig_before_exec():
        libc_child = ctypes.CDLL(None, use_errno=True)
        if libc_child.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != launch_parent_pid:
            os._exit(125)
    report_receiver, report_sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    script_fd = os.memfd_create('checkpoint-namespace-bootstrap-input', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(script_bytes):
            count = os.write(script_fd, script_bytes[offset:])
            if count <= 0:
                raise RuntimeError('short write of bounded namespace bootstrap input')
            offset += count
        fcntl.fcntl(script_fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        os.lseek(script_fd, 0, os.SEEK_SET)
        proc = subprocess.Popen(namespace_command(watched_parent_fd, report_sender.fileno(), fixture_mode), stdin=script_fd,
                                pass_fds=(supervisor_pidfd, watched_parent_fd, work_fd, report_sender.fileno()), close_fds=True,
                                preexec_fn=pdeathsig_before_exec)
    except BaseException:
        report_receiver.close()
        raise
    finally:
        os.close(script_fd)
        report_sender.close()
    proc_fd = os.pidfd_open(proc.pid, 0)
    waiter = select.poll()
    waiter.register(proc_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return proc, proc_fd, waiter, report_receiver

def receive_descendant_pidfds(report_socket):
    report_socket.settimeout(5)
    held = {}
    try:
        while len(held) < 2:
            message, ancillary, flags, _ = report_socket.recvmsg(64, socket.CMSG_SPACE(array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
            fds = [array.array('i', data[:len(data) - (len(data) % array.array('i').itemsize)]).tolist()
                   for level, kind, data in ancillary if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS]
            received = [fd for group in fds for fd in group]
            try:
                role = message.decode('ascii', errors='strict')
            except UnicodeDecodeError as exc:
                for fd in received:
                    os.close(fd)
                raise RuntimeError('cleanup fixture returned malformed pidfd role') from exc
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or role not in ('listener', 'descendant') or role in held or len(received) != 1:
                for fd in received:
                    os.close(fd)
                raise RuntimeError('cleanup fixture returned malformed or duplicate original pidfd evidence')
            held[role] = received[0]
        if set(held) != {'listener', 'descendant'}:
            raise RuntimeError('cleanup fixture descendant roles are incomplete')
        for fd in held.values():
            live = select.poll()
            live.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
            ready = live.poll(0)
            if ready:
                raise RuntimeError('descendant pidfd liveness positive control was not established')
        return held
    except Exception:
        for fd in held.values():
            os.close(fd)
        raise

def assert_pidfds_terminal(held, until):
    pending = set(held)
    waiters = {role: select.poll() for role in pending}
    for role in pending:
        waiters[role].register(held[role], select.POLLIN | select.POLLHUP | select.POLLERR)
    while pending and time.monotonic() < until:
        for role in tuple(pending):
            ready = waiters[role].poll(50)
            if ready:
                mask = ready[0][1]
                if not mask & select.POLLIN or mask & (select.POLLERR | select.POLLNVAL):
                    raise RuntimeError('descendant pidfd did not report a valid terminal state: ' + role)
                pending.remove(role)
    if pending:
        raise RuntimeError('TERM-resistant descendant pidfds did not reach terminal state: ' + ','.join(sorted(pending)))
    for fd in held.values():
        os.close(fd)

def wait_terminal(proc, waiter, until):
    while proc.poll() is None and time.monotonic() < until:
        ready = waiter.poll(100)
        if ready and (not ready[0][1] & select.POLLIN or ready[0][1] & (select.POLLERR | select.POLLNVAL)):
            raise RuntimeError('owned unshare pidfd returned an invalid terminal poll state')
    ready = waiter.poll(0)
    return bool(ready and ready[0][1] & select.POLLIN and not ready[0][1] & (select.POLLERR | select.POLLNVAL))

def wait_terminal_parent(pidfd, until):
    waiter = select.poll()
    waiter.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while time.monotonic() < until:
        ready = waiter.poll(100)
        if ready:
            if not ready[0][1] & select.POLLIN or ready[0][1] & (select.POLLERR | select.POLLNVAL):
                raise RuntimeError('held original-parent pidfd returned an invalid terminal poll state')
            return True
    ready = waiter.poll(0)
    return bool(ready and ready[0][1] & select.POLLIN and not ready[0][1] & (select.POLLERR | select.POLLNVAL))

def read_port_marker(name, until):
    marker_identity = None
    while time.monotonic() < until:
        marker_fd = None
        try:
            marker_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=work_fd)
        except FileNotFoundError:
            time.sleep(min(0.025, max(0.0, until - time.monotonic())))
            continue
        try:
            marker_stat = os.fstat(marker_fd)
            identity = (marker_stat.st_dev, marker_stat.st_ino)
            if not stat.S_ISREG(marker_stat.st_mode) or marker_stat.st_nlink != 1 or marker_stat.st_uid != 1000 or marker_stat.st_mode & 0o077:
                raise RuntimeError('cleanup control marker is not a private held regular file')
            if marker_stat.st_size > 5:
                raise RuntimeError('cleanup control listener marker exceeds its fixed width')
            if marker_identity is not None and identity != marker_identity:
                raise RuntimeError('cleanup control marker inode changed while awaiting readiness')
            marker_identity = identity
            marker_path = os.stat(name, dir_fd=work_fd, follow_symlinks=False)
            if (marker_path.st_dev, marker_path.st_ino) != identity:
                raise RuntimeError('cleanup control marker path does not name its held inode')
            raw = os.read(marker_fd, 6)
            held_after = os.fstat(marker_fd)
            path_after = os.stat(name, dir_fd=work_fd, follow_symlinks=False)
            if (held_after.st_dev, held_after.st_ino) != identity or (path_after.st_dev, path_after.st_ino) != identity:
                raise RuntimeError('cleanup control marker changed during readiness observation')
            if not stat.S_ISREG(held_after.st_mode) or held_after.st_nlink != 1 or held_after.st_uid != 1000 or held_after.st_mode & 0o077:
                raise RuntimeError('cleanup control marker metadata changed during readiness observation')
            if len(raw) > 5 or held_after.st_size > 5:
                raise RuntimeError('cleanup control listener marker exceeds its fixed width')
            if held_after.st_size == 5 and len(raw) == 5:
                if not raw.isdigit() or not 1 <= int(raw) <= 65535:
                    raise RuntimeError('cleanup control listener marker is malformed')
                return int(raw)
        finally:
            os.close(marker_fd)
        time.sleep(min(0.025, max(0.0, until - time.monotonic())))
    raise RuntimeError('cleanup control did not publish its exact five-byte listener marker before the bound')

def assert_port_absent(port):
    for _ in range(8):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.15)
        try:
            result = probe.connect_ex(('127.0.0.1', port))
        finally:
            probe.close()
        if result == errno.ECONNREFUSED:
            return
        time.sleep(0.05)
    raise RuntimeError('listener survived private PID namespace termination')

def assert_port_live(port):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        if probe.connect_ex(('127.0.0.1', port)) != 0:
            raise RuntimeError('cleanup control listener did not establish its live positive control')
    finally:
        probe.close()

def assert_descendant_marker(name, until):
    marker_identity = None
    while time.monotonic() < until:
        marker_fd = None
        try:
            marker_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=work_fd)
        except FileNotFoundError:
            time.sleep(min(0.025, max(0.0, until - time.monotonic())))
            continue
        try:
            marker_stat = os.fstat(marker_fd)
            identity = (marker_stat.st_dev, marker_stat.st_ino)
            if not stat.S_ISREG(marker_stat.st_mode) or marker_stat.st_nlink != 1 or marker_stat.st_uid != 1000 or marker_stat.st_mode & 0o077:
                raise RuntimeError('TERM-resistant detached descendant marker is not an exact private regular file')
            if marker_identity is not None and identity != marker_identity:
                raise RuntimeError('TERM-resistant detached descendant marker inode changed while awaiting readiness')
            marker_identity = identity
            path_stat = os.stat(name, dir_fd=work_fd, follow_symlinks=False)
            if (path_stat.st_dev, path_stat.st_ino) != identity:
                raise RuntimeError('TERM-resistant detached descendant marker path no longer names its held inode')
            marker = os.read(marker_fd, 32)
            held_after = os.fstat(marker_fd)
            path_after = os.stat(name, dir_fd=work_fd, follow_symlinks=False)
            if (held_after.st_dev, held_after.st_ino) != identity or (path_after.st_dev, path_after.st_ino) != identity:
                raise RuntimeError('TERM-resistant detached descendant marker changed during readiness observation')
            if not stat.S_ISREG(held_after.st_mode) or held_after.st_nlink != 1 or held_after.st_uid != 1000 or held_after.st_mode & 0o077:
                raise RuntimeError('TERM-resistant detached descendant marker metadata changed during readiness observation')
            if held_after.st_size == 7 and marker == b'running':
                return
            if held_after.st_size > 7:
                raise RuntimeError('TERM-resistant detached descendant marker has an invalid size')
        finally:
            os.close(marker_fd)
        time.sleep(min(0.025, max(0.0, until - time.monotonic())))
    raise RuntimeError('TERM-resistant detached descendant readiness marker was not observed before its bound')

def make_control_script(prefix):
    nl = chr(10)
    listener = nl.join(['import os,pathlib,signal,socket,sys', 'signal.signal(signal.SIGTERM,signal.SIG_IGN)',
                        's=socket.socket()', 's.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,0)',
                        "s.bind(('127.0.0.1',0))", 's.listen(8)',
                        'f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)',
                        "port=f'{s.getsockname()[1]:05d}'.encode('ascii')",
                        'written=os.write(f,port)',
                        "if written != 5: raise RuntimeError('short listener marker write')",
                        'os.fsync(f); os.close(f)',
                        'while True:', ' c,_=s.accept(); c.close()', ''])
    descendant = nl.join(['import pathlib,signal,sys,time', 'signal.signal(signal.SIGTERM,signal.SIG_IGN)',
                          "pathlib.Path(sys.argv[1]).write_text('running',encoding='ascii')",
                          'while True: time.sleep(1)', ''])
    body = nl.join(['import array,os,pathlib,socket,subprocess,sys,time', "root=pathlib.Path(os.environ['work'])",
                    "report=socket.socket(fileno=int(os.environ['CHECKPOINT_CLEANUP_REPORT_FD']))",
                    'listener=' + repr(listener), 'descendant=' + repr(descendant),
                    "listener_proc=subprocess.Popen([sys.executable,'-c',listener,str(root/('" + prefix + ".port'))],start_new_session=True)",
                    "descendant_proc=subprocess.Popen([sys.executable,'-c',descendant,str(root/('" + prefix + ".descendant'))],start_new_session=True)",
                    "for role,proc in [('listener',listener_proc),('descendant',descendant_proc)]:",
                    ' pfd=os.pidfd_open(proc.pid,0)',
                    " payload=role.encode('ascii')",
                    ' try:',
                    "  sent=report.sendmsg([payload],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[pfd]))])",
                    "  if sent != len(payload): raise RuntimeError('short pidfd evidence transfer')",
                    ' finally: os.close(pfd)',
                    'while True: time.sleep(1)', ''])
    return (nl.join(['set -euo pipefail', "python3 - <<'PY'", body, 'PY', ''])).encode()

overall_deadline = time.monotonic() + 840
child, child_pidfd, poller, primary_report = launch_namespace(script, parent_pidfd, mode)
timed_out = False
while child.poll() is None and time.monotonic() < overall_deadline:
    poller.poll(100)
if child.poll() is None:
    timed_out = True
    signal.pidfd_send_signal(child_pidfd, signal.SIGKILL)
    end = time.monotonic() + 20
    while not poller.poll(100) and time.monotonic() < end:
        pass
    if not poller.poll(0):
        raise SystemExit('owned unshare pidfd did not reach a confirmed terminal state; preserving workspace')
status = child.wait(timeout=5)
os.close(child_pidfd)
primary_report.close()
if timed_out:
    raise SystemExit('private CPU fixture exceeded its independent 840-second Linux deadline')
if status:
    raise SystemExit(status)

if mode == 'controls':
    sentinel_parent_pid = os.getpid()
    def sentinel_pdeath():
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != sentinel_parent_pid:
            os._exit(125)
    sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], close_fds=True, preexec_fn=sentinel_pdeath)
    sentinel_fd = None
    try:
        sentinel_fd = os.pidfd_open(sentinel.pid, 0)
        sentinel_poll = select.poll()
        sentinel_poll.register(sentinel_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if sentinel_poll.poll(0):
            raise RuntimeError('unrelated outside-process positive control was not live')
        timeout_proc, timeout_fd, timeout_waiter, timeout_report = launch_namespace(make_control_script('timeout-control'), parent_pidfd, 'timeout-control')
        timeout_port = read_port_marker('timeout-control.port', min(overall_deadline, time.monotonic() + 5))
        assert_port_live(timeout_port)
        assert_descendant_marker('timeout-control.descendant', min(overall_deadline, time.monotonic() + 5))
        timeout_descendants = receive_descendant_pidfds(timeout_report)
        short_deadline = min(overall_deadline, time.monotonic() + 2)
        while time.monotonic() < short_deadline:
            time.sleep(0.05)
        signal.pidfd_send_signal(timeout_fd, signal.SIGKILL)
        if not wait_terminal(timeout_proc, timeout_waiter, min(overall_deadline, time.monotonic() + 8)):
            raise RuntimeError('short timeout did not reap the exact held unshare pidfd; preserving workspace')
        if timeout_proc.wait(timeout=3) == 0:
            raise RuntimeError('short timeout unexpectedly reported a successful fixture')
        os.close(timeout_fd)
        assert_pidfds_terminal(timeout_descendants, min(overall_deadline, time.monotonic() + 8))
        timeout_report.close()
        assert_port_absent(timeout_port)
        if sentinel_poll.poll(0):
            raise RuntimeError('unrelated outside process did not survive timeout cleanup')
        print('CHECKPOINT_CLEANUP_TIMEOUT_CONTROL_PASS', flush=True)

        parent_script = make_control_script('parent-death-control')
        parent_launcher = r'''import ctypes,os,pathlib,signal,subprocess,sys,time
supervisor_fd,work_fd,report_fd=map(int,sys.argv[1:4]); work=pathlib.Path(sys.argv[4]); bootstrap=sys.argv[5]; outer=sys.argv[6]
builder,patch,generator=sys.argv[7:10]; fixture_script=sys.argv[10].encode(); own_fd=os.pidfd_open(os.getpid(),0)
cmd=['unshare','--user','--map-current-user','--mount','--propagation','private','--pid','--fork','--kill-child=KILL','--mount-proc','python3','-c',bootstrap,str(supervisor_fd),str(own_fd),str(work_fd),str(report_fd),str(work),outer,builder,patch,generator,'parent-death-control']
parent_pid=os.getpid()
def pdeath():
 libc=ctypes.CDLL(None,use_errno=True)
 if libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent_pid: os._exit(125)
p=subprocess.Popen(cmd,stdin=subprocess.PIPE,pass_fds=(supervisor_fd,own_fd,work_fd,report_fd),close_fds=True,preexec_fn=pdeath)
p.stdin.write(fixture_script); p.stdin.close(); raw=pathlib.Path('/proc',str(p.pid),'stat').read_text(); print(str(p.pid)+' '+raw[raw.rfind(')')+2:].split()[19],flush=True)
sys.stdin.readline()
'''
        parent_report, parent_report_sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        launcher_parent_pid = os.getpid()
        def launcher_pdeath():
            if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != launcher_parent_pid:
                os._exit(125)
        launcher = subprocess.Popen([sys.executable, '-c', parent_launcher, str(supervisor_pidfd), str(work_fd), str(parent_report_sender.fileno()), str(work), bootstrap, json.dumps(outer_namespaces), builder, patch_file, generator, parent_script.decode()],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, pass_fds=(supervisor_pidfd, work_fd, parent_report_sender.fileno()), close_fds=True,
                                    preexec_fn=launcher_pdeath)
        parent_report_sender.close()
        launcher_fd = os.pidfd_open(launcher.pid, 0)
        line_poll = select.poll()
        line_poll.register(launcher.stdout.fileno(), select.POLLIN | select.POLLHUP)
        if not line_poll.poll(5000):
            raise RuntimeError('parent-death fixture did not publish its exact unshare PID')
        child_identity = launcher.stdout.readline().strip().split()
        if len(child_identity) != 2 or not all(value.isdecimal() for value in child_identity):
            raise RuntimeError('parent-death fixture returned a malformed unshare PID/start identity')
        parent_child_pid, parent_child_start = map(int, child_identity)
        if proc_start(parent_child_pid) != parent_child_start:
            raise RuntimeError('parent-death unshare PID/start identity changed before pidfd acquisition')
        parent_child_fd = os.pidfd_open(parent_child_pid, 0)
        if proc_start(parent_child_pid) != parent_child_start:
            os.close(parent_child_fd)
            raise RuntimeError('parent-death unshare PID/start identity changed while pinning pidfd')
        parent_port = read_port_marker('parent-death-control.port', min(overall_deadline, time.monotonic() + 5))
        assert_port_live(parent_port)
        assert_descendant_marker('parent-death-control.descendant', min(overall_deadline, time.monotonic() + 5))
        parent_descendants = receive_descendant_pidfds(parent_report)
        signal.pidfd_send_signal(launcher_fd, signal.SIGKILL)
        parent_waiter = select.poll()
        parent_waiter.register(launcher_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if not parent_waiter.poll(5000):
            raise RuntimeError('original fixture-parent pidfd did not terminate')
        if not wait_terminal_parent(parent_child_fd, min(overall_deadline, time.monotonic() + 8)):
            signal.pidfd_send_signal(parent_child_fd, signal.SIGKILL)
            raise RuntimeError('parent-death watcher did not terminate exact unshare pidfd; preserving workspace')
        launcher.wait(timeout=3)
        assert_pidfds_terminal(parent_descendants, min(overall_deadline, time.monotonic() + 8))
        os.close(parent_child_fd); os.close(launcher_fd)
        parent_report.close()
        assert_port_absent(parent_port)
        if sentinel_poll.poll(0):
            raise RuntimeError('unrelated outside process did not survive parent-death cleanup')
        print('CHECKPOINT_PARENT_DEATH_CONTROL_PASS', flush=True)
    finally:
        if sentinel.poll() is None and sentinel_fd is not None:
            signal.pidfd_send_signal(sentinel_fd, signal.SIGTERM)
            sentinel.wait(timeout=3)
        if sentinel_fd is not None:
            os.close(sentinel_fd)
os.close(supervisor_pidfd)
os.close(parent_pidfd)

marker_fd = os.open('.fixture-safe-to-clean', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=work_fd)
try:
    marker = os.read(marker_fd, 64)
    marker_stat = os.fstat(marker_fd)
finally:
    os.close(marker_fd)
if marker != b'completed\n' or not stat.S_ISREG(marker_stat.st_mode) or marker_stat.st_nlink != 1:
    raise SystemExit('fixture did not produce an exact completed cleanup marker; preserving workspace')
current = os.stat(work, follow_symlinks=False)
if (current.st_dev, current.st_ino, current.st_uid, current.st_gid) != (root_stat.st_dev, root_stat.st_ino, outer_uid, outer_gid):
    raise SystemExit('private workspace root identity changed after namespace exit; preserving workspace')
complete_fd = os.open('.fixture-supervisor-complete', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=work_fd)
try:
    if os.write(complete_fd, b'namespace-child-reaped\n') != len(b'namespace-child-reaped\n'):
        raise SystemExit('short write of supervisor cleanup marker')
    os.fsync(complete_fd)
finally:
    os.close(complete_fd)
os.fsync(work_fd)
`;

const script = String.raw`set -euo pipefail
[[ "$(id -u)" == 1000 && "$(id -u)" != 0 ]] || { echo 'unexpected WSL UID' >&2; exit 2; }
umask 077
mkdir -p "$HOME/.cache"
work=$(mktemp -d "$HOME/.cache/checkpoint-compat.XXXXXX")
work=$(realpath -e -- "$work")
[[ "$work" == "$HOME"/.cache/checkpoint-compat.* ]]
[[ "$(stat -c %u -- "$work")" == 1000 ]]
export work
work_identity=$(stat -c '%d:%i' -- "$work")
exec {workfd}<"$work"
shell_start=$(python3 - "$$" <<'PY'
import pathlib, sys
raw = pathlib.Path('/proc', sys.argv[1], 'stat').read_text()
print(raw[raw.rfind(')') + 2:].split()[19])
PY
)
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -f "$work/.fixture-safe-to-clean" && -f "$work/.fixture-supervisor-complete" ]]; then
    [[ "$(realpath -m -- "$work")" == "$HOME"/.cache/checkpoint-compat.* ]] || exit 91
    [[ "$(stat -Lc '%d:%i' -- "/proc/self/fd/$workfd")" == "$work_identity" ]]
    [[ "$(stat -c '%d:%i' -- "$work")" == "$work_identity" ]]
    [[ "$(cat -- "$work/.fixture-supervisor-complete")" == 'namespace-child-reaped' ]]
    rm -rf -- "$work"
  else
    printf 'fixture cleanup uncertain; preserving private workspace %s\n' "$work" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM
builder=$1
patch_file=$2
generator=$3
mode=$4
export CHECKPOINT_FIXTURE_ROOT="$work"
export CHECKPOINT_FIXTURE_MODE="$mode"
python3 -c ${shellQuote(supervisor)} "$work" "$workfd" "$builder" "$patch_file" "$generator" "$mode" "$$" "$shell_start" <<'INNER'
set -euo pipefail
builder=$1
patch_file=$2
generator=$3
mode=$4
bash "$builder" "$work" "$patch_file" "$work/provenance.json"
timeout --signal=TERM --kill-after=5s 30s python3 "$generator" "$work/tiny-llama.gguf" "$work/tiny-llama.json"
export CHECKPOINT_FIXTURE_ROOT="$work"
export CHECKPOINT_FIXTURE_MODE="$mode"
python3 - <<'PY'
import hashlib
import http.client
import json
import math
import os
import pathlib
import re
import signal
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request
import atexit

root = pathlib.Path(os.environ['CHECKPOINT_FIXTURE_ROOT'])
mode = os.environ['CHECKPOINT_FIXTURE_MODE']
server = root / 'build/bin/llama-server'
model = root / 'tiny-llama.gguf'
meta = json.loads((root / 'tiny-llama.json').read_text(encoding='utf-8'))
inventory = []
expected_metadata = {'format': 'GGUF v3', 'architecture': 'llama', 'contextLength': 1024,
                     'ropeFrequencyBase': 10000.0, 'ropeScalingType': 'linear', 'yarnExtFactor': 0.0,
                     'yarnAttnFactor': 1.0, 'yarnBetaFast': 32.0, 'yarnBetaSlow': 1.0,
                     'embeddingLength': 256, 'feedForwardLength': 512,
                     'heads': 4, 'kvHeads': 4, 'headDimension': 64, 'layers': 1,
                     'vTransposed': True, 'defaultCacheTypeK': 'f16', 'defaultCacheTypeV': 'f16',
                     'vocabularySize': 8, 'alignment': 32, 'tensorCount': 12}
if any(meta.get(key) != value for key, value in expected_metadata.items()):
    raise RuntimeError('synthetic GGUF metadata does not match the pinned fixture contract')
if set(meta) != set(expected_metadata) | {'fileBytes', 'tensorCount', 'tensors'} or not isinstance(meta.get('fileBytes'), int) or meta['fileBytes'] <= 0:
    raise RuntimeError('synthetic GGUF metadata field inventory/size is invalid')
expected_tensor_names = ['token_embd.weight', 'output_norm.weight', 'blk.0.attn_norm.weight',
                         'blk.0.attn_q.weight', 'blk.0.attn_k.weight', 'blk.0.attn_v.weight',
                         'blk.0.attn_output.weight', 'blk.0.ffn_norm.weight', 'blk.0.ffn_gate.weight',
                         'blk.0.ffn_down.weight', 'blk.0.ffn_up.weight', 'output.weight']
expected_tensor_shapes = [[256, 8], [256], [256], [256, 256], [256, 256], [256, 256], [256, 256],
                         [256], [256, 512], [512, 256], [256, 512], [256, 8]]
if (len(meta.get('tensors', [])) != meta['tensorCount'] or
        [t.get('name') for t in meta['tensors']] != expected_tensor_names or
        [t.get('shape') for t in meta['tensors']] != expected_tensor_shapes or
        any(set(t) != {'name', 'shape', 'type', 'offset', 'bytes'} or t.get('type') != 'F32' or
            t.get('offset', -1) % meta['alignment'] != 0 or
            t.get('bytes') != 4 * math.prod(t['shape']) for t in meta['tensors'])):
    raise RuntimeError('synthetic GGUF tensor inventory/type differs from the deterministic F32 fixture')
if model.stat().st_size != meta['fileBytes']:
    raise RuntimeError('synthetic GGUF byte length differs from its fixture metadata')

def f32_bits(value):
    return f'{struct.unpack("<I", struct.pack("<f", value))[0]:08x}'

def is_uint(value):
    return type(value) is int and value >= 0

def run_case(name, action):
    print('RUN ' + name, flush=True)
    try:
        result = action()
    except BaseException:
        print('FAIL ' + name, flush=True)
        raise
    inventory.append(name)
    print('PASS ' + name, flush=True)
    return result

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def proc_start(pid):
    stat = pathlib.Path(f'/proc/{pid}/stat').read_text()
    return stat[stat.rfind(')') + 2:].split()[19]

def listener_inode(pid, p):
    target = f'{p:04X}'
    inodes = []
    for table in ('/proc/net/tcp', '/proc/net/tcp6'):
        lines = pathlib.Path(table).read_text().splitlines()[1:]
        for row in lines:
            cols = row.split()
            address, state, inode = cols[1], cols[3], cols[9]
            if address in ('0100007F:' + target, '00000000000000000000000001000000:' + target) and state == '0A':
                inodes.append(inode)
    if len(inodes) != 1:
        raise RuntimeError(f'expected one listener on owned loopback port, got {len(inodes)}')
    owners = []
    for fd in pathlib.Path('/proc').glob('[0-9]*/fd/*'):
        try:
            if os.readlink(fd) == f'socket:[{inodes[0]}]':
                owners.append(int(fd.parts[2]))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    if owners != [pid]:
        raise RuntimeError('listener is not held solely by the live fixture child')

def request(p, method='GET', route='/checkpoint/compat', body=None):
    data = None if body is None else json.dumps(body, separators=(',', ':')).encode()
    req = urllib.request.Request(f'http://127.0.0.1:{p}{route}', data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status, response.read(65537)
    except urllib.error.HTTPError as error:
        return error.code, error.read(65537)

def validate_descriptor(data, requested, slots, cache_types=None, rope_scale=1.0):
    if len(data) > 65536:
        raise RuntimeError('descriptor exceeded bounded response size')
    parsed = json.loads(data)
    canonical = json.dumps(parsed, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    if data != canonical:
        raise RuntimeError('descriptor response is not canonical JSON')
    if set(parsed) != {'schemaVersion', 'support', 'architecture', 'sequenceSerializer', 'context', 'kv', 'slots', 'processId', 'authority'}:
        raise RuntimeError('descriptor top-level field inventory mismatch')
    if type(parsed['schemaVersion']) is not int or parsed['schemaVersion'] != 1 or parsed['support'] != 'plain-llama-kv' or parsed['architecture'] != 'llama':
        raise RuntimeError('descriptor support identity mismatch')
    if parsed['authority'] != 'compatibility-only' or type(parsed['processId']) is not int or parsed['processId'] != child.pid:
        raise RuntimeError('descriptor process or authority mismatch')
    if parsed['sequenceSerializer'] != 'llama-state-seq-62acc89-v1':
        raise RuntimeError('serializer version mismatch')
    ctx, kv = parsed['context'], parsed['kv']
    if set(ctx) != {'nCtx', 'nCtxSeq', 'nBatch', 'nUbatch', 'nSeqMax', 'nRsSeq', 'kvUnified', 'causalAttention', 'rope'}:
        raise RuntimeError('context field inventory mismatch')
    if set(ctx['rope']) != {'originalContext', 'freqBaseBits', 'freqScaleBits', 'yarnExtFactorBits', 'yarnAttnFactorBits', 'yarnBetaFastBits', 'yarnBetaSlowBits'}:
        raise RuntimeError('RoPE field inventory mismatch')
    if ctx['rope']['originalContext'] != meta['contextLength']:
        raise RuntimeError('effective YaRN original context differs from synthetic LLAMA metadata')
    if not all(is_uint(ctx[k]) for k in ('nCtx', 'nCtxSeq', 'nBatch', 'nUbatch', 'nSeqMax', 'nRsSeq')) or not all(ctx[k] > 0 for k in ('nCtx', 'nCtxSeq', 'nBatch', 'nUbatch', 'nSeqMax')) or not all(type(ctx[k]) is bool for k in ('kvUnified', 'causalAttention')):
        raise RuntimeError('context capacity values have the wrong type or range')
    rounded_total = ((requested + 255) // 256) * 256
    if ctx['kvUnified']:
        expected_total = rounded_total
        expected_seq = rounded_total
    else:
        expected_seq = ((rounded_total // slots + 255) // 256) * 256
        expected_total = expected_seq * slots
    if ctx['nCtx'] != expected_total or ctx['nCtxSeq'] != expected_seq:
        raise RuntimeError('effective global/per-sequence context padding differs from independent two-stage calculation')
    if ctx['nSeqMax'] != slots or ctx['nRsSeq'] != 0 or not ctx['causalAttention']:
        raise RuntimeError('effective sequence capacity mismatch')
    expected_slot = min(ctx['nCtxSeq'], meta['contextLength'])
    if len(parsed['slots']) != slots or any(set(s) != {'id', 'contextCapacity'} or not is_uint(s['id']) or not is_uint(s['contextCapacity']) or s['id'] != i or s['contextCapacity'] != expected_slot for i, s in enumerate(parsed['slots'])):
        raise RuntimeError('initialized slot IDs/caps differ from independently calculated capacity')
    if set(kv) != {'subtype', 'typeK', 'typeV', 'streams', 'cells', 'padding', 'vTransposed', 'rotation', 'layers'}:
        raise RuntimeError('KV field inventory mismatch')
    if not isinstance(kv['vTransposed'], bool) or kv['vTransposed'] is not meta['vTransposed'] or set(kv['rotation']) != {'k', 'v'} or not all(isinstance(kv['rotation'][x], bool) for x in ('k', 'v')):
        raise RuntimeError('actual V transposition or rotation flags are absent/malformed')
    expected_streams = 1 if ctx['kvUnified'] else ctx['nSeqMax']
    if (kv['subtype'] != 'llama_kv_cache' or not is_uint(kv['padding']) or not is_uint(kv['cells']) or
            not is_uint(kv['streams']) or kv['padding'] < 1 or kv['cells'] != ctx['nCtxSeq'] or
            kv['cells'] % kv['padding'] != 0 or kv['streams'] != expected_streams):
        raise RuntimeError('KV cache subtype, padding, or streams invalid')
    if cache_types is None:
        cache_types = (meta['defaultCacheTypeK'], meta['defaultCacheTypeV'])
    if (kv['typeK'], kv['typeV']) != cache_types:
        raise RuntimeError('initialized K/V cache types differ from exact fixture launch options')
    if len(kv['layers']) != meta['layers'] or [x['layer'] for x in kv['layers']] != [0] or any(set(x) != {'layer', 'k', 'v'} or not is_uint(x['layer']) for x in kv['layers']):
        raise RuntimeError('ordered K/V layer inventory mismatch')
    for side in ('k', 'v'):
        tensor = kv['layers'][0][side]
        expected_type = cache_types[0 if side == 'k' else 1]
        block_bytes, block_items = {'f16': (2, 1), 'f32': (4, 1), 'q8_0': (34, 32)}[expected_type]
        width = meta['headDimension'] * meta['kvHeads']
        expected_shape = [width, ctx['nCtxSeq'], expected_streams, 1]
        row_bytes = (width // block_items) * block_bytes
        expected_strides = [block_bytes, row_bytes, row_bytes * ctx['nCtxSeq'], row_bytes * ctx['nCtxSeq'] * expected_streams]
        if (set(tensor) != {'type', 'shape', 'strides', 'rowBytes'} or
                tensor['type'] != expected_type or tensor['shape'] != expected_shape or tensor['strides'] != expected_strides or
                len(tensor['shape']) != 4 or len(tensor['strides']) != 4 or
                any(type(x) is not int or x <= 0 for x in tensor['shape']) or
                any(type(x) is not int or x <= 0 for x in tensor['strides']) or
                not is_uint(tensor['rowBytes']) or tensor['rowBytes'] != row_bytes):
            raise RuntimeError('actual K/V tensor geometry is absent or inconsistent')
    rope = ctx['rope']
    if not all(isinstance(rope[k], str) and re.fullmatch(r'[0-9a-f]{8}', rope[k]) for k in (
        'freqBaseBits', 'freqScaleBits', 'yarnExtFactorBits', 'yarnAttnFactorBits', 'yarnBetaFastBits', 'yarnBetaSlowBits')):
        raise RuntimeError('effective RoPE float bit patterns are incomplete')
    expected_bits = {'freqBaseBits': meta['ropeFrequencyBase'], 'freqScaleBits': rope_scale,
                     'yarnExtFactorBits': meta['yarnExtFactor'], 'yarnAttnFactorBits': meta['yarnAttnFactor'],
                     'yarnBetaFastBits': meta['yarnBetaFast'], 'yarnBetaSlowBits': meta['yarnBetaSlow']}
    if any(rope[key] != f32_bits(value) for key, value in expected_bits.items()):
        raise RuntimeError('effective RoPE float bits differ from independent model metadata/CLI values')
    return parsed

def launch(requested=300, slots=2, optin=True, extra=(), env_extra=None):
    p = port()
    env = os.environ.copy()
    env.pop('LLAMA_ATTN_ROT_DISABLE', None)
    if optin:
        env['LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR'] = '1'
    else:
        env.pop('LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR', None)
    if env_extra:
        env.update(env_extra)
    global child, child_start
    child = subprocess.Popen([str(server), '--model', str(model), '--ctx-size', str(requested),
                              '--parallel', str(slots), '--flash-attn', 'off', '--rope-freq-scale', '1',
                              '--host', '127.0.0.1', '--port', str(p), *extra],
                             cwd=root, env=env, stdout=(root / f'server-{p}.log').open('wb'), stderr=subprocess.STDOUT)
    start = proc_start(child.pid)
    child_start = start
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and child.poll() is None:
        try:
            status, body = request(p, route='/health')
            if status == 200:
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(0.1)
    else:
        raise RuntimeError('initialized server did not become ready')
    listener_inode(child.pid, p)
    return p, start

def stop():
    global child, child_start
    if child is not None:
        if child.poll() is None and proc_start(child.pid) != child_start:
            raise RuntimeError('fixture child PID incarnation changed; refusing to signal an unowned process')
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if proc_start(child.pid) != child_start:
                raise RuntimeError('fixture child PID incarnation changed before bounded reap')
            child.kill()
            child.wait(timeout=5)
        child = None
        child_start = None

child = None
child_start = None
build_proc = None
build_log = None

def stop_build():
    global build_proc, build_log
    if build_proc is not None and build_proc.poll() is None:
        try:
            os.killpg(build_proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            build_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(build_proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            build_proc.wait(timeout=5)
    build_proc = None
    if build_log is not None:
        build_log.close()
        build_log = None

def build_server():
    global build_proc, build_log
    build_log = (root / 'mutant-build.log').open('wb')
    build_proc = subprocess.Popen(['cmake', '--build', str(root / 'build'), '--target', 'llama-server', '--parallel', '2'],
                                  cwd=root, stdout=build_log, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + 600
    while build_proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    if build_proc.poll() is None:
        stop_build()
        raise RuntimeError('bounded mutant CPU rebuild timed out')
    build_proc.wait(timeout=5)
    status = build_proc.returncode
    build_proc = None
    build_log.close()
    build_log = None
    if status != 0:
        raise RuntimeError('compileable C++ mutant rebuild failed: ' + (root / 'mutant-build.log').read_text(errors='replace')[-3000:])

def compiled_mutant(relative, old, new, kind):
    source = root / 'source' / relative
    original = source.read_text(encoding='utf-8')
    if original.count(old) != 1:
        raise RuntimeError('mutant source anchor is missing or ambiguous: ' + relative)
    try:
        if kind == 'rowBytes':
            p, _ = launch(512, 2, True, extra=('--cache-type-k', 'q8_0', '--cache-type-v', 'f16'))
            status, body = request(p)
            if status != 200:
                raise RuntimeError('rowBytes positive-control descriptor endpoint was not live')
            validate_descriptor(body, 512, 2, ('q8_0', 'f16'))
            stop()
        source.write_text(original.replace(old, new, 1), encoding='utf-8')
        build_server()
        p, _ = launch(512, 2, True, extra=('--cache-type-k', 'q8_0', '--cache-type-v', 'f16'))
        if child.poll() is not None:
            raise RuntimeError('mutant model did not initialize on CPU')
        if kind == 'rowBytes':
            status, body = request(p)
            if status != 200:
                raise RuntimeError('descriptor mutant endpoint was not live after model initialization')
            try:
                validate_descriptor(body, 512, 2, ('q8_0', 'f16'))
            except RuntimeError as error:
                if 'K/V tensor geometry' not in str(error):
                    raise
            else:
                raise RuntimeError('strict initialized descriptor parser accepted a compiled missing-field mutant')
        elif kind == 'optin':
            status, _ = request(p)
            if status != 404:
                raise RuntimeError('compiled startup-opt-in name mutant did not disable the original opt-in')
        stop()
    finally:
        stop()
        source.write_text(original, encoding='utf-8')
        build_server()

def compiled_mutant_lora_guard():
    relative = 'tools/server/server-context.cpp'
    source = root / 'source' / relative
    original = source.read_text(encoding='utf-8')
    marker = 'this->post_lora_adapters ='
    prefix, found, suffix = original.partition(marker)
    guard = 'if (checkpoint_compat_enabled_for_process()) {'
    if not found or suffix.count(guard) < 1:
        raise RuntimeError('LoRA endpoint guard mutant anchor missing')
    mutated = prefix + found + suffix.replace(guard, 'if (false) {', 1)
    try:
        source.write_text(mutated, encoding='utf-8')
        build_server()
        p, _ = launch(512, 2, True)
        status, body = request(p, 'POST', '/lora-adapters', [])
        if status >= 400 or b'adapter mutation disabled by checkpoint descriptor opt-in' in body:
            raise RuntimeError('compiled disabled LoRA guard was not detected by the initialized mutation-policy oracle')
        stop()
    finally:
        stop()
        source.write_text(original, encoding='utf-8')
        build_server()

def stop_on_signal(signum, frame):
    stop()
    stop_build()
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, stop_on_signal)
signal.signal(signal.SIGINT, stop_on_signal)
atexit.register(stop)
try:
    print('CHECKPOINT_CONTROL_TRANSCRIPT_BEGIN', flush=True)
    if mode == 'cpu':
        def positive_cpu():
            p, start = launch(512, 2, True)
            status, first = request(p)
            status2, second = request(p)
            if status != 200 or status2 != 200:
                raise RuntimeError('supported initialized descriptor endpoint did not return 200')
            a = validate_descriptor(first, 512, 2)
            b = validate_descriptor(second, 512, 2)
            stable_a = {k: v for k, v in a.items() if k != 'processId'}
            stable_b = {k: v for k, v in b.items() if k != 'processId'}
            if stable_a != stable_b or proc_start(child.pid) != start:
                raise RuntimeError('stable semantics or live child identity changed between reads')
            listener_inode(child.pid, p)
        run_case('initialized-supported-descriptor', positive_cpu)
        stop()
    elif mode == 'controls':
        state = {}
        def positive_first():
            p, _ = launch(512, 2, True)
            status, body = request(p)
            if status != 200:
                raise RuntimeError('supported initialized positive control missing')
            state['base'] = validate_descriptor(body, 512, 2)
            if state['base']['kv']['rotation'] != {'k': False, 'v': False}:
                raise RuntimeError('F16 baseline unexpectedly claims quantized attention rotation')
        run_case('supported-positive-first', positive_first)
        stop()

        def context_variant():
            p, _ = launch(600, 2, True)
            st, body = request(p)
            variant = validate_descriptor(body, 600, 2) if st == 200 else None
            if variant is None or variant['context']['nCtx'] != 1024 or variant['context']['nCtxSeq'] != 512:
                raise RuntimeError('initialized two-stage per-sequence padding was not distinguished')
            if variant['slots'][0]['contextCapacity'] != 512 or variant['context']['nCtx'] == state['base']['context']['nCtx']:
                raise RuntimeError('initialized context/slot capacity variant was not distinguished')
        run_case('context-padding-variant', context_variant)
        stop()

        def rope_variant():
            p, _ = launch(512, 2, True, extra=('--rope-freq-scale', '2'))
            st, body = request(p)
            rope = validate_descriptor(body, 512, 2, rope_scale=2.0) if st == 200 else None
            if rope is None or rope['context']['rope'] == state['base']['context']['rope']:
                raise RuntimeError('initialized effective RoPE variant was not distinguished')
        run_case('rope-effective-variant', rope_variant)
        stop()

        # Quantize K only: this exercises the pinned 64-dimension rotation
        # policy without relying on backend-specific quantized-V/flash-attn support.
        quantized = ('--cache-type-k', 'q8_0', '--cache-type-v', 'f16')
        def rotation_enabled():
            p, _ = launch(512, 2, True, extra=quantized)
            st, body = request(p)
            state['rotation_on'] = validate_descriptor(body, 512, 2, ('q8_0', 'f16')) if st == 200 else None
            if state['rotation_on'] is None or state['rotation_on']['kv']['rotation'] != {'k': True, 'v': False}:
                raise RuntimeError('initialized quantized-K/F16-V cache did not expose the exact K-only rotation policy')
        run_case('rotation-enabled-quantized', rotation_enabled)
        stop()

        def rotation_disabled():
            p, _ = launch(512, 2, True, extra=quantized, env_extra={'LLAMA_ATTN_ROT_DISABLE': '1'})
            st, body = request(p)
            value = validate_descriptor(body, 512, 2, ('q8_0', 'f16')) if st == 200 else None
            if value is None or value['kv']['rotation'] != {'k': False, 'v': False} or value['kv']['rotation'] == state['rotation_on']['kv']['rotation']:
                raise RuntimeError('initialized quantized cache did not report explicit rotation disable')
        run_case('rotation-disabled-quantized', rotation_disabled)
        stop()

        def mutation_reject(label, method, route, payload, expected_error):
            def action():
                p, _ = launch(512, 2, True)
                try:
                    status, body = request(p, method, route, payload)
                    if status < 400 or expected_error.encode() not in body:
                        raise RuntimeError(label + ' lacked the exact opt-in-specific rejection')
                finally:
                    stop()
            return action
        run_case('props-mutation-rejected', mutation_reject('props', 'POST', '/props', {}, 'properties mutation disabled by checkpoint descriptor opt-in'))
        run_case('lora-mutation-rejected', mutation_reject('lora', 'POST', '/lora-adapters', [], 'adapter mutation disabled by checkpoint descriptor opt-in'))
        run_case('request-adapter-rejected', mutation_reject('request adapter', 'POST', '/completion', {'prompt': 'a', 'n_predict': 1, 'lora': [{'id': 1, 'scale': 1.0}]}, 'per-request adapter mutation disabled by checkpoint descriptor opt-in'))
        def parallel_variant():
            p, _ = launch(512, 1, True)
            st, body = request(p)
            parallel = validate_descriptor(body, 512, 1) if st == 200 else None
            if parallel is None or len(parallel['slots']) != 1 or parallel['slots'][0]['id'] != 0 or parallel['slots'][0]['contextCapacity'] != 512 or state['base']['slots'][0]['contextCapacity'] != 256:
                raise RuntimeError('initialized exact slot ID/capacity variant was not distinguished')
        run_case('parallel-slot-capacity-variant', parallel_variant)
        stop()

        def unsupported_context():
            p, _ = launch(512, 2, True, extra=('--embedding',))
            if child.poll() is not None:
                raise RuntimeError('unsupported-context fixture did not initialize')
            st, body = request(p)
            if st != 409 or b'unsupported' not in body:
                raise RuntimeError('initialized unsupported context was not rejected')
        run_case('initialized-unsupported-context', unsupported_context)
        stop()

        def startup_optout():
            p, _ = launch(512, 2, False)
            st, _ = request(p)
            if st != 404:
                raise RuntimeError('descriptor endpoint ignored startup opt-out')
        run_case('startup-optout', startup_optout)
        stop()

        run_case('compiled-mutant-rowbytes-rejected', lambda: compiled_mutant('src/llama-context.cpp', r'\"rowBytes\":', r'\"rowBytesMutant\":', 'rowBytes'))
        run_case('compiled-mutant-optin-rejected', lambda: compiled_mutant('tools/server/server-context.cpp', 'LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR', 'LLAMA_CHECKPOINT_COMPAT_MUTANT', 'optin'))
        run_case('compiled-mutant-lora-guard-rejected', lambda: compiled_mutant_lora_guard())

        expected = ['supported-positive-first', 'context-padding-variant', 'rope-effective-variant',
                    'rotation-enabled-quantized', 'rotation-disabled-quantized', 'props-mutation-rejected',
                    'lora-mutation-rejected', 'request-adapter-rejected', 'parallel-slot-capacity-variant',
                    'initialized-unsupported-context', 'startup-optout', 'compiled-mutant-rowbytes-rejected',
                    'compiled-mutant-optin-rejected', 'compiled-mutant-lora-guard-rejected', 'exact-run-pass-inventory']
        print('RUN exact-run-pass-inventory', flush=True)
        if inventory != expected[:-1]:
            print('FAIL exact-run-pass-inventory', flush=True)
            raise RuntimeError('ordered RUN/PASS transcript inventory mismatch')
        inventory.append('exact-run-pass-inventory')
        print('PASS exact-run-pass-inventory', flush=True)
    else:
        raise RuntimeError('unknown fixture mode')
finally:
    stop()
    stop_build()
if child is not None:
    raise RuntimeError('fixture child was not reaped')
print('CHECKPOINT_CONTROL_TRANSCRIPT_END', flush=True)
(root / '.fixture-safe-to-clean').write_text('completed\n', encoding='ascii')
PY
INNER
`;

const launchElapsedMs = Math.floor(performance.now() - cpuStartedAt);
if (launchElapsedMs > CPU_PREFLIGHT_BUDGET_MS) {
  throw new Error(`cumulative WSL preflight exceeded ${CPU_PREFLIGHT_BUDGET_MS} ms; private namespace/build was not launched`);
}
const mainWslTimeoutMs = CPU_WSL_TIMEOUT_MS - launchElapsedMs;
if (mainWslTimeoutMs < CPU_MAIN_MIN_REMAINING_MS) {
  throw new Error(`only ${mainWslTimeoutMs} ms remain for the bounded Linux fixture; private namespace/build was not launched`);
}
const result = spawnSync('wsl.exe', ['-d', 'Ubuntu', '--exec', 'bash', '--noprofile', '--norc', '-s', '--', builderWsl, patchWsl, generatorWsl, mode], {
  input: script, encoding: 'utf8', timeout: mainWslTimeoutMs, maxBuffer: limit, windowsHide: true,
});
if (result.error || result.status !== 0) {
  const summary = formatFailureSummary({ status: result.status, error: result.error, stdout: result.stdout, stderr: result.stderr });
  throw new Error(`fixture orchestration ${failureOutcome(result)}: ${summary}`);
}
const expected = mode === 'cpu' ? ['initialized-supported-descriptor'] : [
  'supported-positive-first', 'context-padding-variant', 'rope-effective-variant', 'rotation-enabled-quantized',
  'rotation-disabled-quantized', 'props-mutation-rejected', 'lora-mutation-rejected', 'request-adapter-rejected',
  'parallel-slot-capacity-variant', 'initialized-unsupported-context', 'startup-optout',
  'compiled-mutant-rowbytes-rejected', 'compiled-mutant-optin-rejected', 'compiled-mutant-lora-guard-rejected',
  'exact-run-pass-inventory',
];
const lines = result.stdout.split(/\r?\n/);
const begin = lines.indexOf('CHECKPOINT_CONTROL_TRANSCRIPT_BEGIN');
const end = lines.indexOf('CHECKPOINT_CONTROL_TRANSCRIPT_END');
const events = begin >= 0 && end > begin ? lines.slice(begin + 1, end) : [];
if (begin < 0 || end <= begin || lines.lastIndexOf('CHECKPOINT_CONTROL_TRANSCRIPT_BEGIN') !== begin ||
    lines.lastIndexOf('CHECKPOINT_CONTROL_TRANSCRIPT_END') !== end || events.length !== expected.length * 2 ||
    !expected.every((name, i) => events[i * 2] === `RUN ${name}` && events[i * 2 + 1] === `PASS ${name}`)) {
  throw new Error('fixture did not produce the exact ordered RUN/PASS inventory');
}
const cleanupMarkers = ['CHECKPOINT_CLEANUP_TIMEOUT_CONTROL_PASS', 'CHECKPOINT_PARENT_DEATH_CONTROL_PASS'];
if (mode === 'controls') {
  const markerPositions = cleanupMarkers.map(marker => lines.indexOf(marker));
  if (markerPositions.some((position, index) => position <= end || lines.lastIndexOf(cleanupMarkers[index]) !== position) ||
      markerPositions[0] >= markerPositions[1]) {
    throw new Error('Linux timeout/parent-death cleanup markers are missing, duplicated, or out of order');
  }
}
console.log(lines.slice(begin, end + 1).join('\n'));
if (mode === 'controls') console.log(cleanupMarkers.join('\n'));
console.log(mode === 'cpu' ? 'checkpoint backend descriptor CPU verification passed' : 'checkpoint backend descriptor controls verification passed');
