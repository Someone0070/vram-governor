//go:build linux && checkpoint_plan_broker_cpu

package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"vram-governor/internal/wsproto"
)

const (
	planBrokerCPUOptIn      = "I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS"
	planBrokerCPUEnv        = "VRAM_PLAN_BROKER_CPU_OPT_IN"
	planBrokerCPURole       = "VRAM_PLAN_BROKER_CPU_ROLE"
	planBrokerCPUClientMode = "VRAM_PLAN_BROKER_CPU_CLIENT_MODE"
	planBrokerCPUNodeGIDEnv = "VRAM_PLAN_BROKER_CPU_NODE_GID"
	planBrokerCPUCrashAtEnv = "VRAM_PLAN_BROKER_CPU_CRASH_AT"
	planBrokerCPUParentGuardEnv = "VRAM_PLAN_BROKER_CPU_PARENT_GUARD"
	planBrokerCPUSystemdRun = "/usr/bin/systemd-run"
	planBrokerCPUCrashExit  = 67
)

type planBrokerCPUBroker struct {
	cmd               *exec.Cmd
	socketPath        string
	socketInfo        os.FileInfo
	waitDone          chan struct{}
	waitErr           error
	expectedCrashExit int
	parentGuardWrite  *os.File
}

type planBrokerCPUParentGuardChild struct {
	cmd              *exec.Cmd
	parentGuardWrite *os.File
}

const planBrokerCPUUnitHolderProgram = `import base64,ctypes,fcntl,os,select,signal,stat,sys,time

GUARD=3
COMMAND=4
STATUS=5
PARENT=6
ROOTFD=7
CONTROL=8
BLOCK=9
DUP_GUARD=10
# Historical Broker55 diagnostic exit only; live object validation no longer exits on unrelated fd10.
HISTORICAL_UNRELATED_FD10_EXIT=193
MAX=1024
started=time.monotonic()
deadline=started+240.0
used=0
buffer=b''
bus=None
sender=None
owner=None
unit=None
root=None
identity=None
phase='boot'
phase_deadline=None
control_case=None
control_target=None
control_done=False
health_cycles=0
control_cases={
    'watchdog_native_expiry':('pre_ready',False),
    'watchdog_absolute_cap':('pre_ready',False),
    'startup_parentdeath':('startup',False),
    'parentdeath_pre_ready_after_arm':('pre_ready',True),
    'parentdeath_import_boundary':('import',True),
    'parentdeath_constructor_boundary':('constructor',True),
    'parentdeath_method_boundary':('method',True),
    'parentdeath_held_idle':('held_idle',True),
    'parentdeath_close_boundary':('close',True),
    'parentdeath_after_rearm':('after_rearm',True),
}
negative_controls={
    'negative_ref_error':'ref_error',
    'negative_watchdog_omitted':'watchdog_omitted',
}

def die(code):
    os._exit(code)

def emit(frame):
    global used
    data=(frame+'\n').encode('ascii','strict')
    if not data or len(data)>192 or used+len(data)>MAX: die(90)
    used+=len(data)
    if os.write(STATUS,data)!=len(data): die(91)

def report(frame):
    global used
    data=(frame+'\n').encode('ascii','strict')
    if not data or len(data)>192 or used+len(data)>MAX: die(90)
    used+=len(data)
    if os.write(1,data)!=len(data): die(91)

def exact_root(fields):
    global root,identity,unit
    if len(fields)!=8: die(92)
    raw=base64.b64decode(fields[0],validate=True)
    root=os.fsdecode(raw)
    dev,ino,uid,gid,nodegid,parentpid=map(int,fields[1:7])
    expected_unit=fields[7]
    if not root.startswith('/') or os.path.normpath(root)!=root or os.path.dirname(root)!='/tmp': die(93)
    name=os.path.basename(root)
    if len(name)!=39 or name[:23]!='vram-plan-relaunch-cpu-' or any(ch not in '0123456789abcdef' for ch in name[23:]): die(94)
    unit=name+'.service'
    st=os.lstat(root)
    held=os.fstat(ROOTFD)
    if not stat.S_ISDIR(st.st_mode) or st.st_dev!=dev or st.st_ino!=ino or held.st_dev!=dev or held.st_ino!=ino or st.st_uid!=uid or st.st_gid!=gid or held.st_uid!=uid or held.st_gid!=gid or stat.S_IMODE(st.st_mode)!=0o711 or uid!=0 or nodegid==0: die(95)
    try:
        info=open('/proc/self/fdinfo/'+str(PARENT),'r',encoding='ascii').read(2048)
        pidline=next(line for line in info.splitlines() if line.startswith('Pid:\t'))
        if int(pidline.split(':',1)[1].strip())!=parentpid: die(96)
        signal.pidfd_send_signal(PARENT,0,None,0)
    except Exception: die(97)
    identity=(dev,ino,uid,gid,nodegid,parentpid)

def validate_guard_duplicate(expected):
    duplicate=None
    initial=None
    try:
        duplicate=os.fstat(DUP_GUARD)
        initial=(descriptor_identity(duplicate),fcntl.fcntl(DUP_GUARD,fcntl.F_GETFL))
    except OSError as e:
        if e.errno!=9:
            die(149)
        if expected:
            die(150)
        duplicate=None
        initial=None
    try:
        observations,guard,scanner_number=scan_guard_writer_provenance()
        if expected:
            duplicate_observation=observations.get(DUP_GUARD)
            if duplicate_observation is None or duplicate_observation[:2]!=initial or not duplicate_observation[2] or not duplicate_observation[3] or initial[1]&os.O_ACCMODE!=os.O_WRONLY:
                die(152)
            if any(observation[3] for fd,observation in observations.items() if fd!=DUP_GUARD):
                die(178)
            duplicate_now=os.fstat(DUP_GUARD)
            duplicate_flags_now=fcntl.fcntl(DUP_GUARD,fcntl.F_GETFL)
            if (descriptor_identity(duplicate_now),duplicate_flags_now)!=initial or guard_snapshot()!=guard:
                die(194)
            return
        if duplicate is None:
            if scanner_number!=DUP_GUARD and DUP_GUARD in observations:
                die(194)
            try:
                os.fstat(DUP_GUARD)
            except OSError as e:
                if e.errno!=9:
                    die(149)
            else:
                die(194)
        else:
            duplicate_observation=observations.get(DUP_GUARD)
            if duplicate_observation is None or duplicate_observation[:2]!=initial:
                die(194)
            duplicate_now=os.fstat(DUP_GUARD)
            duplicate_flags_now=fcntl.fcntl(DUP_GUARD,fcntl.F_GETFL)
            if (descriptor_identity(duplicate_now),duplicate_flags_now)!=initial or guard_snapshot()!=guard:
                die(194)
            if duplicate_observation[2]:
                if duplicate_observation[3]:
                    die(151)
                die(152)
        if any(observation[3] for observation in observations.values()):
            die(195)
        if guard_snapshot()!=guard:
            die(194)
    except Exception:
        die(194)

class LinuxDirent64(ctypes.Structure):
    _fields_=[('d_ino',ctypes.c_ulong),('d_off',ctypes.c_long),('d_reclen',ctypes.c_ushort),('d_type',ctypes.c_ubyte),('d_name',ctypes.c_char*256)]

def descriptor_identity(info):
    return (info.st_dev,info.st_ino,info.st_mode)

def guard_snapshot():
    info=os.fstat(GUARD)
    flags=fcntl.fcntl(GUARD,fcntl.F_GETFL)
    if not stat.S_ISFIFO(info.st_mode):
        raise RuntimeError('unsupported guard descriptor')
    return (descriptor_identity(info),flags)

def scan_guard_writer_provenance():
    if sys.platform!='linux' or ctypes.sizeof(ctypes.c_void_p)!=8 or ctypes.sizeof(ctypes.c_ulong)!=8 or ctypes.sizeof(ctypes.c_long)!=8 or ctypes.sizeof(LinuxDirent64)!=280 or LinuxDirent64.d_name.offset!=19:
        raise RuntimeError('unsupported Linux directory ABI')
    libc=ctypes.CDLL(None,use_errno=True)
    libc.fdopendir.argtypes=[ctypes.c_int]
    libc.fdopendir.restype=ctypes.c_void_p
    libc.readdir.argtypes=[ctypes.c_void_p]
    libc.readdir.restype=ctypes.POINTER(LinuxDirent64)
    libc.rewinddir.argtypes=[ctypes.c_void_p]
    libc.rewinddir.restype=None
    libc.closedir.argtypes=[ctypes.c_void_p]
    libc.closedir.restype=ctypes.c_int
    libc.dirfd.argtypes=[ctypes.c_void_p]
    libc.dirfd.restype=ctypes.c_int
    deadline=time.monotonic_ns()+100000000
    scanner_fd=-1
    stream=None
    try:
        scanner_fd=os.open('/proc/self/fd',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        ctypes.set_errno(0)
        stream=libc.fdopendir(scanner_fd)
        if not stream:
            raise OSError(ctypes.get_errno(),'fdopendir failed')
        scanner_fd=-1
        scanner_number=libc.dirfd(stream)
        if scanner_number<0:
            raise RuntimeError('scanner descriptor unavailable')
        def check_deadline():
            if time.monotonic_ns()>=deadline:
                raise RuntimeError('descriptor observation deadline')
        def scanner_snapshot():
            info=os.fstat(scanner_number)
            flags=fcntl.fcntl(scanner_number,fcntl.F_GETFL)
            if not stat.S_ISDIR(info.st_mode) or flags&os.O_ACCMODE!=os.O_RDONLY:
                raise RuntimeError('scanner identity changed')
            return (descriptor_identity(info),flags)
        def enumerate_pass(name_budget):
            seen=set()
            numeric={}
            total=name_budget
            while True:
                check_deadline()
                ctypes.set_errno(0)
                entry=libc.readdir(stream)
                if not entry:
                    if ctypes.get_errno()!=0:
                        raise OSError(ctypes.get_errno(),'readdir failed')
                    break
                record=entry.contents
                record_length=record.d_reclen
                if record_length<LinuxDirent64.d_name.offset+1 or record_length>ctypes.sizeof(LinuxDirent64):
                    raise RuntimeError('malformed directory record')
                raw=ctypes.string_at(ctypes.addressof(record)+LinuxDirent64.d_name.offset,record_length-LinuxDirent64.d_name.offset)
                terminator=raw.find(b'\0')
                if terminator<0 or record_length!=((LinuxDirent64.d_name.offset+terminator+1+7)//8)*8:
                    raise RuntimeError('malformed or unterminated directory name')
                raw_name=raw[:terminator]
                if not raw_name or raw_name in seen:
                    raise RuntimeError('empty or duplicate directory name')
                seen.add(raw_name)
                total+=len(raw_name)
                if total>=8192:
                    raise RuntimeError('descriptor name byte cap')
                if raw_name.isdigit():
                    number=int(raw_name)
                    if str(number).encode('ascii')!=raw_name or number in numeric:
                        raise RuntimeError('noncanonical or duplicate descriptor number')
                    numeric[number]=raw_name
                    if len(numeric)>=128:
                        raise RuntimeError('descriptor entry cap')
                elif raw_name not in (b'.',b'..'):
                    raise RuntimeError('unexpected proc descriptor entry')
            if scanner_number not in numeric:
                raise RuntimeError('held scanner missing from descriptor set')
            return numeric,total
        def observe_fd(fd,expected_guard):
            check_deadline()
            guard_before=guard_snapshot()
            if guard_before!=expected_guard:
                raise RuntimeError('guard changed before descriptor classification')
            before_info=os.fstat(fd)
            before_flags=fcntl.fcntl(fd,fcntl.F_GETFL)
            identity=descriptor_identity(before_info)
            same_pipe=stat.S_ISFIFO(before_info.st_mode) and identity[0]==expected_guard[0][0] and identity[1]==expected_guard[0][1]
            writer=same_pipe and before_flags&os.O_ACCMODE in (os.O_WRONLY,os.O_RDWR)
            after_flags=fcntl.fcntl(fd,fcntl.F_GETFL)
            after_info=os.fstat(fd)
            guard_after=guard_snapshot()
            if descriptor_identity(after_info)!=identity or after_flags!=before_flags or guard_after!=expected_guard:
                raise RuntimeError('descriptor changed during classification')
            check_deadline()
            return (identity,before_flags,same_pipe,writer)
        before_scanner=scanner_snapshot()
        guard=guard_snapshot()
        first_names,used_names=enumerate_pass(0)
        if scanner_snapshot()!=before_scanner:
            raise RuntimeError('scanner changed during first pass')
        first={fd:observe_fd(fd,guard) for fd in first_names if fd!=scanner_number}
        if scanner_snapshot()!=before_scanner or guard_snapshot()!=guard:
            raise RuntimeError('descriptor identity changed after first pass')
        libc.rewinddir(stream)
        check_deadline()
        second_names,used_names=enumerate_pass(used_names)
        if second_names!=first_names or scanner_snapshot()!=before_scanner:
            raise RuntimeError('descriptor set changed between passes')
        second={fd:observe_fd(fd,guard) for fd in second_names if fd!=scanner_number}
        if second!=first or scanner_snapshot()!=before_scanner or guard_snapshot()!=guard:
            raise RuntimeError('descriptor identity changed between passes')
        check_deadline()
        return second,guard,scanner_number
    finally:
        if stream:
            ctypes.set_errno(0)
            close_result=libc.closedir(stream)
            stream=None
            if close_result!=0:
                raise OSError(ctypes.get_errno(),'closedir failed')
        elif scanner_fd>=0:
            os.close(scanner_fd)
        if time.monotonic_ns()>=deadline:
            raise RuntimeError('descriptor observation deadline')

def native_state():
    bit=1 << (signal.SIGALRM-1)
    if signal.getsignal(signal.SIGALRM)!=signal.SIG_DFL: die(98)
    if signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK,set()): die(99)
    values={}
    with open('/proc/self/status','rb') as f:
        raw=f.read(4097)
    if len(raw)>4096: die(124)
    try:
        lines=raw.decode('ascii','strict').splitlines()
    except Exception: die(125)
    for line in lines:
        if line.startswith(('SigBlk:','SigIgn:','SigCgt:','SigPnd:','ShdPnd:')):
            k,v=line.split(':',1); values[k]=int(v.strip(),16)
    if set(values)!={'SigBlk','SigIgn','SigCgt','SigPnd','ShdPnd'}: die(100)
    if any(values[k]&bit for k in values): die(101)
    timer=signal.getitimer(signal.ITIMER_REAL)
    remaining=deadline-time.monotonic()
    if remaining<=0 or timer[0]<=0 or timer[1]!=0: die(102)
    return remaining

def guard_check(rearm):
    global used
    if phase_deadline is not None and time.monotonic()>=phase_deadline: die(134)
    if time.monotonic()>=deadline: die(103)
    try:
        signal.pidfd_send_signal(PARENT,0,None,0)
        poller=select.poll(); poller.register(PARENT,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
        if poller.poll(0): die(104)
        flags=fcntl.fcntl(GUARD,fcntl.F_GETFL)
        if not flags&os.O_NONBLOCK: die(105)
        try:
            extra=os.read(GUARD,2)
            if extra: die(106)
            die(107)
        except BlockingIOError:
            pass
        native_state()
        if rearm:
            remaining=deadline-time.monotonic()
            if remaining<=0: die(108)
            signal.setitimer(signal.ITIMER_REAL,min(3.0,remaining),0.0)
            native_state()
    except SystemExit:
        raise
    except Exception:
        die(109)

def cap_terminal_state():
    """Keep checking authority without competing with the default native alarm."""
    if signal.getsignal(signal.SIGALRM)!=signal.SIG_DFL: die(156)
    if signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK,set()): die(157)
    values={}
    try:
        with open('/proc/self/status','rb') as f:
            raw=f.read(4097)
        if len(raw)>4096: die(158)
        for line in raw.decode('ascii','strict').splitlines():
            if line.startswith(('SigBlk:','SigIgn:','SigCgt:','SigPnd:','ShdPnd:')):
                key,value=line.split(':',1); values[key]=int(value.strip(),16)
    except SystemExit:
        raise
    except Exception:
        die(159)
    bit=1 << (signal.SIGALRM-1)
    if set(values)!={'SigBlk','SigIgn','SigCgt','SigPnd','ShdPnd'} or any(values[key]&bit for key in values): die(160)
    timer=signal.getitimer(signal.ITIMER_REAL)
    if timer[1]!=0.0: die(161)
    left=deadline-time.monotonic()
    if left>0 and timer[0]<=0.0: die(162)

def cap_terminal_wait():
    """The immutable one-shot ITIMER_REAL is the only successful terminal."""
    cap_terminal_state()
    try:
        signal.pidfd_send_signal(PARENT,0,None,0)
        parent=select.poll(); parent.register(PARENT,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
        guard=fcntl.fcntl(GUARD,fcntl.F_GETFL)
        if not guard&os.O_NONBLOCK: die(163)
        poller=select.poll()
        poller.register(PARENT,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
        poller.register(GUARD,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
        poller.register(COMMAND,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
        events=poller.poll(25)
        if parent.poll(0): die(164)
        for fd,mask in events:
            if mask & (select.POLLERR|select.POLLNVAL): die(165)
            if fd==PARENT: die(166)
            if fd==GUARD:
                extra=os.read(GUARD,2)
                if extra: die(167)
                die(168)
            if fd==COMMAND:
                extra=os.read(COMMAND,2)
                if extra: die(169)
                die(170)
        cap_terminal_state()
    except SystemExit:
        raise
    except Exception:
        die(171)

def send_reply(frame):
    emit(frame)

def phase_remaining():
    limit=deadline if phase_deadline is None else min(deadline,phase_deadline)
    remaining=limit-time.monotonic()
    if remaining<=0: die(134)
    return remaining

def method_timeout():
    return min(2.0,phase_remaining())

def wait_cap_guard_token():
    try:
        signal.pidfd_send_signal(PARENT,0,None,0)
        poller=select.poll()
        poller.register(PARENT,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
        poller.register(GUARD,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
        while True:
            events=poller.poll(25)
            if any(fd==PARENT for fd,_ in events): die(173)
            for fd,mask in events:
                if fd==GUARD:
                    if mask&(select.POLLHUP|select.POLLERR|select.POLLNVAL): die(174)
                    if mask&select.POLLIN: return
                    die(175)
    except SystemExit:
        raise
    except ProcessLookupError:
        die(176)
    except Exception:
        die(177)

def control_ready(target,block=True):
    global control_done
    if control_case is None or control_done or control_target!=target: return
    emit('CONTROL_READY\t'+control_case+'\t'+target)
    control_done=True
    if block:
        part=os.read(BLOCK,1)
        if part: die(128)
        if control_case=='parentdeath_after_rearm':
            try:
                extra=os.read(GUARD,2)
                if extra: die(153)
                die(154)
            except BlockingIOError:
                report('GUARD_DUP_NON_EOF')
        try: signal.pidfd_send_signal(PARENT,0,None,0)
        except ProcessLookupError:
            if control_case=='parentdeath_after_rearm':
                report('GUARD_DUP_PARENT_PIDFD_CONFIRMED')
            os._exit(0)
        die(129)

def main():
    global used,buffer,bus,sender,owner,unit,phase,phase_deadline,control_case,control_target,deadline,health_cycles
    signal.signal(signal.SIGALRM,signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGALRM})
    signal.setitimer(signal.ITIMER_REAL,3.0,0.0)
    os.set_blocking(GUARD,False)
    os.set_blocking(COMMAND,False)
    try:
        has_control=True
        try:
            fcntl.fcntl(CONTROL,fcntl.F_GETFD)
        except OSError as e:
            if e.errno!=9: raise
            has_control=False
        if has_control:
            raw_control=os.read(CONTROL,80)
            if not raw_control.endswith(b'\n') or raw_control.count(b'\n')!=1: die(130)
            used+=len(raw_control)
            if used>MAX: die(133)
            control_case=raw_control[:-1].decode('ascii','strict')
            if control_case in control_cases:
                control_target,_=control_cases[control_case]
            elif control_case in negative_controls:
                control_target=negative_controls[control_case]
            else: die(131)
            validate_guard_duplicate(control_case=='parentdeath_after_rearm')
            if control_case=='watchdog_absolute_cap': deadline=time.monotonic()+10.0
            if control_case=='negative_watchdog_omitted':
                signal.setitimer(signal.ITIMER_REAL,0.0,0.0)
                emit('NEGATIVE_READY\tnegative_watchdog_omitted')
                time.sleep(30.0)
                die(155)
            if control_target=='pre_ready' and control_case!='startup_parentdeath':
                guard_check(True)
                control_ready('pre_ready',control_case!='watchdog_absolute_cap')
            if control_case=='watchdog_absolute_cap':
                wait_cap_guard_token()
            if control_case=='startup_parentdeath':
                guard_check(True)
                poller=select.poll(); poller.register(GUARD,select.POLLIN|select.POLLHUP|select.POLLERR)
                events=poller.poll(5000)
                if not events or not any(mask&select.POLLHUP for _,mask in events) or any(mask&select.POLLERR for _,mask in events): die(126)
                try: signal.pidfd_send_signal(PARENT,0,None,0)
                except ProcessLookupError: os._exit(0)
                die(127)
        else:
            try:
                fcntl.fcntl(BLOCK,fcntl.F_GETFD)
                die(132)
            except OSError as block_error:
                if block_error.errno!=9: raise
            validate_guard_duplicate(False)
        token=os.read(GUARD,1)
        if token!=b'P': die(110)
        used+=1
        guard_check(True)
        emit('GUARD_READY')
        phase='await_acquire'
        while True:
            if phase=='cap_terminal':
                cap_terminal_wait()
                continue
            guard_check(True)
            control_ready('after_rearm')
            if phase=='import':
                control_ready('import')
                import dbus
                phase='bus'; continue
            if phase=='bus':
                control_ready('constructor')
                bus=dbus.SystemBus(private=True)
                sender=bus.get_unique_name()
                if not sender or len(sender)>64: die(117)
                phase='owner_before_ref'; continue
            if phase=='owner_before_ref':
                owner=bus.call_blocking('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetNameOwner','s',('org.freedesktop.systemd1',),timeout=method_timeout())
                if not owner or len(owner)>64: die(118)
                phase='ref'; continue
            if phase=='ref':
                if control_case=='negative_ref_error':
                    emit('NEGATIVE_RESULT\tnegative_ref_error\tinjected_before_ref')
                    die(148)
                control_ready('method')
                bus.call_blocking('org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','RefUnit','s',(unit,),timeout=method_timeout())
                phase='owner_after_ref'; continue
            if phase=='owner_after_ref':
                current=bus.call_blocking('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetNameOwner','s',('org.freedesktop.systemd1',),timeout=method_timeout())
                if current!=owner: die(119)
                emit('REF_READY\t'+sender+'\t'+owner); phase='held'; phase_deadline=None
                control_ready('held_idle')
                continue
            if phase=='health_owner':
                current=bus.call_blocking('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetNameOwner','s',('org.freedesktop.systemd1',),timeout=method_timeout())
                if current!=owner or bus.get_unique_name()!=sender: die(120)
                emit('HEALTH_READY')
                if control_case=='watchdog_absolute_cap':
                    health_cycles+=1
                    if health_cycles>3: die(172)
                    if health_cycles==3:
                        remaining=deadline-time.monotonic()
                        if remaining<=0: die(173)
                        native_state()
                        signal.setitimer(signal.ITIMER_REAL,remaining,0.0)
                        timer=signal.getitimer(signal.ITIMER_REAL)
                        if timer[1]!=0.0 or timer[0]<=0.0: die(174)
                        phase='cap_terminal'; phase_deadline=None
                    else:
                        phase='held'; phase_deadline=None
                else:
                    phase='held'; phase_deadline=None
                continue
            if phase=='unref':
                control_ready('close')
                bus.call_blocking('org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','UnrefUnit','s',(unit,),timeout=method_timeout())
                bus.close(); bus=None
                emit('RELEASED'); return 0
            poller=select.poll(); poller.register(GUARD,select.POLLIN|select.POLLHUP|select.POLLERR); poller.register(COMMAND,select.POLLIN|select.POLLHUP|select.POLLERR)
            ready=poller.poll(min(250,max(1,int(phase_remaining()*1000))) )
            if any(fd==GUARD for fd,_ in ready): die(111)
            if not any(fd==COMMAND for fd,_ in ready): continue
            part=os.read(COMMAND,256)
            if not part: die(112)
            used+=len(part)
            if used>MAX: die(113)
            buffer+=part
            if len(buffer)>192: die(114)
            if b'\n' not in buffer: continue
            if buffer.count(b'\n')!=1: die(115)
            request=buffer[:-1].decode('ascii','strict').split('\t'); buffer=b''
            if phase=='await_acquire' and len(request)==9 and request[0]=='ACQUIRE':
                phase_deadline=min(deadline,time.monotonic()+5.0)
                exact_root(request[1:])
                if request[8]!=unit: die(116)
                phase='import'
                continue
            if phase=='held' and request==['HEALTH']:
                phase_deadline=min(deadline,time.monotonic()+3.0)
                phase='health_owner'
                continue
            if phase=='held' and request==['RELEASE']:
                phase_deadline=min(deadline,time.monotonic()+5.0)
                st=os.lstat(root)
                dev,ino,uid,gid,nodegid,parentpid=identity
                held=os.fstat(ROOTFD)
                if (st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(dev,ino,uid,gid,0o711) or (held.st_dev,held.st_ino,held.st_uid,held.st_gid)!=(dev,ino,uid,gid) or os.path.basename(root)+'.service'!=unit: die(121)
                phase='unref'; continue
            die(122)
    except BaseException:
        die(123)
    return 0

def descriptor_control_main(name):
    cases={
        'false_absent_no_writer':(False,True),
        'false_unrelated_no_writer':(False,False),
        'true_exact_fd10_writer':(True,False),
        'false_fd10_writer':(False,False),
        'false_unrelated_higher_writer':(False,False),
        'false_absent_higher_writer':(False,True),
        'true_missing_fd10':(True,True),
        'true_unrelated_fd10':(True,False),
        'true_exact_plus_extra_writer':(True,False),
    }
    if name not in cases: die(179)
    expected,close_duplicate=cases[name]
    if close_duplicate:
        try:
            os.close(DUP_GUARD)
        except OSError:
            die(180)
    validate_guard_duplicate(expected)
    token=('__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__\t'+name+'\t0\n').encode('ascii','strict')
    if os.write(1,token)!=len(token): die(181)
    os._exit(0)

if len(sys.argv)==2 and sys.argv[1].startswith('--descriptor-control='):
    descriptor_control_main(sys.argv[1].split('=',1)[1])
raise SystemExit(main())`

type planBrokerCPUUnitHolder struct {
	cmd        *exec.Cmd
	command    *os.File
	guard      *os.File
	status     *os.File
	parent     *os.File
	root       *os.File
	rootFD     int
	controlBlock *os.File
	childPIDFD int
	pid        int
	startTicks uint64
	image      planBrokerCPUProcessIdentity
	unit       string
	maxHealth  int
	healthSites int
	bytes      int
	messages   int
	maxFrame   int
	readBuffer []byte
	waitDone   chan struct{}
	waitErr    error
	closed     bool
	closeErr   error
	abortDone  bool
	abortErr   error
	releaseDone bool
	releaseErr error
}

type planBrokerCPUHolderControl string

const (
	planBrokerCPUHolderOmittedDefinitionPredicate = "__PLAN_RELAUNCH_HOLDER_RETENTION_MISSING_DEFINITION__"
	planBrokerCPUHolderEarlyReleasePredicate      = "__PLAN_RELAUNCH_HOLDER_EARLY_RELEASE_MISSING_DEFINITION__"
	planBrokerCPUHolderEOFAlivePredicate = "__PLAN_RELAUNCH_HOLDER_EOF_PARENT_ALIVE_CONFIRMED__"
	planBrokerCPUHolderRefErrorNotConsumedPredicate = "__PLAN_RELAUNCH_REF_ERROR_NOT_CONSUMED__"
	planBrokerCPUHolderWatchdogOracleBypassedPredicate = "__PLAN_RELAUNCH_WATCHDOG_OMISSION_ORACLE_BYPASSED__"
)

const (
	planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = ""
	planBrokerCPUControlWatchdogNative       planBrokerCPUHolderControl = "watchdog_native_expiry"
	planBrokerCPUControlWatchdogCap          planBrokerCPUHolderControl = "watchdog_absolute_cap"
	planBrokerCPUControlStartupDeath         planBrokerCPUHolderControl = "startup_parentdeath"
	planBrokerCPUControlPreReadyDeath        planBrokerCPUHolderControl = "parentdeath_pre_ready_after_arm"
	planBrokerCPUControlImportDeath          planBrokerCPUHolderControl = "parentdeath_import_boundary"
	planBrokerCPUControlConstructorDeath     planBrokerCPUHolderControl = "parentdeath_constructor_boundary"
	planBrokerCPUControlMethodDeath          planBrokerCPUHolderControl = "parentdeath_method_boundary"
	planBrokerCPUControlHeldIdleDeath        planBrokerCPUHolderControl = "parentdeath_held_idle"
	planBrokerCPUControlCloseDeath           planBrokerCPUHolderControl = "parentdeath_close_boundary"
	planBrokerCPUControlAfterRearmDeath      planBrokerCPUHolderControl = "parentdeath_after_rearm"
	planBrokerCPUControlNegativeRefError     planBrokerCPUHolderControl = "negative_ref_error"
	planBrokerCPUControlNegativeWatchdogOmit planBrokerCPUHolderControl = "negative_watchdog_omitted"
)

func planBrokerCPUHolderControlTarget(control planBrokerCPUHolderControl) string {
	switch control {
	case planBrokerCPUControlWatchdogNative, planBrokerCPUControlWatchdogCap, planBrokerCPUControlPreReadyDeath:
		return "pre_ready"
	case planBrokerCPUControlStartupDeath:
		return "startup"
	case planBrokerCPUControlImportDeath:
		return "import"
	case planBrokerCPUControlConstructorDeath:
		return "constructor"
	case planBrokerCPUControlMethodDeath:
		return "method"
	case planBrokerCPUControlHeldIdleDeath:
		return "held_idle"
	case planBrokerCPUControlCloseDeath:
		return "close"
	case planBrokerCPUControlAfterRearmDeath:
		return "after_rearm"
	case planBrokerCPUControlNegativeRefError:
		return "ref_error"
	case planBrokerCPUControlNegativeWatchdogOmit:
		return "watchdog_omitted"
	default:
		return ""
	}
}

type planBrokerCPUProcessIdentity struct {
	PID              int    `json:"pid"`
	StartTicks       uint64 `json:"start_ticks"`
	ExecutablePath   string `json:"executable_path"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ExecutableDevice uint64 `json:"executable_device"`
	ExecutableInode  uint64 `json:"executable_inode"`
}

type planBrokerCPUParentDeathReport struct {
	RootDevice   uint64                         `json:"root_device"`
	RootInode    uint64                         `json:"root_inode"`
	SocketDevice uint64                         `json:"socket_device"`
	SocketInode  uint64                         `json:"socket_inode"`
	Broker       planBrokerCPUProcessIdentity   `json:"broker"`
	Unrelated    planBrokerCPUProcessIdentity   `json:"unrelated"`
}

type planBrokerCPULaunchIdentity struct {
	Plan                 CheckpointLaunchPlan
	PlanSHA256           string
	CurrentIncarnation   string
	CustodyBindingSHA256 string
	Alias                string
	UnitName, Invocation string
	PID                  int
	StartTicks           uint64
	ControlGroup         string
	ExecutablePath       string
	ExecutableSHA256     string
	ExecutableDevice     uint64
	ExecutableInode      uint64
	ModelPath            string
	ModelSHA256          string
	ModelDevice          uint64
	ModelInode           uint64
}

func capturePlanBrokerCPULaunch(paths checkpointPlanBrokerPaths, plan CheckpointLaunchPlan, unit checkpointFixedUnitState, priorInvocation string) (planBrokerCPULaunchIdentity, error) {
	var identity planBrokerCPULaunchIdentity
	unitName := paths.fixtureUnit
	if !planBrokerCPUFixtureUnitBound(paths, unitName) || unit.MainPID <= 1 || unit.Active != "active" || unit.Invocation == "" || unit.Invocation == strings.ToLower(priorInvocation) || unit.ControlGroup == "" {
		return identity, errors.New("worker launch is not a fresh active exact fixture unit")
	}
	binding, err := observePlanBrokerCPUWorker(context.Background(), plan, sha256Hex(mustJSON(plan)), priorInvocation)
	if err != nil || binding.Association.Identity.PID != unit.MainPID || binding.Association.Invocation != unit.Invocation || binding.Association.ControlGroup != unit.ControlGroup || binding.PlanSHA256 != sha256Hex(mustJSON(plan)) {
		return identity, errors.New("observer did not join the exact active fixture worker and plan")
	}
	if !checkpointSHA256RE.MatchString(binding.CurrentIncarnation) || !checkpointSHA256RE.MatchString(binding.CustodyBindingSHA256) || binding.Alias != plan.Alias {
		return identity, errors.New("managed current-incarnation or custody binding was not observed")
	}
	startTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(unit.MainPID)), unit.MainPID)
	if err != nil || startTicks == 0 {
		return identity, errors.New("worker process incarnation is unavailable")
	}
	cgroupRaw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(unit.MainPID), "cgroup"))
	if err != nil || len(cgroupRaw) == 0 || len(cgroupRaw) > 16<<10 {
		return identity, errors.New("worker cgroup identity is unavailable")
	}
	procCgroup := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(cgroupRaw), "\n"), "\n") {
		if strings.HasPrefix(line, "0::") {
			if procCgroup != "" {
				return identity, errors.New("worker has duplicate unified cgroup identities")
			}
			procCgroup = strings.TrimPrefix(line, "0::")
		}
	}
	if procCgroup != unit.ControlGroup {
		return identity, errors.New("worker proc cgroup differs from its pinned systemd unit")
	}
	executablePath, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(unit.MainPID), "exe"))
	if err != nil || filepath.Clean(executablePath) != plan.Executable.Path || filepath.Clean(plan.Executable.Path) != filepath.Join(paths.fixtureRoot, "worker") {
		return identity, errors.New("worker executable path differs from the private fixture image")
	}
	executableInfo, err := os.Stat(filepath.Join("/proc", strconv.Itoa(unit.MainPID), "exe"))
	imageInfo, imageErr := os.Stat(plan.Executable.Path)
	executableSHA, executableBytes, digestErr := fileDigest(plan.Executable.Path)
	if err != nil || imageErr != nil || !os.SameFile(executableInfo, imageInfo) || executableBytes <= 0 || executableSHA != plan.Executable.SHA256 || digestErr != nil {
		return identity, errors.New("worker executable inode or digest differs from the approved fixture image")
	}
	modelInfo, err := os.Stat(plan.Model.Path)
	modelSHA, modelBytes, modelErr := fileDigest(plan.Model.Path)
	if err != nil || modelErr != nil || modelBytes != plan.Model.Bytes || modelSHA != plan.Model.SHA256 {
		return identity, errors.New("approved worker model source inode or digest is unavailable")
	}
	fdEntries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(unit.MainPID), "fd"))
	if err != nil {
		return identity, errors.New("worker held descriptor table is unavailable")
	}
	modelHeld := false
	for _, entry := range fdEntries {
		fdPath := filepath.Join("/proc", strconv.Itoa(unit.MainPID), "fd", entry.Name())
		target, linkErr := os.Readlink(fdPath)
		if linkErr == nil && target == plan.Model.Path {
			fdInfo, statErr := os.Stat(fdPath)
			if statErr == nil && os.SameFile(fdInfo, modelInfo) {
				modelHeld = true
				break
			}
		}
	}
	if !modelHeld {
		return identity, errors.New("worker does not hold the approved model source inode")
	}
	currentUnit, err := planBrokerCPUFixtureUnitState(context.Background(), paths)
	currentTicks, ticksErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(unit.MainPID)), unit.MainPID)
	if err != nil || ticksErr != nil || currentTicks != startTicks || currentUnit.MainPID != unit.MainPID || currentUnit.Invocation != unit.Invocation || currentUnit.ControlGroup != unit.ControlGroup || currentUnit.Active != "active" {
		return identity, errors.New("worker incarnation or unit identity changed during custody capture")
	}
	identity = planBrokerCPULaunchIdentity{Plan: plan, PlanSHA256: binding.PlanSHA256, CurrentIncarnation: binding.CurrentIncarnation, CustodyBindingSHA256: binding.CustodyBindingSHA256, Alias: binding.Alias, UnitName: unitName, Invocation: unit.Invocation, PID: unit.MainPID, StartTicks: startTicks,
		ControlGroup: unit.ControlGroup, ExecutablePath: executablePath, ExecutableSHA256: executableSHA, ExecutableDevice: infoSysDevice(executableInfo), ExecutableInode: infoSysInode(executableInfo),
		ModelPath: plan.Model.Path, ModelSHA256: modelSHA, ModelDevice: infoSysDevice(modelInfo), ModelInode: infoSysInode(modelInfo)}
	if identity.ExecutableDevice == 0 || identity.ExecutableInode == 0 || identity.ModelDevice == 0 || identity.ModelInode == 0 {
		return planBrokerCPULaunchIdentity{}, errors.New("worker source identity lacks device or inode pins")
	}
	return identity, nil
}

func planBrokerCPULaunchStillCurrent(paths checkpointPlanBrokerPaths, held planBrokerCPULaunchIdentity) error {
	unit, err := planBrokerCPUFixtureUnitState(context.Background(), paths)
	if err != nil || unit.MainPID != held.PID || unit.Invocation != held.Invocation || unit.ControlGroup != held.ControlGroup || unit.Active != "active" || held.UnitName != paths.fixtureUnit {
		return errors.New("held worker unit identity changed before exact stop")
	}
	current, err := capturePlanBrokerCPULaunch(paths, held.Plan, unit, "")
	if err != nil || current.PlanSHA256 != held.PlanSHA256 || current.CurrentIncarnation != held.CurrentIncarnation || current.CustodyBindingSHA256 != held.CustodyBindingSHA256 || current.Alias != held.Alias || current.UnitName != held.UnitName || current.Invocation != held.Invocation || current.PID != held.PID || current.StartTicks != held.StartTicks || current.ControlGroup != held.ControlGroup || current.ExecutablePath != held.ExecutablePath || current.ExecutableSHA256 != held.ExecutableSHA256 || current.ExecutableDevice != held.ExecutableDevice || current.ExecutableInode != held.ExecutableInode || current.ModelPath != held.ModelPath || current.ModelSHA256 != held.ModelSHA256 || current.ModelDevice != held.ModelDevice || current.ModelInode != held.ModelInode {
		return errors.New("held worker process, executable, model descriptor, or plan changed before exact stop")
	}
	return nil
}

// TestCheckpointPlanRelaunchCPULifecycleSequence is deliberately build-tagged
// and opt-in. It creates one root-owned searchable anchor, private descendants,
// one exact transient unit, and a same-binary UID 65534 node child. It is not a
// production GPU/custody proof.
type planBrokerCPUFailureStage string
type planBrokerCPUFailureReason string

const (
	planBrokerCPUStageMatrixAdmission planBrokerCPUFailureStage = "matrix_admission"
	planBrokerCPUStageMatrixCase planBrokerCPUFailureStage = "matrix_case"
	planBrokerCPUStageMatrixReserve planBrokerCPUFailureStage = "matrix_reserve"
	planBrokerCPUStageParentSetup planBrokerCPUFailureStage = "parentdeath_setup"
	planBrokerCPUStageParentReady planBrokerCPUFailureStage = "parentdeath_ready"
	planBrokerCPUStageParentSignal planBrokerCPUFailureStage = "parentdeath_signal"
	planBrokerCPUStageParentTerminal planBrokerCPUFailureStage = "parentdeath_terminal"
	planBrokerCPUStageHolderAcquire planBrokerCPUFailureStage = "holder_acquire"
	planBrokerCPUStageCleanup planBrokerCPUFailureStage = "cleanup"
	planBrokerCPUReasonDeadline planBrokerCPUFailureReason = "deadline"
	planBrokerCPUReasonIdentity planBrokerCPUFailureReason = "identity"
	planBrokerCPUReasonPipe planBrokerCPUFailureReason = "pipe_or_frame"
	planBrokerCPUReasonExit planBrokerCPUFailureReason = "unexpected_exit"
	planBrokerCPUReasonUnit planBrokerCPUFailureReason = "unit_or_worker_state"
	planBrokerCPUReasonClose planBrokerCPUFailureReason = "descriptor_close"
	planBrokerCPUReasonUncertain planBrokerCPUFailureReason = "result_uncertain"
	planBrokerCPUReasonUnavailable planBrokerCPUFailureReason = "unavailable"
	planBrokerCPUReasonReportReady planBrokerCPUFailureReason = "report_ready"
	planBrokerCPUReasonReportMetrics planBrokerCPUFailureReason = "report_metrics"
	planBrokerCPUReasonReportResult planBrokerCPUFailureReason = "report_result"
	planBrokerCPUReasonReportPass planBrokerCPUFailureReason = "report_pass"
	planBrokerCPUReasonReportEOF planBrokerCPUFailureReason = "report_eof"
	planBrokerCPUReasonChildCaseOrRoot planBrokerCPUFailureReason = "child_case_or_root"
	planBrokerCPUReasonChildBudget planBrokerCPUFailureReason = "child_budget"
	planBrokerCPUReasonChildUnit planBrokerCPUFailureReason = "child_unit"
	planBrokerCPUReasonChildPlan planBrokerCPUFailureReason = "child_plan"
	planBrokerCPUReasonChildLaunch planBrokerCPUFailureReason = "child_launch"
	planBrokerCPUReasonChildWorkerPIDFD planBrokerCPUFailureReason = "child_worker_pidfd"
	planBrokerCPUReasonChildHolderHandshake planBrokerCPUFailureReason = "child_holder_handshake"
	planBrokerCPUReasonChildCapHealthIdentity planBrokerCPUFailureReason = "child_cap_health_identity"
	planBrokerCPUReasonChildCapHealthSend planBrokerCPUFailureReason = "child_cap_health_send"
	planBrokerCPUReasonChildCapHealthReply planBrokerCPUFailureReason = "child_cap_health_reply"
	planBrokerCPUReasonChildPhaseFrame planBrokerCPUFailureReason = "child_phase_frame"
	planBrokerCPUReasonChildTranscript planBrokerCPUFailureReason = "child_transcript"
	planBrokerCPUReasonChildHelperEarlyExit planBrokerCPUFailureReason = "child_helper_early_exit"
	planBrokerCPUReasonChildHolderPreSpawnBinding planBrokerCPUFailureReason = "child_holder_pre_spawn_binding"
	planBrokerCPUReasonChildHolderPreSpawnDeadline planBrokerCPUFailureReason = "child_holder_pre_spawn_deadline"
	planBrokerCPUReasonChildHolderRootMetadata planBrokerCPUFailureReason = "child_holder_root_metadata"
	planBrokerCPUReasonChildHolderLaunchCurrent planBrokerCPUFailureReason = "child_holder_launch_current"
	planBrokerCPUReasonChildHolderUnitCurrent planBrokerCPUFailureReason = "child_holder_unit_current"
	planBrokerCPUReasonChildHolderPipeSetup planBrokerCPUFailureReason = "child_holder_pipe_setup"
	planBrokerCPUReasonChildHolderTokenSetup planBrokerCPUFailureReason = "child_holder_token_setup"
	planBrokerCPUReasonChildHolderParentPIDFD planBrokerCPUFailureReason = "child_holder_parent_pidfd"
	planBrokerCPUReasonChildHolderRootHandle planBrokerCPUFailureReason = "child_holder_root_handle"
	planBrokerCPUReasonChildHolderSpawn planBrokerCPUFailureReason = "child_holder_spawn"
	planBrokerCPUReasonChildHolderChildIdentity planBrokerCPUFailureReason = "child_holder_child_identity"
	planBrokerCPUReasonChildHolderChildCgroup planBrokerCPUFailureReason = "child_holder_child_cgroup"
	planBrokerCPUReasonChildHolderHelperRead planBrokerCPUFailureReason = "child_holder_helper_read"
	planBrokerCPUReasonChildHolderHelperShape planBrokerCPUFailureReason = "child_holder_helper_shape"
	planBrokerCPUReasonChildHolderCapGuardSend planBrokerCPUFailureReason = "child_holder_cap_guard_send"
	planBrokerCPUReasonChildHolderCapGuardRead planBrokerCPUFailureReason = "child_holder_cap_guard_read"
	planBrokerCPUReasonChildHolderCapGuardShape planBrokerCPUFailureReason = "child_holder_cap_guard_shape"
	planBrokerCPUReasonChildHolderCapRootMetadata planBrokerCPUFailureReason = "child_holder_cap_root_metadata"
	planBrokerCPUReasonChildHolderCapAcquireSend planBrokerCPUFailureReason = "child_holder_cap_acquire_send"
	planBrokerCPUReasonChildHolderCapRefRead planBrokerCPUFailureReason = "child_holder_cap_ref_read"
	planBrokerCPUReasonChildHolderCapRefShape planBrokerCPUFailureReason = "child_holder_cap_ref_shape"
)

type planBrokerCPUHolderBranch struct { class planBrokerCPUFailureReason; cause error }
func (branch *planBrokerCPUHolderBranch) Error() string { return branch.cause.Error() }
func (branch *planBrokerCPUHolderBranch) Unwrap() error { return branch.cause }
func planBrokerCPUHolderBranchAt(class planBrokerCPUFailureReason, cause error) error {
	if cause == nil { return nil }
	return &planBrokerCPUHolderBranch{class: class, cause: cause}
}

func planBrokerCPUHolderBranchClass(err error) planBrokerCPUFailureReason {
	var branch *planBrokerCPUHolderBranch
	if errors.As(err, &branch) { return branch.class }
	return ""
}

type planBrokerCPUFailure struct {
	stage planBrokerCPUFailureStage
	reason planBrokerCPUFailureReason
	caseName string
	helperReadDiagnostic *planBrokerCPUHolderReadDiagnostic
	err error
}

type planBrokerCPUHolderReadDiagnostic struct {
	readReason string
	waitPhase string
	waitStatus string
}

type planBrokerCPUHolderReadDiagnosticFailure struct {
	diagnostic planBrokerCPUHolderReadDiagnostic
	cause error
}

func (failure *planBrokerCPUHolderReadDiagnosticFailure) Error() string { return failure.cause.Error() }
func (failure *planBrokerCPUHolderReadDiagnosticFailure) Unwrap() error { return failure.cause }

func planBrokerCPUHolderReadDiagnosticReason(err error) string {
	switch planBrokerCPUFailureReasonOf(err) {
	case planBrokerCPUReasonDeadline, planBrokerCPUReasonPipe, planBrokerCPUReasonExit, planBrokerCPUReasonUnit, planBrokerCPUReasonClose:
		return string(planBrokerCPUFailureReasonOf(err))
	default:
		return string(planBrokerCPUReasonUnavailable)
	}
}

func planBrokerCPUHolderReadDiagnosticForState(readReason string, settledBeforeAbort, settledAfterAbort bool, statusKind string, statusCode int) (planBrokerCPUHolderReadDiagnostic, bool) {
	diagnostic := planBrokerCPUHolderReadDiagnostic{readReason: readReason, waitPhase: "unavailable", waitStatus: "unavailable"}
	validReadReason := readReason == string(planBrokerCPUReasonDeadline) || readReason == string(planBrokerCPUReasonPipe) || readReason == string(planBrokerCPUReasonExit) || readReason == string(planBrokerCPUReasonUnit) || readReason == string(planBrokerCPUReasonClose) || readReason == string(planBrokerCPUReasonUnavailable)
	if !validReadReason || settledBeforeAbort && !settledAfterAbort { return planBrokerCPUHolderReadDiagnostic{}, false }
	if !settledAfterAbort { return diagnostic, true }
	switch statusKind {
	case "exit":
		if statusCode < 0 || statusCode > 255 { return planBrokerCPUHolderReadDiagnostic{}, false }
	case "signal":
		if statusCode < 1 || statusCode > 64 { return planBrokerCPUHolderReadDiagnostic{}, false }
	default:
		return diagnostic, true
	}
	diagnostic.waitStatus = statusKind + "_" + strconv.Itoa(statusCode)
	if settledBeforeAbort { diagnostic.waitPhase = "pre_settled" } else { diagnostic.waitPhase = "post_settled" }
	return diagnostic, true
}

func planBrokerCPUHolderReadDiagnosticValid(diagnostic planBrokerCPUHolderReadDiagnostic) bool {
	parsed, ok := planBrokerCPUHolderReadDiagnosticForState(diagnostic.readReason, diagnostic.waitPhase == "pre_settled", diagnostic.waitPhase == "pre_settled" || diagnostic.waitPhase == "post_settled", strings.SplitN(diagnostic.waitStatus, "_", 2)[0], func() int {
		parts := strings.SplitN(diagnostic.waitStatus, "_", 2)
		if len(parts) != 2 { return -1 }
		code, err := strconv.Atoi(parts[1]); if err != nil || strconv.Itoa(code) != parts[1] { return -1 }
		return code
	}())
	if diagnostic.waitPhase == "unavailable" && diagnostic.waitStatus == "unavailable" {
		parsed, ok = planBrokerCPUHolderReadDiagnosticForState(diagnostic.readReason, false, false, "", 0)
	}
	return ok && parsed == diagnostic
}

func planBrokerCPUHolderReadDiagnosticBeforeAbort(holder *planBrokerCPUUnitHolder) bool {
	if holder == nil || holder.waitDone == nil { return false }
	select { case <-holder.waitDone: return true; default: return false }
}

func planBrokerCPUHolderReadDiagnosticAfterAbort(holder *planBrokerCPUUnitHolder, readReason string, settledBeforeAbort bool) planBrokerCPUHolderReadDiagnostic {
	if holder == nil || holder.waitDone == nil { diagnostic, _ := planBrokerCPUHolderReadDiagnosticForState(readReason, settledBeforeAbort, false, "", 0); return diagnostic }
	select {
	case <-holder.waitDone:
		if holder.cmd == nil || holder.cmd.ProcessState == nil { diagnostic, _ := planBrokerCPUHolderReadDiagnosticForState(readReason, settledBeforeAbort, true, "", 0); return diagnostic }
		status, ok := holder.cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !ok { diagnostic, _ := planBrokerCPUHolderReadDiagnosticForState(readReason, settledBeforeAbort, true, "", 0); return diagnostic }
		if status.Exited() { diagnostic, _ := planBrokerCPUHolderReadDiagnosticForState(readReason, settledBeforeAbort, true, "exit", status.ExitStatus()); return diagnostic }
		if status.Signaled() { diagnostic, _ := planBrokerCPUHolderReadDiagnosticForState(readReason, settledBeforeAbort, true, "signal", int(status.Signal())); return diagnostic }
		diagnostic, _ := planBrokerCPUHolderReadDiagnosticForState(readReason, settledBeforeAbort, true, "", 0)
		return diagnostic
	default:
		diagnostic, _ := planBrokerCPUHolderReadDiagnosticForState(readReason, settledBeforeAbort, false, "", 0)
		return diagnostic
	}
}

func planBrokerCPUJoinPrimaryAbortForHelperRead(reason planBrokerCPUFailureReason, readErr, primary error, holder *planBrokerCPUUnitHolder) error {
	readReason := planBrokerCPUHolderReadDiagnosticReason(readErr)
	settledBeforeAbort := planBrokerCPUHolderReadDiagnosticBeforeAbort(holder)
	joined := planBrokerCPUJoinPrimaryAbort(reason, primary, holder)
	diagnostic := planBrokerCPUHolderReadDiagnosticAfterAbort(holder, readReason, settledBeforeAbort)
	return &planBrokerCPUHolderReadDiagnosticFailure{diagnostic: diagnostic, cause: joined}
}

func planBrokerCPUParseHolderReadWaitStatus(value string) (string, int, bool) {
	if value == "unavailable" { return "", 0, true }
	for _, kind := range []string{"exit", "signal"} {
		prefix := kind + "_"
		if !strings.HasPrefix(value, prefix) { continue }
		number := strings.TrimPrefix(value, prefix)
		code, err := strconv.Atoi(number)
		if err != nil || strconv.Itoa(code) != number { return "", 0, false }
		if kind == "exit" && (code < 0 || code > 255) || kind == "signal" && (code < 1 || code > 64) { return "", 0, false }
		return kind, code, true
	}
	return "", 0, false
}

type planBrokerCPUFailureEmission struct {
	primaryEmitted bool
	cleanupEmitted bool
}

type planBrokerCPUSurvivorPredicateFailure struct { err error }
type planBrokerCPUFixedMessageFailure struct { message string; cause error }

func (failure *planBrokerCPUFixedMessageFailure) Error() string { return failure.message }
func (failure *planBrokerCPUFixedMessageFailure) Unwrap() error { return failure.cause }

func (failure *planBrokerCPUSurvivorPredicateFailure) Error() string {
	return "__PLAN_RELAUNCH_PARENT_DEATH_SURVIVOR_ASSERTED__ __PLAN_RELAUNCH_PARENT_DEATH_PIDFD_CLEANUP_PROVED__ direct child survived exact parent death and required pidfd-only cleanup"
}
func (failure *planBrokerCPUSurvivorPredicateFailure) Unwrap() error { return failure.err }

func (failure *planBrokerCPUFailure) Error() string { return failure.err.Error() }
func (failure *planBrokerCPUFailure) Unwrap() error { return failure.err }

func planBrokerCPUFailureOrigin(reason planBrokerCPUFailureReason, err error) error {
	if err == nil { return nil }
	var existing *planBrokerCPUFailure
	if errors.As(err, &existing) { return err }
	return &planBrokerCPUFailure{reason: reason, err: err}
}

func planBrokerCPUFailureAt(stage planBrokerCPUFailureStage, reason planBrokerCPUFailureReason, caseName string, err error) error {
	if err == nil { return nil }
	var existing *planBrokerCPUFailure
	if errors.As(err, &existing) {
		if existing.reason != "" { reason = existing.reason }
		if stage == planBrokerCPUStageMatrixCase && caseName == "" { caseName = existing.caseName }
	}
	return &planBrokerCPUFailure{stage: stage, reason: reason, caseName: caseName, err: err}
}

func planBrokerCPUHolderControlMatrixFailure(caseName string, err error) error {
	wrapped := planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonUncertain, string(caseName), fmt.Errorf("fixed holder control %s failed: %w", caseName, err))
	if wrapped == nil { return nil }
	wrappedFailure, ok := wrapped.(*planBrokerCPUFailure)
	if !ok { return wrapped }
	inner := planBrokerCPUFirstFailure(err, false)
	outer := planBrokerCPUFirstFailure(wrapped, false)
	if inner == nil || outer != wrappedFailure || inner.helperReadDiagnostic == nil ||
		inner.stage != planBrokerCPUStageMatrixCase || inner.reason != planBrokerCPUReasonChildHolderHelperRead || inner.caseName != string(planBrokerCPUControlWatchdogNative) ||
		wrappedFailure.stage != inner.stage || wrappedFailure.reason != inner.reason || wrappedFailure.caseName != inner.caseName ||
		!planBrokerCPUHolderReadDiagnosticValid(*inner.helperReadDiagnostic) {
		return wrapped
	}
	diagnostic := *inner.helperReadDiagnostic
	planBrokerCPUFailureAttachHolderReadDiagnostic(wrapped, diagnostic)
	return wrapped
}

func planBrokerCPUCleanupFailure(reason planBrokerCPUFailureReason, err error) error {
	if err == nil { return nil }
	return planBrokerCPUFailureAt(planBrokerCPUStageCleanup, reason, "", planBrokerCPUFailureOrigin(reason, err))
}

func planBrokerCPUJoinPrimaryAbort(reason planBrokerCPUFailureReason, primary error, holder *planBrokerCPUUnitHolder) error {
	primaryFailure := planBrokerCPUFailureOrigin(reason, primary)
	if holder == nil { return primaryFailure }
	abortErr := holder.abort()
	if abortErr == nil { return primaryFailure }
	cleanupFailure := planBrokerCPUCleanupFailure(planBrokerCPUFailureReasonOf(abortErr), abortErr)
	return errors.Join(primaryFailure, cleanupFailure)
}

func planBrokerCPUAbortCleanup(holder *planBrokerCPUUnitHolder) error {
	if holder == nil { return nil }
	err := holder.abort()
	if err == nil { return nil }
	return planBrokerCPUCleanupFailure(planBrokerCPUFailureReasonOf(err), err)
}

func planBrokerCPUFailureMarker(owner string, err error) string {
	validOwner := owner == "TestCheckpointPlanRelaunchCPULifecycleSequence" || owner == "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect"
	if !validOwner { return "__PLAN_RELAUNCH_FAILURE_STAGE__:unavailable:unavailable:unavailable" }
	var failure *planBrokerCPUFailure
	if !errors.As(err, &failure) { return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable" }
	validReason := failure.reason == planBrokerCPUReasonDeadline || failure.reason == planBrokerCPUReasonIdentity || failure.reason == planBrokerCPUReasonPipe || failure.reason == planBrokerCPUReasonExit || failure.reason == planBrokerCPUReasonUnit || failure.reason == planBrokerCPUReasonClose || failure.reason == planBrokerCPUReasonUncertain || failure.reason == planBrokerCPUReasonUnavailable || failure.reason == planBrokerCPUReasonReportReady || failure.reason == planBrokerCPUReasonReportMetrics || failure.reason == planBrokerCPUReasonReportResult || failure.reason == planBrokerCPUReasonReportPass || failure.reason == planBrokerCPUReasonReportEOF || planBrokerCPUPreReadyFailureReasonAllowed(failure.reason) || planBrokerCPUHolderBranchReasonAllowed(failure.reason)
	validStage := false
	caseStage := false
	if owner == "TestCheckpointPlanRelaunchCPULifecycleSequence" {
		validStage = failure.stage == planBrokerCPUStageMatrixAdmission || failure.stage == planBrokerCPUStageMatrixCase || failure.stage == planBrokerCPUStageMatrixReserve || failure.stage == planBrokerCPUStageCleanup
		caseStage = failure.stage == planBrokerCPUStageMatrixCase
	} else {
		validStage = failure.stage == planBrokerCPUStageParentSetup || failure.stage == planBrokerCPUStageParentReady || failure.stage == planBrokerCPUStageParentSignal || failure.stage == planBrokerCPUStageParentTerminal || failure.stage == planBrokerCPUStageHolderAcquire || failure.stage == planBrokerCPUStageCleanup
	}
	caseName := failure.caseName
	reportReason := failure.reason == planBrokerCPUReasonReportReady || failure.reason == planBrokerCPUReasonReportMetrics || failure.reason == planBrokerCPUReasonReportResult || failure.reason == planBrokerCPUReasonReportPass || failure.reason == planBrokerCPUReasonReportEOF
	if (planBrokerCPUPreReadyFailureReasonAllowed(failure.reason) || planBrokerCPUHolderBranchReasonAllowed(failure.reason)) && (owner != "TestCheckpointPlanRelaunchCPULifecycleSequence" || !caseStage || (caseName != string(planBrokerCPUControlWatchdogNative) && caseName != string(planBrokerCPUControlWatchdogCap))) {
		return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable"
	}
	if (planBrokerCPUPreReadyFailureReasonCapOnly(failure.reason) || planBrokerCPUHolderBranchCapOnly(failure.reason)) && caseName != string(planBrokerCPUControlWatchdogCap) {
		return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable"
	}
	if reportReason && (owner != "TestCheckpointPlanRelaunchCPULifecycleSequence" || !caseStage || (caseName != string(planBrokerCPUControlWatchdogNative) && caseName != string(planBrokerCPUControlWatchdogCap))) {
		return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable"
	}
	if caseName != "" {
		known := false
		for _, item := range planBrokerCPUHolderControlCases { if string(item.control) == caseName { known = true; break } }
		if !caseStage || !known { return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable" }
	} else if caseStage { return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable" }
	if !validReason || !validStage { return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable" }
	if failure.reason == planBrokerCPUReasonChildHolderHelperRead && caseName == string(planBrokerCPUControlWatchdogNative) && failure.helperReadDiagnostic == nil {
		return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable"
	}
	if failure.helperReadDiagnostic != nil && (failure.reason != planBrokerCPUReasonChildHolderHelperRead || caseName != string(planBrokerCPUControlWatchdogNative)) {
		return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable"
	}
	marker := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":" + string(failure.stage) + ":" + string(failure.reason)
	if caseName != "" { marker += ":" + caseName }
	if failure.helperReadDiagnostic != nil {
		diagnostic := *failure.helperReadDiagnostic
		if owner != "TestCheckpointPlanRelaunchCPULifecycleSequence" || failure.stage != planBrokerCPUStageMatrixCase || failure.reason != planBrokerCPUReasonChildHolderHelperRead || caseName != string(planBrokerCPUControlWatchdogNative) || !planBrokerCPUHolderReadDiagnosticValid(diagnostic) {
			return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable"
		}
		marker += ":diag:" + diagnostic.readReason + ":" + diagnostic.waitPhase + ":" + diagnostic.waitStatus
	}
	if len(marker) > 192 { return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable" }
	return marker
}

func planBrokerCPUFailureOfStage(err error, stage planBrokerCPUFailureStage) *planBrokerCPUFailure {
	if err == nil { return nil }
	if failure, ok := err.(*planBrokerCPUFailure); ok && failure.stage == stage { return failure }
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range many.Unwrap() { if found := planBrokerCPUFailureOfStage(child, stage); found != nil { return found } }
	}
	if one, ok := err.(interface{ Unwrap() error }); ok { return planBrokerCPUFailureOfStage(one.Unwrap(), stage) }
	return nil
}

func planBrokerCPUPrimaryFailureMarker(owner string, err error) (string, bool) {
	failure := planBrokerCPUFirstFailure(err, false)
	if failure == nil { return "", false }
	return planBrokerCPUFailureMarker(owner, failure), true
}

func planBrokerCPUFirstFailure(err error, cleanup bool) *planBrokerCPUFailure {
	if err == nil { return nil }
	if failure, ok := err.(*planBrokerCPUFailure); ok {
		if cleanup == (failure.stage == planBrokerCPUStageCleanup) { return failure }
		return planBrokerCPUFirstFailure(failure.err, cleanup)
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range many.Unwrap() { if found := planBrokerCPUFirstFailure(child, cleanup); found != nil { return found } }
	}
	if one, ok := err.(interface{ Unwrap() error }); ok { return planBrokerCPUFirstFailure(one.Unwrap(), cleanup) }
	return nil
}

func planBrokerCPUFailureReasonOf(err error) planBrokerCPUFailureReason {
	if failure := planBrokerCPUFirstFailure(err, false); failure != nil && failure.reason != "" { return failure.reason }
	return planBrokerCPUReasonUnavailable
}

func planBrokerCPUFailureMarkers(budget *planBrokerCPUFailureEmission, owner string, err error) []string {
	if budget == nil { return []string{planBrokerCPUFailureMarker(owner, errors.New("failure emission budget unavailable"))} }
	markers := make([]string, 0, 2)
	if !budget.primaryEmitted {
		if primary := planBrokerCPUFirstFailure(err, false); primary != nil {
			markers = append(markers, planBrokerCPUFailureMarker(owner, primary))
		} else {
			markers = append(markers, planBrokerCPUFailureMarker(owner, errors.New("primary diagnostic origin unavailable")))
		}
		budget.primaryEmitted = true
	}
	if !budget.cleanupEmitted {
		if cleanup := planBrokerCPUFailureOfStage(err, planBrokerCPUStageCleanup); cleanup != nil {
			markers = append(markers, planBrokerCPUFailureMarker(owner, cleanup))
			budget.cleanupEmitted = true
		}
	}
	if len(markers) > 2 { return []string{planBrokerCPUFailureMarker(owner, errors.New("failure record bound exceeded"))} }
	return markers
}

func verifyPlanBrokerCPUHolderControlMessageCountControls() error {
	capFrames := [...]string{
		"control-token:watchdog_absolute_cap\n",
		"status:CONTROL_READY\twatchdog_absolute_cap\tpre_ready\n",
		"guard-token:P",
		"status:GUARD_READY\n",
		"command:ACQUIRE\n",
		"status:REF_READY\n",
		"command:HEALTH\n",
		"status:HEALTH_READY\n",
		"command:HEALTH\n",
		"status:HEALTH_READY\n",
		"command:HEALTH\n",
		"status:HEALTH_READY\n",
	}
	capExpected := planBrokerCPUHolderControlMessageCount(planBrokerCPUControlWatchdogCap)
	frameCountMatches := func(frames []string) bool { return len(frames) == capExpected }
	if !frameCountMatches(capFrames[:]) {
		return errors.New("absolute-cap message count differs from independent literal frame schedule")
	}
	missingFrame := capFrames[:len(capFrames)-1]
	extraFrame := append(append([]string(nil), capFrames[:]...), "status:unexpected\n")
	if frameCountMatches(missingFrame) {
		return errors.New("absolute-cap message count accepted a missing frame")
	}
	if frameCountMatches(extraFrame) {
		return errors.New("absolute-cap message count accepted an extra frame")
	}
	if planBrokerCPUHolderControlMessageCount(planBrokerCPUControlWatchdogNative) == capExpected {
		return errors.New("absolute-cap message count was incorrectly assigned to native watchdog")
	}
	return nil
}

// verifyPlanBrokerCPUFailureMarkerControls exercises the real production
// wrappers, origin selection, canonical marker formatter, and per-owner
// emission budget without touching the fixture or any external process.
func verifyPlanBrokerCPUFailureMarkerControls() error {
	if err := verifyPlanBrokerCPUHolderControlMessageCountControls(); err != nil {
		return err
	}
	const owner = "TestCheckpointPlanRelaunchCPULifecycleSequence"
	commonSites := []planBrokerCPUPreReadyFailureSite{
		planBrokerCPUFailureSiteCaseOrRoot, planBrokerCPUFailureSiteBudget, planBrokerCPUFailureSiteUnit,
		planBrokerCPUFailureSitePlan, planBrokerCPUFailureSiteLaunch, planBrokerCPUFailureSiteWorkerPIDFD,
		planBrokerCPUFailureSiteHolderHandshake, planBrokerCPUFailureSitePhaseFrame,
		planBrokerCPUFailureSiteTranscript, planBrokerCPUFailureSiteHelperEarlyExit,
	}
	capSites := []planBrokerCPUPreReadyFailureSite{planBrokerCPUFailureSiteCapHealthIdentity, planBrokerCPUFailureSiteCapHealthSend, planBrokerCPUFailureSiteCapHealthReply}
	for _, testCase := range []struct {
		control planBrokerCPUHolderControl
		sites []planBrokerCPUPreReadyFailureSite
	}{
		{control: planBrokerCPUControlWatchdogNative, sites: commonSites},
		{control: planBrokerCPUControlWatchdogCap, sites: append(append([]planBrokerCPUPreReadyFailureSite{}, commonSites...), capSites...)},
	} {
		for _, site := range testCase.sites {
			var captured bytes.Buffer
			writes := 0
			writer := planBrokerCPUPreReadyWriteFunc(func(p []byte) (int, error) { writes++; return captured.Write(p) })
			if !planBrokerCPUWritePreReadyFailureFrame(writer, testCase.control, site) || writes != 1 { return errors.New("private pre-READY frame writer did not make exactly one successful checked write") }
			frame, ok := planBrokerCPUPreReadyFailureFrame(testCase.control, site)
			if !ok || captured.String() != frame || !strings.HasSuffix(frame, "\n") || len(frame) > 192 || strings.Count(frame, "\t") != 2 || strings.Count(frame, "\n") != 1 {
				return errors.New("private pre-READY frame was not the exact bounded three-field wire record")
			}
			reason, parsed := planBrokerCPUParsePreReadyFailureFrame(strings.TrimSuffix(frame, "\n"), testCase.control)
			if !parsed || reason != planBrokerCPUPreReadyFailureReason(site) || !planBrokerCPUPreReadyFailureReasonAllowed(reason) {
				return errors.New("private pre-READY frame parser lost its closed elected site")
			}
			primary := planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, reason, string(testCase.control), errors.New("fixed child pre-READY branch elected"))
			want := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":matrix_case:" + string(site) + ":" + string(testCase.control)
			if marker := planBrokerCPUFailureMarker(owner, primary); marker != want { return errors.New("pre-READY site did not format as its selected watchdog matrix reason") }
		}
	}
	if _, ok := planBrokerCPUPreReadyFailureFrame(planBrokerCPUControlWatchdogNative, planBrokerCPUFailureSiteCapHealthIdentity); ok { return errors.New("native watchdog accepted a cap-only pre-READY site") }
	if _, ok := planBrokerCPUParsePreReadyFailureFrame("CONTROL_FAILURE\twatchdog_native_expiry\tchild_cap_health_identity", planBrokerCPUControlWatchdogNative); ok { return errors.New("native watchdog parser accepted a cap-only site") }
	for _, reason := range []planBrokerCPUFailureReason{planBrokerCPUReasonChildCapHealthIdentity, planBrokerCPUReasonChildCapHealthSend, planBrokerCPUReasonChildCapHealthReply} {
		marker := planBrokerCPUFailureMarker(owner, planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, reason, string(planBrokerCPUControlWatchdogNative), errors.New("synthetic native cap-health reason")))
		if marker != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":unavailable:unavailable" { return errors.New("native watchdog formatter accepted a cap-only health reason") }
	}
	if _, ok := planBrokerCPUPreReadyFailureFrame(planBrokerCPUControlWatchdogCap, planBrokerCPUPreReadyFailureSite("child_native_only_unknown")); ok { return errors.New("cap watchdog accepted an unknown pre-READY site") }
	if _, ok := planBrokerCPUPreReadyFailureFrame(planBrokerCPUControlStartupDeath, planBrokerCPUFailureSiteBudget); ok { return errors.New("non-watchdog case emitted a pre-READY failure frame") }
	for _, invalid := range []string{
		"CONTROL_FAILURE\twatchdog_absolute_cap\tchild_budget\textra",
		"CONTROL_FAILURE\twatchdog_native_expiry\tchild_budget",
		"CONTROL_FAILURE\twatchdog_absolute_cap\tchild_cap_health_send\r",
		"CONTROL_FAILURE\twatchdog_native_expiry\tchild_cap_health_reply",
		"CONTROL_FAILURE\twatchdog_absolute_cap\tchild_budget\nCONTROL_FAILURE\twatchdog_absolute_cap\tchild_plan\n",
		"CONTROL_FAILURE\twatchdog_absolute_cap\tchild_budget\x01",
		"CONTROL_FAILURE\twatchdog_absolute_cap\t" + strings.Repeat("x", 193),
	} {
		if _, ok := planBrokerCPUParsePreReadyFailureFrame(invalid, planBrokerCPUControlWatchdogCap); ok { return errors.New("private pre-READY parser accepted malformed, foreign, duplicate, cap-only, or over-bound input") }
	}
	preDiagnostic, preOK := planBrokerCPUHolderReadDiagnosticForState("deadline", true, true, "exit", 17)
	postDiagnostic, postOK := planBrokerCPUHolderReadDiagnosticForState("pipe_or_frame", false, true, "signal", 9)
	unsettledDiagnostic, unsettledOK := planBrokerCPUHolderReadDiagnosticForState("unexpected_exit", false, false, "signal", 9)
	if !preOK || preDiagnostic != (planBrokerCPUHolderReadDiagnostic{readReason:"deadline", waitPhase:"pre_settled", waitStatus:"exit_17"}) ||
		!postOK || postDiagnostic != (planBrokerCPUHolderReadDiagnostic{readReason:"pipe_or_frame", waitPhase:"post_settled", waitStatus:"signal_9"}) ||
		!unsettledOK || unsettledDiagnostic != (planBrokerCPUHolderReadDiagnostic{readReason:"unexpected_exit", waitPhase:"unavailable", waitStatus:"unavailable"}) {
		return errors.New("native first-read diagnostic did not preserve typed reason and pre/post/unavailable settlement")
	}
	if _, ok := planBrokerCPUHolderReadDiagnosticForState("deadline", true, false, "exit", 17); ok ||
		planBrokerCPUHolderReadDiagnosticValid(planBrokerCPUHolderReadDiagnostic{readReason:"deadline", waitPhase:"post_settled", waitStatus:"unavailable"}) ||
		planBrokerCPUHolderReadDiagnosticValid(planBrokerCPUHolderReadDiagnostic{readReason:"deadline", waitPhase:"unavailable", waitStatus:"signal_9"}) ||
		planBrokerCPUHolderReadDiagnosticValid(planBrokerCPUHolderReadDiagnostic{readReason:"deadline", waitPhase:"pre_settled", waitStatus:"exit_256"}) ||
		planBrokerCPUHolderReadDiagnosticValid(planBrokerCPUHolderReadDiagnostic{readReason:"deadline", waitPhase:"pre_settled", waitStatus:"signal_65"}) {
		return errors.New("native first-read diagnostic accepted impossible settlement or out-of-range wait status")
	}
	frame, frameOK := planBrokerCPUNativeHelperReadFailureFrame(planBrokerCPUControlWatchdogNative, planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead), postDiagnostic)
	parsedDiagnostic, parsedOK := planBrokerCPUParseNativeHelperReadFailureFrame(strings.TrimSuffix(frame, "\n"), planBrokerCPUControlWatchdogNative)
	writes := 0
	var captured bytes.Buffer
	writer := planBrokerCPUPreReadyWriteFunc(func(p []byte) (int, error) { writes++; return captured.Write(p) })
	if !frameOK || !parsedOK || parsedDiagnostic != postDiagnostic || frame != "CONTROL_FAILURE\twatchdog_native_expiry\tchild_holder_helper_read\tpipe_or_frame\tpost_settled\tsignal_9\n" || len(frame) > 192 || strings.Count(frame, "\t") != 5 || strings.Count(frame, "\n") != 1 || !planBrokerCPUWriteNativeHelperReadFailureFrame(writer, planBrokerCPUControlWatchdogNative, planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead), postDiagnostic) || writes != 1 || captured.String() != frame {
		return errors.New("native helper-read diagnostic did not round-trip through one exact bounded failure frame")
	}
	if _, ok := planBrokerCPUNativeHelperReadFailureFrame(planBrokerCPUControlWatchdogCap, planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead), postDiagnostic); ok ||
		planBrokerCPUWritePreReadyFailureFrame(writer, planBrokerCPUControlWatchdogNative, planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead)) {
		return errors.New("native helper-read diagnostic accepted cap substitution or generic field omission")
	}
	for _, invalid := range []string{
		"CONTROL_FAILURE\twatchdog_native_expiry\tchild_holder_helper_read\tpost_settled\tsignal_9",
		"CONTROL_FAILURE\twatchdog_absolute_cap\tchild_holder_helper_read\tpipe_or_frame\tpost_settled\tsignal_9",
		"CONTROL_FAILURE\twatchdog_native_expiry\tchild_holder_cap_guard_read\tpipe_or_frame\tpost_settled\tsignal_9",
		"CONTROL_FAILURE\twatchdog_native_expiry\tchild_holder_helper_read\tpipe_or_frame\tunavailable\tsignal_9",
		"CONTROL_FAILURE\twatchdog_native_expiry\tchild_holder_helper_read\tpipe_or_frame\tpost_settled\tunavailable",
		"CONTROL_FAILURE\twatchdog_native_expiry\tchild_holder_helper_read\tpipe_or_frame\tpre_settled\tsignal_65",
		"CONTROL_FAILURE\twatchdog_native_expiry\tchild_holder_helper_read\tpipe_or_frame\tpost_settled\tsignal_09",
		"CONTROL_FAILURE\twatchdog_native_expiry\tchild_holder_helper_read\tpipe_or_frame\tpost_settled\tsignal_9\nCONTROL_FAILURE\twatchdog_native_expiry\tchild_holder_helper_read\tpipe_or_frame\tpost_settled\tsignal_9",
	} {
		if _, ok := planBrokerCPUParseNativeHelperReadFailureFrame(invalid, planBrokerCPUControlWatchdogNative); ok { return errors.New("native helper-read parser accepted malformed, unavailable-settled, duplicate, foreign, or out-of-range data") }
	}
	if !planBrokerCPUFailureAttachHolderReadDiagnostic(planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), errors.New("synthetic helper-read failure")), postDiagnostic) {
		return errors.New("closed native helper-read diagnostic did not attach to its exact typed matrix failure")
	}
	diagnosticPrimaryCause := errors.New("native helper-read primary cause")
	diagnosticCleanupCause := errors.New("native helper-read cleanup cause")
	checkedDiagnosticFailure := func(label string, err error) (*planBrokerCPUFailure, error) {
		failure, ok := err.(*planBrokerCPUFailure)
		if err == nil || !ok || failure == nil { return nil, fmt.Errorf("%s constructor returned an unexpected failure type", label) }
		return failure, nil
	}
	if !frameOK || !parsedOK || parsedDiagnostic != postDiagnostic { return errors.New("six-field native helper-read frame did not produce the expected validated value") }
	inner, innerErr := checkedDiagnosticFailure("native helper-read primary", planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), &planBrokerCPUHolderReadDiagnosticFailure{diagnostic: parsedDiagnostic, cause: diagnosticPrimaryCause}))
	if innerErr != nil { return innerErr }
	if !planBrokerCPUFailureAttachHolderReadDiagnostic(inner, parsedDiagnostic) { return errors.New("native helper-read inner primary did not accept its parsed validated diagnostic") }
	diagnosticCleanup := planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, diagnosticCleanupCause)
	wrapped := planBrokerCPUHolderControlMatrixFailure(string(planBrokerCPUControlWatchdogNative), errors.Join(inner, diagnosticCleanup))
	outer := planBrokerCPUFirstFailure(wrapped, false)
	markers := planBrokerCPUFailureMarkers(&planBrokerCPUFailureEmission{}, owner, wrapped)
	wantNativeMarker := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":matrix_case:child_holder_helper_read:watchdog_native_expiry:diag:pipe_or_frame:post_settled:signal_9"
	if outer == nil || outer == inner || outer.helperReadDiagnostic == nil || *outer.helperReadDiagnostic != postDiagnostic ||
		outer.helperReadDiagnostic == inner.helperReadDiagnostic || len(markers) != 2 || markers[0] != wantNativeMarker ||
		strings.Contains(markers[1], ":diag:") || strings.Contains(markers[1], "watchdog_native_expiry") ||
		!errors.Is(wrapped, diagnosticPrimaryCause) || !errors.Is(wrapped, diagnosticCleanupCause) {
		return errors.New("actual matrix wrapper did not value-copy the selected native diagnostic while preserving primary-first causes")
	}
	foreignCase, foreignCaseErr := checkedDiagnosticFailure("foreign cap case", planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogCap), errors.New("foreign cap case")))
	if foreignCaseErr != nil { return foreignCaseErr }
	foreignCase.helperReadDiagnostic = &postDiagnostic
	foreignReason, foreignReasonErr := checkedDiagnosticFailure("foreign primary reason", planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonPipe, string(planBrokerCPUControlWatchdogNative), errors.New("foreign primary reason")))
	if foreignReasonErr != nil { return foreignReasonErr }
	foreignReason.helperReadDiagnostic = &postDiagnostic
	foreignStage, foreignStageErr := checkedDiagnosticFailure("foreign primary stage", planBrokerCPUFailureAt(planBrokerCPUStageMatrixReserve, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), errors.New("foreign primary stage")))
	if foreignStageErr != nil { return foreignStageErr }
	foreignStage.helperReadDiagnostic = &postDiagnostic
	invalidDiagnostic, invalidDiagnosticErr := checkedDiagnosticFailure("invalid diagnostic", planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), errors.New("invalid diagnostic")))
	if invalidDiagnosticErr != nil { return invalidDiagnosticErr }
	invalidDiagnostic.helperReadDiagnostic = &planBrokerCPUHolderReadDiagnostic{readReason: "deadline", waitPhase: "unavailable", waitStatus: "signal_9"}
	cleanupOnly, cleanupOnlyErr := checkedDiagnosticFailure("cleanup-only diagnostic", planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, errors.New("cleanup-only diagnostic")))
	if cleanupOnlyErr != nil { return cleanupOnlyErr }
	cleanupOnly.helperReadDiagnostic = &postDiagnostic
	nestedNative, nestedNativeErr := checkedDiagnosticFailure("nested native diagnostic", planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), errors.New("nested native diagnostic")))
	if nestedNativeErr != nil { return nestedNativeErr }
	nestedNative.helperReadDiagnostic = &postDiagnostic
	differentSelectedPrimary := errors.Join(foreignReason, nestedNative)
	for _, negative := range []struct { name string; err error }{
		{"foreign cap case", foreignCase}, {"foreign reason", foreignReason}, {"foreign stage", foreignStage},
		{"invalid diagnostic", invalidDiagnostic}, {"cleanup-only diagnostic", cleanupOnly},
		{"native diagnostic behind different selected primary", differentSelectedPrimary},
	} {
		negativeWrapper := planBrokerCPUHolderControlMatrixFailure(string(planBrokerCPUControlWatchdogNative), negative.err)
		if selected := planBrokerCPUFirstFailure(negativeWrapper, false); selected == nil || selected.helperReadDiagnostic != nil {
			return fmt.Errorf("matrix wrapper borrowed a native helper-read diagnostic from %s", negative.name)
		}
	}
	if planBrokerCPUWritePreReadyFailureFrame(planBrokerCPUPreReadyWriteFunc(func(p []byte) (int, error) { return len(p)-1, nil }), planBrokerCPUControlWatchdogNative, planBrokerCPUFailureSiteBudget) ||
		planBrokerCPUWritePreReadyFailureFrame(planBrokerCPUPreReadyWriteFunc(func([]byte) (int, error) { return 0, errors.New("injected frame write error") }), planBrokerCPUControlWatchdogNative, planBrokerCPUFailureSiteBudget) {
		return errors.New("short or failed private frame write was treated as authoritative")
	}
	if planBrokerCPUHolderControlReportMessageCount(planBrokerCPUControlWatchdogNative) != 3 || planBrokerCPUHolderControlReportMessageCount(planBrokerCPUControlWatchdogCap) != 3 {
		return errors.New("failure-only frame changed the original successful three-record inventory")
	}
	branchClasses := []planBrokerCPUFailureReason{
		planBrokerCPUReasonChildHolderPreSpawnBinding, planBrokerCPUReasonChildHolderPreSpawnDeadline,
		planBrokerCPUReasonChildHolderRootMetadata, planBrokerCPUReasonChildHolderLaunchCurrent,
		planBrokerCPUReasonChildHolderUnitCurrent, planBrokerCPUReasonChildHolderPipeSetup,
		planBrokerCPUReasonChildHolderTokenSetup, planBrokerCPUReasonChildHolderParentPIDFD,
		planBrokerCPUReasonChildHolderRootHandle, planBrokerCPUReasonChildHolderSpawn,
		planBrokerCPUReasonChildHolderChildIdentity, planBrokerCPUReasonChildHolderChildCgroup,
		planBrokerCPUReasonChildHolderHelperRead, planBrokerCPUReasonChildHolderHelperShape,
		planBrokerCPUReasonChildHolderCapGuardSend, planBrokerCPUReasonChildHolderCapGuardRead,
		planBrokerCPUReasonChildHolderCapGuardShape, planBrokerCPUReasonChildHolderCapRootMetadata,
		planBrokerCPUReasonChildHolderCapAcquireSend, planBrokerCPUReasonChildHolderCapRefRead,
		planBrokerCPUReasonChildHolderCapRefShape,
	}
	for _, class := range branchClasses {
		primaryCause := errors.New("synthetic primary holder cause")
		cleanupCause := errors.New("synthetic cleanup holder cause")
		cleanupClass := planBrokerCPUReasonChildHolderPipeSetup
		if class == planBrokerCPUReasonChildHolderPipeSetup { cleanupClass = planBrokerCPUReasonChildHolderTokenSetup }
		if cleanupClass == class { return errors.New("primary and cleanup holder annotations reused one class") }
		annotated := planBrokerCPUHolderBranchAt(class, primaryCause)
		cleanupAnnotated := planBrokerCPUHolderBranchAt(cleanupClass, cleanupCause)
		if annotated == nil || cleanupAnnotated == nil || annotated.Error() != primaryCause.Error() || !errors.Is(annotated, primaryCause) { return errors.New("typed holder annotation changed Error or lost its original cause") }
		var exact *planBrokerCPUHolderBranch
		if !errors.As(annotated, &exact) || exact.class != class || exact.Unwrap() != primaryCause { return errors.New("typed holder annotation was not discoverable by errors.As") }
		direct := errors.Join(annotated, cleanupAnnotated)
		exact = nil
		if !errors.Is(direct, primaryCause) || !errors.Is(direct, cleanupCause) || !errors.As(direct, &exact) || exact != annotated || exact.class != class || planBrokerCPUHolderBranchClass(direct) != class { return errors.New("direct primary-first cleanup join lost both causes or selected the wrong annotation") }
		wrapped := planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, annotated)
		cleanup := planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, cleanupAnnotated)
		joined := errors.Join(wrapped, errors.Join(errors.New("nested cleanup context"), cleanup))
		exact = nil
		if !errors.Is(joined, primaryCause) { return errors.New("nested primary-first cleanup join lost its primary cause") }
		if !errors.Is(joined, cleanupCause) { return errors.New("nested primary-first cleanup join lost its cleanup cause") }
		if !errors.As(joined, &exact) || exact != annotated || exact.class != class || planBrokerCPUHolderBranchClass(joined) != class { return errors.New("nested primary-first cleanup join selected the wrong annotation") }
		for _, control := range []planBrokerCPUHolderControl{planBrokerCPUControlWatchdogNative, planBrokerCPUControlWatchdogCap} {
			if planBrokerCPUHolderBranchCapOnly(class) && control != planBrokerCPUControlWatchdogCap { continue }
			if class == planBrokerCPUReasonChildHolderHelperRead && control == planBrokerCPUControlWatchdogNative {
				frame, ok := planBrokerCPUNativeHelperReadFailureFrame(control, planBrokerCPUPreReadyFailureSite(class), postDiagnostic)
				parsed, parsedOK := planBrokerCPUParseNativeHelperReadFailureFrame(strings.TrimSuffix(frame, "\n"), control)
				marker := planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, class, string(control), annotated)
				if !ok || !parsedOK || parsed != postDiagnostic || !planBrokerCPUFailureAttachHolderReadDiagnostic(marker, postDiagnostic) || planBrokerCPUFailureMarker(owner, marker) != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":matrix_case:"+string(class)+":"+string(control)+":diag:pipe_or_frame:post_settled:signal_9" {
					return errors.New("native helper-read diagnostic did not reach its exact bounded typed failure marker")
				}
				continue
			}
			frame, ok := planBrokerCPUPreReadyFailureFrame(control, planBrokerCPUPreReadyFailureSite(class))
			parsed, parsedOK := planBrokerCPUParsePreReadyFailureFrame(strings.TrimSuffix(frame, "\n"), control)
			if !ok || !parsedOK || parsed != class || frame != "CONTROL_FAILURE\t"+string(control)+"\t"+string(class)+"\n" { return errors.New("holder branch class did not round-trip through its exact case-bound frame") }
			marker := planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, class, string(control), annotated)
			want := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":matrix_case:" + string(class) + ":" + string(control)
			if got := planBrokerCPUFailureMarker(owner, marker); got != want { return errors.New("holder branch class did not round-trip through its typed matrix marker") }
		}
		if planBrokerCPUHolderBranchCapOnly(class) {
			if _, ok := planBrokerCPUPreReadyFailureFrame(planBrokerCPUControlWatchdogNative, planBrokerCPUPreReadyFailureSite(class)); ok { return errors.New("native watchdog accepted a cap-only holder branch frame") }
			if _, ok := planBrokerCPUParsePreReadyFailureFrame("CONTROL_FAILURE\t"+string(planBrokerCPUControlWatchdogNative)+"\t"+string(class), planBrokerCPUControlWatchdogNative); ok { return errors.New("native watchdog parser accepted a cap-only holder branch frame") }
			marker := planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, class, string(planBrokerCPUControlWatchdogNative), annotated)
			if planBrokerCPUFailureMarker(owner, marker) != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":unavailable:unavailable" { return errors.New("native watchdog formatter accepted a cap-only holder branch") }
		}
	}
	if planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderPipeSetup, nil) != nil || planBrokerCPUHolderBranchClass(errors.New("unannotated")) != "" || planBrokerCPUHolderBranchReasonAllowed("child_holder_unknown") || planBrokerCPUHolderBranchFailureSite(planBrokerCPUHolderBranchAt("child_holder_unknown", errors.New("unknown")), planBrokerCPUControlWatchdogNative) != planBrokerCPUFailureSiteHolderHandshake { return errors.New("nil or unknown holder branch annotation was accepted") }
	primaryCause := errors.New("synthetic cap primary origin")
	cleanupCause := errors.New("synthetic cleanup close origin")
	primaryOrigin := planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, primaryCause)
	primary := planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonUnavailable, string(planBrokerCPUControlWatchdogCap), primaryOrigin)
	cleanup := planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, cleanupCause)
	joined := errors.Join(primary, fmt.Errorf("nested cleanup: %w", cleanup))
	if !errors.Is(joined, primaryCause) || !errors.Is(joined, cleanupCause) {
		return errors.New("failure wrapper lost a primary or cleanup cause")
	}
	first := planBrokerCPUFirstFailure(joined, false)
	firstCleanup := planBrokerCPUFirstFailure(joined, true)
	if first != primary || firstCleanup != cleanup || first.stage != planBrokerCPUStageMatrixCase || first.reason != planBrokerCPUReasonDeadline || first.caseName != string(planBrokerCPUControlWatchdogCap) || firstCleanup.caseName != "" {
		return errors.New("failure origin selection changed primary order or cleanup ownership")
	}
	want := []string{
		"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":matrix_case:deadline:" + string(planBrokerCPUControlWatchdogCap),
		"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":cleanup:descriptor_close",
	}
	budget := &planBrokerCPUFailureEmission{}
	got := planBrokerCPUFailureMarkers(budget, owner, joined)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") || !budget.primaryEmitted || !budget.cleanupEmitted {
		return errors.New("positive primary cap plus real cleanup markers differ from the exact two-marker contract")
	}
	if !strings.Contains(got[0], ":matrix_case:deadline:watchdog_absolute_cap") || strings.Contains(got[1], "watchdog_absolute_cap") {
		return errors.New("cleanup marker inherited matrix case context or cap primary lost its exact case")
	}
	cleanupFromMatrix := planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUncertain, "", primary)
	if !errors.Is(cleanupFromMatrix, primaryCause) {
		return errors.New("direct cleanup wrapper lost the matrix primary cause")
	}
	if firstMatrixPrimary := planBrokerCPUFirstFailure(cleanupFromMatrix, false); firstMatrixPrimary != primary {
		return errors.New("direct cleanup wrapper changed the first matrix primary origin")
	}
	firstMatrixCleanup := planBrokerCPUFirstFailure(cleanupFromMatrix, true)
	if firstMatrixCleanup != cleanupFromMatrix || firstMatrixCleanup.stage != planBrokerCPUStageCleanup || firstMatrixCleanup.reason != planBrokerCPUReasonDeadline || firstMatrixCleanup.caseName != "" {
		return errors.New("direct cleanup wrapper failed to inherit only the primary reason without matrix case context")
	}
	if marker := planBrokerCPUFailureMarker(owner, cleanupFromMatrix); marker != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":cleanup:deadline" {
		return errors.New("direct matrix-primary cleanup marker is not the exact case-free cleanup:deadline form")
	}
	cleanupViaHelper := planBrokerCPUCleanupFailure(planBrokerCPUFailureReasonOf(primary), primary)
	if !errors.Is(cleanupViaHelper, primaryCause) || planBrokerCPUFirstFailure(cleanupViaHelper, false) != primary {
		return errors.New("cleanup helper changed matrix primary identity or first-origin selection")
	}
	if viaHelper := planBrokerCPUFirstFailure(cleanupViaHelper, true); viaHelper != cleanupViaHelper || viaHelper.reason != planBrokerCPUReasonDeadline || viaHelper.caseName != "" || planBrokerCPUFailureMarker(owner, cleanupViaHelper) != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":cleanup:deadline" {
		return errors.New("cleanup helper leaked matrix case context or changed inherited deadline reason")
	}
	secondaryCause := errors.New("secondary joined cause")
	nestedMatrix := errors.Join(fmt.Errorf("wrapped matrix cause: %w", primary), secondaryCause)
	nestedCleanup := planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUncertain, "", nestedMatrix)
	if !errors.Is(nestedCleanup, primaryCause) || !errors.Is(nestedCleanup, secondaryCause) {
		return errors.New("nested cleanup wrapper lost joined matrix causes")
	}
	if firstNestedPrimary := planBrokerCPUFirstFailure(nestedCleanup, false); firstNestedPrimary != primary {
		return errors.New("nested cleanup wrapper changed the first matrix primary origin")
	}
	if firstNestedCleanup := planBrokerCPUFirstFailure(nestedCleanup, true); firstNestedCleanup != nestedCleanup || firstNestedCleanup.reason != planBrokerCPUReasonDeadline || firstNestedCleanup.caseName != "" || planBrokerCPUFailureMarker(owner, nestedCleanup) != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":cleanup:deadline" {
		return errors.New("nested matrix origin did not remain a case-free cleanup:deadline marker")
	}
	if repeated := planBrokerCPUFailureMarkers(budget, owner, joined); len(repeated) != 0 {
		return errors.New("same owner emission budget allowed a repeated marker")
	}

	// A joined tree with cleanup first selects its stage-empty Close origin
	// before the later typed matrix origin under the existing fail-closed
	// traversal, while retaining both causes and the cleanup marker.
	reversed := errors.Join(cleanup, fmt.Errorf("nested primary: %w", primary))
	reversedMarkers := planBrokerCPUFailureMarkers(&planBrokerCPUFailureEmission{}, owner, reversed)
	reversedWant := []string{
		"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable",
		"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":cleanup:descriptor_close",
	}
	reversedFirst := planBrokerCPUFirstFailure(reversed, false)
	if strings.Join(reversedMarkers, "\x00") != strings.Join(reversedWant, "\x00") ||
		!errors.Is(reversed, primaryCause) || !errors.Is(reversed, cleanupCause) ||
		reversedFirst == nil || reversedFirst.stage != "" || reversedFirst.reason != planBrokerCPUReasonClose ||
		reversedFirst.caseName != "" || planBrokerCPUFailureReasonOf(reversed) != planBrokerCPUReasonClose {
		return errors.New("cleanup-first joined origins lost a cause or changed the existing fail-closed Close traversal")
	}

	cleanupOnlyMarkers := planBrokerCPUFailureMarkers(&planBrokerCPUFailureEmission{}, owner, cleanup)
	cleanupOnlyWant := []string{
		"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable",
		"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":cleanup:descriptor_close",
	}
	if strings.Join(cleanupOnlyMarkers, "\x00") != strings.Join(cleanupOnlyWant, "\x00") {
		return errors.New("cleanup-only failure did not fail closed with the canonical unavailable primary")
	}
	invalidCase := planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonDeadline, "foreign_case", primaryOrigin)
	invalidWant := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable"
	if marker := planBrokerCPUFailureMarker(owner, invalidCase); marker != invalidWant || strings.Contains(marker, "foreign_case") {
		return errors.New("foreign matrix case escaped the fixed unavailable representation")
	}
	foreignWant := "__PLAN_RELAUNCH_FAILURE_STAGE__:unavailable:unavailable:unavailable"
	if marker := planBrokerCPUFailureMarker("unexpected-owner", primary); marker != foreignWant {
		return errors.New("foreign owner escaped the fixed unavailable representation")
	}
	reportReasons := []planBrokerCPUFailureReason{planBrokerCPUReasonReportReady, planBrokerCPUReasonReportMetrics, planBrokerCPUReasonReportResult, planBrokerCPUReasonReportPass, planBrokerCPUReasonReportEOF}
	for _, control := range []planBrokerCPUHolderControl{planBrokerCPUControlWatchdogNative, planBrokerCPUControlWatchdogCap} {
		for _, reason := range reportReasons {
			cause := errors.New("synthetic report observation cause")
			origin := planBrokerCPUFailureOrigin(reason, cause)
			failure := planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonPipe, string(control), origin)
			marker := planBrokerCPUFailureMarker(owner, failure)
			want := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":matrix_case:" + string(reason) + ":" + string(control)
			if marker != want || len(marker) > 192 || !errors.Is(failure, cause) {
				return errors.New("watchdog report origin lost its exact reason, case, or underlying cause")
			}
		}
	}
	for _, invalid := range []*planBrokerCPUFailure{
		{stage: planBrokerCPUStageCleanup, reason: planBrokerCPUReasonReportEOF, caseName: string(planBrokerCPUControlWatchdogCap), err: errors.New("cleanup report reason")},
		{stage: planBrokerCPUStageMatrixCase, reason: planBrokerCPUReasonReportEOF, caseName: string(planBrokerCPUControlNegativeRefError), err: errors.New("other case report reason")},
		{stage: planBrokerCPUStageMatrixCase, reason: planBrokerCPUReasonReportEOF, caseName: string(planBrokerCPUControlWatchdogCap), err: errors.New("crash owner report reason")},
	} {
		invalidOwner := owner
		if invalid.reason == planBrokerCPUReasonReportEOF && invalid.err.Error() == "crash owner report reason" { invalidOwner = "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect" }
		invalidOwnerWant := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + invalidOwner + ":unavailable:unavailable"
		if marker := planBrokerCPUFailureMarker(invalidOwner, invalid); marker != invalidOwnerWant {
			return errors.New("report observation reason escaped its lifecycle watchdog case boundary")
		}
	}
	return nil
}

func TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {
	if os.Getenv(planBrokerCPUEnv) != planBrokerCPUOptIn || os.Geteuid() != 0 {
		t.Fatal("CPU lifecycle fixture requires its explicit local root opt-in")
	}
	if err := verifyPlanBrokerCPUTestInventoryParserControls(); err != nil {
		t.Fatalf("helper inventory parser controls failed: %v", err)
	}
	nodeUser, err := user.LookupId("65534")
	if err != nil || nodeUser.Username == "" {
		t.Fatal("fixed unprivileged fixture principal 65534 is unavailable")
	}
	uid, err := strconv.ParseUint(nodeUser.Uid, 10, 32)
	if err != nil || uid == 0 || uid != 65534 {
		t.Fatal("fixture node principal did not resolve to exact UID 65534")
	}
	gid, err := strconv.ParseUint(nodeUser.Gid, 10, 32)
	if err != nil || gid == 0 || gid > uint64(^uint32(0)) {
		t.Fatal("fixture node group did not resolve to a non-root GID")
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Fatal("local systemd-run is unavailable")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Fatal("local systemctl is unavailable")
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Fatal("bounded privilege fixture tooling is unavailable")
	}
	if !strings.Contains(strings.ToLower(readPlanBrokerCPUOSRelease(t)), "microsoft") {
		t.Fatal("CPU lifecycle fixture is limited to the declared local WSL environment")
	}

	root, err := newPlanBrokerCPUFixtureRoot()
	if err != nil {
		t.Fatal("create exact private fixture root")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o711 {
		t.Fatalf("private root anchor identity is unavailable: %v", err)
	}
	paths := checkpointPlanBrokerCPUPaths(root, uint32(uid), uint32(gid))
	unitIdentity, err := prebindPlanBrokerCPUFixtureUnit(paths, root, rootInfo)
	if err != nil {
		t.Fatalf("private fixture unit could not be safely bound; preserving root %s: %v", root, err)
	}
	// The durable start_requested boundary remains excluded from this
	// auto-reconverging matrix. A separate tagged crash/no-effect oracle below
	// covers it, but source presence is not runtime evidence; a cold recovery
	// must remain pending rather than dispatch a second start.
	faultStages := []string{"intent_durable", "plan_published", "published_durable", "systemd_start_returned", "start_accepted_durable", "binding_observed", "receipt_durable", "acknowledged_durable"}
	var faultIndex atomic.Uint32
	paths.faultInjector = func(boundary string) bool {
		index := int(faultIndex.Load())
		if index >= len(faultStages) || boundary != faultStages[index] {
			return false
		}
		return faultIndex.CompareAndSwap(uint32(index), uint32(index+1))
	}
	privateOwned := true
	cleaned := false
	cleanupAttempted := false
	var cleanupOutcome error
	knownLaunches := make(map[string]planBrokerCPULaunchIdentity)
	heldPIDFDs := make(map[string]int)
	lastHeldInvocation := ""
	var broker *planBrokerCPUBroker
	var holder *planBrokerCPUUnitHolder
	normalCleanupRequested := false
	var brokerRestartCount atomic.Uint32
	var unrelated *planBrokerCPUParentGuardChild
	var failureEmission planBrokerCPUFailureEmission
	cleanup := func() error {
		if cleanupAttempted { return cleanupOutcome }
		cleanupAttempted = true
		if cleaned {
			return nil
		}
		var cleanupErr error
		if holder != nil && !normalCleanupRequested {
			cleanupErr = errors.Join(cleanupErr, planBrokerCPUAbortCleanup(holder))
			holder = nil
		}
		if unrelated != nil && unrelated.cmd != nil && unrelated.cmd.Process != nil {
			if stopErr := stopPlanBrokerCPUUnrelatedChild(unrelated); stopErr != nil {
				cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, stopErr))
			} else {
				unrelated = nil
			}
		}
		if broker != nil {
			if stopErr := stopPlanBrokerCPUBroker(broker); stopErr != nil {
				cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, stopErr))
			} else {
				broker = nil
			}
		}
		if cleanupErr != nil && holder != nil {
			cleanupErr = errors.Join(cleanupErr, planBrokerCPUAbortCleanup(holder))
			holder = nil
			normalCleanupRequested = false
		}
		if planBrokerCPUFixtureUnitBound(paths, unitIdentity) {
			unit, unitErr := planBrokerCPUFixtureUnitState(context.Background(), paths)
			invocation := unit.Invocation
			if invocation == "" || unitErr != nil {
				invocation = lastHeldInvocation
			}
			held, known := knownLaunches[invocation]
			if !known || held.UnitName != unitIdentity || (unitErr == nil && unit.MainPID > 1 && (held.PID != unit.MainPID || held.Invocation != unit.Invocation)) {
				cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("transient unit does not join an exact held fixture launch; preserving private fixture")))
			} else {
				pidfd, fdHeld := heldPIDFDs[held.Invocation]
				openedHere := false
				var fdErr error
				if !fdHeld {
					pidfd, fdErr = holdPlanBrokerCPUTerminalPIDFD(held)
					if fdErr == nil {
						openedHere = true
					}
				}
				if fdErr != nil || pidfd < 0 {
					cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("exact held worker pidfd is unavailable; preserving private fixture")))
				} else if unitErr == nil && unit.MainPID > 1 && planBrokerCPULaunchStillCurrent(paths, held) != nil {
					cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("active held worker changed before cleanup stop; preserving private fixture")))
				} else if unitErr == nil && unit.MainPID > 1 && holder != nil && holder.health() != nil {
					cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, errors.New("unit holder health failed before exact cleanup stop; preserving fixture")))
				} else if unitErr == nil && unit.MainPID > 1 && stopPlanBrokerCPUUnit(unitIdentity) != nil {
					cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, errors.New("exact private worker cleanup stop failed; preserving fixture")))
				} else if holder != nil && normalCleanupRequested && holder.assertCurrent() != nil {
					cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("unit holder changed before final loaded stopped proof; preserving fixture")))
				} else if _, proofErr := waitPlanBrokerCPUStoppedCleanupProof(paths, held, pidfd); proofErr != nil {
					cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, proofErr))
				} else if holder != nil && normalCleanupRequested {
					if err := holder.release(); err != nil {
						cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, err))
					} else {
						holder = nil
					}
				}
				if cleanupErr == nil {
					if err := confirmPlanBrokerCPUUnitAbsentWithin(paths, unitIdentity, time.Now().Add(5*time.Second)); err != nil {
						cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, err))
					}
				}
				if cleanupErr != nil && holder != nil {
					cleanupErr = errors.Join(cleanupErr, planBrokerCPUAbortCleanup(holder))
					holder = nil
					normalCleanupRequested = false
				}
				if openedHere {
					cleanupErr = planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, settlePlanBrokerCPUOpenedPIDFDClose(cleanupErr, pidfd, unix.Close))
				}
			}
		} else if !planBrokerCPUUnitConfirmedAbsent(unitIdentity) {
				cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, errors.New("private fixture binding is incomplete and exact unit absence is unknown; preserving private fixture")))
		} else {
			cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, errors.New("private fixture binding is incomplete; preserving private fixture")))
		}
		if cleanupErr != nil && holder != nil {
			cleanupErr = errors.Join(cleanupErr, planBrokerCPUAbortCleanup(holder))
			holder = nil
			normalCleanupRequested = false
		}
	for invocation, pidfd := range heldPIDFDs {
			if err := unix.Close(pidfd); err != nil {
				cleanupErr = errors.Join(cleanupErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, errors.New("held worker pidfd close failed; preserving private fixture")))
			}
			delete(heldPIDFDs, invocation)
		}
		if cleanupErr == nil && privateOwned {
			current, statErr := os.Lstat(root)
			if statErr != nil || !os.SameFile(rootInfo, current) || !current.IsDir() || filepath.Dir(root) != os.TempDir() || !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root)) {
				cleanupErr = planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("private workspace identity is uncertain; preserving it"))
			} else if removeErr := os.RemoveAll(root); removeErr != nil {
				cleanupErr = planBrokerCPUCleanupFailure(planBrokerCPUReasonUncertain, fmt.Errorf("remove exact private workspace: %w", removeErr))
			} else {
				cleaned = true
			}
		} else if cleanupErr == nil && !cleaned {
			cleanupErr = planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("private fixture identity is uncertain; preserving the reported workspace"))
		}
		cleanupOutcome = cleanupErr
		return cleanupOutcome
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			for _, marker := range planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPULifecycleSequence", planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUnavailable, "", cleanupErr)) { fmt.Fprintln(os.Stdout, marker) }
			t.Errorf("bounded fixture cleanup failed; recovery identities: root=%s unit=%s: %v", root, unitIdentity, cleanupErr)
		}
	}()

	if err := createPlanBrokerCPUFixtureTree(paths); err != nil {
		t.Fatalf("create exact private fixture tree: %v", err)
	}
	if !checkpointPlanBrokerPrivateFixturePathSet(paths) {
		t.Fatal("private path set did not satisfy exact fixture boundary")
	}
	currentRoot, rootErr := os.Lstat(root)
	if rootErr != nil || !os.SameFile(rootInfo, currentRoot) {
		t.Fatal("private fixture root changed identity while its tree was created")
	}
	if checkpointPlanBrokerUnitName(paths) != unitIdentity {
		t.Fatal("post-tree production unit binding differs from the pre-bound private fixture unit")
	}
	pathMutant := paths
	pathMutant.ActivePlan = filepath.Join(root, "etc", "alternate-plan.json")
	if fixedCheckpointPlanBrokerPathSet(pathMutant) {
		t.Fatal("private path mutation crossed the exact fixture boundary")
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("create fixture root acknowledgement key")
	}
	stopPublic, stopPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("create fixture stop acknowledgement key")
	}
	if err := writePlanBrokerCPUKeys(paths, rootPrivate, rootPublic, stopPrivate, stopPublic, uint32(gid)); err != nil {
		t.Fatal("write exact private fixture keys")
	}
	workerSHA, err := installPlanBrokerCPUWorker(paths)
	if err != nil {
		t.Fatal("install exact worker test image")
	}
	workerExecutable := filepath.Join(root, "worker")
	victim, urgent, err := writePlanBrokerCPUPlans(paths, workerSHA)
	if err != nil {
		t.Fatal("write distinct approved CPU plans")
	}
	if err := writePlanBrokerCPUConfig(paths, uint32(gid)); err != nil {
		t.Fatal("write pinned node fixture configuration")
	}
	secret := strings.Repeat("S", 48)
	if err := writePlanBrokerCPUEnv(paths, secret, uint32(gid)); err != nil {
		t.Fatal("write pinned node fixture environment")
	}
	catalogRaw, err := encodePlanBrokerCPUCatalog(victim, urgent)
	if err != nil || writePlanBrokerCPUFile(paths.Catalog, catalogRaw, 0o644, 0, 0) != nil {
		t.Fatal("write root-approved plan catalog")
	}
	if err := makePlanBrokerCPUUnrelatedChild(&unrelated, workerExecutable, root, uint32(gid)); err != nil {
		t.Fatal("start exact unrelated child control")
	}
	broker, err = startPlanBrokerCPUBroker(workerExecutable, paths)
	if err != nil {
		privateOwned = false
		t.Fatalf("root lifecycle broker process did not become available; preserving fixture root=%s: %v", root, err)
	}
	restartBroker := func() error {
		if err := stopPlanBrokerCPUBroker(broker); err != nil {
			return err
		}
		broker, err = startPlanBrokerCPUBroker(workerExecutable, paths)
		if err == nil {
			brokerRestartCount.Add(1)
		} else {
			privateOwned = false
		}
		return err
	}

	initialWorkerLaunchRequestedAt := time.Now()
	if err := startPlanBrokerCPUTransient(paths, workerSHA); err != nil {
		t.Fatalf("start exact initial victim unit %s: %v", unitIdentity, err)
	}
	if err := assertPlanBrokerCPUUnitHasParentIndependentDeadline(paths, unitIdentity); err != nil {
		t.Fatalf("transient unit lacks bounded cleanup if its test parent disappears: %v", err)
	}
	victimBefore, err := planBrokerCPUFixtureUnitState(context.Background(), paths)
	if err != nil || victimBefore.MainPID <= 1 || victimBefore.Invocation == "" {
		t.Fatal("initial victim unit did not reach a fresh live process identity")
	}
	if err := assertPlanBrokerCPUOutsideWorkerCgroup(victimBefore.ControlGroup); err != nil {
		t.Fatal("root broker/test supervisor entered the worker control group")
	}
	if err := waitPlanBrokerCPUWorkerEvent(paths, victimBefore.MainPID); err != nil {
		t.Fatal("initial victim did not record its held source descriptor")
	}
	victimLaunch, err := capturePlanBrokerCPULaunch(paths, victim, victimBefore, "")
	if err != nil {
		t.Fatalf("initial victim custody could not be pinned: %v", err)
	}
	knownLaunches[victimBefore.Invocation] = victimLaunch
	if err := planBrokerCPULaunchStillCurrent(paths, victimLaunch); err != nil {
		t.Fatalf("initial victim identity changed before exact stop: %v", err)
	}
	victimPIDFD, err := holdPlanBrokerCPUTerminalPIDFD(victimLaunch)
	if err != nil {
		t.Fatalf("initial victim pidfd could not be held before stop: %v", err)
	}
	heldPIDFDs[victimLaunch.Invocation] = victimPIDFD
	lastHeldInvocation = victimLaunch.Invocation
	if planBrokerCPUHolderNegativeControl == planBrokerCPUControlNegativeWatchdogOmit {
		controlDeadline := time.Now().Add(planBrokerCPUHolderNegativeControlBudget(planBrokerCPUControlNegativeWatchdogOmit))
		err := runPlanBrokerCPUHolderControlCase(paths, root, rootInfo, victimLaunch, planBrokerCPUControlNegativeWatchdogOmit, controlDeadline)
		if err == nil || err.Error() != "negative_watchdog_omitted: helper survived parent death beyond five seconds and was pidfd-cleaned" {
			t.Fatalf("negative watchdog control did not prove the intended omission: %v", err)
		}
		t.Fatal(err)
	}
	if planBrokerCPUHolderNegativeControl == planBrokerCPUControlNegativeWatchdogOmit {
		fmt.Println(planBrokerCPUHolderWatchdogOracleBypassedPredicate)
		t.Fatal("fixed watchdog omission oracle did not execute")
	}
	if planBrokerCPUHolderNegativeControl == "" {
		if err := runPlanBrokerCPUHolderControlMatrix(paths, root, rootInfo, victimLaunch, initialWorkerLaunchRequestedAt); err != nil {
			privateOwned = false
			for _, marker := range planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPULifecycleSequence", err) { fmt.Fprintln(os.Stdout, marker) }
			t.Fatalf("fixed ten-case unit holder control matrix did not complete safely; preserving fixture: %v", err)
		}
	}
	holder, err = startPlanBrokerCPUUnitHolder(paths, rootInfo, victimLaunch, 27)
	if holder == nil && err == nil {
		t.Fatal(provePlanBrokerCPUOmittedHolderRetention(paths, unitIdentity, victimLaunch, victimPIDFD))
	}
	if err != nil {
		if planBrokerCPUHolderNegativeControl == planBrokerCPUControlNegativeRefError {
			if isPlanBrokerCPUInjectedRefError(err) {
				t.Fatal("negative_ref_error: normal holder acquisition consumed the exact injected pre-RefUnit error")
			}
			if errors.Is(err, errPlanBrokerCPUInjectedRefError) {
				fmt.Println(planBrokerCPUHolderRefErrorNotConsumedPredicate)
				t.Fatal("injected RefUnit error escaped the exact negative-case assertion")
			}
			t.Fatal("negative_ref_error control did not preserve the injected typed error")
		}
		for _, marker := range planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPULifecycleSequence", planBrokerCPUFailureAt(planBrokerCPUStageMatrixAdmission, planBrokerCPUReasonUnit, "", err)) { fmt.Fprintln(os.Stdout, marker) }
		t.Fatalf("single private unit reference holder could not be established before first stop: %v", err)
	}
	if err := holder.health(); err != nil {
		t.Fatal("holder same-connection health failed before first exact unit stop")
	}
	if !holder.releaseDone {
	if err := planBrokerCPUHolderEOFParentAliveOutcome(holder, paths, victimLaunch, rootInfo); err != nil {
		if err.Error() == planBrokerCPUHolderEOFAlivePredicate {
			holder = nil
			t.Fatal(planBrokerCPUHolderEOFAlivePredicate)
		}
		t.Fatalf("EOF-alive control remained unproved: %v", err)
	}
	}
	if err := stopPlanBrokerCPUUnit(unitIdentity); err != nil {
		t.Fatal("stop the exact initial victim unit")
	}
	waitCode, err := waitPlanBrokerCPUStoppedProof(paths, victimLaunch, victimPIDFD)
	if err != nil {
		if holder.releaseDone {
			if waitCode != "unit_definition_missing" {
				t.Fatalf("early-release proof was inconclusive (%s), not the intended missing-definition predicate: %v", waitCode, err)
			}
			fmt.Println(planBrokerCPUHolderEarlyReleasePredicate)
		} else {
			fmt.Fprintln(os.Stdout, planBrokerCPUInactiveWaitMarker("TestCheckpointPlanRelaunchCPULifecycleSequence", waitCode))
		}
		t.Fatalf("holder retention/lifetime oracle: confirm the first worker remains an exact loaded stopped unit with empty cgroup: %v", err)
	}
	if holder.releaseDone {
		t.Fatal("early-release mutant unexpectedly passed: exact loaded stopped-unit retention proof still succeeded")
	}
	secretCommand, victimStopReceipt, err := makePlanBrokerCPUStopAck(paths, "victim_stop", victimBefore, victimLaunch, victimPIDFD, secret, stopPrivate)
	if err != nil {
		t.Fatal("create linked root-signed victim stop acknowledgement")
	}
	if err := writePlanBrokerCPUStopAck(paths, secretCommand, victimStopReceipt, uint32(gid)); err != nil {
		t.Fatal("persist exact victim stop acknowledgement")
	}
	urgentCommand, err := makePlanBrokerCPUCommand(paths, secret, "urgent_load", "urgent-catalog", "victim-catalog", "victim_stop", secretCommand, victimStopReceipt)
	if err != nil {
		t.Fatal("sign linked urgent-load intent")
	}
	if err := runPlanBrokerCPUNodeCommand(paths, uint32(uid), uint32(gid), secret, urgentCommand, "urgent_load", victimStopReceipt, nil, true, restartBroker, holder); err != nil {
		t.Fatalf("UID 65534 command processor did not complete urgent-load round trip: %v", err)
	}
	if int(faultIndex.Load()) != len(faultStages) {
		t.Fatalf("engine recovery matrix missed boundaries: observed=%d expected=%d", faultIndex.Load(), len(faultStages))
	}
	if int(brokerRestartCount.Load()) != len(faultStages) {
		t.Fatalf("broker process was not killed and restarted after every uncertain boundary: observed=%d expected=%d", brokerRestartCount.Load(), len(faultStages))
	}
	urgentReceiptRaw, err := readPlanBrokerCPUReceipt(paths, urgentCommand.ID)
	if err != nil {
		t.Fatal("urgent root acknowledgement receipt unavailable")
	}
	urgentReceipt, err := verifyCheckpointPlanRelaunchReceipt(urgentReceiptRaw, rootPublic, mustPlanBrokerWire(urgentCommand), secret)
	if err != nil || urgentReceipt.MainPID <= 1 || urgentReceipt.InvocationID == victimBefore.Invocation || urgentReceipt.Alias != urgent.Alias || urgentReceipt.CatalogID != "urgent-catalog" || urgentReceipt.LinkedCatalogID != "victim-catalog" {
		t.Fatal("urgent acknowledgement lacks a fresh distinct live process identity")
	}
	urgentLiveUnit, err := planBrokerCPUFixtureUnitState(context.Background(), paths)
	if err != nil || urgentLiveUnit.MainPID != urgentReceipt.MainPID || urgentLiveUnit.Invocation != urgentReceipt.InvocationID {
		t.Fatal("urgent receipt did not identify the current held unit")
	}
	urgentLaunch, err := capturePlanBrokerCPULaunch(paths, urgent, urgentLiveUnit, victimBefore.Invocation)
	if err != nil {
		t.Fatalf("urgent worker custody could not be pinned: %v", err)
	}
	knownLaunches[urgentReceipt.InvocationID] = urgentLaunch
	if err := provePlanBrokerCPUPhysicalSubstitutionRejected(paths, urgent); err != nil {
		t.Fatal("fake physical association substitution was not rejected")
	}
	if err := planBrokerCPULaunchStillCurrent(paths, urgentLaunch); err != nil {
		t.Fatalf("urgent worker identity changed before exact stop: %v", err)
	}
	urgentPIDFD, err := holdPlanBrokerCPUTerminalPIDFD(urgentLaunch)
	if err != nil {
		t.Fatalf("urgent worker pidfd could not be held before stop: %v", err)
	}
	heldPIDFDs[urgentLaunch.Invocation] = urgentPIDFD
	lastHeldInvocation = urgentLaunch.Invocation
	if err := holder.health(); err != nil {
		t.Fatal("holder same-connection health failed before urgent worker stop")
	}
	if err := stopPlanBrokerCPUUnit(unitIdentity); err != nil {
		t.Fatal("stop exact urgent worker unit")
	}
	if _, err := waitPlanBrokerCPUStoppedProof(paths, urgentLaunch, urgentPIDFD); err != nil {
		t.Fatal("confirm urgent worker stop and empty cgroup")
	}
	urgentUnit := checkpointFixedUnitState{MainPID: urgentReceipt.MainPID, Invocation: urgentReceipt.InvocationID, ControlGroup: victimBefore.ControlGroup, Active: "active", Sub: "running"}
	urgentStopCommand, urgentStopReceipt, err := makePlanBrokerCPUStopAck(paths, "urgent_stop", urgentUnit, urgentLaunch, urgentPIDFD, secret, stopPrivate)
	if err != nil {
		t.Fatal("create linked root-signed urgent stop acknowledgement")
	}
	if err := writePlanBrokerCPUStopAck(paths, urgentStopCommand, urgentStopReceipt, uint32(gid)); err != nil {
		t.Fatal("persist exact urgent stop acknowledgement")
	}
	victimCommand, err := makePlanBrokerCPUCommand(paths, secret, "victim_reload", "victim-catalog", "", "urgent_stop", urgentStopCommand, urgentStopReceipt)
	if err != nil {
		t.Fatal("sign linked victim-reload intent")
	}
	if err := runPlanBrokerCPUNodeCommand(paths, uint32(uid), uint32(gid), secret, victimCommand, "victim_reload", victimStopReceipt, urgentStopReceipt, false, nil, holder); err != nil {
		t.Fatalf("UID 65534 command processor did not complete victim-reload round trip: %v", err)
	}
	victimReceiptRaw, err := readPlanBrokerCPUReceipt(paths, victimCommand.ID)
	if err != nil {
		t.Fatal("victim root acknowledgement receipt unavailable")
	}
	victimReceipt, err := verifyCheckpointPlanRelaunchReceipt(victimReceiptRaw, rootPublic, mustPlanBrokerWire(victimCommand), secret)
	victimPlanSHA := sha256Hex(mustJSON(victim))
	if err != nil || victimReceipt.MainPID <= 1 || victimReceipt.InvocationID == urgentReceipt.InvocationID || victimReceipt.Alias != victim.Alias || victimReceipt.CatalogID != "victim-catalog" || victimReceipt.PlanSHA256 != victimPlanSHA {
		t.Fatal("reloaded victim acknowledgement lacks a fresh process identity")
	}
	victimLiveUnit, err := planBrokerCPUFixtureUnitState(context.Background(), paths)
	if err != nil || victimLiveUnit.MainPID != victimReceipt.MainPID || victimLiveUnit.Invocation != victimReceipt.InvocationID {
		t.Fatal("victim receipt did not identify the current held unit")
	}
	victimLaunch, err = capturePlanBrokerCPULaunch(paths, victim, victimLiveUnit, urgentReceipt.InvocationID)
	if err != nil {
		t.Fatalf("reloaded victim custody could not be pinned: %v", err)
	}
	knownLaunches[victimReceipt.InvocationID] = victimLaunch
	victimPIDFD, err = holdPlanBrokerCPUTerminalPIDFD(victimLaunch)
	if err != nil {
		t.Fatal("final victim pidfd could not be held before exact stop")
	}
	heldPIDFDs[victimLaunch.Invocation] = victimPIDFD
	lastHeldInvocation = victimLaunch.Invocation
	if !planBrokerCPUUnrelatedChildAlive(unrelated) {
		t.Fatal("unrelated child was affected by the exact-unit sequence")
	}
	if err := planBrokerCPULaunchStillCurrent(paths, victimLaunch); err != nil {
		t.Fatalf("final victim identity changed before exact stop: %v", err)
	}
	if err := holder.health(); err != nil {
		t.Fatal("holder same-connection health failed before final victim stop")
	}
	if err := stopPlanBrokerCPUUnit(unitIdentity); err != nil {
		t.Fatal("stop exact final victim unit")
	}
	if err := holder.health(); err != nil {
		t.Fatal("holder same-connection health failed before final loaded stopped proof")
	}
	if _, err := waitPlanBrokerCPUStoppedProof(paths, victimLaunch, victimPIDFD); err != nil {
		t.Fatal("confirm final worker stop and empty cgroup")
	}
	if victimReceipt.MainPID == urgentReceipt.MainPID || victimBefore.MainPID == victimReceipt.MainPID || victimReceipt.InvocationID == victimBefore.Invocation || victimReceipt.CurrentIncarnation == urgentReceipt.CurrentIncarnation || (victim.Model.Path != urgent.Model.Path && victim.Model.SHA256 == urgent.Model.SHA256) || victim.Alias == urgent.Alias {
		t.Fatal("victim/urgent/victim sequence failed distinct source or identity controls")
	}
	if err := verifyPlanBrokerCPUHeldSourceEvents(paths, victim, urgent, victimBefore.MainPID, urgentReceipt.MainPID, victimReceipt.MainPID); err != nil {
		t.Fatal("worker did not hold the exact per-launch model source descriptor")
	}
	normalCleanupRequested = true
	if err := cleanup(); err != nil {
		privateOwned = false
		t.Fatalf("fixture cleanup could not prove exact effects: root=%s unit=%s: %v", root, unitIdentity, err)
	}
	privateOwned = false
	fmt.Println("__PLAN_RELAUNCH_CPU_SEQUENCE_POSITIVE__")
}

func TestCheckpointPlanRelaunchCPUNodeClient(t *testing.T) {
	if os.Getenv(planBrokerCPURole) != "node-client" {
		return
	}
	if os.Geteuid() != 65534 || os.Getenv(planBrokerCPUEnv) != planBrokerCPUOptIn {
		t.Fatal("node client did not run as exact unprivileged opt-in principal")
	}
	root := os.Getenv("VRAM_PLAN_BROKER_CPU_ROOT")
	phase := os.Getenv("VRAM_PLAN_BROKER_CPU_PHASE")
	role := os.Getenv(planBrokerCPUClientMode)
	if !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root)) || filepath.Dir(root) != os.TempDir() || (phase != "urgent_load" && phase != "victim_reload") || (role != "command" && role != "query") {
		t.Fatal("node client fixture identity or step is invalid")
	}
	paths := checkpointPlanBrokerCPUPaths(root, 65534, uint32(os.Getgid()))
	secret := os.Getenv("VRAM_NODE_COMMAND_SECRET")
	if len(secret) < 32 {
		t.Fatal("node client signing material is unavailable")
	}
	commandRaw, err := os.ReadFile(filepath.Join(root, "var", "node", phase+".command.json"))
	if err != nil {
		t.Fatal("exact node command fixture is unavailable")
	}
	var command wsproto.CommandPayload
	if json.Unmarshal(commandRaw, &command) != nil || command.Command == "" {
		t.Fatal("node command fixture is malformed")
	}
	cfg := &Config{NodeID: command.NodeID, CommandStatePath: paths.NodeState, CommandSigningSecret: secret, CommandSigningSecretEnv: "VRAM_NODE_COMMAND_SECRET", CommandRecoveryEpoch: fmt.Sprint(command.Args["recovery_epoch"]),
		LlamaCPP: struct {
			Servers []LlamaCPPServerConfig `yaml:"servers"`
		}{Servers: []LlamaCPPServerConfig{{ID: "server", Endpoint: "http://127.0.0.1:18421"}}}}
	processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	processor.planBrokerPaths = paths
	processor.ownedStopPaths = checkpointPlanBrokerOwnedStopPaths(paths)
	if role == "query" {
		attempt, err := strconv.Atoi(os.Getenv("VRAM_PLAN_BROKER_CPU_QUERY_ATTEMPT"))
		if err != nil || attempt < 1 || attempt > 20 {
			t.Fatal("linked recovery query attempt is outside the fixed bound")
		}
		query := makePlanBrokerCPUQuery(command, phase, secret, attempt)
		result := processor.Handle(context.Background(), query)
		if result.OK && !result.Uncertain && result.Result["reconciled"] == true {
			fmt.Println("__PLAN_RELAUNCH_CPU_RECONCILED__")
			return
		}
		if result.Uncertain {
			fmt.Println("__PLAN_RELAUNCH_CPU_UNCERTAIN__")
			return
		}
		t.Fatalf("linked recovery query was rejected: %s", result.Error)
	}
	if phase == "urgent_load" {
		var seed struct {
			Command wsproto.CommandPayload `json:"command"`
			Receipt []byte                 `json:"receipt"`
		}
		seedRaw, readErr := os.ReadFile(filepath.Join(root, "var", "node", "victim_stop.seed.json"))
		if readErr != nil || json.Unmarshal(seedRaw, &seed) != nil || len(seed.Receipt) == 0 {
			t.Fatal("exact predecessor seed is unavailable")
		}
		wire, wireErr := wsproto.CanonicalCommandEnvelope(seed.Command)
		if wireErr != nil {
			t.Fatal("predecessor envelope is invalid")
		}
		processor.recoveryEpoch = fmt.Sprint(command.Args["recovery_epoch"])
		processor.fences[ownedStopFenceKey(fmt.Sprint(command.Args["accelerator_id"]))] = int64FromArg(command.Args["fencing_token"])
		processor.ownedStopOperations[fmt.Sprint(command.Args["accelerator_id"])] = ownedStopOperationState{OperationID: fmt.Sprint(command.Args["operation_id"]), AcceleratorID: fmt.Sprint(command.Args["accelerator_id"]), RecoveryEpoch: processor.recoveryEpoch, Fence: int64FromArg(command.Args["fencing_token"]), UsedOperationIDs: map[string]bool{fmt.Sprint(command.Args["operation_id"]): true}, Steps: map[string]ownedStopStepState{"victim_stop": {CommandID: seed.Command.ID, IdempotencyKey: seed.Command.IdempotencyKey, EnvelopeSHA256: sha256Hex(wire), ReceiptSHA256: sha256Hex(seed.Receipt), PinnedRootStopPublicKey: mustReadPlanBrokerCPUStopPublic(paths), Status: "acknowledged"}}}
		if err := seedPlanBrokerCPUDurableStopResult(processor, seed.Command, seed.Receipt, paths, secret); err != nil {
			t.Fatal("persist exact successful victim-stop predecessor result")
		}
		if err := processor.save(); err != nil {
			t.Fatal("persist exact initial node fence and predecessor")
		}
		if len(processor.pending) != 0 || len(processor.inflight) != 0 {
			t.Fatal("victim predecessor reload fixture unexpectedly contains pending work")
		}
		var expectedReceipt ownedStopReceipt
		if err := json.Unmarshal(seed.Receipt, &expectedReceipt); err != nil {
			t.Fatal("decode independently seeded victim predecessor receipt")
		}
		expectedHeld := planBrokerCPULaunchIdentity{PlanSHA256: expectedReceipt.ManagedPlanSHA256, CurrentIncarnation: expectedReceipt.ManagedCurrentIncarnation, CustodyBindingSHA256: expectedReceipt.CustodyBindingSHA256, Alias: expectedReceipt.ModelAlias}
		processor = verifySavedReadbackPlanBrokerCPUPredecessor(t, cfg, paths, command, seed.Command, "victim_stop", secret, seed.Receipt, expectedHeld)
	} else {
		var seed struct {
			Command wsproto.CommandPayload `json:"command"`
			Receipt []byte                 `json:"receipt"`
		}
		seedRaw, readErr := os.ReadFile(filepath.Join(root, "var", "node", "urgent_stop.seed.json"))
		if readErr != nil || json.Unmarshal(seedRaw, &seed) != nil || len(seed.Receipt) == 0 {
			t.Fatal("exact urgent-stop seed is unavailable")
		}
		wire, wireErr := wsproto.CanonicalCommandEnvelope(seed.Command)
		if wireErr != nil {
			t.Fatal("urgent-stop envelope is invalid")
		}
		accelerator := fmt.Sprint(command.Args["accelerator_id"])
		stop := processor.ownedStopOperations[accelerator]
		stop.Steps["urgent_stop"] = ownedStopStepState{CommandID: seed.Command.ID, IdempotencyKey: seed.Command.IdempotencyKey, EnvelopeSHA256: sha256Hex(wire), ReceiptSHA256: sha256Hex(seed.Receipt), PinnedRootStopPublicKey: mustReadPlanBrokerCPUStopPublic(paths), Status: "acknowledged"}
		stop.UsedOperationIDs[fmt.Sprint(command.Args["operation_id"])] = true
		processor.ownedStopOperations[accelerator] = stop
		if err := seedPlanBrokerCPUDurableStopResult(processor, seed.Command, seed.Receipt, paths, secret); err != nil {
			t.Fatal("persist exact successful urgent-stop predecessor result")
		}
		if err := processor.save(); err != nil {
			t.Fatal("persist exact urgent-stop acknowledgement")
		}
		if len(processor.pending) != 0 || len(processor.inflight) != 0 {
			t.Fatal("urgent predecessor reload fixture unexpectedly contains pending work")
		}
		var expectedReceipt ownedStopReceipt
		if err := json.Unmarshal(seed.Receipt, &expectedReceipt); err != nil {
			t.Fatal("decode independently seeded urgent predecessor receipt")
		}
		expectedHeld := planBrokerCPULaunchIdentity{PlanSHA256: expectedReceipt.ManagedPlanSHA256, CurrentIncarnation: expectedReceipt.ManagedCurrentIncarnation, CustodyBindingSHA256: expectedReceipt.CustodyBindingSHA256, Alias: expectedReceipt.ModelAlias}
		processor = verifySavedReadbackPlanBrokerCPUPredecessor(t, cfg, paths, command, seed.Command, "urgent_stop", secret, seed.Receipt, expectedHeld)
	}
	result := processor.Handle(context.Background(), command)
	settled := result.OK && !result.Uncertain
	if !settled && result.Uncertain {
		fmt.Println("__PLAN_RELAUNCH_CPU_UNCERTAIN__")
		return
	}
	if !settled {
		t.Fatalf("real node command processor did not settle %s: ok=%t uncertain=%t error=%s", phase, result.OK, result.Uncertain, result.Error)
	}
	if processor.inflight[ownedStopFenceKey(fmt.Sprint(command.Args["accelerator_id"]))] || len(processor.pending) != 0 {
		t.Fatal("settled plan transition retained its accelerator fence")
	}
}

func verifySavedReadbackPlanBrokerCPUPredecessor(t *testing.T, cfg *Config, paths checkpointPlanBrokerPaths, planCommand, priorCommand wsproto.CommandPayload, stepName, secret string, expectedReceiptRaw []byte, expectedHeld planBrokerCPULaunchIdentity) *commandProcessor {
	t.Helper()
	if stepName != "victim_stop" && stepName != "urgent_stop" {
		t.Fatal("saved predecessor control received an unknown step")
	}
	if err := verifyOwnedStopReceipt(expectedReceiptRaw, mustReadPlanBrokerCPUStopPublic(paths), mustPlanBrokerWire(priorCommand), secret); err != nil {
		t.Fatalf("independent seeded %s receipt is not valid against its exact original command: %v", stepName, err)
	}
	var expectedReceipt ownedStopReceipt
	if err := json.Unmarshal(expectedReceiptRaw, &expectedReceipt); err != nil || verifyPlanBrokerCPUStopReceiptBinding(expectedHeld, expectedReceipt) != nil {
		t.Fatalf("independent seeded %s held binding is invalid", stepName)
	}
	// A fresh normal processor constructor reads and validates the same persisted
	// state file and journal that the just-completed save wrote.
	reloaded := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	reloaded.planBrokerPaths = paths
	reloaded.ownedStopPaths = checkpointPlanBrokerOwnedStopPaths(paths)
	if reloaded.initError != nil || reloaded.stateBlocked || len(reloaded.pending) != 0 || len(reloaded.inflight) != 0 || !reloaded.ready.Load() {
		t.Fatalf("fresh processor did not accept the saved checksum/journal state without pending work: init=%v blocked=%t pending=%d inflight=%d ready=%t", reloaded.initError, reloaded.stateBlocked, len(reloaded.pending), len(reloaded.inflight), reloaded.ready.Load())
	}
	accelerator := fmt.Sprint(planCommand.Args["accelerator_id"])
	operation, ok := reloaded.ownedStopOperations[accelerator]
	if !ok {
		t.Fatal("fresh processor omitted saved owned-stop operation")
	}
	step, ok := operation.Steps[stepName]
	if !ok || step.CommandID != priorCommand.ID {
		t.Fatal("fresh processor omitted exact saved predecessor step")
	}
	readback := reloaded.commandStatePayload()
	result, ok := readback.Results[priorCommand.ID]
	if !ok || result.Result == nil {
		t.Fatal("fresh processor omitted exact saved predecessor result")
	}
	receiptText, ok := result.Result["receipt"].(string)
	if !ok || receiptText == "" {
		t.Fatal("fresh processor predecessor result omitted its signed receipt")
	}
	receiptRaw := []byte(receiptText)
	public := append(ed25519.PublicKey(nil), step.PinnedRootStopPublicKey...)
	if err := verifyCheckpointPlanBrokerPriorStopResult(readback, paths, planCommand, operation, step, receiptRaw, public, secret); err != nil {
		t.Fatalf("known valid saved/reloaded %s predecessor was rejected: %v", stepName, err)
	}
	if err := verifyOwnedStopReceipt(receiptRaw, public, mustPlanBrokerWire(priorCommand), secret); err != nil {
		t.Fatalf("saved/reloaded %s receipt is not fully signed against its original command: %v", stepName, err)
	}
	if !bytes.Equal(receiptRaw, expectedReceiptRaw) {
		t.Fatalf("saved/reloaded %s receipt differs from its independently seeded bytes", stepName)
	}
	var stored ownedStopReceipt
	if err := json.Unmarshal(receiptRaw, &stored); err != nil {
		t.Fatal("decode saved/reloaded predecessor receipt")
	}
	if err := verifyPlanBrokerCPUStopReceiptBinding(expectedHeld, stored); err != nil {
		t.Fatalf("valid saved/reloaded held managed binding was rejected: %v", err)
	}
	copyState := func() commandStatePayload {
		mutant := readback
		mutant.Results = make(map[string]wsproto.CommandResultPayload, len(readback.Results))
		for key, value := range readback.Results {
			if value.Result != nil {
				fields := make(map[string]any, len(value.Result))
				for field, item := range value.Result {
					fields[field] = item
				}
				value.Result = fields
			}
			mutant.Results[key] = value
		}
		return mutant
	}
	missing := copyState()
	delete(missing.Results, priorCommand.ID)
	if err := verifyCheckpointPlanBrokerPriorStopResult(missing, paths, planCommand, operation, step, receiptRaw, public, secret); err == nil || !strings.Contains(err.Error(), "durable prior stop result is unavailable") {
		t.Errorf("saved/reloaded %s missing-result mutant did not reject at the result lookup: %v", stepName, err)
	}
	changedResult := copyState()
	changed := changedResult.Results[priorCommand.ID]
	changed.Result["receipt_sha256"] = strings.Repeat("0", 64)
	changedResult.Results[priorCommand.ID] = changed
	if err := verifyCheckpointPlanBrokerPriorStopResult(changedResult, paths, planCommand, operation, step, receiptRaw, public, secret); err == nil || !strings.Contains(err.Error(), "durable prior stop result no longer matches its pinned command and receipt") {
		t.Errorf("saved/reloaded %s changed-result mutant did not reject at the result join: %v", stepName, err)
	}
	for name, mutate := range map[string]func(*planBrokerCPULaunchIdentity){
		"plan":        func(value *planBrokerCPULaunchIdentity) { value.PlanSHA256 = strings.Repeat("c", 64) },
		"incarnation": func(value *planBrokerCPULaunchIdentity) { value.CurrentIncarnation = strings.Repeat("d", 64) },
		"custody":     func(value *planBrokerCPULaunchIdentity) { value.CustodyBindingSHA256 = strings.Repeat("e", 64) },
		"alias":       func(value *planBrokerCPULaunchIdentity) { value.Alias = "other-model" },
	} {
		mutantHeld := expectedHeld
		mutate(&mutantHeld)
		if err := verifyPlanBrokerCPUStopReceiptBinding(mutantHeld, stored); err == nil || !strings.Contains(err.Error(), "synthetic stop receipt does not match the exact held managed binding") {
			t.Errorf("saved/reloaded %s %s held-binding mutant did not reject at its intended comparison: %v", stepName, name, err)
		}
	}
	return reloaded
}

func seedPlanBrokerCPUDurableStopResult(processor *commandProcessor, command wsproto.CommandPayload, receipt []byte, paths checkpointPlanBrokerPaths, secret string) error {
	if processor == nil || len(receipt) == 0 {
		return errors.New("synthetic durable stop result is incomplete")
	}
	wire, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil || !bytes.Equal(wire, mustPlanBrokerWire(command)) {
		return errors.New("synthetic durable stop command is not canonical")
	}
	public := mustReadPlanBrokerCPUStopPublic(paths)
	if err := verifyOwnedStopReceipt(receipt, public, wire, secret); err != nil {
		return errors.New("synthetic durable stop receipt does not verify against its exact command")
	}
	result := wsproto.CommandResultPayload{ID: command.ID, NodeID: command.NodeID, OK: true, Result: map[string]any{
		"action": command.Command, "command_id": command.ID, "idempotency_key": command.IdempotencyKey,
		"original_envelope": base64.StdEncoding.EncodeToString(wire), "pinned_root_public_key": base64.StdEncoding.EncodeToString(public),
		"receipt": string(receipt), "receipt_sha256": sha256Hex(receipt),
	}, CompletedAt: time.Now().UTC()}
	processor.results[command.ID] = result
	processor.results["key:"+command.IdempotencyKey] = result
	fingerprint := processor.semanticFingerprint(command)
	processor.commandFingerprints["id:"+command.ID] = fingerprint
	processor.commandFingerprints[command.IdempotencyKey] = fingerprint
	return nil
}

func makePlanBrokerCPUQuery(original wsproto.CommandPayload, phase, secret string, attempt int) wsproto.CommandPayload {
	args := map[string]any{
		"operation_id": original.Args["operation_id"], "target_kind": original.Args["target_kind"], "target_id": original.Args["target_id"],
		"accelerator_id": original.Args["accelerator_id"], "workload_id": original.Args["workload_id"], "workload_revision": original.Args["workload_revision"],
		"recovery_epoch": original.Args["recovery_epoch"], "fencing_token": original.Args["fencing_token"], "catalog_id": original.Args["catalog_id"],
		"prior_command_id": original.Args["prior_command_id"], "prior_idempotency_key": original.Args["prior_idempotency_key"], "prior_receipt_sha256": original.Args["prior_receipt_sha256"],
		"query_step": phase, "original_command_id": original.ID, "original_idempotency_key": original.IdempotencyKey,
		"original_envelope_sha256": "", "expected_fence": original.Args["fencing_token"], "observed_after_fence": original.Args["fencing_token"],
	}
	originalWire, _ := wsproto.CanonicalCommandEnvelope(original)
	args["original_envelope_sha256"] = sha256Hex(originalWire)
	if phase == "urgent_load" {
		args["linked_catalog_id"] = original.Args["linked_catalog_id"]
	}
	now := time.Now().UTC()
	query := wsproto.CommandPayload{ID: fmt.Sprintf("cpu-plan-query-%s-%02d", phase, attempt), IdempotencyKey: fmt.Sprintf("cpu-plan-query-key-%s-%02d", phase, attempt), NodeID: original.NodeID, Command: checkpointPlanRelaunchQueryCommand, Args: args, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(3 * time.Minute)}
	query.Signature, _ = wsproto.SignCommand(query, []byte(secret))
	return query
}

// TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect is a separate,
// build-tagged opt-in crash oracle. The child broker exits only after the
// start_requested journal fsync and before systemd start; subsequent cold
// linked queries must preserve that ambiguity rather than start twice.
func provePlanBrokerCPUOmittedHolderRetention(paths checkpointPlanBrokerPaths, unit string, launch planBrokerCPULaunchIdentity, pidfd int) error {
	if !planBrokerCPUFixtureUnitBound(paths, unit) || launch.UnitName != unit || planBrokerCPULaunchStillCurrent(paths, launch) != nil {
		return errors.New("holder retention oracle: original unit/worker binding was not exact")
	}
	if err := stopPlanBrokerCPUUnit(unit); err != nil { return errors.New("holder retention oracle: exact unit stop failed") }
	code, err := waitPlanBrokerCPUStoppedProof(paths, launch, pidfd)
	if err != nil && code == "unit_definition_missing" {
		fmt.Println(planBrokerCPUHolderOmittedDefinitionPredicate)
		return fmt.Errorf("holder retention oracle: exact intended missing-definition predicate after omitted reference: %w", err)
	}
	if err != nil { return fmt.Errorf("omitted-reference proof was inconclusive (%s), not the intended missing-definition predicate: %w", code, err) }
	return errors.New("holder retention unexpectedly passed the exact loaded stopped-unit proof")
}

func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {
	if os.Getenv(planBrokerCPUEnv) != planBrokerCPUOptIn || os.Geteuid() != 0 {
		t.Fatal("CPU start-request crash fixture requires its explicit local root opt-in")
	}
	if err := verifyPlanBrokerCPUTestInventoryParserControls(); err != nil {
		t.Fatalf("helper inventory parser controls failed: %v", err)
	}
	nodeUser, err := user.LookupId("65534")
	if err != nil || nodeUser.Username == "" {
		t.Fatal("fixed unprivileged fixture principal 65534 is unavailable")
	}
	uid, err := strconv.ParseUint(nodeUser.Uid, 10, 32)
	if err != nil || uid != 65534 {
		t.Fatal("fixture node principal did not resolve to exact UID 65534")
	}
	gid, err := strconv.ParseUint(nodeUser.Gid, 10, 32)
	if err != nil || gid == 0 || gid > uint64(^uint32(0)) {
		t.Fatal("fixture node group did not resolve to a non-root GID")
	}
	for _, binary := range []string{"systemd-run", "systemctl", "setpriv"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Fatalf("fixed fixture tooling %s is unavailable", binary)
		}
	}
	if !strings.Contains(strings.ToLower(readPlanBrokerCPUOSRelease(t)), "microsoft") {
		t.Fatal("CPU fixture is limited to the declared local WSL environment")
	}
	root, err := newPlanBrokerCPUFixtureRoot()
	if err != nil {
		t.Fatal("create exact private fixture root")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o711 {
		t.Fatalf("private root anchor identity is unavailable: %v", err)
	}
	paths := checkpointPlanBrokerCPUPaths(root, uint32(uid), uint32(gid))
	unitName, err := prebindPlanBrokerCPUFixtureUnit(paths, root, rootInfo)
	if err != nil {
		t.Fatalf("private fixture unit could not be safely bound; preserving root %s: %v", root, err)
	}
	var broker *planBrokerCPUBroker
	var holder *planBrokerCPUUnitHolder
	normalCleanupRequested := false
	var unrelated *planBrokerCPUParentGuardChild
	var failureEmission planBrokerCPUFailureEmission
	privateOwned := true
	cleaned := false
	cleanupAttempted := false
	var cleanupOutcome error
	knownLaunches := make(map[string]planBrokerCPULaunchIdentity)
	heldPIDFDs := make(map[string]int)
	lastHeldInvocation := ""
	cleanup := func() error {
		if cleanupAttempted { return cleanupOutcome }
		cleanupAttempted = true
		if cleaned {
			return nil
		}
		var result error
		if holder != nil && !normalCleanupRequested {
			result = errors.Join(result, planBrokerCPUAbortCleanup(holder))
			holder = nil
		}
		if unrelated != nil && unrelated.cmd != nil && unrelated.cmd.Process != nil {
			if err := stopPlanBrokerCPUUnrelatedChild(unrelated); err != nil {
				result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, err))
			} else {
				unrelated = nil
			}
		}
		if broker != nil {
			if err := stopPlanBrokerCPUBroker(broker); err != nil {
				result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, err))
			} else {
				broker = nil
			}
		}
		if result != nil && holder != nil {
			result = errors.Join(result, planBrokerCPUAbortCleanup(holder))
			holder = nil
			normalCleanupRequested = false
		}
		if planBrokerCPUFixtureUnitBound(paths, unitName) {
			unit, unitErr := planBrokerCPUFixtureUnitState(context.Background(), paths)
			invocation := unit.Invocation
			if invocation == "" || unitErr != nil {
				invocation = lastHeldInvocation
			}
			held, known := knownLaunches[invocation]
			if !known || held.UnitName != unitName || (unitErr == nil && unit.MainPID > 1 && (held.PID != unit.MainPID || held.Invocation != unit.Invocation)) {
				result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("unit does not join an exact held fixture launch; preserving private fixture")))
			} else {
				pidfd, fdHeld := heldPIDFDs[held.Invocation]
				openedHere := false
				var fdErr error
				if !fdHeld {
					pidfd, fdErr = holdPlanBrokerCPUTerminalPIDFD(held)
					if fdErr == nil {
						openedHere = true
					}
				}
				if fdErr != nil || pidfd < 0 {
					result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("exact held worker pidfd is unavailable; preserving private fixture")))
				} else if unitErr == nil && unit.MainPID > 1 && planBrokerCPULaunchStillCurrent(paths, held) != nil {
					result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("active held worker changed before cleanup stop; preserving private fixture")))
				} else if unitErr == nil && unit.MainPID > 1 && holder != nil && holder.health() != nil {
					result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, errors.New("unit holder health failed before exact cleanup stop; preserving fixture")))
				} else if unitErr == nil && unit.MainPID > 1 && stopPlanBrokerCPUUnit(unitName) != nil {
					result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, errors.New("exact private worker cleanup stop failed; preserving fixture")))
				} else if holder != nil && normalCleanupRequested && holder.health() != nil {
					result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, errors.New("unit holder health failed before final loaded stopped proof; preserving fixture")))
				} else if _, proofErr := waitPlanBrokerCPUStoppedCleanupProof(paths, held, pidfd); proofErr != nil {
					result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, proofErr))
				} else if holder != nil && normalCleanupRequested {
					if err := holder.release(); err != nil {
						result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, err))
					} else {
						holder = nil
					}
				}
				if result == nil {
					if err := confirmPlanBrokerCPUUnitAbsentWithin(paths, unitName, time.Now().Add(5*time.Second)); err != nil {
						result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnit, err))
					}
				}
				if result != nil && holder != nil {
					result = errors.Join(result, planBrokerCPUAbortCleanup(holder))
					holder = nil
					normalCleanupRequested = false
				}
				if openedHere {
					result = planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, settlePlanBrokerCPUOpenedPIDFDClose(result, pidfd, unix.Close))
				}
			}
		} else if !planBrokerCPUUnitConfirmedAbsent(unitName) {
			result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, errors.New("private fixture binding is incomplete and exact unit absence is unknown; preserving private fixture")))
		} else {
			result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, errors.New("private fixture binding is incomplete; preserving private fixture")))
		}
		if result != nil && holder != nil {
			result = errors.Join(result, planBrokerCPUAbortCleanup(holder))
			holder = nil
			normalCleanupRequested = false
		}
		for invocation, pidfd := range heldPIDFDs {
			if err := unix.Close(pidfd); err != nil {
				result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, errors.New("held worker pidfd close failed; preserving private fixture")))
			}
			delete(heldPIDFDs, invocation)
		}
		if result == nil && privateOwned {
			current, err := os.Lstat(root)
			if err != nil || !os.SameFile(rootInfo, current) || !current.IsDir() || filepath.Dir(root) != os.TempDir() || !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root)) {
				result = planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("private workspace identity is uncertain; preserving it"))
			} else if err := os.RemoveAll(root); err != nil {
				result = planBrokerCPUCleanupFailure(planBrokerCPUReasonUncertain, fmt.Errorf("remove exact private workspace: %w", err))
			} else {
				cleaned = true
			}
		} else if result == nil {
			result = planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("private fixture identity is uncertain; preserving it"))
		}
		cleanupOutcome = result
		return cleanupOutcome
	}
	defer func() {
		if err := cleanup(); err != nil {
			for _, marker := range planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect", planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUnavailable, "", err)) { fmt.Fprintln(os.Stdout, marker) }
			t.Errorf("bounded fixture cleanup failed; recovery identities: root=%s unit=%s: %v", root, unitName, err)
		}
	}()

	if err := createPlanBrokerCPUFixtureTree(paths); err != nil || !checkpointPlanBrokerPrivateFixturePathSet(paths) {
		t.Fatal("create exact private fixture tree")
	}
	currentRoot, rootErr := os.Lstat(root)
	if rootErr != nil || !os.SameFile(rootInfo, currentRoot) {
		t.Fatal("private fixture root changed identity while its tree was created")
	}
	if checkpointPlanBrokerUnitName(paths) != unitName {
		t.Fatal("post-tree production unit binding differs from the pre-bound private fixture unit")
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("create fixture root acknowledgement key")
	}
	stopPublic, stopPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("create fixture stop acknowledgement key")
	}
	if err := writePlanBrokerCPUKeys(paths, rootPrivate, rootPublic, stopPrivate, stopPublic, uint32(gid)); err != nil {
		t.Fatal("write exact private fixture keys")
	}
	workerSHA, err := installPlanBrokerCPUWorker(paths)
	if err != nil {
		t.Fatal("install exact worker test image")
	}
	workerExecutable := filepath.Join(root, "worker")
	victim, urgent, err := writePlanBrokerCPUPlans(paths, workerSHA)
	if err != nil {
		t.Fatal("write distinct approved CPU plans")
	}
	secret := strings.Repeat("S", 48)
	if err := writePlanBrokerCPUConfig(paths, uint32(gid)); err != nil {
		t.Fatal("write pinned node fixture configuration")
	}
	if err := writePlanBrokerCPUEnv(paths, secret, uint32(gid)); err != nil {
		t.Fatal("write pinned node fixture environment")
	}
	catalogRaw, err := encodePlanBrokerCPUCatalog(victim, urgent)
	if err != nil || writePlanBrokerCPUFile(paths.Catalog, catalogRaw, 0o644, 0, 0) != nil {
		t.Fatal("write root-approved plan catalog")
	}
	if err := runPlanBrokerCPUParentDeathOracle(workerExecutable, paths, rootInfo, uint32(gid)); err != nil {
		privateOwned = false
		for _, marker := range planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect", err) { fmt.Fprintln(os.Stdout, marker) }
		t.Log("__PLAN_RELAUNCH_PARENT_DEATH_ROOT_PRESERVED__")
		t.Fatalf("fixed parent-death EOF oracle failed; preserving private fixture: %v", err)
	}
	t.Log("__PLAN_RELAUNCH_PARENT_DEATH_EOF_POSITIVE__")
	if err := makePlanBrokerCPUUnrelatedChild(&unrelated, workerExecutable, root, uint32(gid)); err != nil {
		t.Fatal("start exact unrelated child control")
	}
	if err := startPlanBrokerCPUTransient(paths, workerSHA); err != nil {
		t.Fatalf("start exact initial victim unit %s: %v", unitName, err)
	}
	if err := assertPlanBrokerCPUUnitHasParentIndependentDeadline(paths, unitName); err != nil {
		t.Fatalf("transient unit lacks bounded cleanup: %v", err)
	}
	victimBefore, err := planBrokerCPUFixtureUnitState(context.Background(), paths)
	if err != nil || victimBefore.MainPID <= 1 || victimBefore.Invocation == "" {
		t.Fatal("initial victim unit did not reach a fresh live process identity")
	}
	if err := assertPlanBrokerCPUOutsideWorkerCgroup(victimBefore.ControlGroup); err != nil {
		t.Fatal("root broker/test supervisor entered the worker control group")
	}
	if err := waitPlanBrokerCPUWorkerEvent(paths, victimBefore.MainPID); err != nil {
		t.Fatal("initial victim did not record its held source descriptor")
	}
	victimLaunch, err := capturePlanBrokerCPULaunch(paths, victim, victimBefore, "")
	if err != nil {
		t.Fatalf("initial victim custody could not be pinned: %v", err)
	}
	knownLaunches[victimBefore.Invocation] = victimLaunch
	if err := planBrokerCPULaunchStillCurrent(paths, victimLaunch); err != nil {
		t.Fatalf("initial victim identity changed before exact stop: %v", err)
	}
	victimPIDFD, err := holdPlanBrokerCPUTerminalPIDFD(victimLaunch)
	if err != nil {
		t.Fatalf("initial victim pidfd could not be held before stop: %v", err)
	}
	heldPIDFDs[victimLaunch.Invocation] = victimPIDFD
	lastHeldInvocation = victimLaunch.Invocation
	holder, err = startPlanBrokerCPUUnitHolder(paths, rootInfo, victimLaunch, 6)
	if err != nil {
		for _, marker := range planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect", planBrokerCPUFailureAt(planBrokerCPUStageHolderAcquire, planBrokerCPUReasonUnit, "", err)) { fmt.Fprintln(os.Stdout, marker) }
		t.Fatalf("single private unit reference holder could not be established before crash-owner stop: %v", err)
	}
	if err := holder.health(); err != nil {
		t.Fatal("holder same-connection health failed before crash-owner exact stop")
	}
	if err := stopPlanBrokerCPUUnit(unitName); err != nil {
		t.Fatal("stop the exact initial victim unit")
	}
	waitCode, err := waitPlanBrokerCPUStoppedProof(paths, victimLaunch, victimPIDFD)
	if err != nil {
		fmt.Fprintln(os.Stdout, planBrokerCPUInactiveWaitMarker("TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect", waitCode))
		t.Fatal("confirm the first worker is stopped and its cgroup empty")
	}
	priorCommand, victimStopReceipt, err := makePlanBrokerCPUStopAck(paths, "victim_stop", victimBefore, victimLaunch, victimPIDFD, secret, stopPrivate)
	if err != nil || writePlanBrokerCPUStopAck(paths, priorCommand, victimStopReceipt, uint32(gid)) != nil {
		t.Fatal("create and persist linked root-signed victim stop acknowledgement")
	}
	urgentCommand, err := makePlanBrokerCPUCommand(paths, secret, "urgent_load", "urgent-catalog", "victim-catalog", "victim_stop", priorCommand, victimStopReceipt)
	if err != nil {
		t.Fatal("sign linked urgent-load intent")
	}
	commandRaw, err := json.Marshal(urgentCommand)
	if err != nil || writePlanBrokerCPUFile(filepath.Join(paths.NodeStateDir, "urgent_load.command.json"), commandRaw, 0o640, int(uid), int(gid)) != nil {
		t.Fatal("persist exact node-owned urgent command")
	}
	if err := holder.health(); err != nil {
		t.Fatal("holder same-connection health failed before crash-boundary command")
	}
	broker, err = startPlanBrokerCPUBroker(workerExecutable, paths, "start_requested_durable")
	if err != nil {
		privateOwned = false
		t.Fatalf("crash-injected root broker did not become available; preserving root=%s: %v", root, err)
	}
	if err := assertPlanBrokerCPUOutsideWorkerCgroup(victimBefore.ControlGroup); err != nil {
		t.Fatal("root broker/test supervisor entered the worker control group")
	}
	commandOutput, commandErr := runPlanBrokerCPUNodeClient(paths, uint32(uid), uint32(gid), secret, "urgent_load", "command", 0)
	if commandErr != nil || strings.Count(commandOutput, "__PLAN_RELAUNCH_CPU_UNCERTAIN__") != 1 || strings.Contains(commandOutput, "__PLAN_RELAUNCH_CPU_RECONCILED__") {
		t.Fatalf("start_requested crash did not return exactly one pending result: %v", commandErr)
	}
	select {
	case <-broker.waitDone:
	case <-time.After(5 * time.Second):
		privateOwned = false
		t.Fatalf("broker did not exit at the fixed start_requested crash hook; preserving root=%s", root)
	}
	var crashExit *exec.ExitError
	if !errors.As(broker.waitErr, &crashExit) || crashExit.ExitCode() != planBrokerCPUCrashExit {
		privateOwned = false
		t.Fatalf("broker did not report the exact injected crash exit; preserving root=%s", root)
	}
	crashedBroker := broker
	if err := stopPlanBrokerCPUBroker(crashedBroker); err != nil {
		privateOwned = false
		t.Fatalf("crashed broker custody/socket cleanup is uncertain; preserving root=%s: %v", root, err)
	}
	broker = nil

	operationID := fmt.Sprint(urgentCommand.Args["operation_id"])
	journalBefore, err := os.ReadFile(paths.Journal)
	if err != nil {
		t.Fatal("read durable start-request journal")
	}
	journal, err := loadCheckpointPlanBrokerJournal(paths.Journal, paths)
	operation, exists := journal.Operations[operationID]
	wire, wireErr := wsproto.CanonicalCommandEnvelope(urgentCommand)
	step := operation.Steps["urgent_load"]
	var durableUrgent wsproto.CommandPayload
	decodeErr := rejectDuplicateJSONKeys(step.OriginalEnvelope)
	if decodeErr == nil {
		decodeErr = json.Unmarshal(step.OriginalEnvelope, &durableUrgent)
	}
	canonicalDurable, canonicalErr := wsproto.CanonicalCommandEnvelope(durableUrgent)
	priorCommandID, commandIDOK := durableUrgent.Args["prior_command_id"].(string)
	priorIdempotencyKey, idempotencyOK := durableUrgent.Args["prior_idempotency_key"].(string)
	priorReceiptSHA256, receiptSHAOK := durableUrgent.Args["prior_receipt_sha256"].(string)
	argsErr := wsproto.ValidatePlanRelaunchCommandArgs(durableUrgent.Command, durableUrgent.Args)
	if err != nil || !exists || operation.Stage != "urgent_load_start_requested" || operation.Operation.OperationID != operationID || operation.Operation.Fence != 41 || operation.Operation.RecoveryEpoch != "cpu-epoch-1" || operation.Operation.UrgentCatalogID != "urgent-catalog" || operation.Operation.VictimCatalogID != "victim-catalog" || operation.PriorInvocation != victimBefore.Invocation || step.CommandID != urgentCommand.ID || step.IdempotencyKey != urgentCommand.IdempotencyKey || step.EnvelopeSHA256 != sha256Hex(wire) || !bytes.Equal(step.OriginalEnvelope, wire) || decodeErr != nil || argsErr != nil || canonicalErr != nil || !bytes.Equal(canonicalDurable, step.OriginalEnvelope) || durableUrgent.ID != urgentCommand.ID || durableUrgent.IdempotencyKey != urgentCommand.IdempotencyKey || priorCommandID != priorCommand.ID || priorIdempotencyKey != priorCommand.IdempotencyKey || priorReceiptSHA256 != sha256Hex(victimStopReceipt) || !commandIDOK || !idempotencyOK || !receiptSHAOK || step.EnvelopeSHA256 != sha256Hex(step.OriginalEnvelope) || step.CommandID != durableUrgent.ID || step.IdempotencyKey != durableUrgent.IdempotencyKey || wireErr != nil {
		t.Fatal("durable journal does not prove the exact linked start_requested boundary")
	}
	planBefore, err := os.ReadFile(paths.ActivePlan)
	if err != nil || sha256Hex(planBefore) != operation.PlanSHA256 || sha256Hex(planBefore) != sha256Hex(mustJSON(urgent)) {
		t.Fatal("published urgent plan does not match the durable journal")
	}
	if _, err := readPlanBrokerCPUReceipt(paths, urgentCommand.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("start_requested boundary unexpectedly has a root receipt")
	}
	unitBefore, err := planBrokerCPUFixtureUnitState(context.Background(), paths)
	if err != nil || unitBefore.MainPID != 0 || unitBefore.Active != "inactive" || unitBefore.Invocation != victimBefore.Invocation || checkpointPlanBrokerWorkerEmpty(context.Background(), paths, unitBefore) != nil {
		t.Fatal("crash boundary did not leave the exact unit inactive with no jobs or worker cgroup")
	}
	eventsBefore, err := os.ReadDir(filepath.Join(root, "var", "events"))
	if err != nil || len(eventsBefore) != 1 || eventsBefore[0].Name() != strconv.Itoa(victimBefore.MainPID)+".json" {
		t.Fatal("unexpected worker event appeared before the first linked query")
	}
	if !planBrokerCPUUnrelatedChildAlive(unrelated) {
		t.Fatal("unrelated child control did not survive the injected crash")
	}

	broker, err = startPlanBrokerCPUBroker(workerExecutable, paths)
	if err != nil {
		privateOwned = false
		t.Fatalf("cold root broker did not restart; preserving root=%s: %v", root, err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := holder.health(); err != nil {
			t.Fatalf("holder same-connection health failed before linked query %d", attempt)
		}
		queryOutput, queryErr := runPlanBrokerCPUNodeClient(paths, uint32(uid), uint32(gid), secret, "urgent_load", "query", attempt)
		unitNow, unitErr := planBrokerCPUFixtureUnitState(context.Background(), paths)
		if unitErr == nil && unitNow.MainPID > 1 && unitNow.Active == "active" && unitNow.Invocation != victimBefore.Invocation {
			eventReadyErr := waitPlanBrokerCPUWorkerEvent(paths, unitNow.MainPID)
			launch, captureErr := capturePlanBrokerCPULaunch(paths, urgent, unitNow, victimBefore.Invocation)
			if eventReadyErr == nil && captureErr == nil {
				knownLaunches[unitNow.Invocation] = launch
				lastHeldInvocation = unitNow.Invocation
			}
		}
		if unitErr != nil || unitNow.MainPID != 0 || unitNow.Active != "inactive" || unitNow.Invocation != victimBefore.Invocation {
			t.Fatalf("ambiguous start recovery changed unit/MainPID on linked query %d", attempt)
		}
		journalNow, journalErr := os.ReadFile(paths.Journal)
		planNow, planErr := os.ReadFile(paths.ActivePlan)
		if checkpointPlanBrokerWorkerEmpty(context.Background(), paths, unitNow) != nil || journalErr != nil || !bytes.Equal(journalNow, journalBefore) || planErr != nil || !bytes.Equal(planNow, planBefore) {
			t.Fatalf("ambiguous start recovery changed durable or unit state on linked query %d", attempt)
		}
		if _, receiptErr := readPlanBrokerCPUReceipt(paths, urgentCommand.ID); !errors.Is(receiptErr, os.ErrNotExist) {
			t.Fatalf("ambiguous start recovery created a receipt on linked query %d", attempt)
		}
		eventsNow, eventsErr := os.ReadDir(filepath.Join(root, "var", "events"))
		if eventsErr != nil || len(eventsNow) != len(eventsBefore) || eventsNow[0].Name() != eventsBefore[0].Name() {
			t.Fatalf("ambiguous start recovery launched another worker on linked query %d", attempt)
		}
		if queryErr != nil || strings.Count(queryOutput, "__PLAN_RELAUNCH_CPU_UNCERTAIN__") != 1 || strings.Contains(queryOutput, "__PLAN_RELAUNCH_CPU_RECONCILED__") {
			t.Fatalf("fresh signed linked query %d did not remain exactly uncertain: %v", attempt, queryErr)
		}
		if !planBrokerCPUUnrelatedChildAlive(unrelated) {
			t.Fatalf("unrelated child control did not survive linked query %d", attempt)
		}
	}
	normalCleanupRequested = true
	if err := cleanup(); err != nil {
		privateOwned = false
		t.Fatalf("crash-owner fixture cleanup could not prove exact effects: root=%s unit=%s: %v", root, unitName, err)
	}
	t.Log("two fresh signed queries remained uncertain without changing journal, plan, receipt, unit state, or unrelated child")
}

func TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {
	role := os.Getenv(planBrokerCPURole)
	if role == "holder-control-parent" {
		runPlanBrokerCPUHolderControlParent(t)
		return
	}
	if role == "parent-helper" {
		runPlanBrokerCPUParentDeathHelper(t)
		return
	}
	if role == "broker" {
		if os.Geteuid() != 0 || os.Getenv(planBrokerCPUEnv) != planBrokerCPUOptIn {
			t.Fatal("broker subprocess requires the local root opt-in")
		}
		root := os.Getenv("VRAM_PLAN_BROKER_CPU_ROOT")
		gid, err := strconv.ParseUint(os.Getenv(planBrokerCPUNodeGIDEnv), 10, 32)
		if !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root)) || filepath.Dir(root) != os.TempDir() || err != nil || gid == 0 {
			t.Fatal("broker subprocess fixture identity is invalid")
		}
		parentCtx, stopParentGuard, err := armPlanBrokerCPUParentGuard()
		if err != nil {
			t.Fatalf("broker parent guard was not ready before socket creation: %v", err)
		}
		defer stopParentGuard()
		ctx, cancel := signal.NotifyContext(parentCtx, syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		paths := checkpointPlanBrokerCPUPaths(root, 65534, uint32(gid))
		if crashAt := os.Getenv(planBrokerCPUCrashAtEnv); crashAt != "" {
			if crashAt != "start_requested_durable" {
				t.Fatal("broker crash selector is outside the one fixed test boundary")
			}
			paths.faultInjector = func(boundary string) bool {
				if boundary == "start_requested_durable" {
					os.Exit(planBrokerCPUCrashExit)
				}
				return false
			}
		}
		if err := runCheckpointLifecycleBrokerPlatform(ctx, paths); err != nil && ctx.Err() == nil {
			t.Fatalf("fixed fixture broker exited unexpectedly: %v", err)
		}
		return
	}
	if role == "unrelated" {
		if os.Geteuid() != 0 || os.Getenv(planBrokerCPUEnv) != planBrokerCPUOptIn {
			t.Fatal("unrelated parent-guard child requires the fixed local opt-in")
		}
		parentCtx, stopParentGuard, err := armPlanBrokerCPUParentGuard()
		if err != nil {
			t.Fatalf("unrelated child parent guard was not armed: %v", err)
		}
		defer stopParentGuard()
		<-parentCtx.Done()
		return
	}
	if role != "worker" {
		return
	}
	root := os.Getenv("VRAM_PLAN_BROKER_CPU_ROOT")
	if !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root)) {
		t.Fatal("worker fixture root is invalid")
	}
	raw, err := os.ReadFile(filepath.Join(root, "etc", "active-plan.json"))
	var plan CheckpointLaunchPlan
	nodeGID, gidErr := strconv.ParseUint(os.Getenv(planBrokerCPUNodeGIDEnv), 10, 32)
	if err != nil || gidErr != nil || json.Unmarshal(raw, &plan) != nil || validateCheckpointPlanBrokerPlan(checkpointPlanBrokerCPUPaths(root, 65534, uint32(nodeGID)), plan) != nil {
		t.Fatal("worker could not read the exact active plan")
	}
	model, err := os.Open(plan.Model.Path)
	if err != nil {
		t.Fatal("worker could not hold its exact model source")
	}
	defer model.Close()
	info, err := model.Stat()
	if err != nil {
		t.Fatal("worker held model descriptor is unavailable")
	}
	executablePath, exeErr := os.Executable()
	executableSHA, executableBytes, digestErr := fileDigest(executablePath)
	executableInfo, exeStatErr := os.Stat(executablePath)
	if exeErr != nil || digestErr != nil || exeStatErr != nil || executableBytes <= 0 {
		t.Fatal("worker executable identity is unavailable")
	}
	pid := os.Getpid()
	ticks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil || ticks == 0 {
		t.Fatal("worker process incarnation is unavailable")
	}
	event := map[string]any{"pid": pid, "start_ticks": ticks, "alias": plan.Alias, "model_path": plan.Model.Path, "model_sha256": plan.Model.SHA256, "model_size": info.Size(), "model_dev": infoSysDevice(info), "model_ino": infoSysInode(info), "executable_path": executablePath, "executable_sha256": executableSHA, "executable_dev": infoSysDevice(executableInfo), "executable_ino": infoSysInode(executableInfo)}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal("worker evidence could not be encoded")
	}
	if err := os.WriteFile(filepath.Join(root, "var", "events", strconv.Itoa(pid)+".json"), encoded, 0o600); err != nil {
		t.Fatal("worker identity event could not be recorded")
	}
	notices := make(chan os.Signal, 2)
	signal.Notify(notices, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(notices)
	<-notices
}

func infoSysDevice(info os.FileInfo) uint64 {
	stat, _ := infoSys(info)
	if stat == nil {
		return 0
	}
	return uint64(stat.Dev)
}
func infoSysInode(info os.FileInfo) uint64 {
	stat, _ := infoSys(info)
	if stat == nil {
		return 0
	}
	return stat.Ino
}

func mustPlanBrokerWire(command wsproto.CommandPayload) []byte {
	wire, _ := wsproto.CanonicalCommandEnvelope(command)
	return wire
}
func mustReadPlanBrokerCPUStopPublic(paths checkpointPlanBrokerPaths) []byte {
	key, _ := readPinnedRootStopPublicKeyAt(paths.StopPublicKey, checkpointPlanBrokerOwnedStopPaths(paths))
	return key
}

func readPlanBrokerCPUOSRelease(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal("WSL kernel identity is unavailable")
	}
	return string(body)
}

func newPlanBrokerCPUFixtureRoot() (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		path := filepath.Join(os.TempDir(), "vram-plan-relaunch-cpu-"+hex.EncodeToString(raw))
		if err := os.Mkdir(path, 0o711); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", err
		}
		if err := os.Chmod(path, 0o711); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", errors.New("could not allocate a unique fixture name")
}

func checkpointPlanBrokerCPUPaths(root string, uid, gid uint32) checkpointPlanBrokerPaths {
	return checkpointPlanBrokerPaths{Socket: filepath.Join(root, "run", "plan.sock"), RuntimeDir: filepath.Join(root, "run"), Catalog: filepath.Join(root, "etc", "checkpoint-plan-catalog.json"), ActivePlan: filepath.Join(root, "etc", "active-plan.json"), PrivateKey: filepath.Join(root, "var", "private", "ed25519.key"), PublicKey: filepath.Join(root, "var", "public", "ed25519.pub"), Journal: filepath.Join(root, "var", "private", "operations.json"), ReceiptDir: filepath.Join(root, "var", "public", "receipts"), StopPrivateKey: filepath.Join(root, "var", "stop-private", "ed25519.key"), StopPublicKey: filepath.Join(root, "var", "stop-public", "ed25519.pub"), StopReceiptDir: filepath.Join(root, "var", "stop-public", "receipts"), NodeConfig: filepath.Join(root, "etc", "node-agent.yaml"), NodeEnv: filepath.Join(root, "etc", "node-agent.env"), NodeState: filepath.Join(root, "var", "node", "commands.json"), NodeStateDir: filepath.Join(root, "var", "node"), NodeUID: uid, NodeGID: gid, fixtureRoot: root, fixtureUnit: filepath.Base(root) + ".service", bindingObserver: observePlanBrokerCPUWorker, privateFixture: true}
}

// Before the descendants exist, checkpointPlanBrokerUnitName intentionally
// falls back to the fixed production unit. Bind the held private root directly.
func prebindPlanBrokerCPUFixtureUnit(paths checkpointPlanBrokerPaths, root string, held os.FileInfo) (string, error) {
	if held == nil || root == "" || filepath.Clean(root) != root || !filepath.IsAbs(root) || paths.fixtureRoot != root || !paths.privateFixture || paths.NodeUID != 65534 || paths.NodeGID == 0 {
		return "", errors.New("private fixture root binding is incomplete")
	}
	parent, parentErr := filepath.EvalSymlinks(filepath.Dir(root))
	temp, tempErr := filepath.EvalSymlinks(os.TempDir())
	current, statErr := os.Lstat(root)
	rootStat, rootStatOK := infoSys(held)
	currentStat, currentStatOK := infoSys(current)
	unit := filepath.Base(root) + ".service"
	if parentErr != nil || tempErr != nil || filepath.Clean(parent) != filepath.Clean(temp) || filepath.Dir(root) != filepath.Clean(os.TempDir()) ||
		statErr != nil || !os.SameFile(held, current) || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || current.Mode().Perm() != 0o711 ||
		!rootStatOK || rootStat.Uid != 0 || !currentStatOK || currentStat.Uid != 0 || !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root)) ||
		paths.fixtureUnit != unit || unit == checkpointPlanBrokerUnit || filepath.Base(unit) != unit || strings.ContainsAny(unit, "/\\") {
		return "", errors.New("private fixture root or unit is not the exact held canonical identity")
	}
	return unit, nil
}

func planBrokerCPUFixtureUnitIdentity(paths checkpointPlanBrokerPaths, unit string) bool {
	return paths.privateFixture && filepath.Clean(paths.fixtureRoot) == paths.fixtureRoot && filepath.IsAbs(paths.fixtureRoot) &&
		checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(paths.fixtureRoot)) && paths.fixtureUnit == filepath.Base(paths.fixtureRoot)+".service" &&
		unit == paths.fixtureUnit && unit != checkpointPlanBrokerUnit && filepath.Base(unit) == unit && !strings.ContainsAny(unit, "/\\")
}

func planBrokerCPUFixtureUnitBound(paths checkpointPlanBrokerPaths, unit string) bool {
	return planBrokerCPUFixtureUnitIdentity(paths, unit) && checkpointPlanBrokerPrivateFixturePathSet(paths) && checkpointPlanBrokerUnitName(paths) == unit
}

func planBrokerCPUFixtureUnitState(ctx context.Context, paths checkpointPlanBrokerPaths) (checkpointFixedUnitState, error) {
	unit, err, _ := planBrokerCPUFixtureUnitStateObserved(ctx, paths)
	return unit, err
}

func planBrokerCPUFixtureUnitStateObserved(ctx context.Context, paths checkpointPlanBrokerPaths) (checkpointFixedUnitState, error, string) {
	capturedUnit := paths.fixtureUnit
	if !planBrokerCPUFixtureUnitBound(paths, capturedUnit) {
		return checkpointFixedUnitState{}, errors.New("exact private fixture unit binding is unavailable"), "private_binding"
	}
	raw, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "show", capturedUnit, "--property=MainPID", "--property=InvocationID", "--property=ControlGroup", "--property=ActiveState", "--property=SubState")
	if err != nil {
		return checkpointFixedUnitState{}, errors.New("exact private fixture unit state is unavailable"), "show_unavailable"
	}
	if len(raw) == 0 || len(raw) > checkpointUnitMaxOutput || raw[len(raw)-1] != '\n' {
		return checkpointFixedUnitState{}, errors.New("exact private fixture unit state is unavailable"), "show_envelope"
	}
	unit, err := parseCheckpointPlanBrokerUnitState(raw)
	if err != nil {
		if shapeCode := planBrokerCPUUnitStateParseShapeCode(raw); shapeCode != "state_parse" {
			return checkpointFixedUnitState{}, err, shapeCode
		}
		return checkpointFixedUnitState{}, err, "state_parse"
	}
	if capturedUnit != paths.fixtureUnit || !planBrokerCPUFixtureUnitBound(paths, capturedUnit) {
		return checkpointFixedUnitState{}, errors.New("private fixture binding changed during unit-state query"), "private_binding"
	}
	return unit, nil, ""
}

func planBrokerCPUFixtureStoppedStateObserved(ctx context.Context, paths checkpointPlanBrokerPaths) (checkpointPlanBrokerStoppedState, error, string) {
	raw, err, code := planBrokerCPUFixtureStoppedStateRaw(ctx, paths)
	if err != nil {
		return checkpointPlanBrokerStoppedState{}, err, code
	}
	observed, err := parseCheckpointPlanBrokerStoppedState(raw)
	if err != nil {
		if shapeCode := planBrokerCPUStoppedStateParseShapeCode(raw, paths.fixtureUnit); shapeCode != "state_parse" {
			return checkpointPlanBrokerStoppedState{}, err, shapeCode
		}
		return checkpointPlanBrokerStoppedState{}, err, "state_parse"
	}
	return observed, nil, ""
}

func planBrokerCPUFixtureStoppedStateRaw(ctx context.Context, paths checkpointPlanBrokerPaths) ([]byte, error, string) {
	capturedUnit := paths.fixtureUnit
	if !planBrokerCPUFixtureUnitBound(paths, capturedUnit) {
		return nil, errors.New("exact private fixture unit binding is unavailable"), "private_binding"
	}
	raw, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "show", capturedUnit, "--property=MainPID", "--property=InvocationID", "--property=ControlGroup", "--property=ActiveState", "--property=SubState", "--property=LoadState")
	if err != nil {
		return nil, errors.New("exact private fixture stopped state is unavailable"), "show_unavailable"
	}
	if len(raw) == 0 || len(raw) > checkpointUnitMaxOutput || raw[len(raw)-1] != '\n' {
		return nil, errors.New("exact private fixture stopped state is unavailable"), "show_envelope"
	}
	if capturedUnit != paths.fixtureUnit || !planBrokerCPUFixtureUnitBound(paths, capturedUnit) {
		return nil, errors.New("private fixture binding changed during stopped-state query"), "private_binding"
	}
	return raw, nil, ""
}

func planBrokerCPUStoppedStateParseShapeCode(raw []byte, unit string) string {
	observed, err := parseCheckpointPlanBrokerStoppedObservation(raw)
	if err != nil || observed.Load != "not-found" || unit == "" || filepath.Base(unit) != unit || !strings.HasSuffix(unit, ".service") {
		return "state_parse"
	}
	invocationEmpty, groupEmpty := observed.Invocation == "", observed.ControlGroup == ""
	if invocationEmpty != groupEmpty {
		return "state_parse"
	}
	if !invocationEmpty {
		decoded, decodeErr := hex.DecodeString(observed.Invocation)
		if decodeErr != nil || len(decoded) != 16 || observed.Invocation != strings.ToLower(observed.Invocation) || observed.ControlGroup != filepath.Join("/system.slice", unit) {
			return "state_parse"
		}
	}
	return "unit_definition_missing"
}

func planBrokerCPUUnitStateParseShapeCode(raw []byte) string {
	if len(raw) == 0 || len(raw) > checkpointUnitMaxOutput || raw[len(raw)-1] != '\n' || !utf8.Valid(raw) {
		return "state_parse"
	}
	values := make(map[string]string, 5)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if strings.IndexFunc(line, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return "state_parse"
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "MainPID" && key != "InvocationID" && key != "ControlGroup" && key != "ActiveState" && key != "SubState") {
			return "state_parse"
		}
		if _, exists := values[key]; exists {
			return "state_parse"
		}
		values[key] = value
	}
	if len(values) != 5 {
		return "state_parse"
	}
	for _, key := range []string{"MainPID", "ActiveState", "SubState"} {
		if values[key] == "" {
			return "state_parse"
		}
	}
	invocationEmpty := values["InvocationID"] == ""
	controlGroupEmpty := values["ControlGroup"] == ""
	pid, err := strconv.Atoi(values["MainPID"])
	pidStateInvalid := err != nil || pid < 0 || pid == 1 ||
		(pid == 0 && values["ActiveState"] != "inactive" && values["ActiveState"] != "failed") ||
		(pid > 1 && values["ActiveState"] != "active")
	if pidStateInvalid {
		if invocationEmpty || controlGroupEmpty {
			return "state_parse"
		}
		return "pid_state_shape"
	}
	switch {
	case invocationEmpty && controlGroupEmpty:
		return "empty_invocation_control_group"
	case invocationEmpty:
		return "empty_invocation"
	case controlGroupEmpty:
		return "empty_control_group"
	default:
		return "state_parse"
	}
}

func createPlanBrokerCPUFixtureTree(paths checkpointPlanBrokerPaths) error {
	root := paths.fixtureRoot
	entries := []struct {
		relative string
		mode     os.FileMode
	}{
		{"run", 0o750}, {"etc", 0o755}, {"var", 0o711}, {"var/private", 0o700},
		{"var/public", 0o755}, {"var/public/receipts", 0o750}, {"var/stop-private", 0o700},
		{"var/stop-public", 0o750}, {"var/stop-public/receipts", 0o750}, {"var/node", 0o700},
		{"var/events", 0o755}, {"var/custody", 0o700}, {"var/snapshots", 0o700}, {"models", 0o755},
	}
	for _, entry := range entries {
		path := filepath.Join(root, filepath.FromSlash(entry.relative))
		if err := os.Mkdir(path, entry.mode); err != nil {
			return err
		}
		uid, gid := 0, 0
		if entry.relative == "var/node" {
			uid, gid = int(paths.NodeUID), int(paths.NodeGID)
		}
		if strings.HasPrefix(entry.relative, "var/public/receipts") || strings.HasPrefix(entry.relative, "var/stop-public") || entry.relative == "run" {
			gid = int(paths.NodeGID)
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(path, entry.mode); err != nil {
			return err
		}
	}
	return nil
}

func startPlanBrokerCPUUnitHolder(paths checkpointPlanBrokerPaths, rootInfo os.FileInfo, held planBrokerCPULaunchIdentity, maxHealth int) (*planBrokerCPUUnitHolder, error) {
	control := planBrokerCPUHolderNegativeControl
	deadline := time.Now().Add(5 * time.Second)
	if control != "" {
		deadline = time.Now().Add(planBrokerCPUHolderNegativeControlBudget(control))
	}
	holder, err := startPlanBrokerCPUUnitHolderMode(paths, rootInfo, held, maxHealth, control, deadline)
	if err != nil || control != planBrokerCPUControlNegativeRefError {
		return holder, err
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonIdentity, errors.New("injected RefUnit negative lacks the exact held root identity"), holder)
	}
	request := fmt.Sprintf("ACQUIRE\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", base64.StdEncoding.EncodeToString([]byte(paths.fixtureRoot)), rootStat.Dev, rootStat.Ino, rootStat.Uid, rootStat.Gid, paths.NodeGID, os.Getpid(), held.UnitName)
	acquireDeadline := time.Now().Add(5 * time.Second)
	if err := holder.send(request); err != nil {
		return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.Join(errors.New("synthetic pre-RefUnit request failed"), err), holder)
	}
	frame, readErr := holder.readFrameUntil(acquireDeadline)
	if readErr != nil || frame != "NEGATIVE_RESULT\tnegative_ref_error\tinjected_before_ref" {
		return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.Join(errors.New("fixed helper did not report the synthetic pre-RefUnit failure"), readErr), holder)
	}
	select {
	case <-holder.waitDone:
	case <-time.After(time.Until(acquireDeadline)):
		return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonDeadline, errors.New("synthetic pre-RefUnit helper did not settle under its original deadline"), holder)
	}
	status, validStatus := holder.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !validStatus || !status.Exited() || status.ExitStatus() != 148 || planBrokerCPULaunchStillCurrent(paths, held) != nil {
		return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonExit, errors.New("synthetic pre-RefUnit failure did not preserve the exact worker or exit status"), holder)
	}
	if closeErr := holder.closeFiles(); closeErr != nil {
		return nil, errors.Join(planBrokerCPUFailureOrigin(planBrokerCPUReasonUnavailable, errors.New("synthetic pre-RefUnit helper custody close is uncertain")), planBrokerCPUCleanupFailure(planBrokerCPUFailureReasonOf(closeErr), closeErr))
	}
	return nil, errPlanBrokerCPUInjectedRefError
}

var errPlanBrokerCPUInjectedRefError = errors.New("synthetic holder failure injected before the RefUnit API call")

func isPlanBrokerCPUInjectedRefError(err error) bool {
	return errors.Is(err, errPlanBrokerCPUInjectedRefError)
}


func startPlanBrokerCPUUnitHolderControl(paths checkpointPlanBrokerPaths, rootInfo os.FileInfo, held planBrokerCPULaunchIdentity, maxHealth int, control planBrokerCPUHolderControl, deadline time.Time) (*planBrokerCPUUnitHolder, string, error) {
	if planBrokerCPUHolderControlTarget(control) == "" {
		return nil, "", errors.New("holder control is not a member of the fixed compiled enum")
	}
	holder, err := startPlanBrokerCPUUnitHolderMode(paths, rootInfo, held, maxHealth, control, deadline)
	if err != nil { return nil, "", err }
	target := planBrokerCPUHolderControlTarget(control)
	if target == "pre_ready" {
		frame, err := holder.readFrameUntil(deadline)
		if err != nil {
			primary := planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderHelperRead, err)
			if control == planBrokerCPUControlWatchdogNative { return nil, "", planBrokerCPUJoinPrimaryAbortForHelperRead(planBrokerCPUReasonPipe, err, primary, holder) }
			return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, primary, holder)
		}
		if frame != "CONTROL_READY\t"+string(control)+"\t"+target { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderHelperShape, errors.New("fixed pre-ready control handshake did not match its compiled case")), holder) }
		if control == planBrokerCPUControlWatchdogCap {
			if n, err := holder.guard.Write([]byte{'P'}); err != nil { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapGuardSend, err), holder) } else if n != 1 { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapGuardSend, errors.New("fixed shortened-cap guard bootstrap was short")), holder) }
			holder.bytes++
			holder.messages++
			if holder.maxFrame < 1 { holder.maxFrame = 1 }
			ready, readyErr := holder.readFrameUntil(deadline)
			if readyErr != nil { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapGuardRead, readyErr), holder) }
			if ready != "GUARD_READY" { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapGuardShape, errors.New("shortened-cap helper did not prove normal guard readiness")), holder) }
			st, ok := rootInfo.Sys().(*syscall.Stat_t)
			if !ok { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonIdentity, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapRootMetadata, errors.New("shortened-cap root metadata is unavailable")), holder) }
			request := fmt.Sprintf("ACQUIRE\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", base64.StdEncoding.EncodeToString([]byte(paths.fixtureRoot)), st.Dev, st.Ino, st.Uid, st.Gid, paths.NodeGID, os.Getpid(), held.UnitName)
			if err := holder.send(request); err != nil { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapAcquireSend, err), holder) }
			ref, refErr := holder.readFrameUntil(deadline)
			parts := strings.Split(ref, "\t")
			if refErr != nil { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapRefRead, refErr), holder) }
			if len(parts) != 3 || parts[0] != "REF_READY" || len(ref) > 192 || !planBrokerCPUValidBusName(parts[1]) || !planBrokerCPUValidBusName(parts[2]) { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapRefShape, errors.New("shortened-cap control did not acquire its one exact D-Bus reference")), holder) }
			holder.unit = held.UnitName
		}
		return holder, frame, nil
	}
	if target == "startup" {
		// This typed event is emitted by the Go controller only after it has
		// captured the spawned helper's exact pidfd/start/image/root identity.
		// The child itself has not reported GUARD_READY or any control phase.
		return holder, "CONTROL_READY\t"+string(control)+"\tstartup", nil
	}
	if target == "after_rearm" {
		frame, err := holder.readFrameUntil(deadline)
		if err != nil || frame != "CONTROL_READY\t"+string(control)+"\t"+target { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.New("fixed after-rearm control handshake did not match"), holder) }
		return holder, frame, nil
	}
	if target == "watchdog_omitted" {
		frame, readErr := holder.readFrameUntil(deadline)
		if readErr != nil || frame != "NEGATIVE_READY\tnegative_watchdog_omitted" {
			return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.New("watchdog omission helper did not emit its exact fixed negative-ready event"), holder)
		}
		return holder, frame, nil
	}
	root := paths.fixtureRoot
	st, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonIdentity, errors.New("controlled holder root metadata is unavailable"), holder) }
	request := fmt.Sprintf("ACQUIRE\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", base64.StdEncoding.EncodeToString([]byte(root)), st.Dev, st.Ino, st.Uid, st.Gid, paths.NodeGID, os.Getpid(), held.UnitName)
	acquireDeadline := time.Now().Add(5 * time.Second)
	if time.Until(deadline) < time.Until(acquireDeadline) { acquireDeadline = deadline }
	if err := holder.send(request); err != nil { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, err, holder) }
	if target == "ref_error" {
		frame, readErr := holder.readFrameUntil(deadline)
		if readErr != nil || frame != "NEGATIVE_RESULT\tnegative_ref_error\tinjected_before_ref" {
			return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.New("RefUnit negative did not report its exact pre-call injection"), holder)
		}
		select {
		case <-holder.waitDone:
		case <-time.After(time.Until(deadline)):
			return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonDeadline, errors.New("injected RefUnit negative did not settle under its shared deadline"), holder)
		}
		status, ok := holder.cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !ok || !status.Exited() || status.ExitStatus() != 148 {
			return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonExit, errors.New("injected RefUnit negative did not exit at its exact fixed pre-call boundary"), holder)
		}
		return holder, frame, nil
	}
	if target == "close" {
		frame, err := holder.readFrameUntil(acquireDeadline)
		if err != nil || !strings.HasPrefix(frame, "REF_READY\t") { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.New("controlled close-boundary case did not acquire the exact unit reference"), holder) }
		holder.unit = held.UnitName
		return holder, frame, nil
	}
	if target == "held_idle" {
		frame, err := holder.readFrameUntil(acquireDeadline)
		if err != nil || !strings.HasPrefix(frame, "REF_READY\t") { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.New("controlled held-idle case did not acquire the exact unit reference"), holder) }
	}
	frame, err := holder.readFrameUntil(acquireDeadline)
	if err != nil || frame != "CONTROL_READY\t"+string(control)+"\t"+target { return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.New("fixed phase control handshake did not match its compiled case"), holder) }
	return holder, frame, nil
}

func readPlanBrokerCPUHolderControlCase() (planBrokerCPUHolderControl, error) {
	file := os.NewFile(3, "fixed-holder-control-case")
	if file == nil { return "", errors.New("fixed holder control pipe is absent") }
	defer file.Close()
	info, statErr := file.Stat()
	if statErr != nil || info.Mode()&os.ModeNamedPipe == 0 { return "", errors.New("fixed holder control transport is not a pipe") }
	var token []byte
	for len(token) <= 64 {
		var one [1]byte
		n, err := file.Read(one[:])
		if err != nil || n != 1 { return "", errors.New("fixed holder control pipe ended before its closed enum") }
		if one[0] == '\n' {
			var trailing [1]byte
			if n, err := file.Read(trailing[:]); n != 0 || !errors.Is(err, io.EOF) { return "", errors.New("fixed holder control pipe has trailing bytes") }
			break
		}
		if one[0] < 0x21 || one[0] > 0x7e { return "", errors.New("fixed holder control enum contains a non-ASCII byte") }
		token = append(token, one[0])
	}
	control := planBrokerCPUHolderControl(token)
	if len(token) == 0 || planBrokerCPUHolderControlTarget(control) == "" { return "", errors.New("fixed holder control token is outside the compiled enum") }
	return control, nil
}

func planBrokerCPUHolderControlMessageCount(control planBrokerCPUHolderControl) int {
	switch control {
	case planBrokerCPUControlNegativeRefError:
		return 5
	case planBrokerCPUControlNegativeWatchdogOmit:
		return 2
	case planBrokerCPUControlWatchdogNative, planBrokerCPUControlPreReadyDeath:
		return 2
	case planBrokerCPUControlWatchdogCap:
		return 12
	case planBrokerCPUControlStartupDeath:
		return 1
	case planBrokerCPUControlImportDeath, planBrokerCPUControlConstructorDeath, planBrokerCPUControlMethodDeath:
		return 5
	case planBrokerCPUControlHeldIdleDeath:
		return 6
	case planBrokerCPUControlCloseDeath:
		return 7
	case planBrokerCPUControlAfterRearmDeath:
		return 6
	default:
		return 0
	}
}

func runPlanBrokerCPUHolderControlParent(t *testing.T) {
	control, err := readPlanBrokerCPUHolderControlCase()
	if err != nil { t.Fatal("private holder control case is invalid") }
	watchdogFailure := control == planBrokerCPUControlWatchdogNative || control == planBrokerCPUControlWatchdogCap
	emitPreReadyFailure := func(site planBrokerCPUPreReadyFailureSite) {
		if watchdogFailure && !planBrokerCPUWritePreReadyFailureFrame(os.Stdout, control, site) {
			// A failed single checked write leaves the original fatal generic.
		}
	}
	emitNativeHelperReadFailure := func(site planBrokerCPUPreReadyFailureSite, diagnostic planBrokerCPUHolderReadDiagnostic) {
		if watchdogFailure && control == planBrokerCPUControlWatchdogNative && !planBrokerCPUWriteNativeHelperReadFailureFrame(os.Stdout, control, site, diagnostic) {
			// A failed single checked write leaves the original fatal generic.
		}
	}
	root := os.Getenv("VRAM_PLAN_BROKER_CPU_ROOT")
	nodeGID, err := strconv.ParseUint(os.Getenv(planBrokerCPUNodeGIDEnv), 10, 32)
	if !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root)) || filepath.Dir(root) != os.TempDir() || err != nil || nodeGID == 0 || os.Geteuid() != 0 {
		emitPreReadyFailure(planBrokerCPUFailureSiteCaseOrRoot)
		t.Fatal("fixed holder control parent identity is invalid")
	}
	paths := checkpointPlanBrokerCPUPaths(root, 65534, uint32(nodeGID))
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o711 { emitPreReadyFailure(planBrokerCPUFailureSiteCaseOrRoot); t.Fatal("fixed holder control root is not exact") }
	caseBudget := planBrokerCPUHolderControlBudget(control)
	if caseBudget == 0 {
		caseBudget = planBrokerCPUHolderNegativeControlBudget(control)
	}
	if caseBudget <= time.Second { emitPreReadyFailure(planBrokerCPUFailureSiteBudget); t.Fatal("fixed holder control case has no finite deadline") }
	caseDeadline := time.Now().Add(caseBudget)
	unitCtx, cancelUnit := context.WithDeadline(context.Background(), caseDeadline)
	unit, err := planBrokerCPUFixtureUnitState(unitCtx, paths)
	cancelUnit()
	if err != nil || unit.MainPID <= 1 || unit.Invocation == "" || unit.Active != "active" { emitPreReadyFailure(planBrokerCPUFailureSiteUnit); t.Fatal("fixed holder control requires the original loaded active worker") }
	planRaw, err := os.ReadFile(paths.ActivePlan)
	var plan CheckpointLaunchPlan
	if err != nil || json.Unmarshal(planRaw, &plan) != nil { emitPreReadyFailure(planBrokerCPUFailureSitePlan); t.Fatal("fixed holder control active plan is unavailable") }
	launch, err := capturePlanBrokerCPULaunch(paths, plan, unit, "")
	if err != nil { emitPreReadyFailure(planBrokerCPUFailureSiteLaunch); t.Fatal("fixed holder control worker identity could not be captured") }
	workerPIDFD, err := holdPlanBrokerCPUTerminalPIDFD(launch)
	if err != nil { emitPreReadyFailure(planBrokerCPUFailureSiteWorkerPIDFD); t.Fatal("fixed holder control worker pidfd could not be captured") }
	defer unix.Close(workerPIDFD)
	controlDeadline := caseDeadline
	holder, frame, err := startPlanBrokerCPUUnitHolderControl(paths, rootInfo, launch, 27, control, controlDeadline)
	if err != nil {
		site := planBrokerCPUHolderBranchFailureSite(err, control)
		if diagnostic, ok := planBrokerCPUHolderReadDiagnosticOf(err); ok && control == planBrokerCPUControlWatchdogNative && site == planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead) {
			emitNativeHelperReadFailure(site, diagnostic)
		} else {
			emitPreReadyFailure(site)
		}
		t.Fatal("fixed holder control handshake failed")
	}
	defer func() { if !holder.closed { if abortErr := planBrokerCPUAbortCleanup(holder); abortErr != nil { t.Errorf("holder control abort failed: %v", abortErr) } } }()
	if control == planBrokerCPUControlNegativeRefError {
		if frame != "NEGATIVE_RESULT\tnegative_ref_error\tinjected_before_ref" || holder.messages != planBrokerCPUHolderControlMessageCount(control) || holder.bytes > 1024 || holder.maxFrame > 192 {
			t.Fatal("negative_ref_error: exact injected-before-RefUnit event or bounded transcript was absent")
		}
		select {
		case <-holder.waitDone:
		case <-time.After(time.Until(controlDeadline)):
			t.Fatal("negative_ref_error: injected helper did not settle under its shared deadline")
		}
		status, ok := holder.cmd.ProcessState.Sys().(syscall.WaitStatus)
		rootNow, rootErr := os.Lstat(root)
		current, stateErr := planBrokerCPUFixtureUnitState(context.Background(), paths)
		if !ok || !status.Exited() || status.ExitStatus() != 148 || stateErr != nil || current.MainPID != unit.MainPID || current.Invocation != unit.Invocation || current.Active != unit.Active || current.ControlGroup != unit.ControlGroup || planBrokerCPULaunchStillCurrent(paths, launch) != nil || rootErr != nil || !os.SameFile(rootInfo, rootNow) {
			t.Fatal("negative_ref_error: injected failure changed the exact loaded worker or root")
		}
		if closeErr := holder.closeFiles(); closeErr != nil { t.Fatalf("negative_ref_error: expected helper custody close was uncertain: %v", closeErr) }
		fmt.Println("NEGATIVE_RESULT\tnegative_ref_error\tinjected_before_ref\tworker_unchanged\tclean")
		return
	}
	if control == planBrokerCPUControlNegativeWatchdogOmit {
		if frame != "NEGATIVE_READY\tnegative_watchdog_omitted" || holder.messages != planBrokerCPUHolderControlMessageCount(control) || holder.bytes > 1024 || holder.maxFrame > 192 {
			t.Fatal("negative_watchdog_omitted: exact fixed omission-ready event or bounded transcript was absent")
		}
		select { case <-holder.waitDone: t.Fatal("negative_watchdog_omitted: helper exited before held-parent death")
		default: }
		fmt.Printf("NEGATIVE_READY\tnegative_watchdog_omitted\t%d\t%d\t%d\t%d\t%d\n", holder.pid, holder.startTicks, holder.bytes, holder.messages, holder.maxFrame)
		select {}
	}
	if control == planBrokerCPUControlWatchdogCap {
		for index := 0; index < 3; index++ {
			time.Sleep(2 * time.Second)
			if time.Until(controlDeadline) <= 0 || planBrokerCPUHolderIdentityCurrent(holder) != nil { emitPreReadyFailure(planBrokerCPUFailureSiteCapHealthIdentity); t.Fatal("fixed cap progress lost its bounded holder/phase identity") }
			if err := holder.send("HEALTH\n"); err != nil { emitPreReadyFailure(planBrokerCPUFailureSiteCapHealthSend); t.Fatal("fixed cap valid progress request failed") }
			response, readErr := holder.readFrameUntil(controlDeadline)
			if readErr != nil || response != "HEALTH_READY" || planBrokerCPUHolderIdentityCurrent(holder) != nil { emitPreReadyFailure(planBrokerCPUFailureSiteCapHealthReply); t.Fatal("fixed cap valid same-connection progress did not complete") }
			holder.healthSites++
		}
	}
	if control == planBrokerCPUControlCloseDeath {
		closeDeadline := controlDeadline
		if err := holder.send("RELEASE\n"); err != nil { t.Fatal("fixed close-boundary release frame failed") }
		frame, err = holder.readFrameUntil(closeDeadline)
		if err != nil || frame != "CONTROL_READY\t"+string(control)+"\tclose" { t.Fatal("fixed close-boundary marker did not match") }
	}
	if frame != "CONTROL_READY\t"+string(control)+"\t"+planBrokerCPUHolderControlTarget(control) {
		emitPreReadyFailure(planBrokerCPUFailureSitePhaseFrame)
		t.Fatal("fixed control case/phase marker did not match its closed enum")
	}
	expectedMessages := planBrokerCPUHolderControlMessageCount(control)
	if control == planBrokerCPUControlAfterRearmDeath { expectedMessages -= 2 }
	if holder.messages != expectedMessages || holder.bytes > 1024 || holder.maxFrame > 192 { emitPreReadyFailure(planBrokerCPUFailureSiteTranscript); t.Fatal("fixed control transcript exceeds its independently derived frame/message budget") }
	select { case <-holder.waitDone: emitPreReadyFailure(planBrokerCPUFailureSiteHelperEarlyExit); t.Fatal("controlled helper exited before its parent-death event"); default: }
	fmt.Printf("CONTROL_READY\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n", control, planBrokerCPUHolderControlTarget(control), holder.pid, holder.startTicks, holder.bytes, holder.messages, holder.maxFrame)
	if control == planBrokerCPUControlWatchdogNative || control == planBrokerCPUControlWatchdogCap {
		remaining := time.Until(controlDeadline)
		if remaining <= 0 { t.Fatal("watchdog control exhausted its case deadline") }
		select {
		case <-holder.waitDone:
		case <-time.After(remaining): t.Fatal("fixed watchdog control did not terminate within its case deadline")
		}
		status, ok := holder.cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGALRM { t.Fatal("fixed watchdog control did not terminate by default SIGALRM") }
		if err := holder.closeFiles(); err != nil { t.Fatal("fixed watchdog control custody did not close") }
		fmt.Printf("CONTROL_RESULT\t%s\twatchdog_sigalrm\n", control)
		return
	}
	select {}
}

func planBrokerCPUHolderControlBudget(control planBrokerCPUHolderControl) time.Duration {
	for _, testCase := range planBrokerCPUHolderControlCases {
		if testCase.control == control { return testCase.budget }
	}
	return 0
}

func planBrokerCPUHolderNegativeControlBudget(control planBrokerCPUHolderControl) time.Duration {
	switch control {
	case planBrokerCPUControlNegativeRefError:
		return 8 * time.Second
	case planBrokerCPUControlNegativeWatchdogOmit:
		return 12 * time.Second
	default:
		return 0
	}
}

var planBrokerCPUHolderControlCases = []struct {
	control planBrokerCPUHolderControl
	phase string
	budget time.Duration
}{
	{planBrokerCPUControlWatchdogNative, "pre_ready", 4*time.Second},
	{planBrokerCPUControlWatchdogCap, "pre_ready", 13*time.Second},
	{planBrokerCPUControlStartupDeath, "startup", 4*time.Second},
	{planBrokerCPUControlPreReadyDeath, "pre_ready", 3*time.Second},
	{planBrokerCPUControlImportDeath, "import", 3*time.Second},
	{planBrokerCPUControlConstructorDeath, "constructor", 3*time.Second},
	{planBrokerCPUControlMethodDeath, "method", 3*time.Second},
	{planBrokerCPUControlHeldIdleDeath, "held_idle", 4*time.Second},
	{planBrokerCPUControlCloseDeath, "close", 3*time.Second},
	{planBrokerCPUControlAfterRearmDeath, "after_rearm", 3*time.Second},
}

const (
	planBrokerCPUHolderControlAggregateBudget = 45 * time.Second
	planBrokerCPUHolderControlContractCeiling = 90 * time.Second
	planBrokerCPUHolderControlWorkerTimeout = 90 * time.Second
	planBrokerCPUHolderControlPostMatrixReserve = 40 * time.Second
	planBrokerCPUHolderNormalWorstCaseBytes = 954
	planBrokerCPUHolderFailureFrameReserveBytes = 64
)

type planBrokerCPUControlReader struct {
	file *os.File
	buffer []byte
	bytes int
	messages int
	maxFrame int
}

type planBrokerCPUPreReadyFailureSite string

const (
	planBrokerCPUFailureSiteCaseOrRoot planBrokerCPUPreReadyFailureSite = "child_case_or_root"
	planBrokerCPUFailureSiteBudget planBrokerCPUPreReadyFailureSite = "child_budget"
	planBrokerCPUFailureSiteUnit planBrokerCPUPreReadyFailureSite = "child_unit"
	planBrokerCPUFailureSitePlan planBrokerCPUPreReadyFailureSite = "child_plan"
	planBrokerCPUFailureSiteLaunch planBrokerCPUPreReadyFailureSite = "child_launch"
	planBrokerCPUFailureSiteWorkerPIDFD planBrokerCPUPreReadyFailureSite = "child_worker_pidfd"
	planBrokerCPUFailureSiteHolderHandshake planBrokerCPUPreReadyFailureSite = "child_holder_handshake"
	planBrokerCPUFailureSiteCapHealthIdentity planBrokerCPUPreReadyFailureSite = "child_cap_health_identity"
	planBrokerCPUFailureSiteCapHealthSend planBrokerCPUPreReadyFailureSite = "child_cap_health_send"
	planBrokerCPUFailureSiteCapHealthReply planBrokerCPUPreReadyFailureSite = "child_cap_health_reply"
	planBrokerCPUFailureSitePhaseFrame planBrokerCPUPreReadyFailureSite = "child_phase_frame"
	planBrokerCPUFailureSiteTranscript planBrokerCPUPreReadyFailureSite = "child_transcript"
	planBrokerCPUFailureSiteHelperEarlyExit planBrokerCPUPreReadyFailureSite = "child_helper_early_exit"
)

func planBrokerCPUPreReadyFailureReason(site planBrokerCPUPreReadyFailureSite) planBrokerCPUFailureReason {
	return planBrokerCPUFailureReason(site)
}

func planBrokerCPUPreReadyFailureReasonAllowed(reason planBrokerCPUFailureReason) bool {
	switch reason {
	case planBrokerCPUReasonChildCaseOrRoot, planBrokerCPUReasonChildBudget, planBrokerCPUReasonChildUnit,
		planBrokerCPUReasonChildPlan, planBrokerCPUReasonChildLaunch, planBrokerCPUReasonChildWorkerPIDFD,
		planBrokerCPUReasonChildHolderHandshake, planBrokerCPUReasonChildPhaseFrame,
		planBrokerCPUReasonChildTranscript, planBrokerCPUReasonChildHelperEarlyExit,
		planBrokerCPUReasonChildCapHealthIdentity, planBrokerCPUReasonChildCapHealthSend, planBrokerCPUReasonChildCapHealthReply:
		return true
	default:
		return false
	}
}

func planBrokerCPUHolderBranchReasonAllowed(reason planBrokerCPUFailureReason) bool {
	switch reason {
	case planBrokerCPUReasonChildHolderPreSpawnBinding, planBrokerCPUReasonChildHolderPreSpawnDeadline,
		planBrokerCPUReasonChildHolderRootMetadata, planBrokerCPUReasonChildHolderLaunchCurrent,
		planBrokerCPUReasonChildHolderUnitCurrent, planBrokerCPUReasonChildHolderPipeSetup,
		planBrokerCPUReasonChildHolderTokenSetup, planBrokerCPUReasonChildHolderParentPIDFD,
		planBrokerCPUReasonChildHolderRootHandle, planBrokerCPUReasonChildHolderSpawn,
		planBrokerCPUReasonChildHolderChildIdentity, planBrokerCPUReasonChildHolderChildCgroup,
		planBrokerCPUReasonChildHolderHelperRead, planBrokerCPUReasonChildHolderHelperShape,
		planBrokerCPUReasonChildHolderCapGuardSend, planBrokerCPUReasonChildHolderCapGuardRead,
		planBrokerCPUReasonChildHolderCapGuardShape, planBrokerCPUReasonChildHolderCapRootMetadata,
		planBrokerCPUReasonChildHolderCapAcquireSend, planBrokerCPUReasonChildHolderCapRefRead,
		planBrokerCPUReasonChildHolderCapRefShape:
		return true
	default:
		return false
	}
}

func planBrokerCPUHolderBranchCapOnly(reason planBrokerCPUFailureReason) bool {
	switch reason {
	case planBrokerCPUReasonChildHolderCapGuardSend, planBrokerCPUReasonChildHolderCapGuardRead,
		planBrokerCPUReasonChildHolderCapGuardShape, planBrokerCPUReasonChildHolderCapRootMetadata,
		planBrokerCPUReasonChildHolderCapAcquireSend, planBrokerCPUReasonChildHolderCapRefRead,
		planBrokerCPUReasonChildHolderCapRefShape:
		return true
	default:
		return false
	}
}

func planBrokerCPUHolderBranchFailureSite(err error, control planBrokerCPUHolderControl) planBrokerCPUPreReadyFailureSite {
	class := planBrokerCPUHolderBranchClass(err)
	if !planBrokerCPUHolderBranchReasonAllowed(class) || (planBrokerCPUHolderBranchCapOnly(class) && control != planBrokerCPUControlWatchdogCap) { return planBrokerCPUFailureSiteHolderHandshake }
	return planBrokerCPUPreReadyFailureSite(class)
}

func planBrokerCPUPreReadyFailureReasonCapOnly(reason planBrokerCPUFailureReason) bool {
	return reason == planBrokerCPUReasonChildCapHealthIdentity || reason == planBrokerCPUReasonChildCapHealthSend || reason == planBrokerCPUReasonChildCapHealthReply
}

func planBrokerCPUPreReadyFailureFrame(control planBrokerCPUHolderControl, site planBrokerCPUPreReadyFailureSite) (string, bool) {
	if control != planBrokerCPUControlWatchdogNative && control != planBrokerCPUControlWatchdogCap {
		return "", false
	}
	if control == planBrokerCPUControlWatchdogNative && site == planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead) { return "", false }
	if site == planBrokerCPUFailureSiteCapHealthIdentity || site == planBrokerCPUFailureSiteCapHealthSend || site == planBrokerCPUFailureSiteCapHealthReply {
		if control != planBrokerCPUControlWatchdogCap { return "", false }
	} else if planBrokerCPUHolderBranchReasonAllowed(planBrokerCPUFailureReason(site)) {
		if planBrokerCPUHolderBranchCapOnly(planBrokerCPUFailureReason(site)) && control != planBrokerCPUControlWatchdogCap { return "", false }
	} else if !planBrokerCPUPreReadyFailureReasonAllowed(planBrokerCPUPreReadyFailureReason(site)) {
		return "", false
	}
	frame := "CONTROL_FAILURE\t" + string(control) + "\t" + string(site) + "\n"
	if len(frame) > 192 { return "", false }
	return frame, true
}

func planBrokerCPUParsePreReadyFailureFrame(record string, control planBrokerCPUHolderControl) (planBrokerCPUFailureReason, bool) {
	if len(record) == 0 || len(record) > 191 || strings.ContainsAny(record, "\r\n") { return "", false }
	fields := strings.Split(record, "\t")
	if len(fields) != 3 || fields[0] != "CONTROL_FAILURE" || fields[1] != string(control) { return "", false }
	site := planBrokerCPUPreReadyFailureSite(fields[2])
	if _, ok := planBrokerCPUPreReadyFailureFrame(control, site); !ok { return "", false }
	return planBrokerCPUPreReadyFailureReason(site), true
}

func planBrokerCPUWritePreReadyFailureFrame(writer io.Writer, control planBrokerCPUHolderControl, site planBrokerCPUPreReadyFailureSite) bool {
	if writer == nil { return false }
	frame, ok := planBrokerCPUPreReadyFailureFrame(control, site)
	if !ok { return false }
	n, err := writer.Write([]byte(frame))
	return err == nil && n == len(frame)
}

func planBrokerCPUNativeHelperReadFailureFrame(control planBrokerCPUHolderControl, site planBrokerCPUPreReadyFailureSite, diagnostic planBrokerCPUHolderReadDiagnostic) (string, bool) {
	if control != planBrokerCPUControlWatchdogNative || site != planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead) || !planBrokerCPUHolderReadDiagnosticValid(diagnostic) { return "", false }
	frame := "CONTROL_FAILURE\t" + string(control) + "\t" + string(site) + "\t" + diagnostic.readReason + "\t" + diagnostic.waitPhase + "\t" + diagnostic.waitStatus + "\n"
	if len(frame) > 192 { return "", false }
	return frame, true
}

func planBrokerCPUParseNativeHelperReadFailureFrame(record string, control planBrokerCPUHolderControl) (planBrokerCPUHolderReadDiagnostic, bool) {
	if control != planBrokerCPUControlWatchdogNative || len(record) == 0 || len(record) > 191 || strings.ContainsAny(record, "\r\n") { return planBrokerCPUHolderReadDiagnostic{}, false }
	fields := strings.Split(record, "\t")
	if len(fields) != 6 || fields[0] != "CONTROL_FAILURE" || fields[1] != string(control) || fields[2] != string(planBrokerCPUReasonChildHolderHelperRead) { return planBrokerCPUHolderReadDiagnostic{}, false }
	diagnostic := planBrokerCPUHolderReadDiagnostic{readReason: fields[3], waitPhase: fields[4], waitStatus: fields[5]}
	if !planBrokerCPUHolderReadDiagnosticValid(diagnostic) { return planBrokerCPUHolderReadDiagnostic{}, false }
	frame, ok := planBrokerCPUNativeHelperReadFailureFrame(control, planBrokerCPUPreReadyFailureSite(fields[2]), diagnostic)
	return diagnostic, ok && strings.TrimSuffix(frame, "\n") == record
}

func planBrokerCPUWriteNativeHelperReadFailureFrame(writer io.Writer, control planBrokerCPUHolderControl, site planBrokerCPUPreReadyFailureSite, diagnostic planBrokerCPUHolderReadDiagnostic) bool {
	if writer == nil { return false }
	frame, ok := planBrokerCPUNativeHelperReadFailureFrame(control, site, diagnostic)
	if !ok { return false }
	n, err := writer.Write([]byte(frame))
	return err == nil && n == len(frame)
}

func planBrokerCPUHolderReadDiagnosticOf(err error) (planBrokerCPUHolderReadDiagnostic, bool) {
	var diagnosticFailure *planBrokerCPUHolderReadDiagnosticFailure
	if !errors.As(err, &diagnosticFailure) || !planBrokerCPUHolderReadDiagnosticValid(diagnosticFailure.diagnostic) { return planBrokerCPUHolderReadDiagnostic{}, false }
	return diagnosticFailure.diagnostic, true
}

func planBrokerCPUFailureAttachHolderReadDiagnostic(err error, diagnostic planBrokerCPUHolderReadDiagnostic) bool {
	if !planBrokerCPUHolderReadDiagnosticValid(diagnostic) { return false }
	failure := planBrokerCPUFirstFailure(err, false)
	if failure == nil || failure.stage != planBrokerCPUStageMatrixCase || failure.reason != planBrokerCPUReasonChildHolderHelperRead || failure.caseName != string(planBrokerCPUControlWatchdogNative) { return false }
	failure.helperReadDiagnostic = &diagnostic
	return true
}

const planBrokerCPUFailureMarkerControlAssertion = "__PLAN_RELAUNCH_PURE_DIAGNOSTIC_CONTROL_FAILURE__"

func TestPlanBrokerCPUFailureMarkerControlsPure(t *testing.T) {
	if err := verifyPlanBrokerCPUFailureMarkerControls(); err != nil {
		t.Fatalf("%s: %v", planBrokerCPUFailureMarkerControlAssertion, err)
	}
}

const planBrokerCPUDescriptorGuardControlAssertion = "__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__"
const planBrokerCPUDescriptorGuardPassPrefix = "__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__\t"

type planBrokerCPUDescriptorGuardBoundedOutput struct {
	buffer bytes.Buffer
	limit  int
	over   bool
}

func (writer *planBrokerCPUDescriptorGuardBoundedOutput) Write(data []byte) (int, error) {
	if writer == nil || writer.limit < 0 { return 0, errors.New("descriptor-control output writer is unavailable") }
	if writer.buffer.Len()+len(data) > writer.limit { writer.over = true; return len(data), nil }
	return writer.buffer.Write(data)
}

type planBrokerCPUDescriptorGuardCase struct {
	name string
	expected int
	fd10 string
	highWriter bool
}

type planBrokerCPUDescriptorGuardOutcome struct {
	exitCode int
	stdout string
	stderr string
}

var planBrokerCPUDescriptorGuardCases = []planBrokerCPUDescriptorGuardCase{
	{name: "false_absent_no_writer", expected: 0, fd10: "unrelated"},
	{name: "false_unrelated_no_writer", expected: 0, fd10: "unrelated"},
	{name: "true_exact_fd10_writer", expected: 0, fd10: "guard_writer"},
	{name: "false_fd10_writer", expected: 151, fd10: "guard_writer"},
	{name: "false_unrelated_higher_writer", expected: 195, fd10: "unrelated", highWriter: true},
	{name: "false_absent_higher_writer", expected: 195, fd10: "unrelated", highWriter: true},
	{name: "true_missing_fd10", expected: 150, fd10: "unrelated"},
	{name: "true_unrelated_fd10", expected: 152, fd10: "unrelated"},
	{name: "true_exact_plus_extra_writer", expected: 178, fd10: "guard_writer", highWriter: true},
}

func runPlanBrokerCPUDescriptorGuardCase(test planBrokerCPUDescriptorGuardCase) (planBrokerCPUDescriptorGuardOutcome, error) {
	guardR, guardW, err := os.Pipe()
	if err != nil { return planBrokerCPUDescriptorGuardOutcome{}, fmt.Errorf("create guard pipe: %w", err) }
	defer guardR.Close()
	defer guardW.Close()
	otherR, otherW, err := os.Pipe()
	if err != nil { return planBrokerCPUDescriptorGuardOutcome{}, fmt.Errorf("create unrelated pipe: %w", err) }
	defer otherR.Close()
	defer otherW.Close()
	extra := []*os.File{guardR}
	for len(extra) < 7 { extra = append(extra, otherR) } // fd4 through fd9 are unrelated read ends.
	if test.fd10 == "guard_writer" { extra = append(extra, guardW) } else { extra = append(extra, otherR) }
	if test.highWriter { extra = append(extra, guardW) }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", planBrokerCPUUnitHolderProgram, "--descriptor-control="+test.name)
	command.ExtraFiles = extra
	command.WaitDelay = 250*time.Millisecond
	stdout, stderr := &planBrokerCPUDescriptorGuardBoundedOutput{limit: 192}, &planBrokerCPUDescriptorGuardBoundedOutput{limit: 192}
	command.Stdout, command.Stderr = stdout, stderr
	runErr := command.Run()
	if ctx.Err() != nil { return planBrokerCPUDescriptorGuardOutcome{}, fmt.Errorf("bounded child timed out: %w", ctx.Err()) }
	if command.ProcessState == nil || !command.ProcessState.Exited() { return planBrokerCPUDescriptorGuardOutcome{}, errors.New("child lacks observed terminal state") }
	if stdout.over || stderr.over { return planBrokerCPUDescriptorGuardOutcome{}, errors.New("child exceeded bounded output") }
	code := command.ProcessState.ExitCode()
	if code < 0 || code == 0 && runErr != nil || code != 0 && runErr == nil { return planBrokerCPUDescriptorGuardOutcome{}, errors.New("child result and observed terminal status disagree") }
	return planBrokerCPUDescriptorGuardOutcome{exitCode: code, stdout: stdout.buffer.String(), stderr: stderr.buffer.String()}, nil
}

func requirePlanBrokerCPUDescriptorGuardControl(test planBrokerCPUDescriptorGuardCase) error {
	outcome, err := runPlanBrokerCPUDescriptorGuardCase(test)
	if err != nil { return err }
	if outcome.exitCode != test.expected { return fmt.Errorf("case exit mismatch: got=%d want=%d", outcome.exitCode, test.expected) }
	if test.expected == 0 {
		want := planBrokerCPUDescriptorGuardPassPrefix + test.name + "\t0\n"
		if outcome.stdout != want || outcome.stderr != "" { return errors.New("case did not produce its exact zero-exit token") }
	} else if outcome.stdout != "" || outcome.stderr != "" { return errors.New("rejection case emitted unexpected output") }
	return nil
}

func planBrokerCPUDescriptorGuardCaseByName(name string) (planBrokerCPUDescriptorGuardCase, bool) {
	for _, test := range planBrokerCPUDescriptorGuardCases { if test.name == name { return test, true } }
	return planBrokerCPUDescriptorGuardCase{}, false
}

func TestPlanBrokerCPUDescriptorGuardControls(t *testing.T) {
	for _, test := range planBrokerCPUDescriptorGuardCases {
		if err := requirePlanBrokerCPUDescriptorGuardControl(test); err != nil {
			t.Fatalf("%s\tcase=%s: %v", planBrokerCPUDescriptorGuardControlAssertion, test.name, err)
		}
		fmt.Printf("%s%s\t%d\n", planBrokerCPUDescriptorGuardPassPrefix, test.name, test.expected)
	}
}

func assertPlanBrokerCPUDescriptorGuardMutantDetected(t *testing.T, name string) {
	t.Helper()
	test, ok := planBrokerCPUDescriptorGuardCaseByName(name)
	if !ok { t.Fatalf("descriptor mutant test has an unknown fixed case: %s", name) }
	outcome, err := runPlanBrokerCPUDescriptorGuardCase(test)
	if err != nil { t.Fatalf("descriptor mutant case did not reach a bounded terminal observation: %s: %v", name, err) }
	if outcome.exitCode == test.expected && outcome.stdout == "" && outcome.stderr == "" { return }
	want := planBrokerCPUDescriptorGuardPassPrefix + name + "\t0\n"
	if outcome.exitCode == 0 && outcome.stdout == want && outcome.stderr == "" {
		t.Fatalf("%s\tcase=%s: forbidden descriptor acceptance observed", planBrokerCPUDescriptorGuardControlAssertion, name)
	}
	t.Fatalf("descriptor mutant case had an unexpected terminal result: case=%s exit=%d", name, outcome.exitCode)
}

func TestPlanBrokerCPUDescriptorGuardMutantFD10(t *testing.T) {
	assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "false_fd10_writer")
}

func TestPlanBrokerCPUDescriptorGuardMutantHigher(t *testing.T) {
	assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "false_unrelated_higher_writer")
}

func TestPlanBrokerCPUDescriptorGuardMutantWrongFD10(t *testing.T) {
	assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "true_unrelated_fd10")
}

func TestPlanBrokerCPUDescriptorGuardMutantExtraWriter(t *testing.T) {
	assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "true_exact_plus_extra_writer")
}

type planBrokerCPUPreReadyWriteFunc func([]byte) (int, error)

func (write planBrokerCPUPreReadyWriteFunc) Write(p []byte) (int, error) { return write(p) }

func (reader *planBrokerCPUControlReader) read(deadline time.Time) (string, error) {
	if reader == nil || reader.file == nil { return "", errors.New("fixed control stream is unavailable") }
	for time.Now().Before(deadline) {
		if newline := bytes.IndexByte(reader.buffer, '\n'); newline >= 0 {
			frameSize := newline + 1
			if newline == 0 || frameSize > 192 || reader.bytes+frameSize > 1024 || bytes.ContainsAny(reader.buffer[:newline], "\r") { return "", errors.New("fixed control record framing or aggregate bounds are invalid") }
			line := string(reader.buffer[:newline])
			reader.buffer = append(reader.buffer[:0], reader.buffer[newline+1:]...)
			reader.bytes += frameSize
			reader.messages++
			if frameSize > reader.maxFrame { reader.maxFrame = frameSize }
			return line, nil
		}
		if len(reader.buffer) > 192 || len(reader.buffer) > 1024 { return "", errors.New("fixed control record exceeded its bounded buffer") }
		remaining := time.Until(deadline)
		ms := int((remaining + time.Millisecond - 1) / time.Millisecond)
		if ms > 100 { ms = 100 }
		if ms < 1 { ms = 1 }
		poll := []unix.PollFd{{Fd: int32(reader.file.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR | unix.POLLNVAL}}
		if _, err := unix.Poll(poll, ms); err != nil && !errors.Is(err, unix.EINTR) { return "", errors.New("fixed control event poll failed") }
		if poll[0].Revents&unix.POLLNVAL != 0 || poll[0].Revents&unix.POLLERR != 0 && poll[0].Revents&unix.POLLIN == 0 { return "", errors.New("fixed control event descriptor is invalid") }
		if poll[0].Revents&unix.POLLIN == 0 { continue }
		chunk := make([]byte, 1024-len(reader.buffer))
		n, err := reader.file.Read(chunk)
		if err != nil || n == 0 { return "", errors.New("fixed control event stream closed") }
		reader.buffer = append(reader.buffer, chunk[:n]...)
		if len(reader.buffer) > 1024 { return "", errors.New("fixed control event aggregate exceeded its bound") }
		for _, b := range reader.buffer { if b != '\n' && (b < 0x20 && b != '\t' || b > 0x7e) { return "", errors.New("fixed control event contains a nonprintable byte") } }
	}
	return "", errors.New("fixed control case exceeded its finite case deadline")
}

func (reader *planBrokerCPUControlReader) requireEOF(deadline time.Time) error {
	if reader == nil || reader.file == nil || !deadline.After(time.Now()) { return errors.New("fixed control report EOF lacks its live bounded reader") }
	if len(reader.buffer) != 0 { return errors.New("fixed control report contains an unexpected queued or duplicate record") }
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		ms := int((remaining + time.Millisecond - 1) / time.Millisecond)
		if ms > 100 { ms = 100 }
		if ms < 1 { ms = 1 }
		poll := []unix.PollFd{{Fd: int32(reader.file.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR | unix.POLLNVAL}}
		if _, err := unix.Poll(poll, ms); err != nil && !errors.Is(err, unix.EINTR) { return errors.New("fixed control report EOF poll failed") }
		if poll[0].Revents&unix.POLLNVAL != 0 || poll[0].Revents&unix.POLLERR != 0 && poll[0].Revents&unix.POLLIN == 0 { return errors.New("fixed control report EOF descriptor is invalid") }
		if poll[0].Revents&unix.POLLIN == 0 && poll[0].Revents&unix.POLLHUP == 0 { continue }
		var extra [1]byte
		n, err := reader.file.Read(extra[:])
		if n != 0 { return errors.New("fixed control report contains an unexpected trailing or duplicate byte") }
		if errors.Is(err, io.EOF) { return nil }
		if err != nil { return errors.New("fixed control report stream did not settle at EOF") }
	}
	return errors.New("fixed control report EOF exceeded its shared finite deadline")
}

func planBrokerCPUHolderControlReportMessageCount(control planBrokerCPUHolderControl) int {
	switch control {
	case planBrokerCPUControlWatchdogNative, planBrokerCPUControlWatchdogCap:
		return 3
	case planBrokerCPUControlNegativeRefError:
		return 2
	case planBrokerCPUControlNegativeWatchdogOmit, planBrokerCPUControlStartupDeath, planBrokerCPUControlPreReadyDeath, planBrokerCPUControlImportDeath, planBrokerCPUControlConstructorDeath, planBrokerCPUControlMethodDeath, planBrokerCPUControlHeldIdleDeath, planBrokerCPUControlCloseDeath:
		return 1
	case planBrokerCPUControlAfterRearmDeath:
		return 3
	default:
		return 0
	}
}

func waitPlanBrokerCPUHolderTerminal(pidfd int, pid int, start uint64, deadline time.Time) error {
	if pidfd <= 0 || pid <= 1 || start == 0 { return errors.New("controlled helper terminal identity is incomplete") }
	for time.Now().Before(deadline) {
		poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR | unix.POLLNVAL}}
		if _, err := unix.Poll(poll, 50); err != nil && !errors.Is(err, unix.EINTR) { return errors.New("controlled helper pidfd poll failed") }
		if poll[0].Revents == 0 { continue }
		if poll[0].Revents&unix.POLLNVAL != 0 || poll[0].Revents&unix.POLLIN == 0 { return errors.New("controlled helper pidfd terminal event is invalid") }
		procPath := filepath.Join("/proc", strconv.Itoa(pid))
		if _, err := os.Stat(procPath); errors.Is(err, os.ErrNotExist) { return nil } else if err != nil { return errors.New("controlled helper /proc identity could not be settled") }
		currentStart, err := checkpointProcessStart(procPath, pid)
		if err != nil { return errors.New("controlled helper original /proc incarnation could not be read") }
		if currentStart != start { return nil }
		// pidfd readiness can precede final /proc removal while the orphan is being reaped.
		// Keep the original absolute five-second deadline; a zombie is not terminal proof.
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("controlled helper did not reach terminal proc settlement within five seconds")
}

func runPlanBrokerCPUHolderControlCase(paths checkpointPlanBrokerPaths, root string, rootInfo os.FileInfo, launch planBrokerCPULaunchIdentity, control planBrokerCPUHolderControl, deadline time.Time) (result error) {
	failure := func(reason planBrokerCPUFailureReason, err error) error {
		return planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, reason, string(control), planBrokerCPUFailureOrigin(reason, err))
	}
	watchdogReport := control == planBrokerCPUControlWatchdogNative || control == planBrokerCPUControlWatchdogCap
	beforeCtx, cancelBefore := context.WithDeadline(context.Background(), deadline)
	unitBefore, err := planBrokerCPUFixtureUnitState(beforeCtx, paths)
	cancelBefore()
	if err != nil || unitBefore.MainPID != launch.PID || unitBefore.Invocation != launch.Invocation || unitBefore.Active != "active" || unitBefore.ControlGroup != launch.ControlGroup || planBrokerCPULaunchStillCurrent(paths, launch) != nil {
		return failure(planBrokerCPUReasonUnit, errors.New("control case did not begin with the exact loaded original worker"))
	}
	controlR, controlW, err := os.Pipe()
	if err != nil { return failure(planBrokerCPUReasonPipe, errors.New("fixed control case pipe could not be created")) }
	if _, err := controlW.Write([]byte(string(control)+"\n")); err != nil { controlR.Close(); controlW.Close(); return failure(planBrokerCPUReasonPipe, errors.New("fixed control case token could not be written")) }
	if err := controlW.Close(); err != nil { controlR.Close(); return failure(planBrokerCPUReasonClose, errors.New("fixed control case token pipe could not close")) }
	command := exec.Command(os.Args[0], "-test.run=^TestCheckpointPlanRelaunchCPUWorker$", "-test.count=1", "-test.timeout=30s")
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/bin", planBrokerCPUEnv+"="+planBrokerCPUOptIn, planBrokerCPURole+"=holder-control-parent", "VRAM_PLAN_BROKER_CPU_ROOT="+root, planBrokerCPUNodeGIDEnv+"="+strconv.FormatUint(uint64(paths.NodeGID), 10)}
	command.ExtraFiles = []*os.File{controlR}
	command.Stderr = io.Discard
	command.WaitDelay = 2*time.Second
	parentPIDFD := -1
	command.SysProcAttr = &syscall.SysProcAttr{PidFD: &parentPIDFD}
	reportR, reportW, err := os.Pipe()
	if err != nil { controlR.Close(); return failure(planBrokerCPUReasonPipe, errors.New("fixed control parent private report pipe could not be created")) }
	command.Stdout = reportW
	stdoutReader := &planBrokerCPUControlReader{file: reportR}
	requireReportEOF := func(until time.Time, reason planBrokerCPUFailureReason) error {
		if err := stdoutReader.requireEOF(until); err != nil { return failure(reason, err) }
		if stdoutReader.messages != planBrokerCPUHolderControlReportMessageCount(control) || stdoutReader.bytes > 1024 || stdoutReader.maxFrame > 192 {
			return failure(reason, errors.New("fixed control report did not match its exact bounded record inventory"))
		}
		return nil
	}
	if err := command.Start(); err != nil { return failure(planBrokerCPUReasonExit, errors.Join(errors.New("fixed control parent did not start"), controlR.Close(), reportR.Close(), reportW.Close())) }
	reportWriterCloseErr := reportW.Close()
	defer func() { if closeErr := reportR.Close(); closeErr != nil { result = errors.Join(result, errors.New("fixed control report reader custody close failed")) } }()
	waitResult := make(chan error, 1)
	waitStarted, waitFinished := false, false
	var waitErr error
	var parentIdentity planBrokerCPUProcessIdentity
	waitUntil := func(until time.Time) error {
		if !waitStarted { waitStarted = true; go func() { waitResult <- command.Wait() }() }
		if waitFinished { return waitErr }
		remaining := time.Until(until)
		if remaining <= 0 { return failure(planBrokerCPUReasonDeadline, errors.New("control parent Wait exceeded its shared terminal deadline")) }
		select { case waitErr = <-waitResult: waitFinished = true; if waitErr != nil { return failure(planBrokerCPUReasonExit, waitErr) }; return nil
		case <-time.After(remaining): return failure(planBrokerCPUReasonDeadline, errors.New("control parent Wait exceeded its shared terminal deadline")) }
	}
	parentValidated := false
	abortParent := func(cause error) error {
		var settlement error
		if parentValidated && parentPIDFD > 0 {
			current, currentErr := capturePlanBrokerCPUProcessIdentity(command.Process.Pid)
			target, targetErr := planBrokerCPUPIDFDTarget(parentPIDFD)
			if currentErr != nil || targetErr != nil || target != command.Process.Pid || current != parentIdentity {
				settlement = errors.Join(settlement, errors.New("control parent identity changed; preserving without signal"))
			} else if signalErr := unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0); signalErr != nil {
				settlement = errors.Join(settlement, errors.New("exact validated control-parent pidfd signal failed"))
			}
		} else {
			settlement = errors.Join(settlement, errors.New("control parent lacked a complete held identity; no signal authority"))
		}
		waitDeadline := time.Now().Add(5 * time.Second)
		if err := waitUntil(waitDeadline); err != nil { settlement = errors.Join(settlement, err) }
		return errors.Join(cause, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUncertain, "", settlement))
	}
	if parentPIDFD <= 0 { return abortParent(failure(planBrokerCPUReasonIdentity, errors.New("fixed control parent spawn-time pidfd is unavailable"))) }
	defer func() { if closeErr := unix.Close(parentPIDFD); closeErr != nil { result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonClose, "", errors.New("control parent pidfd close failed"))) } }()
	parentIdentity, identityErr := capturePlanBrokerCPUProcessIdentity(command.Process.Pid)
	parentTarget, targetErr := planBrokerCPUPIDFDTarget(parentPIDFD)
	parentImage, parentImageErr := os.Stat(os.Args[0])
	var parentStat *syscall.Stat_t
	if parentImageErr == nil { parentStat, _ = parentImage.Sys().(*syscall.Stat_t) }
	if identityErr != nil || targetErr != nil || parentTarget != command.Process.Pid || parentImageErr != nil || parentStat == nil || parentIdentity.ExecutableDevice != uint64(parentStat.Dev) || parentIdentity.ExecutableInode != uint64(parentStat.Ino) || parentIdentity.StartTicks == 0 {
		return abortParent(failure(planBrokerCPUReasonIdentity, errors.New("fixed control parent process/pidfd identity is not exact")))
	}
	parentValidated = true
	if closeErr := controlR.Close(); closeErr != nil { return abortParent(failure(planBrokerCPUReasonClose, errors.New("fixed control parent token pipe close failed"))) }
	if reportWriterCloseErr != nil { return abortParent(failure(planBrokerCPUReasonClose, errors.Join(errors.New("fixed control parent report writer custody close failed"), reportWriterCloseErr))) }
	first, err := stdoutReader.read(deadline)
	if err == nil && stdoutReader.messages == 1 {
		if control == planBrokerCPUControlWatchdogNative {
			if diagnostic, ok := planBrokerCPUParseNativeHelperReadFailureFrame(first, control); ok {
				primary := failure(planBrokerCPUReasonChildHolderHelperRead, errors.New("source-owned native helper first-read diagnostic frame was observed"))
				if !planBrokerCPUFailureAttachHolderReadDiagnostic(primary, diagnostic) { return abortParent(failure(planBrokerCPUReasonUnavailable, errors.New("native helper first-read diagnostic could not bind its selected typed failure"))) }
				return abortParent(primary)
			}
		}
		if reason, ok := planBrokerCPUParsePreReadyFailureFrame(first, control); ok {
			return abortParent(failure(reason, errors.New("source-owned pre-READY child branch frame was observed")))
		}
	}
	if err != nil {
		reason := planBrokerCPUReasonPipe
		if watchdogReport { reason = planBrokerCPUReasonReportReady }
		return abortParent(failure(reason, err))
	}
	if control == planBrokerCPUControlNegativeRefError {
		if first != "NEGATIVE_RESULT\tnegative_ref_error\tinjected_before_ref\tworker_unchanged\tclean" {
			return abortParent(failure(planBrokerCPUReasonPipe, errors.New("negative_ref_error control parent did not report the exact pre-RefUnit behavior")))
		}
		pass, passErr := stdoutReader.read(deadline)
		if passErr != nil || pass != "PASS" { return abortParent(failure(planBrokerCPUReasonPipe, errors.New("negative_ref_error control parent did not finish its exact worker/root checks"))) }
		if err := waitUntil(deadline); err != nil { return abortParent(failure(planBrokerCPUReasonExit, errors.New("negative_ref_error control parent failed its bounded result"))) }
		if err := planBrokerCPULaunchStillCurrent(paths, launch); err != nil { return failure(planBrokerCPUReasonIdentity, errors.New("negative_ref_error changed the exact original worker")) }
		if err := requireReportEOF(deadline, planBrokerCPUReasonPipe); err != nil { return errors.Join(failure(planBrokerCPUReasonPipe, errors.New("negative_ref_error control report was not exact and final")), err) }
		return failure(planBrokerCPUReasonUncertain, errors.New("negative_ref_error: normal RefUnit acquisition surfaced the injected pre-call error with no manager side effect"))
	}
	fields := strings.Split(first, "\t")
	wantPhase := planBrokerCPUHolderControlTarget(control)
	fieldOffset := 3
	if control == planBrokerCPUControlNegativeWatchdogOmit {
		if len(fields) != 7 || fields[0] != "NEGATIVE_READY" || fields[1] != string(control) { return abortParent(failure(planBrokerCPUReasonPipe, errors.New("watchdog omission event is not its fixed case/phase"))) }
		fieldOffset = 2
	} else if len(fields) != 8 || fields[0] != "CONTROL_READY" || fields[1] != string(control) || fields[2] != wantPhase {
		reason := planBrokerCPUReasonPipe
		if watchdogReport { reason = planBrokerCPUReasonReportReady }
		return abortParent(failure(reason, errors.New("control event is not its fixed case/phase")))
	}
	helperPID, pidErr := strconv.Atoi(fields[fieldOffset])
	helperStart, startErr := strconv.ParseUint(fields[fieldOffset+1], 10, 64)
	transcriptBytes, bytesErr := strconv.Atoi(fields[fieldOffset+2])
	transcriptMessages, messagesErr := strconv.Atoi(fields[fieldOffset+3])
	maximumFrame, frameErr := strconv.Atoi(fields[fieldOffset+4])
	expectedMessagesBeforeDeath := planBrokerCPUHolderControlMessageCount(control)
	if control == planBrokerCPUControlAfterRearmDeath { expectedMessagesBeforeDeath -= 2 }
	if bytesErr != nil || messagesErr != nil || frameErr != nil || transcriptBytes < 1 || transcriptBytes > 1024 || transcriptMessages != expectedMessagesBeforeDeath || maximumFrame < 1 || maximumFrame > 192 {
		reason := planBrokerCPUReasonPipe
		if watchdogReport { reason = planBrokerCPUReasonReportMetrics }
		metricFailure := error(errors.New("control event transcript metrics violate fixed bounds"))
		if bytesErr != nil || messagesErr != nil || frameErr != nil { metricFailure = errors.Join(metricFailure, bytesErr, messagesErr, frameErr) }
		return abortParent(failure(reason, metricFailure))
	}
	helperIdentity, helperIdentityErr := capturePlanBrokerCPUProcessIdentity(helperPID)
	helperPIDFD := -1
	var openErr error
	if pidErr == nil && startErr == nil { helperPIDFD, openErr = unix.PidfdOpen(helperPID, 0) }
	if openErr == nil { defer func() { if closeErr := unix.Close(helperPIDFD); closeErr != nil { result = errors.Join(result, errors.New("controlled helper pidfd close failed")) } }() }
	helperTarget, helperTargetErr := planBrokerCPUPIDFDTarget(helperPIDFD)
	pythonInfo, pythonErr := os.Stat("/usr/bin/python3")
	var pythonStat *syscall.Stat_t
	if pythonErr == nil { pythonStat, _ = pythonInfo.Sys().(*syscall.Stat_t) }
	helperCurrent, helperCurrentErr := capturePlanBrokerCPUProcessIdentity(helperPID)
	if pidErr != nil || startErr != nil || helperIdentityErr != nil || openErr != nil || helperTargetErr != nil || helperTarget != helperPID || helperIdentity.StartTicks != helperStart || helperCurrentErr != nil || helperCurrent != helperIdentity || pythonErr != nil || pythonStat == nil || helperIdentity.ExecutableDevice != uint64(pythonStat.Dev) || helperIdentity.ExecutableInode != uint64(pythonStat.Ino) {
		return abortParent(failure(planBrokerCPUReasonIdentity, errors.New("controlled Python holder identity is not exact")))
	}
	if watchdogReport {
		second, readErr := stdoutReader.read(deadline)
		if readErr != nil || second != "CONTROL_RESULT\t"+string(control)+"\twatchdog_sigalrm" {
			resultFailure := error(errors.New("watchdog control did not report the exact default-signal result"))
			if readErr != nil { resultFailure = errors.Join(resultFailure, readErr) }
			return abortParent(failure(planBrokerCPUReasonReportResult, resultFailure))
		}
		tail, tailErr := stdoutReader.read(deadline)
		if tailErr != nil || tail != "PASS" {
			passFailure := error(errors.New("watchdog control parent did not finish with its exact test result"))
			if tailErr != nil { passFailure = errors.Join(passFailure, tailErr) }
			return abortParent(failure(planBrokerCPUReasonReportPass, passFailure))
		}
		if waitErr := waitUntil(deadline); waitErr != nil { return failure(planBrokerCPUReasonExit, errors.New("watchdog control parent failed its fixed source-owned result")) }
		if err := waitPlanBrokerCPUHolderTerminal(helperPIDFD, helperPID, helperStart, deadline); err != nil { return failure(planBrokerCPUReasonExit, err) }
		if err := requireReportEOF(deadline, planBrokerCPUReasonReportEOF); err != nil { return failure(planBrokerCPUReasonPipe, err) }
		if err := planBrokerCPULaunchStillCurrent(paths, launch); err != nil { return failure(planBrokerCPUReasonIdentity, errors.New("watchdog control changed the original worker")) }
		afterCtx, cancelAfter := context.WithDeadline(context.Background(), deadline)
		unitAfter, stateErr := planBrokerCPUFixtureUnitState(afterCtx, paths)
		cancelAfter()
		if stateErr != nil || unitAfter.MainPID != unitBefore.MainPID || unitAfter.Invocation != unitBefore.Invocation || unitAfter.Active != unitBefore.Active || unitAfter.ControlGroup != unitBefore.ControlGroup { return failure(planBrokerCPUReasonUnit, errors.New("watchdog control changed the exact loaded worker state")) }
		currentRoot, rootErr := os.Lstat(root)
		if rootErr != nil || !os.SameFile(rootInfo, currentRoot) { return failure(planBrokerCPUReasonIdentity, errors.New("watchdog control changed private root identity")) }
		fmt.Printf("__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\t%s\t%s\n", control, wantPhase)
		return nil
	}
	if err := planBrokerCPULaunchStillCurrent(paths, launch); err != nil { return abortParent(failure(planBrokerCPUReasonIdentity, errors.New("original worker changed before controlled parent death"))) }
	terminalDeadline := time.Now().Add(5*time.Second)
	if deadline.Before(terminalDeadline) { terminalDeadline = deadline }
	currentParent, currentParentErr := capturePlanBrokerCPUProcessIdentity(command.Process.Pid)
	currentTarget, currentTargetErr := planBrokerCPUPIDFDTarget(parentPIDFD)
	if currentParentErr != nil || currentTargetErr != nil || currentTarget != command.Process.Pid || currentParent != parentIdentity { return abortParent(failure(planBrokerCPUReasonIdentity, errors.New("control parent identity changed before exact pidfd death"))) }
		if err := unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0); err != nil { return errors.Join(failure(planBrokerCPUReasonExit, errors.New("exact control-parent pidfd death signal failed")), planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUncertain, "", waitUntil(terminalDeadline))) }
	parentWaitErr := waitUntil(terminalDeadline)
	var parentExit *exec.ExitError
	if !errors.As(parentWaitErr, &parentExit) { return failure(planBrokerCPUReasonExit, errors.New("control parent did not terminate through the exact held pidfd")) }
	parentStatus, ok := parentExit.Sys().(syscall.WaitStatus)
	if !ok || !parentStatus.Signaled() || parentStatus.Signal() != syscall.SIGKILL { return failure(planBrokerCPUReasonExit, errors.New("control parent terminal status differs from the exact requested signal")) }
	if control == planBrokerCPUControlAfterRearmDeath {
		nonEOF, nonEOFErr := stdoutReader.read(terminalDeadline)
		if nonEOFErr != nil || nonEOF != "GUARD_DUP_NON_EOF" {
			return failure(planBrokerCPUReasonPipe, errors.New("guard-writer duplicate did not independently prevent guard EOF after held-parent death"))
		}
		confirmed, readErr := stdoutReader.read(terminalDeadline)
		if readErr != nil || confirmed != "GUARD_DUP_PARENT_PIDFD_CONFIRMED" {
			return failure(planBrokerCPUReasonExit, errors.New("guard-writer duplicate prevented EOF but original held parent pidfd death was not independently confirmed"))
		}
		lateProofBytes := len("GUARD_DUP_NON_EOF\n") + len("GUARD_DUP_PARENT_PIDFD_CONFIRMED\n")
		if transcriptBytes+lateProofBytes > 1024 || transcriptMessages+2 != planBrokerCPUHolderControlMessageCount(control) || maximumFrame > 192 {
			return failure(planBrokerCPUReasonPipe, errors.New("guard duplicate status and late proof exceeded the independent combined byte/message/frame cap"))
		}
	}
	if control == planBrokerCPUControlNegativeWatchdogOmit {
		var identity planBrokerCPUProcessIdentity
		var identityErr error
		for time.Now().Before(terminalDeadline) {
			poll := []unix.PollFd{{Fd: int32(helperPIDFD), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR | unix.POLLNVAL}}
			if _, pollErr := unix.Poll(poll, 0); pollErr != nil && !errors.Is(pollErr, unix.EINTR) { return failure(planBrokerCPUReasonExit, errors.New("watchdog omission pidfd poll failed during parent-death survival window")) }
			identity, identityErr = capturePlanBrokerCPUProcessIdentity(helperPID)
			currentTarget, currentTargetErr = planBrokerCPUPIDFDTarget(helperPIDFD)
			if poll[0].Revents != 0 || identityErr != nil || identity != helperIdentity || currentTargetErr != nil || currentTarget != helperPID {
				return failure(planBrokerCPUReasonIdentity, errors.New("watchdog omission helper did not remain the exact live process after original parent death"))
			}
			time.Sleep(25 * time.Millisecond)
		}
		identity, identityErr = capturePlanBrokerCPUProcessIdentity(helperPID)
		currentTarget, currentTargetErr = planBrokerCPUPIDFDTarget(helperPIDFD)
		if identityErr != nil || identity != helperIdentity || currentTargetErr != nil || currentTarget != helperPID {
			return failure(planBrokerCPUReasonIdentity, errors.New("watchdog omission survivor identity changed before exact pidfd cleanup"))
		}
		if err := unix.PidfdSendSignal(helperPIDFD, syscall.SIGKILL, nil, 0); err != nil { return failure(planBrokerCPUReasonExit, errors.New("watchdog omission exact helper pidfd cleanup failed")) }
		cleanupDeadline := time.Now().Add(5 * time.Second)
		if deadline.Before(cleanupDeadline) { cleanupDeadline = deadline }
		if err := waitPlanBrokerCPUHolderTerminal(helperPIDFD, helperPID, helperStart, cleanupDeadline); err != nil { return failure(planBrokerCPUReasonExit, errors.New("watchdog omission helper did not settle after exact pidfd cleanup")) }
		if err := requireReportEOF(cleanupDeadline, planBrokerCPUReasonPipe); err != nil { return failure(planBrokerCPUReasonPipe, err) }
		if err := planBrokerCPULaunchStillCurrent(paths, launch); err != nil { return failure(planBrokerCPUReasonIdentity, errors.New("watchdog omission changed the exact original worker")) }
		afterCtx, cancelAfter := context.WithDeadline(context.Background(), deadline)
		unitAfter, stateErr := planBrokerCPUFixtureUnitState(afterCtx, paths)
		cancelAfter()
		currentRoot, rootErr := os.Lstat(root)
		if stateErr != nil || unitAfter.MainPID != unitBefore.MainPID || unitAfter.Invocation != unitBefore.Invocation || unitAfter.Active != unitBefore.Active || unitAfter.ControlGroup != unitBefore.ControlGroup || rootErr != nil || !os.SameFile(rootInfo, currentRoot) {
			return failure(planBrokerCPUReasonUnit, errors.New("watchdog omission changed the original unit or held private root"))
		}
		return failure(planBrokerCPUReasonUncertain, errors.New("negative_watchdog_omitted: helper survived parent death beyond five seconds and was pidfd-cleaned"))
	}
	if err := waitPlanBrokerCPUHolderTerminal(helperPIDFD, helperPID, helperStart, terminalDeadline); err != nil { return failure(planBrokerCPUReasonExit, err) }
	if err := requireReportEOF(terminalDeadline, planBrokerCPUReasonPipe); err != nil { return failure(planBrokerCPUReasonPipe, err) }
	if err := planBrokerCPULaunchStillCurrent(paths, launch); err != nil { return failure(planBrokerCPUReasonIdentity, errors.New("parentdeath control changed the original worker")) }
	afterCtx, cancelAfter := context.WithDeadline(context.Background(), deadline)
	unitAfter, stateErr := planBrokerCPUFixtureUnitState(afterCtx, paths)
	cancelAfter()
	if stateErr != nil || unitAfter.MainPID != unitBefore.MainPID || unitAfter.Invocation != unitBefore.Invocation || unitAfter.Active != unitBefore.Active || unitAfter.ControlGroup != unitBefore.ControlGroup { return failure(planBrokerCPUReasonUnit, errors.New("parentdeath control changed the exact loaded worker state")) }
	currentRoot, rootErr := os.Lstat(root)
	if rootErr != nil || !os.SameFile(rootInfo, currentRoot) { return failure(planBrokerCPUReasonIdentity, errors.New("parentdeath control changed private root identity")) }
	fmt.Printf("__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\t%s\t%s\n", control, wantPhase)
	return nil
}

func runPlanBrokerCPUHolderControlMatrix(paths checkpointPlanBrokerPaths, root string, rootInfo os.FileInfo, launch planBrokerCPULaunchIdentity, workerLaunchRequestedAt time.Time) error {
	started := time.Now()
	workerDeadline := workerLaunchRequestedAt.Add(planBrokerCPUHolderControlWorkerTimeout)
	reserveDeadline := workerDeadline.Add(-planBrokerCPUHolderControlPostMatrixReserve)
	aggregateDeadline := started.Add(planBrokerCPUHolderControlAggregateBudget)
	if reserveDeadline.Before(aggregateDeadline) { aggregateDeadline = reserveDeadline }
	if len(planBrokerCPUHolderControlCases) != 10 { return planBrokerCPUFailureAt(planBrokerCPUStageMatrixAdmission, planBrokerCPUReasonUncertain, "", errors.New("holder control matrix does not contain the exact ten closed cases")) }
	var schedule time.Duration
	for _, testCase := range planBrokerCPUHolderControlCases { schedule += testCase.budget }
	if workerLaunchRequestedAt.IsZero() || planBrokerCPUHolderControlAggregateBudget >= planBrokerCPUHolderControlContractCeiling || planBrokerCPUHolderControlContractCeiling != planBrokerCPUHolderControlWorkerTimeout || schedule > planBrokerCPUHolderControlAggregateBudget || planBrokerCPUHolderControlWorkerTimeout <= planBrokerCPUHolderControlPostMatrixReserve || time.Until(workerDeadline) <= schedule+planBrokerCPUHolderControlPostMatrixReserve || planBrokerCPUHolderNormalWorstCaseBytes+planBrokerCPUHolderFailureFrameReserveBytes > 1024 {
		reason := planBrokerCPUReasonDeadline
		return planBrokerCPUFailureAt(planBrokerCPUStageMatrixAdmission, reason, "", errors.New("holder control schedule does not leave its measured 40-second normal-operation reserve inside the original worker90s deadline"))
	}
	for _, testCase := range planBrokerCPUHolderControlCases {
		if testCase.phase != planBrokerCPUHolderControlTarget(testCase.control) || testCase.budget <= 0 || time.Until(aggregateDeadline) <= 0 { return planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonDeadline, string(testCase.control), errors.New("holder control matrix phase or aggregate deadline is invalid")) }
		caseDeadline := time.Now().Add(testCase.budget)
		if time.Until(aggregateDeadline) < time.Until(caseDeadline) { caseDeadline = aggregateDeadline }
		if err := runPlanBrokerCPUHolderControlCase(paths, root, rootInfo, launch, testCase.control, caseDeadline); err != nil { return planBrokerCPUHolderControlMatrixFailure(string(testCase.control), err) }
	}
	elapsed := time.Since(started)
	workerRemaining := time.Until(workerDeadline)
	if elapsed > planBrokerCPUHolderControlAggregateBudget || workerRemaining < planBrokerCPUHolderControlPostMatrixReserve { return planBrokerCPUFailureAt(planBrokerCPUStageMatrixReserve, planBrokerCPUReasonDeadline, "", errors.New("holder control matrix exceeded its fixed wall or worker-reserve deadline")) }
	fmt.Printf("__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL_MATRIX__ cases=10 budget_ms=45000 worker_ms=90000 reserve_ms=40000 elapsed_ms=%d worker_remaining_ms=%d\n", elapsed.Milliseconds(), workerRemaining.Milliseconds())
	return nil
}

func startPlanBrokerCPUUnitHolderMode(paths checkpointPlanBrokerPaths, rootInfo os.FileInfo, held planBrokerCPULaunchIdentity, maxHealth int, control planBrokerCPUHolderControl, deadline time.Time) (*planBrokerCPUUnitHolder, error) {
	origin := func(reason planBrokerCPUFailureReason, err error) (*planBrokerCPUUnitHolder, error) { return nil, planBrokerCPUFailureOrigin(reason, err) }
	originBranch := func(reason planBrokerCPUFailureReason, class planBrokerCPUFailureReason, err error) (*planBrokerCPUUnitHolder, error) { return origin(reason, planBrokerCPUHolderBranchAt(class, err)) }
	if maxHealth != 27 && maxHealth != 6 || rootInfo == nil || !planBrokerCPUFixtureUnitBound(paths, held.UnitName) || held.PID <= 1 || held.StartTicks == 0 {
		return originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderPreSpawnBinding, errors.New("unit holder requires an exact private root, held worker and fixed health budget"))
	}
	if !deadline.After(time.Now()) { return originBranch(planBrokerCPUReasonDeadline, planBrokerCPUReasonChildHolderPreSpawnDeadline, errors.New("unit holder phase deadline is expired")) }
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 || rootInfo.Mode().Perm() != 0o711 || paths.NodeGID == 0 {
		return originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderRootMetadata, errors.New("unit holder root ownership or non-root node group is not independently pinned"))
	}
	if err := planBrokerCPULaunchStillCurrent(paths, held); err != nil {
		return originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderLaunchCurrent, err)
	}
	unitCtx, cancelUnit := context.WithDeadline(context.Background(), deadline)
	unit, err := planBrokerCPUFixtureUnitState(unitCtx, paths)
	cancelUnit()
	if err != nil || unit.MainPID != held.PID || unit.Invocation != held.Invocation || unit.Active != "active" || unit.ControlGroup != held.ControlGroup {
		primary := err
		if primary == nil { primary = errors.New("unit holder requires the exact original loaded active worker") }
		return originBranch(planBrokerCPUReasonUnit, planBrokerCPUReasonChildHolderUnitCurrent, primary)
	}
	guardR, guardW, err := os.Pipe()
	if err != nil { return originBranch(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderPipeSetup, err) }
	commandR, commandW, err := os.Pipe()
	if err != nil { guardR.Close(); guardW.Close(); return originBranch(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderPipeSetup, err) }
	statusR, statusW, err := os.Pipe()
	if err != nil { guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); return originBranch(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderPipeSetup, err) }
	var controlR, controlW, blockR, blockW *os.File
	if control != "" {
		if planBrokerCPUHolderControlTarget(control) == "" { guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); return origin(planBrokerCPUReasonIdentity, errors.New("holder control is not a fixed compiled enum")) }
		controlR, controlW, err = os.Pipe()
		if err != nil { guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); return originBranch(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderPipeSetup, err) }
		blockR, blockW, err = os.Pipe()
		if err != nil { guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); controlR.Close(); controlW.Close(); return originBranch(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderPipeSetup, err) }
		if _, err := controlW.Write([]byte(string(control)+"\n")); err != nil { guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); controlR.Close(); controlW.Close(); blockR.Close(); blockW.Close(); return originBranch(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderTokenSetup, err) }
		if err := controlW.Close(); err != nil { guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); controlR.Close(); blockR.Close(); blockW.Close(); return originBranch(planBrokerCPUReasonClose, planBrokerCPUReasonChildHolderTokenSetup, err) }
	}
	parentFD, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil { guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); if controlR!=nil { controlR.Close() }; if blockR!=nil { blockR.Close() }; if blockW!=nil { blockW.Close() }; return originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderParentPIDFD, err) }
	parentTarget, err := planBrokerCPUPIDFDTarget(parentFD)
	if err != nil || parentTarget != os.Getpid() {
		unix.Close(parentFD); guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); if controlR!=nil { controlR.Close() }; if blockR!=nil { blockR.Close() }; if blockW!=nil { blockW.Close() }
		return originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderParentPIDFD, errors.New("original test-parent pidfd target is not exact"))
	}
	parentFile := os.NewFile(uintptr(parentFD), "original-test-parent-pidfd")
	rootFD, err := unix.Open(paths.fixtureRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil { parentFile.Close(); guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); if controlR!=nil { controlR.Close() }; if blockR!=nil { blockR.Close() }; if blockW!=nil { blockW.Close() }; return originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderRootHandle, err) }
	rootFile := os.NewFile(uintptr(rootFD), "held-private-fixture-root")
	var rootStatNow unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStatNow); err != nil || rootStatNow.Dev != rootStat.Dev || rootStatNow.Ino != rootStat.Ino || rootStatNow.Uid != 0 || rootStatNow.Gid != rootStat.Gid || rootStatNow.Mode&syscall.S_IFMT != syscall.S_IFDIR || rootStatNow.Mode&0o777 != 0o711 {
		rootFile.Close(); parentFile.Close(); guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); if controlR!=nil { controlR.Close() }; if blockR!=nil { blockR.Close() }; if blockW!=nil { blockW.Close() }; return originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderRootHandle, errors.New("held fixture root descriptor does not match the original root object"))
	}
	childPIDFD := -1
	cmd := exec.Command("/usr/bin/python3", "-I", "-c", planBrokerCPUUnitHolderProgram)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	if control == planBrokerCPUControlAfterRearmDeath {
		cmd.Stdout = os.Stdout
	}
	cmd.ExtraFiles = []*os.File{guardR, commandR, statusW, parentFile, rootFile}
	if controlR != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, controlR, blockR)
		if control == planBrokerCPUControlAfterRearmDeath {
			cmd.ExtraFiles = append(cmd.ExtraFiles, guardW)
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &childPIDFD}
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		rootFile.Close(); parentFile.Close(); guardR.Close(); guardW.Close(); commandR.Close(); commandW.Close(); statusR.Close(); statusW.Close(); if controlR!=nil { controlR.Close() }; if blockR!=nil { blockR.Close() }; if blockW!=nil { blockW.Close() }
		return originBranch(planBrokerCPUReasonExit, planBrokerCPUReasonChildHolderSpawn, err)
	}
	guardR.Close(); commandR.Close(); statusW.Close()
	if controlR!=nil { controlR.Close(); blockR.Close() }
	holder := &planBrokerCPUUnitHolder{cmd: cmd, command: commandW, guard: guardW, status: statusR, parent: parentFile, root: rootFile, rootFD: rootFD, childPIDFD: childPIDFD, pid: cmd.Process.Pid, maxHealth: maxHealth, controlBlock: blockW, waitDone: make(chan struct{})}
	go func() { holder.waitErr = cmd.Wait(); close(holder.waitDone) }()
	if control != "" {
		holder.bytes += len(string(control)) + 1
		holder.messages++
		holder.maxFrame = len(string(control)) + 1
	}
	identity, identityErr := capturePlanBrokerCPUProcessIdentity(holder.pid)
	childTarget, targetErr := planBrokerCPUPIDFDTarget(holder.childPIDFD)
	pythonInfo, imageErr := os.Stat("/usr/bin/python3")
	if identityErr != nil || targetErr != nil || childTarget != holder.pid || imageErr != nil || identity.ExecutableDevice != uint64(pythonInfo.Sys().(*syscall.Stat_t).Dev) || identity.ExecutableInode != uint64(pythonInfo.Sys().(*syscall.Stat_t).Ino) {
		var cause error = errors.New("unit holder child pidfd or resolved Python image is not exact")
		if identityErr != nil { cause = identityErr } else if targetErr != nil { cause = targetErr } else if imageErr != nil { cause = imageErr }
		return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonIdentity, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderChildIdentity, cause), holder)
	}
	helperCgroup, cgroupErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(holder.pid), "cgroup"))
	workerCgroup, workerCgroupErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(held.PID), "cgroup"))
	if cgroupErr != nil || workerCgroupErr != nil || !planBrokerCPUOutsideExactWorkerCgroup(helperCgroup, workerCgroup) {
		var cause error = errors.New("unit holder entered the original worker cgroup or its descendants")
		if cgroupErr != nil { cause = cgroupErr } else if workerCgroupErr != nil { cause = workerCgroupErr }
		return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonUnit, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderChildCgroup, cause), holder)
	}
	holder.image, holder.startTicks = identity, identity.StartTicks
	target := planBrokerCPUHolderControlTarget(control)
	if control != "" && (target == "pre_ready" || target == "startup") { return holder, nil }
	if control != "" && target == "watchdog_omitted" { return holder, nil }
	if n, err := guardW.Write([]byte("P")); err != nil || n != 1 { return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.New("unit holder guard bootstrap token failed"), holder) }
	holder.bytes++
	holder.messages++
	if holder.maxFrame < 1 { holder.maxFrame = 1 }
	frame, err := holder.readFrameUntil(deadline)
	if err != nil || frame != "GUARD_READY" { return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.New("unit holder did not prove installed watchdog and parent guard"), holder) }
	if control != "" { return holder, nil }
	acquireDeadline := time.Now().Add(5 * time.Second)
	rootPath := paths.fixtureRoot
	request := fmt.Sprintf("ACQUIRE\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", base64.StdEncoding.EncodeToString([]byte(rootPath)), rootStat.Dev, rootStat.Ino, rootStat.Uid, rootStat.Gid, paths.NodeGID, os.Getpid(), held.UnitName)
	if err := holder.send(request); err != nil { return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, err, holder) }
	frame, err = holder.readFrameUntil(acquireDeadline)
	parts := strings.Split(frame, "\t")
	if err != nil || len(parts) != 3 || parts[0] != "REF_READY" || len(frame) > 192 || !planBrokerCPUValidBusName(parts[1]) || !planBrokerCPUValidBusName(parts[2]) {
		return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, errors.New("unit holder did not confirm one bounded same-connection reference"), holder)
	}
	if err := planBrokerCPULaunchStillCurrent(paths, held); err != nil { return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonIdentity, errors.New("original worker changed across unit reference acquisition"), holder) }
	verifyCtx, cancelVerify := context.WithDeadline(context.Background(), acquireDeadline)
	unit, err = planBrokerCPUFixtureUnitState(verifyCtx, paths)
	cancelVerify()
	if err != nil || unit.MainPID != held.PID || unit.Invocation != held.Invocation || unit.Active != "active" || unit.ControlGroup != held.ControlGroup {
		return nil, planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonUnit, errors.New("loaded active original worker changed across unit reference acquisition"), holder)
	}
	holder.unit = held.UnitName
	return holder, nil
}

func (holder *planBrokerCPUUnitHolder) send(frame string) error {
	if holder == nil || holder.closed { return planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, errors.New("unit holder protocol budget or state is invalid")) }
	if len(frame) == 0 || len(frame) > 192 || holder.bytes+len(frame) > 1024 { return planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder protocol budget or state is invalid")) }
	n, err := holder.command.Write([]byte(frame))
	if err != nil || n != len(frame) { return planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, &planBrokerCPUFixedMessageFailure{message: "unit holder command frame was not completely written", cause: err}) }
	holder.bytes += n
	holder.messages++
	if n > holder.maxFrame { holder.maxFrame = n }
	return nil
}

func (holder *planBrokerCPUUnitHolder) readFrame(timeout time.Duration) (string, error) {
	if timeout <= 0 { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder response deadline is invalid")) }
	return holder.readFrameUntil(time.Now().Add(timeout))
}

func (holder *planBrokerCPUUnitHolder) readFrameUntil(deadline time.Time) (string, error) {
	if holder == nil || holder.closed || holder.status == nil {
		return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, errors.New("unit holder response budget or state is invalid"))
	}
	if !deadline.After(time.Now()) { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder response budget or state is invalid")) }
	if holder.bytes >= 1024 { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder response budget or state is invalid")) }
	for time.Now().Before(deadline) {
		if newline := bytes.IndexByte(holder.readBuffer, '\n'); newline >= 0 {
			frameSize := newline + 1
			if newline == 0 || frameSize > 192 || bytes.ContainsAny(holder.readBuffer[:newline], "\r") || holder.bytes+frameSize > 1024 {
				return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder response frame or aggregate transcript is invalid"))
			}
			frame := string(holder.readBuffer[:newline])
			holder.readBuffer = append(holder.readBuffer[:0], holder.readBuffer[frameSize:]...)
			holder.bytes += frameSize
			holder.messages++
			if frameSize > holder.maxFrame { holder.maxFrame = frameSize }
			return frame, nil
		}
		if len(holder.readBuffer) > 192 || holder.bytes+len(holder.readBuffer) > 1024 {
			return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder partial response exceeded its fixed frame/transcript bound"))
		}
		remaining := time.Until(deadline)
		poll := []unix.PollFd{{Fd: int32(holder.status.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR | unix.POLLNVAL}}
		ms := int((remaining + time.Millisecond - 1) / time.Millisecond)
		if ms > 250 { ms = 250 }
		if ms < 1 { ms = 1 }
		if _, err := unix.Poll(poll, ms); err != nil && !errors.Is(err, unix.EINTR) { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder status poll failed")) }
		if poll[0].Revents&unix.POLLNVAL != 0 || poll[0].Revents&unix.POLLERR != 0 && poll[0].Revents&unix.POLLIN == 0 {
			reason := planBrokerCPUReasonPipe
			if poll[0].Revents&unix.POLLNVAL != 0 { reason = planBrokerCPUReasonClose }
			return "", planBrokerCPUFailureOrigin(reason, errors.New("unit holder status descriptor reported an invalid event"))
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			select { case <-holder.waitDone: return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, errors.New("unit holder exited before its response")); default: }
			continue
		}
		readLimit := 1024 - holder.bytes - len(holder.readBuffer)
		if readLimit > 256 { readLimit = 256 }
		if readLimit <= 0 { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder aggregate response buffer exceeded its fixed cap")) }
		chunk := make([]byte, readLimit)
		n, err := holder.status.Read(chunk)
		if err != nil || n == 0 { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder response stream closed before a complete frame")) }
		holder.readBuffer = append(holder.readBuffer, chunk[:n]...)
	}
	return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder response exceeded its fixed phase deadline"))
}

func (holder *planBrokerCPUUnitHolder) health() error {
	if holder == nil || holder.closed || holder.healthSites >= holder.maxHealth { return errors.New("unit holder health site exceeded its fixed owner budget") }
	if holder.bytes > 1024 || planBrokerCPUHolderIdentityCurrent(holder) != nil { return errors.New("unit holder identity changed before health check") }
	if err := holder.send("HEALTH\n"); err != nil { return err }
	frame, err := holder.readFrame(3 * time.Second)
	if err != nil || frame != "HEALTH_READY" || planBrokerCPUHolderIdentityCurrent(holder) != nil { return errors.New("unit holder same-connection manager health failed") }
	holder.healthSites++
	return nil
}

func (holder *planBrokerCPUUnitHolder) assertCurrent() error {
	if holder == nil || holder.closed || holder.bytes > 1024 || planBrokerCPUHolderIdentityCurrent(holder) != nil {
		return errors.New("unit holder identity or latched Wait state changed")
	}
	select {
	case <-holder.waitDone:
		return errors.New("unit holder exited before top-level result certification")
	default:
		return nil
	}
}

func planBrokerCPUHolderEOFParentAliveOutcome(holder *planBrokerCPUUnitHolder, paths checkpointPlanBrokerPaths, launch planBrokerCPULaunchIdentity, rootInfo os.FileInfo) error {
	if holder == nil || holder.parent == nil || holder.cmd == nil || holder.pid <= 1 || holder.startTicks == 0 {
		return errors.New("holder identity is unavailable for the parent-alive EOF check")
	}
	parentTarget, parentErr := planBrokerCPUPIDFDTarget(int(holder.parent.Fd()))
	parentEvents := []unix.PollFd{{Fd: int32(holder.parent.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR | unix.POLLNVAL}}
	if parentErr != nil || parentTarget != os.Getpid() { return errors.New("original Go test parent pidfd is not exact") }
	if _, pollErr := unix.Poll(parentEvents, 0); pollErr != nil || parentEvents[0].Revents != 0 { return errors.New("original Go test parent is not independently live") }
	deadline := time.Now().Add(5 * time.Second)
	confirmExactTerminal := func() error {
		status, ok := holder.cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !ok || !status.Exited() || (status.ExitStatus() != 107 && status.ExitStatus() != 111) { return errors.New("helper terminal was not one of the exact fixed guard-EOF-alive rejection branches") }
		if holder.bytes > 1024 || holder.messages != 4+2*holder.healthSites || holder.maxFrame > 192 || holder.unit != launch.UnitName || holder.releaseDone { return errors.New("guard-EOF rejection exceeded its transcript or lost the exact held unit") }
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		unit, stateErr := planBrokerCPUFixtureUnitState(ctx, paths)
		cancel()
		if stateErr != nil || unit.MainPID != launch.PID || unit.Invocation != launch.Invocation || unit.Active != "active" || unit.ControlGroup != launch.ControlGroup || planBrokerCPULaunchStillCurrent(paths, launch) != nil { return errors.New("guard-EOF rejection changed the exact original active worker") }
		currentRoot, rootErr := os.Lstat(paths.fixtureRoot)
		if rootErr != nil || !os.SameFile(rootInfo, currentRoot) { return errors.New("guard-EOF rejection changed private root identity") }
		if closeErr := holder.closeFiles(); closeErr != nil { return errors.New("guard-EOF rejection descriptor custody close was uncertain") }
		return errors.New(planBrokerCPUHolderEOFAlivePredicate)
	}
	waitExactTerminal := func() error {
		remaining := time.Until(deadline)
		if remaining <= 0 { return errors.New("guard-EOF helper Wait exceeded its original absolute terminal deadline") }
		select {
		case <-holder.waitDone:
			return confirmExactTerminal()
		case <-time.After(remaining):
			return errors.New("guard-EOF helper Wait did not settle within its original absolute terminal deadline")
		}
	}
	if holder.guard == nil {
		// The closed-sole-writer case must await the existing Wait owner. Do not
		// route this intentional terminal through the live-helper assertion.
		return waitExactTerminal()
	}
	select {
	case <-holder.waitDone:
		return confirmExactTerminal()
	case <-time.After(100 * time.Millisecond):
		if err := holder.assertCurrent(); err != nil {
			// A pidfd terminal can precede publication by the sole Wait owner.
			// Give that owner only the residual time from the original deadline.
			return waitExactTerminal()
		}
	}
	return nil
}

func (holder *planBrokerCPUUnitHolder) release() error {
	if holder == nil { return planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, errors.New("unit holder release lacks its exact held state")) }
	if holder.releaseDone { return holder.releaseErr }
	holder.releaseDone = true
	finish := func(err error) error { holder.releaseErr = err; return holder.releaseErr }
	if holder.closed || holder.unit == "" { return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, errors.New("unit holder release lacks its exact held state"))) }
	if holder.bytes > 1024 { return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder identity changed before normal release"))) }
	if planBrokerCPUHolderIdentityCurrent(holder) != nil { return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonIdentity, errors.New("unit holder identity changed before normal release"))) }
	deadline := time.Now().Add(5 * time.Second)
	if err := holder.send("RELEASE\n"); err != nil { return finish(err) }
	frame, err := holder.readFrameUntil(deadline)
	if err != nil || frame != "RELEASED" {
		return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, &planBrokerCPUFixedMessageFailure{message: "unit holder did not confirm same-connection release", cause: err}))
	}
	remaining := time.Until(deadline)
	if remaining <= 0 { return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder normal release exhausted its total five-second deadline"))) }
	select {
	case <-holder.waitDone:
	case <-time.After(remaining):
		return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder did not reap within the fixed release deadline")))
	}
	if holder.waitErr != nil || holder.cmd.ProcessState == nil || holder.cmd.ProcessState.ExitCode() != 0 { return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, errors.New("unit holder normal release did not produce one zero-exit Wait"))) }
	// Wait means the child closed its only writer. Require EOF and no queued
	// bytes, so a duplicate/trailing final frame cannot escape transcript bounds.
	if err := holder.requireStatusEOFUntil(deadline); err != nil { return finish(err) }
	if holder.messages != 6+2*holder.healthSites || holder.maxFrame > 192 || holder.bytes > 1024 { return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder normal transcript metrics differ from the exact finite callsite schedule"))) }
	fmt.Printf("__PLAN_RELAUNCH_UNIT_HOLDER_RELEASED__ bytes=%d messages=%d max_frame=%d health=%d\n", holder.bytes, holder.messages, holder.maxFrame, holder.healthSites)
	return finish(holder.closeFiles())
}

func (holder *planBrokerCPUUnitHolder) requireStatusEOFUntil(deadline time.Time) error {
	if holder == nil || holder.status == nil { return planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, errors.New("unit holder status EOF lacks a live bounded descriptor")) }
	if !deadline.After(time.Now()) { return planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder status EOF lacks a live bounded descriptor")) }
	if len(holder.readBuffer) != 0 { return planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder left an unconsumed trailing response frame")) }
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		ms := int((remaining + time.Millisecond - 1) / time.Millisecond)
		if ms > 100 { ms = 100 }
		if ms < 1 { ms = 1 }
		poll := []unix.PollFd{{Fd: int32(holder.status.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR | unix.POLLNVAL}}
		if _, err := unix.Poll(poll, ms); err != nil && !errors.Is(err, unix.EINTR) { return planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder status EOF poll failed")) }
		if poll[0].Revents&unix.POLLNVAL != 0 { return planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, errors.New("unit holder status EOF descriptor reported an invalid event")) }
		if poll[0].Revents&unix.POLLERR != 0 && poll[0].Revents&unix.POLLIN == 0 { return planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder status EOF descriptor reported an invalid event")) }
		if poll[0].Revents&unix.POLLIN == 0 && poll[0].Revents&unix.POLLHUP == 0 { continue }
		var trailing [1]byte
		n, readErr := holder.status.Read(trailing[:])
		if n != 0 { return planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder status stream contained a trailing or duplicate response")) }
		if errors.Is(readErr, io.EOF) { return nil }
		if readErr != nil { return planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder status stream did not settle at exact EOF")) }
	}
	return planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder status stream did not reach exact EOF within the shared release deadline"))
}

func (holder *planBrokerCPUUnitHolder) abort() error {
	if holder == nil { return nil }
	if holder.abortDone { return holder.abortErr }
	holder.abortDone = true
	var result error
	if holder.controlBlock != nil {
		if err := holder.controlBlock.Close(); err != nil { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, err)) }
		holder.controlBlock = nil
	}
	if holder.guard != nil {
		if err := holder.guard.Close(); err != nil { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, err)) }
		holder.guard = nil
	}
	if holder.command != nil {
		if err := holder.command.Close(); err != nil { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, err)) }
		holder.command = nil
	}
	deadline := time.Now().Add(5 * time.Second)
	select { case <-holder.waitDone: default:
		grace := time.Until(deadline) - time.Second
		if grace > 0 { select { case <-holder.waitDone: case <-time.After(grace): } }
		select { case <-holder.waitDone: default:
			if holder.childPIDFD <= 0 || planBrokerCPUHolderIdentityCurrent(holder) != nil {
				result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonIdentity, errors.New("holder abort lacked exact child pidfd identity; preserving fixture")))
			} else if err := unix.PidfdSendSignal(holder.childPIDFD, syscall.SIGKILL, nil, 0); err != nil {
				result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, errors.New("exact holder abort signal failed")))
			} else {
				result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, errors.New("unit holder required emergency kill; normal custody failed")))
			}
			remaining := time.Until(deadline)
			if remaining > 0 { select { case <-holder.waitDone: case <-time.After(remaining): result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder did not reap within its single five-second abort bound"))) } } else { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder abort deadline expired before reap"))) }
		}
	}
	if holder.waitErr != nil { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, errors.New("unit holder terminated without normal release"))) }
	holder.abortErr = errors.Join(result, holder.closeFiles())
	return holder.abortErr
}

func (holder *planBrokerCPUUnitHolder) closeFiles() error {
	if holder == nil { return nil }
	if holder.closed { return holder.closeErr }
	var result error
	closeFile := func(file **os.File) {
		if *file == nil { return }
		if err := (*file).Close(); err != nil { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, &planBrokerCPUFixedMessageFailure{message: "unit holder pipe close failed", cause: err})) }
		*file = nil
	}
	closeFile(&holder.command)
	closeFile(&holder.guard)
	closeFile(&holder.status)
	closeFile(&holder.parent)
	closeFile(&holder.root)
	closeFile(&holder.controlBlock)
	if holder.childPIDFD > 0 {
		if err := unix.Close(holder.childPIDFD); err != nil { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, &planBrokerCPUFixedMessageFailure{message: "unit holder pidfd close failed", cause: err})) }
		holder.childPIDFD = -1
	}
	holder.closed = true
	holder.closeErr = result
	return holder.closeErr
}

func planBrokerCPUHolderIdentityCurrent(holder *planBrokerCPUUnitHolder) error {
	if holder == nil || holder.pid <= 1 || holder.startTicks == 0 || holder.childPIDFD <= 0 { return errors.New("holder identity is incomplete") }
	target, err := planBrokerCPUPIDFDTarget(holder.childPIDFD)
	current, currentErr := capturePlanBrokerCPUProcessIdentity(holder.pid)
	_, signalErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(holder.pid)), holder.pid)
	poll := []unix.PollFd{{Fd: int32(holder.childPIDFD), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR | unix.POLLNVAL}}
	_, pollErr := unix.Poll(poll, 0)
	if err != nil || currentErr != nil || signalErr != nil || pollErr != nil || poll[0].Revents != 0 || target != holder.pid || current.StartTicks != holder.startTicks || current.ExecutableDevice != holder.image.ExecutableDevice || current.ExecutableInode != holder.image.ExecutableInode || current.ExecutableSHA256 != holder.image.ExecutableSHA256 { return errors.New("holder pidfd, process start or image changed") }
	return nil
}

func planBrokerCPUOutsideExactWorkerCgroup(holder, worker []byte) bool {
	parse := func(raw []byte) string {
		if len(raw) == 0 || len(raw) > 16<<10 { return "" }
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			fields := strings.SplitN(line, ":", 3)
			if len(fields) == 3 && fields[0] == "0" && fields[1] == "" && strings.HasPrefix(fields[2], "/") && filepath.Clean(fields[2]) == fields[2] { return fields[2] }
		}
		return ""
	}
	a, b := parse(holder), parse(worker)
	return a != "" && b != "" && a != b && !strings.HasPrefix(a, b+string(os.PathSeparator))
}

func planBrokerCPUValidBusName(name string) bool {
	if len(name) < 2 || len(name) > 64 || name[0] != ':' { return false }
	for _, r := range name[1:] { if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r == '.' || r == '_') { return false } }
	return strings.Contains(name, ".")
}

func writePlanBrokerCPUFile(path string, body []byte, mode os.FileMode, uid, gid int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(body) == 0 || len(body) > checkpointPlanCatalogMaxBytes {
		return errors.New("fixture file path or bound is invalid")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if n, err := f.Write(body); err != nil || n != len(body) {
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	closed = true
	return checkpointPlanBrokerSyncDir(filepath.Dir(path))
}

func writePlanBrokerCPUKeys(paths checkpointPlanBrokerPaths, rootPrivate ed25519.PrivateKey, rootPublic ed25519.PublicKey, stopPrivate ed25519.PrivateKey, stopPublic ed25519.PublicKey, gid uint32) error {
	for _, item := range []struct {
		path  string
		body  []byte
		mode  os.FileMode
		group int
	}{
		{paths.PrivateKey, []byte(hex.EncodeToString(rootPrivate)), 0o600, 0}, {paths.PublicKey, []byte(hex.EncodeToString(rootPublic)), 0o644, 0},
		{paths.StopPrivateKey, []byte(hex.EncodeToString(stopPrivate)), 0o600, 0}, {paths.StopPublicKey, []byte(hex.EncodeToString(stopPublic)), 0o640, int(gid)},
	} {
		if err := writePlanBrokerCPUFile(item.path, item.body, item.mode, 0, item.group); err != nil {
			return err
		}
	}
	return nil
}

func installPlanBrokerCPUWorker(paths checkpointPlanBrokerPaths) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	input, err := os.Open(executable)
	if err != nil {
		return "", err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
		return "", errors.New("test worker image is not a bounded regular file")
	}
	output, err := os.OpenFile(filepath.Join(paths.fixtureRoot, "worker"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o700)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, info.Size()+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || n != info.Size() {
		return "", errors.Join(copyErr, syncErr, closeErr, errors.New("worker image copy was incomplete"))
	}
	if err := os.Chmod(filepath.Join(paths.fixtureRoot, "worker"), 0o755); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writePlanBrokerCPUPlans(paths checkpointPlanBrokerPaths, workerSHA string) (CheckpointLaunchPlan, CheckpointLaunchPlan, error) {
	victimPath, urgentPath := filepath.Join(paths.fixtureRoot, "models", "victim.gguf"), filepath.Join(paths.fixtureRoot, "models", "urgent.gguf")
	if err := writePlanBrokerCPUFile(victimPath, []byte("synthetic CPU-only victim source\n"), 0o644, 0, 0); err != nil {
		return CheckpointLaunchPlan{}, CheckpointLaunchPlan{}, err
	}
	if err := writePlanBrokerCPUFile(urgentPath, []byte("synthetic CPU-only urgent source\n"), 0o644, 0, 0); err != nil {
		return CheckpointLaunchPlan{}, CheckpointLaunchPlan{}, err
	}
	makePlan := func(alias, modelPath string) (CheckpointLaunchPlan, error) {
		modelSHA, modelBytes, err := fileDigest(modelPath)
		if err != nil {
			return CheckpointLaunchPlan{}, err
		}
		return CheckpointLaunchPlan{Version: checkpointLaunchPlanVersion2, Alias: alias, Model: CheckpointLaunchModel{Path: modelPath, SHA256: modelSHA, Bytes: modelBytes}, Executable: CheckpointLaunchExecutable{Path: filepath.Join(paths.fixtureRoot, "worker"), SHA256: workerSHA}, Endpoint: CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: 18421}, TotalContextTokens: 1024, ParallelSlots: 1, SnapshotRoot: filepath.Join(paths.fixtureRoot, "var", "snapshots"), Custody: CheckpointLaunchCustodyQuotas{Root: filepath.Join(paths.fixtureRoot, "var", "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 2 << 20, ReserveBytes: 0}, Placement: &CheckpointLaunchPlacement{Backend: "cuda", IdentityKind: "uuid", PhysicalIdentity: "GPU-01234567-89ab-cdef-0123-456789abcdef", RuntimeDeviceToken: "CUDA0", RuntimeVersion: "llama.cpp commit 62acc89 CPU fixture", MaxAccelerators: 1, OffloadPolicy: "full_gpu", MinGPUBytes: 1, MaxHostRSSBytes: 1 << 30}}, nil
	}
	victim, err := makePlan("victim-model", victimPath)
	if err != nil {
		return victim, CheckpointLaunchPlan{}, err
	}
	urgent, err := makePlan("urgent-model", urgentPath)
	if err != nil {
		return victim, urgent, err
	}
	victimRaw, err := json.Marshal(victim)
	if err != nil {
		return victim, urgent, err
	}
	if err := writePlanBrokerCPUFile(paths.ActivePlan, victimRaw, 0o644, 0, 0); err != nil {
		return victim, urgent, err
	}
	return victim, urgent, nil
}

func writePlanBrokerCPUConfig(paths checkpointPlanBrokerPaths, gid uint32) error {
	body := []byte("node_id: cpu-plan-node\ncommand_signing_secret_env: VRAM_NODE_COMMAND_SECRET\ncommand_state_path: " + paths.NodeState + "\nllamacpp:\n  servers:\n    - id: server\n      endpoint: http://127.0.0.1:18421\n")
	return writePlanBrokerCPUFile(paths.NodeConfig, body, 0o640, 0, int(gid))
}

func writePlanBrokerCPUEnv(paths checkpointPlanBrokerPaths, secret string, gid uint32) error {
	body := []byte("VRAM_NODE_TOKEN=" + strings.Repeat("T", 32) + "\nVRAM_NODE_COMMAND_SECRET=" + secret + "\n")
	return writePlanBrokerCPUFile(paths.NodeEnv, body, 0o640, 0, int(gid))
}

func encodePlanBrokerCPUCatalog(victim, urgent CheckpointLaunchPlan) ([]byte, error) {
	entries := make([]checkpointPlanCatalogEntry, 0, 2)
	for _, item := range []struct {
		id, model, workload string
		plan                CheckpointLaunchPlan
	}{{"victim-catalog", "victim-model", "cpu-workload", victim}, {"urgent-catalog", "urgent-model", "cpu-workload", urgent}} {
		body, err := json.Marshal(item.plan)
		if err != nil {
			return nil, err
		}
		entries = append(entries, checkpointPlanCatalogEntry{CatalogID: item.id, ModelID: item.model, WorkloadID: item.workload, WorkloadRevision: 1, PlanSHA256: sha256Hex(body), PlanBase64: base64.StdEncoding.EncodeToString(body)})
	}
	body, err := json.Marshal(checkpointPlanCatalog{Version: 1, Entries: entries})
	if err != nil {
		return nil, err
	}
	return body, nil
}

func makePlanBrokerCPUStopAck(paths checkpointPlanBrokerPaths, step string, unit checkpointFixedUnitState, held planBrokerCPULaunchIdentity, pidfd int, secret string, private ed25519.PrivateKey) (wsproto.CommandPayload, []byte, error) {
	if unit.MainPID != held.PID || unit.Invocation != held.Invocation || unit.ControlGroup != held.ControlGroup || held.UnitName != paths.fixtureUnit {
		return wsproto.CommandPayload{}, nil, errors.New("synthetic stop acknowledgement does not name the pre-stop held worker")
	}
	if err := verifyPlanBrokerCPUTerminalPIDFD(pidfd, held); err != nil {
		return wsproto.CommandPayload{}, nil, err
	}
	if err := verifyPlanBrokerCPUStopReceiptBinding(held, ownedStopReceipt{LocalCheckpointBinding: held.CurrentIncarnation, ManagedCurrentIncarnation: held.CurrentIncarnation, ManagedPlanSHA256: held.PlanSHA256, CustodyBindingSHA256: held.CustodyBindingSHA256, ModelAlias: held.Alias}); err != nil {
		return wsproto.CommandPayload{}, nil, err
	}
	candidate := ownedStopReceipt{WorkerPID: held.PID, WorkerStartTicks: held.StartTicks, InvocationID: held.Invocation, ControlGroup: held.ControlGroup, SignalSent: true, ReleaseTerminal: true}
	if err := checkpointPlanBrokerStoppedWorkerEmpty(context.Background(), paths, candidate); err != nil {
		return wsproto.CommandPayload{}, nil, errors.New("synthetic stop acknowledgement lacks the exact stopped unit, job, and old-cgroup proof")
	}
	binding := held.CurrentIncarnation
	if !checkpointSHA256RE.MatchString(binding) || !checkpointSHA256RE.MatchString(held.PlanSHA256) || !checkpointSHA256RE.MatchString(held.CustodyBindingSHA256) || held.Alias != held.Plan.Alias {
		return wsproto.CommandPayload{}, nil, errors.New("synthetic stop receipt lacks the exact held managed plan and custody identity")
	}
	snapshotBody := []byte("synthetic CPU fixture snapshot\n")
	snapshotName := step + ".kv"
	if err := writePlanBrokerCPUFile(filepath.Join(paths.fixtureRoot, "var", "snapshots", snapshotName), snapshotBody, 0o600, 0, 0); err != nil {
		return wsproto.CommandPayload{}, nil, err
	}
	command, err := ownedStopFixtureCommand("cpu-plan-node", binding, snapshotName, sha256Hex(snapshotBody), "cpu-epoch-1", secret)
	if err != nil {
		return command, nil, err
	}
	command.ID, command.IdempotencyKey = "cpu-stop-"+step, "cpu-stop-key-"+step
	command.Args["step_id"] = step
	command.Args["operation_id"] = "cpu-operation-1"
	command.Args["workload_id"] = "cpu-workload"
	command.Args["model_alias"] = map[string]string{"victim_stop": "victim-model", "urgent_stop": "urgent-model"}[step]
	command.Signature, err = wsproto.SignCommand(command, []byte(secret))
	if err != nil {
		return command, nil, err
	}
	public := private.Public().(ed25519.PublicKey)
	request, err := ownedStopFixtureRequest(command, public, secret)
	if err != nil {
		return command, nil, err
	}
	receiptRaw, err := signOwnedStopFixtureReceipt(command, request, private)
	if err != nil {
		return command, nil, err
	}
	var receipt ownedStopReceipt
	if json.Unmarshal(receiptRaw, &receipt) != nil {
		return command, nil, errors.New("fixture stop receipt decode failed")
	}
	receipt.WorkerPID = held.PID
	receipt.WorkerStartTicks = held.StartTicks
	receipt.InvocationID = held.Invocation
	receipt.ControlGroup = held.ControlGroup
	receipt.LocalCheckpointBinding = held.CurrentIncarnation
	receipt.ManagedCurrentIncarnation = held.CurrentIncarnation
	receipt.ManagedPlanSHA256 = held.PlanSHA256
	receipt.CustodyBindingSHA256 = held.CustodyBindingSHA256
	receipt.ModelAlias = held.Alias
	if err := verifyPlanBrokerCPUStopReceiptBinding(held, receipt); err != nil {
		return command, nil, err
	}
	receipt.SupervisorPID = os.Getpid()
	receipt.SupervisorStartTicks, err = checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(receipt.SupervisorPID)), receipt.SupervisorPID)
	if err != nil || receipt.SupervisorStartTicks == 0 {
		return command, nil, errors.New("synthetic stop acknowledgement signer incarnation is unavailable")
	}
	receipt.SignalSent, receipt.ReleaseTerminal = true, true
	receipt.Signature = ""
	unsigned, _ := json.Marshal(receipt)
	receipt.Signature = hex.EncodeToString(ed25519.Sign(private, ownedStopReceiptSigningMaterial(unsigned)))
	receiptRaw, err = json.Marshal(receipt)
	return command, receiptRaw, err
}

func verifyPlanBrokerCPUStopReceiptBinding(held planBrokerCPULaunchIdentity, receipt ownedStopReceipt) error {
	if !checkpointSHA256RE.MatchString(held.PlanSHA256) || !checkpointSHA256RE.MatchString(held.CurrentIncarnation) || !checkpointSHA256RE.MatchString(held.CustodyBindingSHA256) || held.Alias == "" ||
		receipt.LocalCheckpointBinding != held.CurrentIncarnation || receipt.ManagedCurrentIncarnation != held.CurrentIncarnation || receipt.ManagedPlanSHA256 != held.PlanSHA256 || receipt.CustodyBindingSHA256 != held.CustodyBindingSHA256 || receipt.ModelAlias != held.Alias {
		return errors.New("synthetic stop receipt does not match the exact held managed binding")
	}
	return nil
}

func writePlanBrokerCPUStopAck(paths checkpointPlanBrokerPaths, command wsproto.CommandPayload, receipt []byte, gid uint32) error {
	if err := writePlanBrokerCPUFile(filepath.Join(paths.StopReceiptDir, ownedStopReceiptFilename(command.ID)), receipt, 0o640, 0, int(gid)); err != nil {
		return err
	}
	seed, err := json.Marshal(struct {
		Command wsproto.CommandPayload `json:"command"`
		Receipt []byte                 `json:"receipt"`
	}{command, receipt})
	if err != nil {
		return err
	}
	commandBytes, err := json.Marshal(command)
	if err != nil {
		return err
	}
	if err := writePlanBrokerCPUFile(filepath.Join(paths.NodeStateDir, fmt.Sprint(command.Args["step_id"])+".command.json"), commandBytes, 0o640, int(paths.NodeUID), int(paths.NodeGID)); err != nil {
		return err
	}
	return writePlanBrokerCPUFile(filepath.Join(paths.NodeStateDir, fmt.Sprint(command.Args["step_id"])+".seed.json"), seed, 0o640, int(paths.NodeUID), int(paths.NodeGID))
}

func makePlanBrokerCPUCommand(paths checkpointPlanBrokerPaths, secret, step, catalogID, linkedID, priorStep string, prior wsproto.CommandPayload, receipt []byte) (wsproto.CommandPayload, error) {
	commandName := checkpointPlanRelaunchUrgentCommand
	if step == "victim_reload" {
		commandName = checkpointPlanRelaunchVictimCommand
	}
	args := map[string]any{"operation_id": "cpu-operation-1", "target_kind": "llamacpp", "target_id": "cpu-plan-node-server", "accelerator_id": "GPU-01234567-89ab-cdef-0123-456789abcdef", "workload_id": "cpu-workload", "workload_revision": int64(1), "recovery_epoch": "cpu-epoch-1", "fencing_token": int64(41), "catalog_id": catalogID, "prior_command_id": prior.ID, "prior_idempotency_key": prior.IdempotencyKey, "prior_receipt_sha256": sha256Hex(receipt)}
	if step == "urgent_load" {
		args["linked_catalog_id"] = linkedID
	}
	now := time.Now().UTC()
	command := wsproto.CommandPayload{ID: "cpu-plan-" + step, IdempotencyKey: "cpu-plan-key-" + step, NodeID: "cpu-plan-node", Command: commandName, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(3 * time.Minute), Args: args}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	return command, nil
}

func runPlanBrokerCPUNodeCommand(paths checkpointPlanBrokerPaths, uid, gid uint32, secret string, command wsproto.CommandPayload, phase string, victimStop, urgentStop []byte, reconcileAfterUncertain bool, restartBroker func() error, holder *planBrokerCPUUnitHolder) error {
	commandPath := filepath.Join(paths.NodeStateDir, phase+".command.json")
	commandRaw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	if err := writePlanBrokerCPUFile(commandPath, commandRaw, 0o640, int(uid), int(gid)); err != nil {
		return err
	}
	if phase == "victim_reload" && (len(victimStop) == 0 || len(urgentStop) == 0) {
		return errors.New("victim reload requires both linked stop receipts")
	}
	if holder == nil || holder.health() != nil {
		return errors.New("unit holder health failed before unit-affecting node command")
	}
	output, err := runPlanBrokerCPUNodeClient(paths, uid, gid, secret, phase, "command", 0)
	if err != nil {
		return err
	}
	if err := holder.assertCurrent(); err != nil { return err }
	uncertain := strings.Count(output, "__PLAN_RELAUNCH_CPU_UNCERTAIN__") == 1 && !strings.Contains(output, "__PLAN_RELAUNCH_CPU_RECONCILED__")
	if !reconcileAfterUncertain {
		if uncertain || strings.Contains(output, "__PLAN_RELAUNCH_CPU_RECONCILED__") {
			return errors.New("victim reload unexpectedly entered urgent recovery path")
		}
		return nil
	}
	if !uncertain || restartBroker == nil {
		return errors.New("urgent command did not return exactly one uncertain result for process-restart recovery")
	}
	for attempt := 1; attempt <= 20; attempt++ {
		if err := restartBroker(); err != nil {
			return fmt.Errorf("exact root broker process restart %d failed: %w", attempt, err)
		}
		if err := holder.health(); err != nil {
			return errors.New("unit holder health failed before consequential recovery query")
		}
		output, err = runPlanBrokerCPUNodeClient(paths, uid, gid, secret, phase, "query", attempt)
		if err != nil {
			return fmt.Errorf("fresh node process linked recovery query %d failed: %w", attempt, err)
		}
		if err := holder.assertCurrent(); err != nil { return err }
		if strings.Count(output, "__PLAN_RELAUNCH_CPU_RECONCILED__") == 1 && !strings.Contains(output, "__PLAN_RELAUNCH_CPU_UNCERTAIN__") {
			return nil
		}
		if strings.Count(output, "__PLAN_RELAUNCH_CPU_UNCERTAIN__") != 1 || strings.Contains(output, "__PLAN_RELAUNCH_CPU_RECONCILED__") {
			return errors.New("fresh query produced neither one uncertain result nor one terminal reconciliation")
		}
	}
	return errors.New("linked query did not reconcile within the fixed broker-restart bound")
}

func runPlanBrokerCPUNodeClient(paths checkpointPlanBrokerPaths, uid, gid uint32, secret, phase, mode string, attempt int) (string, error) {
	if (mode != "command" && mode != "query") || (mode == "command" && attempt != 0) || (mode == "query" && (attempt < 1 || attempt > 20)) {
		return "", errors.New("node client mode is outside its fixed fixture contract")
	}
	child := exec.Command(filepath.Join(paths.fixtureRoot, "worker"), "-test.v", "-test.run=^TestCheckpointPlanRelaunchCPUNodeClient$", "-test.count=1", "-test.timeout=90s")
	child.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/bin", planBrokerCPUEnv + "=" + planBrokerCPUOptIn, planBrokerCPURole + "=node-client", planBrokerCPUClientMode + "=" + mode, "VRAM_PLAN_BROKER_CPU_ROOT=" + paths.fixtureRoot, "VRAM_PLAN_BROKER_CPU_PHASE=" + phase, "VRAM_NODE_TOKEN=" + strings.Repeat("T", 32), "VRAM_NODE_COMMAND_SECRET=" + secret}
	if mode == "query" {
		child.Env = append(child.Env, "VRAM_PLAN_BROKER_CPU_QUERY_ATTEMPT="+strconv.Itoa(attempt))
	}
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{gid}}}
	child.WaitDelay = 2 * time.Second
	output, err := child.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("unprivileged node helper failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	if err := verifyPlanBrokerCPUTestInventory(string(output), "TestCheckpointPlanRelaunchCPUNodeClient"); err != nil {
		return "", fmt.Errorf("unprivileged node helper test inventory is invalid: %w", err)
	}
	return string(output), nil
}

func verifyPlanBrokerCPUTestInventory(output, expected string) error {
	if expected == "" || len(output) == 0 || len(output) > 1<<20 {
		return errors.New("selected helper output is empty or oversized")
	}
	events := make([]string, 0, 2)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "=== RUN") {
			if strings.TrimSpace(strings.TrimPrefix(line, "=== RUN")) != expected {
				return errors.New("unexpected or malformed helper RUN event")
			}
			events = append(events, "RUN")
		}
		if strings.HasPrefix(line, "--- PASS:") || strings.HasPrefix(line, "--- SKIP:") || strings.HasPrefix(line, "--- FAIL:") {
			if !strings.HasPrefix(line, "--- PASS:") || !strings.HasPrefix(strings.TrimPrefix(line, "--- PASS:"), " "+expected+" (") || !strings.HasSuffix(line, ")") {
				return errors.New("unexpected, skipped, failed, or malformed helper result event")
			}
			events = append(events, "PASS")
		}
	}
	if len(events) != 2 || events[0] != "RUN" || events[1] != "PASS" {
		return errors.New("selected helper test did not produce exactly one ordered RUN and PASS")
	}
	return nil
}

func verifyPlanBrokerCPUTestInventoryParserControls() error {
	if err := verifyPlanBrokerCPUFailureMarkerControls(); err != nil {
		return err
	}
	for _, positive := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"empty ControlGroup", []byte("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=\nActiveState=inactive\nSubState=dead\n"), "empty_control_group"},
		{"empty InvocationID", []byte("MainPID=0\nInvocationID=\nControlGroup=/system.slice/fixed.service\nActiveState=inactive\nSubState=dead\n"), "empty_invocation"},
		{"both diagnostic fields empty", []byte("MainPID=0\nInvocationID=\nControlGroup=\nActiveState=inactive\nSubState=dead\n"), "empty_invocation_control_group"},
		{"complete PID/state shape failure", []byte("MainPID=1\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=/system.slice/fixed.service\nActiveState=active\nSubState=running\n"), "pid_state_shape"},
	} {
		if got := planBrokerCPUUnitStateParseShapeCode(positive.raw); got != positive.want {
			return errors.New("complete five-key diagnostic shape positive was not classified")
		}
		if _, err := parseCheckpointPlanBrokerUnitState(positive.raw); err == nil {
			return errors.New("diagnostic-only complete envelope passed the strict state parser")
		}
	}
	notFoundDiagnostic := []byte("MainPID=0\nInvocationID=\nControlGroup=\nActiveState=inactive\nSubState=dead\nLoadState=not-found\n")
	if _, err := parseCheckpointPlanBrokerStoppedState(notFoundDiagnostic); err == nil {
		return errors.New("not-found diagnostic unexpectedly passed the loaded-state parser")
	}
	missingCode := planBrokerCPUStoppedStateParseShapeCode(notFoundDiagnostic, "vram-plan-relaunch-cpu-0123456789abcdef.service")
	if missingCode != "unit_definition_missing" {
		return errors.New("captured exact not-found shape did not produce its finite diagnostic")
	}
	for _, owner := range []string{"TestCheckpointPlanRelaunchCPULifecycleSequence", "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect"} {
		want := "__PLAN_RELAUNCH_INACTIVE_WAIT__:" + owner + ":unit_definition_missing"
		if got := planBrokerCPUInactiveWaitMarker(owner, missingCode); got != want {
			return errors.New("actual owning failure marker lost the finite not-found category")
		}
	}
	for _, malformed := range [][]byte{
		[]byte("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=\nActiveState=inactive\n"),
		[]byte("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=\nControlGroup=\nActiveState=inactive\nSubState=dead\n"),
		[]byte("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=\nActiveState=inactive\nSubState=dead"),
		[]byte("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=\nActiveState=inactive\nSubState=dead\nPrivatePath=/secret\n"),
		[]byte("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=/system.slice/example.service\nActiveState=inactive\nSubState=dead\n"),
		[]byte("MainPID=0\nInvocationID=\nControlGroup=/system.slice/fixed.service\nActiveState=inactive\nSubState=\n"),
		[]byte("MainPID=0\nInvocationID=\nControlGroup=/system.slice/fixed.service\nActiveState=inactive\nSubState=dead\nPrivatePath=/secret\n"),
		[]byte("MainPID=invalid\nInvocationID=\nControlGroup=\nActiveState=inactive\nSubState=dead\n"),
		[]byte("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=\r\nActiveState=inactive\nSubState=dead\n"),
		[]byte("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=/system.slice/fixed.service\nActiveState=inactive\nSubState=dead\xff\n"),
		append(bytes.Repeat([]byte("x"), checkpointUnitMaxOutput+1), '\n'),
	} {
		if planBrokerCPUUnitStateParseShapeCode(malformed) != "state_parse" {
			return errors.New("malformed, mixed, oversized, or unsupported state shape gained a finite diagnostic")
		}
	}
	for _, control := range []struct {
		err  error
		want string
	}{
		{errors.New("fixed worker is not freshly inactive"), "worker_state"},
		{errors.New("systemd pending-job state is unavailable"), "jobs_unavailable"},
		{errors.New("systemd pending-job state is malformed"), "jobs_malformed"},
		{errors.New("fixed worker has a pending systemd job"), "pending_job"},
		{errors.New("fixed worker control group is not confirmed empty"), "cgroup_unconfirmed"},
		{errors.New("private unit /secret/path pid=1234"), "unavailable"},
	} {
		if got := planBrokerCPUWorkerEmptyDiagnosticCode(control.err); got != control.want {
			return errors.New("fixed worker-empty diagnostic category mapping changed")
		}
	}
	if planBrokerCPUWorkerEmptyDiagnosticCode(nil) != "unavailable" ||
		planBrokerCPUInactiveWaitMarker("unexpected-owner", "nonzero_pid") != "__PLAN_RELAUNCH_INACTIVE_WAIT__:unavailable:nonzero_pid" ||
		planBrokerCPUInactiveWaitMarker("TestCheckpointPlanRelaunchCPULifecycleSequence", "private /secret/path pid=1234") != "__PLAN_RELAUNCH_INACTIVE_WAIT__:TestCheckpointPlanRelaunchCPULifecycleSequence:unavailable" {
		return errors.New("inactive wait diagnostic marker did not fail closed")
	}
	for _, positive := range []struct {
		value string
		want  uint64
	}{
		{"90000000", 90000000}, {"1min 30s", 90000000}, {"5000000", 5000000}, {"5s", 5000000},
		{"1s 5ms", 1005000}, {"1ms 1us", 1001},
	} {
		got, err := parsePlanBrokerCPUDurationMicros(positive.value)
		if err != nil || got != positive.want {
			return errors.New("valid exact systemd duration representation was rejected")
		}
	}
	positiveOutput := []byte("RuntimeMaxUSec=1min 30s\nTimeoutStopUSec=5s\n")
	runtimeMicros, stopMicros, err := parsePlanBrokerCPUDeadlineOutput(positiveOutput)
	if err != nil || runtimeMicros != 90000000 || stopMicros != 5000000 {
		return errors.New("valid two-field systemd deadline output was rejected")
	}
	for _, malformed := range []string{"", "0", "00", "090000000", "-5s", "+5s", "05s", "1.5s", "Inf", "5fortnights", "5s 1min", "5s 5s", "1min 0s", " 5s", "5s ", "5s\t1ms", "5s  1ms", "18446744073709551615min", "18446744073709551615"} {
		if _, err := parsePlanBrokerCPUDurationMicros(malformed); err == nil {
			return errors.New("malformed or overflowing systemd duration was accepted")
		}
	}
	for _, malformed := range [][]byte{
		[]byte("TimeoutStopUSec=5s\n"),
		[]byte("RuntimeMaxUSec=1min 30s\nTimeoutStopUSec=5s\nRuntimeMaxUSec=90s\n"),
		[]byte("RuntimeMaxUSec=90s\nTimeoutStopUSec=5s\nUnexpected=1s\n"),
		[]byte("RuntimeMaxUSec=90s\nRuntimeMaxUSec=90s\nTimeoutStopUSec=5s\n"),
		[]byte("RuntimeMaxUSec=30s\nTimeoutStopUSec=90s\n"),
		[]byte("RuntimeMaxUSec=90s\nTimeoutStopUSec=6s\n"),
		[]byte("RuntimeMaxUSec=90s\nTimeoutStopUSec=5s"),
	} {
		if _, _, err := parsePlanBrokerCPUDeadlineOutput(malformed); err == nil {
			return errors.New("malformed or non-exact systemd deadline output was accepted")
		}
	}
	const name = "TestSelected"
	if err := verifyPlanBrokerCPUTestInventory("=== RUN   TestSelected\n--- PASS: TestSelected (0.00s)\nPASS\n", name); err != nil {
		return errors.New("valid ordered helper inventory was rejected")
	}
	for _, mutant := range []string{
		"--- PASS: TestSelected (0.00s)\n",
		"=== RUN   TestSelected\n=== RUN   TestSelected\n--- PASS: TestSelected (0.00s)\n",
		"--- PASS: TestSelected (0.00s)\n=== RUN   TestSelected\n",
		"=== RUN   TestSelected\n--- SKIP: TestSelected (0.00s)\n",
		"=== RUN   TestSelected\n--- FAIL: TestSelected (0.00s)\n",
		"=== RUN   TestUnexpected\n--- PASS: TestUnexpected (0.00s)\n",
		"=== RUN   TestSelected\n--- PASS: TestSelected\n",
	} {
		if err := verifyPlanBrokerCPUTestInventory(mutant, name); err == nil {
			return errors.New("helper inventory parser accepted an invalid event sequence")
		}
	}
	notFound := []byte("MainPID=0\nInvocationID=\nControlGroup=\nActiveState=inactive\nSubState=dead\nLoadState=not-found\n")
	if _, err := parseCheckpointPlanBrokerStoppedState(notFound); err == nil || planBrokerCPUStoppedStateParseShapeCode(notFound, "vram-plan-relaunch-cpu-0123456789abcdef.service") != "unit_definition_missing" {
		return errors.New("exact six-field not-found sample lost strict parser failure or finite missing-definition diagnosis")
	}
	for _, malformed := range [][]byte{
		[]byte(strings.Replace(string(notFound), "InvocationID=\n", "InvocationID=0123456789abcdef0123456789abcdef\n", 1)),
		[]byte(strings.Replace(string(notFound), "ControlGroup=\n", "ControlGroup=/system.slice/other.service\n", 1)),
		[]byte(strings.Replace(string(notFound), "LoadState=not-found", "LoadState=loaded", 1)),
		[]byte(strings.Replace(string(notFound), "MainPID=0", "MainPID=2", 1)),
		[]byte(strings.Replace(string(notFound), "ActiveState=inactive", "ActiveState=failed", 1)),
		append(append([]byte(nil), notFound...), []byte("PrivatePath=/secret\n")...),
	} {
		if planBrokerCPUStoppedStateParseShapeCode(malformed, "vram-plan-relaunch-cpu-0123456789abcdef.service") != "state_parse" {
			return errors.New("malformed or mixed six-field not-found sample gained missing-definition classification")
		}
	}
	for _, terminal := range []int16{
		int16(unix.POLLIN),
		int16(unix.POLLIN | unix.POLLHUP),
		int16(unix.POLLIN) | planBrokerCPUPollRDNORM,
		int16(unix.POLLIN|unix.POLLHUP) | planBrokerCPUPollRDNORM,
	} {
		if !planBrokerCPUTerminalPollEventsValid(terminal) {
			return errors.New("documented terminal pidfd readiness mask was rejected")
		}
	}
	for _, malformedMask := range []int16{
		int16(unix.POLLHUP),
		int16(unix.POLLIN | unix.POLLERR),
		int16(unix.POLLIN | unix.POLLNVAL),
		int16(unix.POLLIN) | 0x1000,
	} {
		if planBrokerCPUTerminalPollEventsValid(malformedMask) {
			return errors.New("missing-IN, error, invalid, or unknown pidfd event was accepted")
		}
	}
	if err := verifyPlanBrokerCPUStoppedSampleControls(); err != nil {
		return err
	}
	if err := verifyPlanBrokerCPUOpenedPIDFDCloseControls(); err != nil {
		return err
	}
	return nil
}

func verifyPlanBrokerCPUStoppedSampleControls() error {
	paths := checkpointPlanBrokerPaths{}
	unit := checkpointPlanBrokerUnitName(paths)
	prior := ownedStopReceipt{WorkerPID: 4321, WorkerStartTicks: 9876, InvocationID: "0123456789abcdef0123456789abcdef", ControlGroup: filepath.Join("/system.slice", unit), SignalSent: true, ReleaseTerminal: true}
	loaded := checkpointPlanBrokerStoppedState{MainPID: 0, Invocation: prior.InvocationID, ControlGroup: prior.ControlGroup, Active: "inactive", Sub: "dead", Load: "loaded"}
	notFound := loaded
	notFound.Invocation, notFound.ControlGroup, notFound.Load = "", "", "not-found"
	procGone := os.ErrNotExist
	valid := func(observed checkpointPlanBrokerStoppedState, procErr error, jobs []byte, jobsErr error, members []byte, membersErr error, cleanup bool) error {
		return verifyCheckpointPlanBrokerStoppedWorkerEmptySample(paths, observed, prior, procErr, jobs, jobsErr, members, membersErr, cleanup)
	}
	if err := valid(loaded, procGone, nil, nil, nil, nil, false); err != nil {
		return errors.New("complete loaded stopped proof positive was rejected")
	}
	if err := valid(notFound, procGone, nil, nil, nil, nil, true); err != nil {
		return errors.New("exact not-found cleanup proof positive was rejected")
	}
	for _, proof := range []struct {
		name      string
		observed  checkpointPlanBrokerStoppedState
		procErr   error
		jobs      []byte
		jobsErr   error
		members   []byte
		membersErr error
		cleanup   bool
	}{
		{"not-found cannot authorize loaded proof", notFound, procGone, nil, nil, nil, nil, false},
		{"inconsistent unit state", checkpointPlanBrokerStoppedState{MainPID: 0, Invocation: prior.InvocationID, ControlGroup: prior.ControlGroup, Active: "active", Sub: "dead", Load: "loaded"}, procGone, nil, nil, nil, nil, false},
		{"live original process", loaded, nil, nil, nil, nil, nil, false},
		{"zombie original process", loaded, errors.New("original process is a zombie"), nil, nil, nil, nil, false},
		{"unavailable original process", loaded, errors.New("permission denied"), nil, nil, nil, nil, false},
		{"pending exact unit job", loaded, procGone, []byte("1 " + unit + " stop running\n"), nil, nil, nil, false},
		{"malformed job inventory", loaded, procGone, []byte("not a job\n"), nil, nil, nil, false},
		{"unavailable job inventory", loaded, procGone, nil, errors.New("unavailable"), nil, nil, false},
		{"nonempty old cgroup", loaded, procGone, nil, nil, []byte("4321\n"), nil, false},
		{"unavailable old cgroup", loaded, procGone, nil, nil, nil, errors.New("unavailable"), false},
		{"foreign old cgroup", loaded, procGone, nil, nil, nil, nil, false},
	} {
		candidate := proof.observed
		if proof.name == "foreign old cgroup" {
			candidate.ControlGroup = "/system.slice/other.service"
		}
		if err := valid(candidate, proof.procErr, proof.jobs, proof.jobsErr, proof.members, proof.membersErr, proof.cleanup); err == nil {
			return errors.New("stopped-state proof accepted an incomplete safety control")
		}
	}
	for _, diagnostic := range []struct {
		name       string
		jobs       []byte
		jobsErr    error
		members    []byte
		membersErr error
		want       string
	}{
		{"pending job", []byte("1 " + unit + " stop running\n"), nil, nil, nil, "pending_job"},
		{"malformed jobs", []byte("not a job\n"), nil, nil, nil, "jobs_malformed"},
		{"unavailable jobs", nil, errors.New("unavailable"), nil, nil, "jobs_unavailable"},
		{"unconfirmed cgroup", nil, nil, nil, errors.New("unavailable"), "cgroup_unconfirmed"},
	} {
		err := valid(loaded, procGone, diagnostic.jobs, diagnostic.jobsErr, diagnostic.members, diagnostic.membersErr, false)
		if code := planBrokerCPUWorkerEmptyDiagnosticCode(err); code != diagnostic.want {
			return fmt.Errorf("%s diagnostic mapped to %s instead of %s", diagnostic.name, code, diagnostic.want)
		}
	}
	held := planBrokerCPULaunchIdentity{PlanSHA256: strings.Repeat("1", 64), CurrentIncarnation: strings.Repeat("2", 64), CustodyBindingSHA256: strings.Repeat("3", 64), Alias: "model-a"}
	receipt := ownedStopReceipt{LocalCheckpointBinding: held.CurrentIncarnation, ManagedCurrentIncarnation: held.CurrentIncarnation, ManagedPlanSHA256: held.PlanSHA256, CustodyBindingSHA256: held.CustodyBindingSHA256, ModelAlias: held.Alias}
	if err := verifyPlanBrokerCPUStopReceiptBinding(held, receipt); err != nil {
		return errors.New("exact held managed binding receipt positive was rejected")
	}
	for _, drift := range []func(*ownedStopReceipt){
		func(receipt *ownedStopReceipt) { receipt.LocalCheckpointBinding = strings.Repeat("4", 64) },
		func(receipt *ownedStopReceipt) { receipt.ManagedCurrentIncarnation = strings.Repeat("4", 64) },
		func(receipt *ownedStopReceipt) { receipt.ManagedPlanSHA256 = strings.Repeat("4", 64) },
		func(receipt *ownedStopReceipt) { receipt.CustodyBindingSHA256 = strings.Repeat("4", 64) },
		func(receipt *ownedStopReceipt) { receipt.ModelAlias = "model-b" },
	} {
		mutant := receipt
		drift(&mutant)
		if err := verifyPlanBrokerCPUStopReceiptBinding(held, mutant); err == nil {
			return errors.New("held managed binding drift was accepted")
		}
	}
	return nil
}

func readPlanBrokerCPUReceipt(paths checkpointPlanBrokerPaths, commandID string) ([]byte, error) {
	if !canonicalPlanCatalogToken(commandID) {
		return nil, errors.New("receipt command identity is invalid")
	}
	body, _, err := readPlanBrokerFile(filepath.Join(paths.ReceiptDir, ownedStopReceiptFilename(commandID)), 32<<10, 0o640)
	return body, err
}

func startPlanBrokerCPUTransient(paths checkpointPlanBrokerPaths, workerSHA string) error {
	if !planBrokerCPUFixtureUnitBound(paths, paths.fixtureUnit) || !checkpointSHA256RE.MatchString(workerSHA) {
		return errors.New("worker executable digest is invalid")
	}
	worker := filepath.Join(paths.fixtureRoot, "worker")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, planBrokerCPUSystemdRun, "--unit="+strings.TrimSuffix(paths.fixtureUnit, ".service"), "--property=Type=simple", "--property=KillMode=control-group", "--property=Restart=no", "--property=RuntimeMaxSec=90s", "--property=TimeoutStopSec=5s", "--property=User=root", "--property=Environment=VRAM_PLAN_BROKER_CPU_ROLE=worker", "--property=Environment=VRAM_PLAN_BROKER_CPU_ROOT="+paths.fixtureRoot, "--property=Environment="+planBrokerCPUEnv+"="+planBrokerCPUOptIn, "--property=Environment="+planBrokerCPUNodeGIDEnv+"="+strconv.FormatUint(uint64(paths.NodeGID), 10), "--quiet", "--", worker, "-test.run=^TestCheckpointPlanRelaunchCPUWorker$", "-test.count=1")
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/bin"}
	cmd.WaitDelay = time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("start exact transient unit failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	if err := waitPlanBrokerCPUActive(paths); err != nil {
		return err
	}
	return assertPlanBrokerCPUUnitHasParentIndependentDeadline(paths, paths.fixtureUnit)
}

func startPlanBrokerCPUBroker(worker string, paths checkpointPlanBrokerPaths, crashAt ...string) (*planBrokerCPUBroker, error) {
	if !filepath.IsAbs(worker) || filepath.Clean(worker) != worker || !checkpointPlanBrokerPrivateFixturePath(worker, paths, "worker") {
		return nil, errors.New("broker executable is not the exact held fixture image")
	}
	if len(crashAt) > 1 || (len(crashAt) == 1 && crashAt[0] != "start_requested_durable") {
		return nil, errors.New("broker crash selector is outside its fixed test boundary")
	}
	cmd := exec.Command(worker, "-test.run=^TestCheckpointPlanRelaunchCPUWorker$", "-test.count=1")
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/bin", planBrokerCPUEnv + "=" + planBrokerCPUOptIn, planBrokerCPURole + "=broker", planBrokerCPUParentGuardEnv + "=1", "VRAM_PLAN_BROKER_CPU_ROOT=" + paths.fixtureRoot, planBrokerCPUNodeGIDEnv + "=" + strconv.FormatUint(uint64(paths.NodeGID), 10)}
	if len(crashAt) == 1 {
		cmd.Env = append(cmd.Env, planBrokerCPUCrashAtEnv+"="+crashAt[0])
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = time.Second
	parentGuardWrite, err := startPlanBrokerCPUGuardedChild(cmd)
	if err != nil {
		return nil, err
	}
	broker := &planBrokerCPUBroker{cmd: cmd, socketPath: paths.Socket, parentGuardWrite: parentGuardWrite}
	if len(crashAt) == 1 {
		broker.expectedCrashExit = planBrokerCPUCrashExit
	}
	if err := waitPlanBrokerCPUSocket(paths.Socket); err != nil {
		_ = stopPlanBrokerCPUStartedChild(cmd, parentGuardWrite)
		if _, statErr := os.Lstat(paths.Socket); statErr == nil {
			return nil, fmt.Errorf("broker socket appeared but could not be pinned; preserving fixture root %s", paths.fixtureRoot)
		}
		return nil, errors.New("broker socket did not appear before its startup deadline")
	}
	info, err := os.Lstat(paths.Socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		_ = stopPlanBrokerCPUStartedChild(cmd, parentGuardWrite)
		return nil, fmt.Errorf("broker socket is not the exact held Unix socket; preserving fixture root %s", paths.fixtureRoot)
	}
	broker.socketInfo = info
	broker.waitDone = make(chan struct{})
	go func() {
		broker.waitErr = cmd.Wait()
		close(broker.waitDone)
	}()
	return broker, nil
}

func armPlanBrokerCPUParentGuard() (context.Context, func(), error) {
	if os.Getenv(planBrokerCPUParentGuardEnv) != "1" {
		return nil, nil, errors.New("fixed parent-guard opt-in is absent")
	}
	guardRead := os.NewFile(3, "plan-broker-parent-liveness")
	readyWrite := os.NewFile(4, "plan-broker-parent-guard-ready")
	if guardRead == nil || readyWrite == nil {
		return nil, nil, errors.New("inherited read-only liveness or ready descriptor is missing")
	}
	var token [1]byte
	if _, err := io.ReadFull(guardRead, token[:]); err != nil || token[0] != 'P' {
		_ = guardRead.Close()
		_ = readyWrite.Close()
		return nil, nil, errors.New("parent liveness handshake token is invalid")
	}
	ctx, cancel := context.WithCancel(context.Background())
	watcherStarted := make(chan struct{})
	go func() {
		close(watcherStarted)
		var extra [1]byte
		n, err := guardRead.Read(extra[:])
		if n != 0 || !errors.Is(err, io.EOF) {
			cancel()
			return
		}
		cancel()
	}()
	<-watcherStarted
	if _, err := readyWrite.Write([]byte("READY\n")); err != nil {
		cancel()
		_ = guardRead.Close()
		_ = readyWrite.Close()
		return nil, nil, errors.New("parent-guard ready handshake could not be sent")
	}
	if err := readyWrite.Close(); err != nil {
		cancel()
		_ = guardRead.Close()
		return nil, nil, errors.New("parent-guard ready descriptor could not be closed")
	}
	stop := func() {
		cancel()
		_ = guardRead.Close()
	}
	return ctx, stop, nil
}

func capturePlanBrokerCPUProcessIdentity(pid int) (planBrokerCPUProcessIdentity, error) {
	var identity planBrokerCPUProcessIdentity
	if pid <= 1 {
		return identity, errors.New("process identity PID is invalid")
	}
	ticks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil || ticks == 0 {
		return identity, errors.New("process start tick is unavailable")
	}
	executablePath, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil || !filepath.IsAbs(executablePath) || filepath.Clean(executablePath) != executablePath {
		return identity, errors.New("process executable path is unavailable")
	}
	executableSHA, executableBytes, err := fileDigest(executablePath)
	executableInfo, statErr := os.Stat(executablePath)
	if err != nil || statErr != nil || executableBytes <= 0 || executableSHA == "" {
		return identity, errors.New("process executable identity is unavailable")
	}
	identity = planBrokerCPUProcessIdentity{PID: pid, StartTicks: ticks, ExecutablePath: executablePath, ExecutableSHA256: executableSHA, ExecutableDevice: infoSysDevice(executableInfo), ExecutableInode: infoSysInode(executableInfo)}
	if identity.ExecutableDevice == 0 || identity.ExecutableInode == 0 {
		return planBrokerCPUProcessIdentity{}, errors.New("process executable device/inode is invalid")
	}
	return identity, nil
}

func verifyPlanBrokerCPUProcessIdentity(held planBrokerCPUProcessIdentity) error {
	current, err := capturePlanBrokerCPUProcessIdentity(held.PID)
	if err != nil || current != held {
		return errors.New("process PID/start/executable identity is not the held incarnation")
	}
	return nil
}

func planBrokerCPUPIDFDReady(pidfd int, timeout time.Duration) (bool, error) {
	if pidfd < 0 || timeout < 0 {
		return false, errors.New("pidfd readiness query is invalid")
	}
	ms := int(timeout / time.Millisecond)
	if timeout > 0 && ms == 0 {
		ms = 1
	}
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, ms)
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	return fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0, nil
}

func holdPlanBrokerCPUTerminalPIDFD(held planBrokerCPULaunchIdentity) (int, error) {
	if held.PID <= 1 || held.StartTicks == 0 || held.UnitName == "" {
		return -1, errors.New("pre-stop worker identity is incomplete")
	}
	start, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(held.PID)), held.PID)
	if err != nil || start != held.StartTicks {
		return -1, errors.New("pre-stop worker PID/start identity changed")
	}
	pidfd, err := unix.PidfdOpen(held.PID, 0)
	if err != nil {
		return -1, errors.New("pre-stop worker pidfd could not be opened")
	}
	closeOnError := func() { _ = unix.Close(pidfd) }
	target, targetErr := planBrokerCPUPIDFDTarget(pidfd)
	currentStart, startErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(held.PID)), held.PID)
	var descriptor [1]unix.PollFd
	descriptor[0] = unix.PollFd{Fd: int32(pidfd), Events: unix.POLLIN}
	n, pollErr := unix.Poll(descriptor[:], 0)
	if targetErr != nil || target != held.PID || startErr != nil || currentStart != held.StartTicks || pollErr != nil || n != 0 || descriptor[0].Revents != 0 || unix.PidfdSendSignal(pidfd, 0, nil, 0) != nil {
		closeOnError()
		return -1, errors.New("pre-stop pidfd did not bind the exact live worker incarnation")
	}
	return pidfd, nil
}

func verifyPlanBrokerCPUTerminalPIDFD(pidfd int, held planBrokerCPULaunchIdentity) error {
	return verifyPlanBrokerCPUTerminalPIDFDUntil(pidfd, held, time.Now().Add(10*time.Second))
}

func verifyPlanBrokerCPUTerminalPIDFDUntil(pidfd int, held planBrokerCPULaunchIdentity, deadline time.Time) error {
	if pidfd < 0 || held.PID <= 1 || held.StartTicks == 0 {
		return errors.New("held worker pidfd or incarnation is invalid")
	}
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		ms := int(remaining / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		descriptor := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		n, err := unix.Poll(descriptor, ms)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return errors.New("held worker pidfd terminal poll failed")
		}
		if n == 0 {
			return errors.New("held worker pidfd did not become terminal within its bound")
		}
		if n != 1 || !planBrokerCPUTerminalPollEventsValid(descriptor[0].Revents) {
			return errors.New("held worker pidfd returned an ambiguous terminal event")
		}
		_, procErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(held.PID)), held.PID)
		if !errors.Is(procErr, os.ErrNotExist) {
			return errors.New("original worker process is still present or its terminal incarnation is ambiguous")
		}
		return nil
	}
	return errors.New("held worker pidfd terminal proof exceeded its fixed bound")
}

// POLLRDNORM is UAPI value 0x0040 but x/sys/unix does not expose it on every
// supported Linux toolchain. pidfd_poll may report it with terminal POLLIN.
const planBrokerCPUPollRDNORM int16 = 0x0040

func planBrokerCPUTerminalPollEventsValid(revents int16) bool {
	allowed := int16(unix.POLLIN|unix.POLLHUP) | planBrokerCPUPollRDNORM
	if revents&int16(unix.POLLIN) == 0 || revents&int16(unix.POLLERR|unix.POLLNVAL) != 0 || revents & ^allowed != 0 {
		return false
	}
	return true
}

func runPlanBrokerCPUParentDeathHelper(t *testing.T) {
	if os.Getenv(planBrokerCPUEnv) != planBrokerCPUOptIn || os.Geteuid() != 0 {
		t.Fatal("parent-death helper requires the fixed local root opt-in")
	}
	root := os.Getenv("VRAM_PLAN_BROKER_CPU_ROOT")
	gid, err := strconv.ParseUint(os.Getenv(planBrokerCPUNodeGIDEnv), 10, 32)
	if err != nil || gid == 0 || !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root)) || filepath.Dir(root) != os.TempDir() {
		t.Fatal("parent-death helper fixture identity is invalid")
	}
	worker := filepath.Join(root, "worker")
	paths := checkpointPlanBrokerCPUPaths(root, 65534, uint32(gid))
	if !checkpointPlanBrokerPrivateFixturePathSet(paths) || !checkpointPlanBrokerPrivateFixturePath(worker, paths, "worker") {
		t.Fatal("parent-death helper paths are outside the exact private fixture")
	}
	readyWrite := os.NewFile(3, "parent-death-helper-ready")
	if readyWrite == nil {
		t.Fatal("parent-death helper report descriptor is missing")
	}
	defer readyWrite.Close()
	var unrelated *planBrokerCPUParentGuardChild
	var broker *planBrokerCPUBroker
	defer func() {
		if unrelated != nil {
			_ = stopPlanBrokerCPUUnrelatedChild(unrelated)
		}
		if broker != nil {
			_ = stopPlanBrokerCPUBroker(broker)
		}
	}()
	if err := makePlanBrokerCPUUnrelatedChild(&unrelated, worker, root, uint32(gid)); err != nil {
		t.Fatalf("unrelated parent-death child did not become ready: %v", err)
	}
	broker, err = startPlanBrokerCPUBroker(worker, paths)
	if err != nil {
		t.Fatalf("guarded broker did not become ready: %v", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o711 {
		t.Fatal("parent-death fixture root identity is unavailable")
	}
	if !planBrokerCPUUnrelatedChildAlive(unrelated) {
		t.Fatal("unrelated parent-guard child exited while its exact parent remained alive")
	}
	brokerIdentity, err := capturePlanBrokerCPUProcessIdentity(broker.cmd.Process.Pid)
	if err != nil {
		t.Fatal("broker process identity could not be captured")
	}
	unrelatedIdentity, err := capturePlanBrokerCPUProcessIdentity(unrelated.cmd.Process.Pid)
	if err != nil {
		t.Fatal("unrelated process identity could not be captured")
	}
	report := planBrokerCPUParentDeathReport{
		RootDevice: infoSysDevice(rootInfo), RootInode: infoSysInode(rootInfo),
		SocketDevice: infoSysDevice(broker.socketInfo), SocketInode: infoSysInode(broker.socketInfo),
		Broker: brokerIdentity, Unrelated: unrelatedIdentity,
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) == 0 || len(encoded) > 2048 {
		t.Fatal("bounded parent-death identity report could not be encoded")
	}
	if _, err := readyWrite.Write(append(encoded, '\n')); err != nil {
		t.Fatal("bounded parent-death identity report could not be sent")
	}
	if err := readyWrite.Close(); err != nil {
		t.Fatal("parent-death helper report writer did not close")
	}
	select {}
}

func planBrokerCPUPIDFDTarget(pidfd int) (int, error) {
	if pidfd < 0 {
		return -1, errors.New("pidfd is invalid")
	}
	file, err := os.Open(filepath.Join("/proc/self/fdinfo", strconv.Itoa(pidfd)))
	if err != nil {
		return -1, errors.New("pidfd target metadata is unavailable")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > 4096 {
		return -1, errors.New("pidfd target metadata could not be read within its bound")
	}
	target := -1
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Pid:") {
			continue
		}
		if target != -1 {
			return -1, errors.New("pidfd target metadata is ambiguous")
		}
		parsed, parseErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Pid:")))
		if parseErr != nil || parsed <= 1 {
			return -1, errors.New("pidfd no longer names one live process")
		}
		target = parsed
	}
	if target <= 1 {
		return -1, errors.New("pidfd target metadata omitted a live PID")
	}
	return target, nil
}

func holdPlanBrokerCPUPIDFD(identity planBrokerCPUProcessIdentity) (int, error) {
	if err := verifyPlanBrokerCPUProcessIdentity(identity); err != nil {
		return -1, err
	}
	pidfd, err := unix.PidfdOpen(identity.PID, 0)
	if err != nil {
		return -1, err
	}
	if err := verifyPlanBrokerCPUProcessIdentity(identity); err != nil {
		return -1, errors.Join(err, unix.Close(pidfd))
	}
	ready, err := planBrokerCPUPIDFDReady(pidfd, 0)
	if err != nil || ready {
		return -1, errors.Join(errors.New("process did not remain live while its exact parent was alive"), err, unix.Close(pidfd))
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return -1, errors.Join(errors.New("held pidfd did not confirm the exact process was live"), err, unix.Close(pidfd))
	}
	return pidfd, nil
}

func runPlanBrokerCPUParentDeathOracle(worker string, paths checkpointPlanBrokerPaths, rootInfo os.FileInfo, gid uint32) (result error) {
	if !filepath.IsAbs(worker) || filepath.Clean(worker) != worker || !checkpointPlanBrokerPrivateFixturePath(worker, paths, "worker") || gid == 0 {
		return planBrokerCPUFailureAt(planBrokerCPUStageParentSetup, planBrokerCPUReasonIdentity, "", errors.New("parent-death oracle inputs are outside the fixed fixture"))
	}
	failure := func(stage planBrokerCPUFailureStage, reason planBrokerCPUFailureReason, err error) error {
		return planBrokerCPUFailureAt(stage, reason, "", err)
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return failure(planBrokerCPUStageParentSetup, planBrokerCPUReasonPipe, errors.New("parent-death report pipe could not be created"))
	}
	cmd := exec.Command(worker, "-test.run=^TestCheckpointPlanRelaunchCPUWorker$", "-test.count=1", "-test.timeout=30s")
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/bin", planBrokerCPUEnv + "=" + planBrokerCPUOptIn, planBrokerCPURole + "=parent-helper", "VRAM_PLAN_BROKER_CPU_ROOT=" + paths.fixtureRoot, planBrokerCPUNodeGIDEnv + "=" + strconv.FormatUint(uint64(gid), 10)}
	cmd.ExtraFiles = []*os.File{readyWrite}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = time.Second
	parentPIDFD := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &parentPIDFD}
	if err := cmd.Start(); err != nil {
		closeErr := errors.Join(readyRead.Close(), readyWrite.Close())
		if parentPIDFD >= 0 {
			closeErr = errors.Join(closeErr, unix.Close(parentPIDFD))
		}
		return errors.Join(failure(planBrokerCPUStageParentSetup, planBrokerCPUReasonExit, errors.New("exact parent helper did not start")), planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, closeErr))
	}
	parentWaitResult := make(chan error, 1)
	parentWaitStarted := false
	startParentWait := func() {
		if parentWaitStarted {
			return
		}
		parentWaitStarted = true
		go func() { parentWaitResult <- cmd.Wait() }()
	}
	closeUnboundParentPIDFD := func() error {
		if parentPIDFD < 0 {
			return nil
		}
		pidfd := parentPIDFD
		parentPIDFD = -1
		return unix.Close(pidfd)
	}
	abortUnboundParent := func(primary error) error {
		closeErr := planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, errors.Join(readyRead.Close(), readyWrite.Close()))
		startParentWait()
		select {
		case waitErr := <-parentWaitResult:
			closeErr = errors.Join(closeErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, closeUnboundParentPIDFD()))
			return errors.Join(planBrokerCPUFailureOrigin(planBrokerCPUReasonIdentity, primary), closeErr, planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, waitErr), errors.New("unbound parent helper was reaped after failed spawn binding; preserving fixture without custody proof"))
		case <-time.After(5 * time.Second):
			closeErr = errors.Join(closeErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, closeUnboundParentPIDFD()))
			return errors.Join(planBrokerCPUFailureOrigin(planBrokerCPUReasonIdentity, primary), closeErr, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonDeadline, "", errors.New("unbound parent helper did not settle within fixed 5s; preserving fixture with custody uncertainty")))
		}
	}
	parentTarget, targetErr := planBrokerCPUPIDFDTarget(parentPIDFD)
	if parentPIDFD < 0 || targetErr != nil || parentTarget != cmd.Process.Pid {
		return abortUnboundParent(failure(planBrokerCPUStageParentSetup, planBrokerCPUReasonIdentity, errors.New("spawn-time parent pidfd did not bind the exact helper PID; preserving fixture")))
	}
	parentIdentity, identityErr := capturePlanBrokerCPUProcessIdentity(cmd.Process.Pid)
	if identityErr != nil || verifyPlanBrokerCPUProcessIdentity(parentIdentity) != nil {
		return abortUnboundParent(failure(planBrokerCPUStageParentSetup, planBrokerCPUReasonIdentity, errors.New("spawn-bound parent helper process identity could not be verified; preserving fixture")))
	}
	if err := unix.PidfdSendSignal(parentPIDFD, 0, nil, 0); err != nil {
		return abortUnboundParent(failure(planBrokerCPUStageParentSetup, planBrokerCPUReasonIdentity, errors.New("spawn-bound parent helper pidfd did not confirm a live exact process; preserving fixture")))
	}
	parentTarget, targetErr = planBrokerCPUPIDFDTarget(parentPIDFD)
	if targetErr != nil || parentTarget != parentIdentity.PID || verifyPlanBrokerCPUProcessIdentity(parentIdentity) != nil {
		return abortUnboundParent(failure(planBrokerCPUStageParentSetup, planBrokerCPUReasonIdentity, errors.New("spawn-bound parent pidfd and captured process identity diverged; preserving fixture")))
	}
	readyWriteCloseErr := readyWrite.Close()
	startParentWait()
	parentWaited := false
	var stopExactParent func() error
	survivorObserved := false
	readyReadClosed := false
	closeReadyRead := func() error {
		if readyReadClosed {
			return nil
		}
		readyReadClosed = true
		return readyRead.Close()
	}
	defer func() {
		if readyWriteCloseErr != nil {
			result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonClose, "", errors.New("parent report writer did not close cleanly; preserving fixture")))
		}
		if err := closeReadyRead(); err != nil {
			result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonClose, "", errors.New("parent-death report reader did not close cleanly; preserving fixture")))
		}
		if !parentWaited {
			if stopExactParent == nil || parentPIDFD < 0 {
				result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonIdentity, "", errors.New("parent helper identity/pidfd custody was not established; bounded helper self-deadline remains, preserving fixture")))
			} else if err := stopExactParent(); err != nil {
				result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUFailureReasonOf(err), "", fmt.Errorf("parent helper pidfd cleanup was not confirmed; preserving fixture: %w", err)))
			}
			if !parentWaited {
				select {
				case <-parentWaitResult:
					parentWaited = true
					result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonExit, "", errors.New("parent helper exited without verified induced pidfd wait status; preserving fixture")))
				case <-time.After(5 * time.Second):
					result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonDeadline, "", errors.New("parent helper wait did not settle within the fixed cleanup bound; preserving fixture")))
				}
			}
		}
		if parentPIDFD >= 0 {
			if err := unix.Close(parentPIDFD); err != nil {
				result = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, errors.New("held parent pidfd did not close cleanly; preserving fixture")))
			}
		}
		if survivorObserved && result != nil && result.Error() == "a direct child survived exact parent death and required pidfd-only emergency cleanup" {
			result = &planBrokerCPUSurvivorPredicateFailure{err: result}
		}
	}()
	stopExactParent = func() error {
		if parentWaited {
			return nil
		}
		if err := verifyPlanBrokerCPUProcessIdentity(parentIdentity); err != nil {
			return failure(planBrokerCPUStageParentSignal, planBrokerCPUReasonIdentity, errors.New("parent helper identity changed before pidfd signal; preserving fixture"))
		}
		ready, err := planBrokerCPUPIDFDReady(parentPIDFD, 0)
		if err != nil || ready {
			return failure(planBrokerCPUStageParentSignal, planBrokerCPUReasonIdentity, errors.New("parent helper was not live immediately before induced death; preserving fixture"))
		}
		if err := unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0); err != nil {
			return failure(planBrokerCPUStageParentSignal, planBrokerCPUReasonExit, errors.New("exact parent helper could not be killed through its held pidfd; preserving fixture"))
		}
		exited, err := planBrokerCPUPIDFDReady(parentPIDFD, 5*time.Second)
		if err != nil || !exited {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonDeadline, errors.New("exact parent helper did not exit within its fixed bound; preserving fixture"))
		}
		select {
		case waitErr := <-parentWaitResult:
			parentWaited = true
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) {
				return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonExit, errors.New("exact parent helper wait did not report the induced signal"))
			}
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonExit, errors.New("exact parent helper did not exit from the intended SIGKILL"))
			}
			return nil
		case <-time.After(5 * time.Second):
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonDeadline, errors.New("exact parent helper could not be reaped within its fixed bound; preserving fixture"))
		}
	}
	childHandles := make([]struct {
		pidfd    int
		identity planBrokerCPUProcessIdentity
	}, 0, 2)
	defer func() {
		if !parentWaited {
			if stopExactParent == nil || parentPIDFD < 0 {
				result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonIdentity, "", errors.New("parent helper lacks exact pidfd custody during deferred cleanup; preserving fixture")))
			} else if err := stopExactParent(); err != nil {
				result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUFailureReasonOf(err), "", fmt.Errorf("deferred exact parent pidfd cleanup failed; preserving fixture: %w", err)))
			}
		}
		cleanupDeadline := time.Now().Add(5 * time.Second)
		for _, child := range childHandles {
			ready, readyErr := planBrokerCPUPIDFDReady(child.pidfd, 0)
			if readyErr != nil {
				result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonIdentity, "", errors.New("deferred child pidfd state is ambiguous; preserving fixture")))
			} else if !ready {
				if err := verifyPlanBrokerCPUProcessIdentity(child.identity); err != nil {
					result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonIdentity, "", errors.New("deferred child identity changed before pidfd cleanup; preserving fixture")))
				} else if err := unix.PidfdSendSignal(child.pidfd, syscall.SIGKILL, nil, 0); err != nil {
					result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonExit, "", errors.New("deferred exact child pidfd signal failed; preserving fixture")))
				}
			}
		}
		for _, child := range childHandles {
			remaining := time.Until(cleanupDeadline)
			if remaining > 0 {
				exited, err := planBrokerCPUPIDFDReady(child.pidfd, remaining)
				if err != nil || !exited {
					result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonExit, "", errors.New("deferred exact child pidfd wait was not confirmed; preserving fixture")))
				}
			} else {
				result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonDeadline, "", errors.New("deferred child cleanup exceeded its fixed deadline; preserving fixture")))
			}
			if err := unix.Close(child.pidfd); err != nil {
				result = errors.Join(result, planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonClose, "", errors.New("deferred child pidfd close failed; preserving fixture")))
			}
		}
	}()
	readDone := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, readErr := io.ReadAll(io.LimitReader(readyRead, 2049))
		readDone <- struct {
			data []byte
			err  error
		}{data: data, err: readErr}
	}()
	var readyBytes []byte
	select {
	case result := <-readDone:
		if err := closeReadyRead(); err != nil {
			return errors.Join(failure(planBrokerCPUStageParentReady, planBrokerCPUReasonClose, errors.New("parent-death report reader close failed; preserving fixture")), planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, err))
		}
		if result.err != nil || len(result.data) == 0 || len(result.data) > 2048 || result.data[len(result.data)-1] != '\n' {
			return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonPipe, errors.New("parent helper did not emit one bounded identity frame; preserving fixture"))
		}
		readyBytes = result.data[:len(result.data)-1]
	case <-time.After(5 * time.Second):
		return errors.Join(failure(planBrokerCPUStageParentReady, planBrokerCPUReasonDeadline, errors.New("parent helper identity handshake exceeded its fixed deadline; preserving fixture")), planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, closeReadyRead()))
	}
	var report planBrokerCPUParentDeathReport
	if err := json.Unmarshal(readyBytes, &report); err != nil {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonPipe, errors.New("parent helper report did not contain its exact bounded identity frame; preserving fixture"))
	}
	if report.RootDevice != infoSysDevice(rootInfo) || report.RootInode != infoSysInode(rootInfo) || report.RootDevice == 0 || report.RootInode == 0 {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonIdentity, errors.New("parent helper report did not bind the exact private root identity; preserving fixture"))
	}
	if report.Broker.PID <= 1 || report.Unrelated.PID <= 1 || report.Broker.PID == report.Unrelated.PID || report.Broker.PID == parentIdentity.PID || report.Unrelated.PID == parentIdentity.PID || report.SocketDevice == 0 || report.SocketInode == 0 {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonIdentity, errors.New("parent helper report contains invalid exact child identities; preserving fixture"))
	}
	if report.Broker.ExecutablePath != worker || report.Unrelated.ExecutablePath != worker {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonIdentity, errors.New("parent helper children do not use the exact fixture executable; preserving fixture"))
	}
	brokerPIDFD, err := holdPlanBrokerCPUPIDFD(report.Broker)
	if err != nil {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonIdentity, errors.New("actual broker child identity or live pidfd could not be held; preserving fixture"))
	}
	childHandles = append(childHandles, struct {
		pidfd    int
		identity planBrokerCPUProcessIdentity
	}{pidfd: brokerPIDFD, identity: report.Broker})
	unrelatedPIDFD, err := holdPlanBrokerCPUPIDFD(report.Unrelated)
	if err != nil {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonIdentity, errors.New("unrelated child identity or live pidfd could not be held; preserving fixture"))
	}
	childHandles = append(childHandles, struct {
		pidfd    int
		identity planBrokerCPUProcessIdentity
	}{pidfd: unrelatedPIDFD, identity: report.Unrelated})
	if err := verifyPlanBrokerCPUProcessIdentity(parentIdentity); err != nil {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonIdentity, errors.New("exact parent helper identity changed before positive liveness check"))
	}
	if err := verifyPlanBrokerCPUProcessIdentity(report.Broker); err != nil {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonIdentity, errors.New("broker child identity changed before induced parent death"))
	}
	if err := verifyPlanBrokerCPUProcessIdentity(report.Unrelated); err != nil {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonIdentity, errors.New("unrelated child identity changed before induced parent death"))
	}
	socketInfo, err := os.Lstat(paths.Socket)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || infoSysDevice(socketInfo) != report.SocketDevice || infoSysInode(socketInfo) != report.SocketInode {
		return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonIdentity, errors.New("broker socket does not match the helper's exact ready identity"))
	}
	if err := stopExactParent(); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	var survivors []struct {
		pidfd    int
		identity planBrokerCPUProcessIdentity
	}
	for _, child := range childHandles {
		remaining := time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		}
		exited, err := planBrokerCPUPIDFDReady(child.pidfd, remaining)
		if err != nil {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonIdentity, errors.New("guarded child pidfd state is ambiguous; preserving fixture"))
		}
		if !exited {
			survivorObserved = true
			survivors = append(survivors, child)
		}
	}
	cleanupDeadline := time.Now().Add(5 * time.Second)
	for _, child := range survivors {
		if err := verifyPlanBrokerCPUProcessIdentity(child.identity); err != nil {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonIdentity, errors.New("surviving child identity changed before exact pidfd cleanup; preserving fixture"))
		}
		if err := unix.PidfdSendSignal(child.pidfd, syscall.SIGKILL, nil, 0); err != nil {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonExit, errors.New("surviving exact child could not be stopped through its held pidfd; preserving fixture"))
		}
	}
	for _, child := range survivors {
		remaining := time.Until(cleanupDeadline)
		if remaining <= 0 {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonDeadline, errors.New("pidfd-only survivor cleanup exceeded its shared deadline; preserving fixture"))
		}
		exited, err := planBrokerCPUPIDFDReady(child.pidfd, remaining)
		if err != nil || !exited {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonExit, errors.New("surviving exact child did not exit after pidfd cleanup; preserving fixture"))
		}
	}
	for _, held := range []planBrokerCPUProcessIdentity{report.Broker, report.Unrelated} {
		currentTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(held.PID)), held.PID)
		if err == nil && currentTicks == held.StartTicks {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonExit, errors.New("pidfd-exited child still has the same live process incarnation; preserving fixture"))
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "PID was reused") {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonIdentity, errors.New("child /proc identity after pidfd exit is ambiguous; preserving fixture"))
		}
	}
	if _, err := os.Lstat(paths.Socket); err == nil {
		current, statErr := os.Lstat(paths.Socket)
		if statErr != nil || !os.SameFile(socketInfo, current) || current.Mode()&os.ModeSocket == 0 {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonIdentity, errors.New("post-death socket path is not the exact held broker socket; preserving fixture"))
		}
		if err := os.Remove(paths.Socket); err != nil {
			return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonClose, errors.New("exact held broker socket could not be cleaned after child exit; preserving fixture"))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonIdentity, errors.New("post-death broker socket state is ambiguous; preserving fixture"))
	}
	if _, err := os.Lstat(paths.Socket); !errors.Is(err, os.ErrNotExist) {
		return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonIdentity, errors.New("broker socket remained after exact parent-death cleanup; preserving fixture"))
	}
	currentRoot, err := os.Lstat(paths.fixtureRoot)
	if err != nil || !os.SameFile(rootInfo, currentRoot) || !currentRoot.IsDir() || currentRoot.Mode().Perm() != 0o711 {
		return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonIdentity, errors.New("private root identity changed during parent-death proof; preserving fixture"))
	}
	if survivorObserved {
		return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonExit, errors.New("a direct child survived exact parent death and required pidfd-only emergency cleanup"))
	}
	return nil
}

func startPlanBrokerCPUGuardedChild(cmd *exec.Cmd) (*os.File, error) {
	if cmd == nil || cmd.Process != nil || len(cmd.ExtraFiles) != 0 {
		return nil, errors.New("parent-guard child command is not pristine")
	}
	guardRead, guardWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		_ = guardRead.Close()
		_ = guardWrite.Close()
		return nil, err
	}
	cmd.ExtraFiles = []*os.File{guardRead, readyWrite}
	if err := cmd.Start(); err != nil {
		_ = guardRead.Close()
		_ = guardWrite.Close()
		_ = readyRead.Close()
		_ = readyWrite.Close()
		return nil, err
	}
	_ = guardRead.Close()
	_ = readyWrite.Close()
	if _, err := guardWrite.Write([]byte{'P'}); err != nil {
		_ = readyRead.Close()
		_ = stopPlanBrokerCPUStartedChild(cmd, guardWrite)
		return nil, errors.New("parent liveness token could not be delivered")
	}
	ready := make(chan error, 1)
	go func() {
		var got [6]byte
		_, readErr := io.ReadFull(readyRead, got[:])
		if readErr == nil && string(got[:]) != "READY\n" {
			readErr = errors.New("child parent-guard ready token mismatch")
		}
		ready <- readErr
	}()
	select {
	case err := <-ready:
		_ = readyRead.Close()
		if err != nil {
			_ = stopPlanBrokerCPUStartedChild(cmd, guardWrite)
			return nil, errors.New("child did not confirm parent guard before effects")
		}
	case <-time.After(5 * time.Second):
		_ = readyRead.Close()
		_ = stopPlanBrokerCPUStartedChild(cmd, guardWrite)
		return nil, errors.New("child parent-guard handshake exceeded its fixed deadline")
	}
	return guardWrite, nil
}

func stopPlanBrokerCPUStartedChild(cmd *exec.Cmd, parentGuardWrite *os.File) error {
	if cmd == nil || cmd.Process == nil || parentGuardWrite == nil {
		return errors.New("started guarded child identity is incomplete")
	}
	identity, err := capturePlanBrokerCPUProcessIdentity(cmd.Process.Pid)
	if err != nil {
		_ = parentGuardWrite.Close()
		return waitPlanBrokerCPUChildAnyExit(cmd, 5*time.Second)
	}
	pidfd, err := unix.PidfdOpen(identity.PID, 0)
	if err != nil {
		_ = parentGuardWrite.Close()
		return waitPlanBrokerCPUChildAnyExit(cmd, 5*time.Second)
	}
	defer unix.Close(pidfd)
	if err := verifyPlanBrokerCPUProcessIdentity(identity); err != nil {
		_ = parentGuardWrite.Close()
		return waitPlanBrokerCPUChildAnyExit(cmd, 5*time.Second)
	}
	if err := unix.PidfdSendSignal(pidfd, syscall.SIGKILL, nil, 0); err != nil {
		return errors.New("exact started guarded child could not be stopped through pidfd")
	}
	if err := waitPlanBrokerCPUChildReaped(cmd, 5*time.Second); err != nil {
		return err
	}
	return parentGuardWrite.Close()
}

func waitPlanBrokerCPUChildAnyExit(cmd *exec.Cmd, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return errors.New("exact child wait identity is incomplete")
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case <-waited:
		return nil
	case <-time.After(timeout):
		return errors.New("guarded child did not exit after its parent writer closed")
	}
}

func waitPlanBrokerCPUChildReaped(cmd *exec.Cmd, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return errors.New("exact child wait identity is incomplete")
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case err := <-waited:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return errors.New("exact child did not report the initiated signal exit")
		}
		status, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			return errors.New("exact child did not exit from the initiated SIGKILL")
		}
		return nil
	case <-time.After(timeout):
		return errors.New("exact child did not reap within its fixed deadline")
	}
}

func stopPlanBrokerCPUBroker(broker *planBrokerCPUBroker) error {
	if broker == nil || broker.cmd == nil || broker.cmd.Process == nil || broker.socketInfo == nil || broker.socketPath == "" || broker.waitDone == nil || broker.parentGuardWrite == nil {
		return errors.New("broker subprocess identity is incomplete")
	}
	killInitiated := false
	select {
	case <-broker.waitDone:
	default:
		if err := broker.cmd.Process.Kill(); err == nil {
			killInitiated = true
		} else if !errors.Is(err, os.ErrProcessDone) {
			return errors.New("exact held broker process could not be terminated")
		}
	}
	select {
	case <-broker.waitDone:
	case <-time.After(5 * time.Second):
		return errors.New("exact held broker process did not reap within its bounded join")
	}
	if broker.waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(broker.waitErr, &exitErr) {
			return errors.New("exact held broker process exit could not be established")
		}
		status, ok := exitErr.Sys().(syscall.WaitStatus)
		if killInitiated {
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				return errors.New("exact held broker did not terminate from the requested SIGKILL")
			}
		} else if broker.expectedCrashExit != 0 {
			if !ok || !status.Exited() || exitErr.ExitCode() != broker.expectedCrashExit {
				return errors.New("exact held broker did not exit at its fixed injected crash boundary")
			}
		} else {
			return errors.New("exact held broker exited without an initiated signal or expected crash status")
		}
	} else {
		return errors.New("exact held broker wait result lacks a verifiable exit cause")
	}
	current, err := os.Lstat(broker.socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return broker.parentGuardWrite.Close()
	}
	if err != nil || !os.SameFile(broker.socketInfo, current) || current.Mode()&os.ModeSocket == 0 {
		return errors.New("broker socket identity is uncertain; preserving fixture")
	}
	if err := os.Remove(broker.socketPath); err != nil {
		return errors.New("exact held broker socket could not be removed")
	}
	return broker.parentGuardWrite.Close()
}

// systemd owns these per-invocation deadlines, so termination of the Go or
// Node fixture supervisors cannot extend a worker past the fixed upper bound.
// Normal teardown still stops only the exact held unit; the deadline is the
// autonomous backstop for abrupt parent death.
func assertPlanBrokerCPUUnitHasParentIndependentDeadline(paths checkpointPlanBrokerPaths, unit string) error {
	if !planBrokerCPUFixtureUnitBound(paths, unit) {
		return errors.New("unit deadline query lacks an exact held identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "show", unit, "--property=RuntimeMaxUSec", "--property=TimeoutStopUSec")
	if err != nil {
		return errors.New("systemd unit cleanup deadline is unavailable")
	}
	runtimeMicros, stopMicros, err := parsePlanBrokerCPUDeadlineOutput(raw)
	if err != nil || runtimeMicros != 90000000 || stopMicros != 5000000 {
		return errors.New("systemd unit cleanup deadline differs from the fixed bound")
	}
	return nil
}

// Accept canonical raw microseconds or bounded integer systemd tokens only;
// this test oracle never rounds or treats an upper bound as an exact match.
func parsePlanBrokerCPUDurationMicros(raw string) (uint64, error) {
	const maxMicros uint64 = 90000000
	if raw == "" || len(raw) > 128 || strings.TrimSpace(raw) != raw {
		return 0, errors.New("duration is not bounded canonical text")
	}
	parseNumber := func(value string) (uint64, error) {
		if value == "" || (len(value) > 1 && value[0] == '0') {
			return 0, errors.New("duration integer is not canonical")
		}
		for _, ch := range value {
			if ch < '0' || ch > '9' {
				return 0, errors.New("duration integer is not ASCII decimal")
			}
		}
		number, err := strconv.ParseUint(value, 10, 64)
		if err != nil || number == 0 {
			return 0, errors.New("duration integer is zero or overflowing")
		}
		return number, nil
	}
	if !strings.Contains(raw, " ") {
		if micros, err := parseNumber(raw); err == nil && micros <= maxMicros {
			return micros, nil
		}
	}
	units := []struct {
		suffix string
		rank   int
		factor uint64
	}{{"min", 4, 60000000}, {"ms", 2, 1000}, {"us", 1, 1}, {"s", 3, 1000000}}
	tokens := strings.Split(raw, " ")
	if len(tokens) < 1 || len(tokens) > 4 {
		return 0, errors.New("duration token count is invalid")
	}
	var total uint64
	previousRank := 5
	for _, token := range tokens {
		var numberText string
		var selected struct {
			suffix string
			rank   int
			factor uint64
		}
		matched := false
		for _, candidate := range units {
			if strings.HasSuffix(token, candidate.suffix) {
				selected, numberText, matched = candidate, strings.TrimSuffix(token, candidate.suffix), true
				break
			}
		}
		if !matched || selected.rank >= previousRank {
			return 0, errors.New("duration units are unknown, repeated, or not descending")
		}
		number, err := parseNumber(numberText)
		if err != nil || number > ^uint64(0)/selected.factor {
			return 0, errors.New("duration multiplication overflows")
		}
		part := number * selected.factor
		if total > ^uint64(0)-part || total+part > maxMicros {
			return 0, errors.New("duration total exceeds the fixed bound")
		}
		total += part
		previousRank = selected.rank
	}
	if total == 0 {
		return 0, errors.New("duration is zero")
	}
	return total, nil
}

func parsePlanBrokerCPUDeadlineOutput(raw []byte) (uint64, uint64, error) {
	if len(raw) == 0 || len(raw) > checkpointUnitMaxOutput || raw[len(raw)-1] != '\n' {
		return 0, 0, errors.New("systemd deadline response envelope is invalid")
	}
	values := make(map[string]uint64, 2)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.Contains(value, "=") || (key != "RuntimeMaxUSec" && key != "TimeoutStopUSec") {
			return 0, 0, errors.New("systemd deadline fields are malformed")
		}
		if _, exists := values[key]; exists {
			return 0, 0, errors.New("systemd deadline fields are duplicated")
		}
		micros, err := parsePlanBrokerCPUDurationMicros(value)
		if err != nil {
			return 0, 0, err
		}
		values[key] = micros
	}
	if len(values) != 2 {
		return 0, 0, errors.New("systemd deadline fields are incomplete")
	}
	runtimeMicros, stopMicros := values["RuntimeMaxUSec"], values["TimeoutStopUSec"]
	if runtimeMicros != 90000000 || stopMicros != 5000000 {
		return 0, 0, errors.New("systemd deadline differs from the exact configured bounds")
	}
	return runtimeMicros, stopMicros, nil
}

func stopPlanBrokerCPUUnit(unit string) error {
	if unit == "" || filepath.Base(unit) != unit || !strings.HasSuffix(unit, ".service") {
		return errors.New("unit cleanup identity is not exact")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "stop", unit)
	return err
}

func waitPlanBrokerCPUActive(paths checkpointPlanBrokerPaths) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		unit, err := planBrokerCPUFixtureUnitState(context.Background(), paths)
		if err == nil && unit.MainPID > 1 && unit.Active == "active" {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("exact transient unit did not reach active MainPID")
}

func waitPlanBrokerCPUWorkerEvent(paths checkpointPlanBrokerPaths, pid int) error {
	if pid <= 1 {
		return errors.New("worker event PID is invalid")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		path := filepath.Join(paths.fixtureRoot, "var", "events", strconv.Itoa(pid)+".json")
		if _, err := os.Lstat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("exact worker held-source event did not appear before its bounded deadline")
}

func waitPlanBrokerCPUInactive(paths checkpointPlanBrokerPaths, priorInvocation string) error {
	_, err := waitPlanBrokerCPUInactiveObserved(paths, priorInvocation)
	return err
}

func planBrokerCPUInactiveWaitMarker(owner, code string) string {
	if owner != "TestCheckpointPlanRelaunchCPULifecycleSequence" && owner != "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect" {
		owner = "unavailable"
	}
	switch code {
	case "private_binding", "show_unavailable", "show_envelope", "state_parse", "empty_invocation", "empty_control_group", "empty_invocation_control_group", "pid_state_shape", "unit_definition_missing", "nonzero_pid", "invocation_mismatch", "worker_state", "jobs_unavailable", "jobs_malformed", "pending_job", "cgroup_unconfirmed", "unavailable":
	default:
		code = "unavailable"
	}
	return "__PLAN_RELAUNCH_INACTIVE_WAIT__:" + owner + ":" + code
}

func closePlanBrokerCPUOpenedPIDFD(pidfd int, closeFD func(int) error) error {
	if pidfd < 0 || closeFD == nil {
		return errors.New("opened pidfd close is unavailable")
	}
	return closeFD(pidfd)
}

func settlePlanBrokerCPUOpenedPIDFDClose(outcome error, pidfd int, closeFD func(int) error) error {
	if closeErr := closePlanBrokerCPUOpenedPIDFD(pidfd, closeFD); closeErr != nil {
		return errors.Join(outcome, errors.New("cleanup-opened worker pidfd close failed; preserving private fixture"), closeErr)
	}
	return outcome
}

func verifyPlanBrokerCPUOpenedPIDFDCloseControls() error {
	calls := 0
	if outcome := settlePlanBrokerCPUOpenedPIDFDClose(nil, 41, func(fd int) error {
		calls++
		if fd != 41 {
			return errors.New("wrong descriptor")
		}
		return nil
	}); outcome != nil || calls != 1 {
		return errors.New("opened pidfd successful close was not settled exactly once")
	}
	calls = 0
	priorProof := errors.New("prior proof uncertainty")
	closeErr := errors.New("injected close failure")
	outcome := settlePlanBrokerCPUOpenedPIDFDClose(priorProof, 41, func(fd int) error {
		calls++
		if fd != 41 {
			return errors.New("wrong descriptor")
		}
		return closeErr
	})
	if calls != 1 || !errors.Is(outcome, priorProof) || !errors.Is(outcome, closeErr) || outcome == nil || !strings.Contains(outcome.Error(), "preserving private fixture") {
		return errors.New("opened pidfd close failure did not join and preserve the prior proof outcome exactly once")
	}
	return nil
}

func planBrokerCPUWorkerEmptyDiagnosticCode(err error) string {
	if err == nil {
		return "unavailable"
	}
	switch err.Error() {
	case "fixed worker is not freshly inactive":
		return "worker_state"
	case "systemd pending-job state is unavailable":
		return "jobs_unavailable"
	case "systemd pending-job state is malformed":
		return "jobs_malformed"
	case "fixed worker has a pending systemd job":
		return "pending_job"
	case "fixed worker control group is not confirmed empty":
		return "cgroup_unconfirmed"
	case "signed prior worker control group is not confirmed empty":
		return "cgroup_unconfirmed"
	default:
		return "unavailable"
	}
}

func waitPlanBrokerCPUStoppedProof(paths checkpointPlanBrokerPaths, held planBrokerCPULaunchIdentity, pidfd int) (string, error) {
	lastCode := "unavailable"
	deadline := time.Now().Add(10 * time.Second)
	prior := ownedStopReceipt{WorkerPID: held.PID, WorkerStartTicks: held.StartTicks, InvocationID: held.Invocation, ControlGroup: held.ControlGroup, SignalSent: true, ReleaseTerminal: true}
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		observed, err, stateCode := planBrokerCPUFixtureStoppedStateObserved(ctx, paths)
		if err == nil {
			if verifyCheckpointPlanBrokerStoppedObservation(observed, paths, prior) != nil {
				lastCode = "invocation_mismatch"
			} else if terminalErr := verifyPlanBrokerCPUTerminalPIDFDUntil(pidfd, held, deadline); terminalErr != nil {
				lastCode = "unavailable"
			} else if emptyErr := checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior); emptyErr == nil {
				cancel()
				return "", nil
			} else {
				lastCode = planBrokerCPUWorkerEmptyDiagnosticCode(emptyErr)
			}
		} else {
			lastCode = stateCode
		}
		cancel()
		time.Sleep(100 * time.Millisecond)
	}
	return lastCode, errors.New("exact transient unit lacks the held-pidfd terminal and signed-old-cgroup proof")
}

func waitPlanBrokerCPUStoppedCleanupProof(paths checkpointPlanBrokerPaths, held planBrokerCPULaunchIdentity, pidfd int) (string, error) {
	lastCode := "unavailable"
	deadline := time.Now().Add(10 * time.Second)
	prior := ownedStopReceipt{WorkerPID: held.PID, WorkerStartTicks: held.StartTicks, InvocationID: held.Invocation, ControlGroup: held.ControlGroup, SignalSent: true, ReleaseTerminal: true}
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		raw, err, stateCode := planBrokerCPUFixtureStoppedStateRaw(ctx, paths)
		if err != nil {
			lastCode = stateCode
		} else if observed, parseErr := parseCheckpointPlanBrokerStoppedObservation(raw); parseErr != nil {
			lastCode = "state_parse"
		} else if observed.Load == "not-found" && planBrokerCPUStoppedStateParseShapeCode(raw, held.UnitName) != "unit_definition_missing" {
			lastCode = "state_parse"
		} else if verifyCheckpointPlanBrokerStoppedCleanupObservation(observed, paths, prior) != nil {
			lastCode = "invocation_mismatch"
		} else if terminalErr := verifyPlanBrokerCPUTerminalPIDFDUntil(pidfd, held, deadline); terminalErr != nil {
			lastCode = "unavailable"
		} else {
			_, procErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(held.PID)), held.PID)
			jobs, jobsErr := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "list-jobs", "--no-legend", "--no-pager")
			if jobsErr == nil && len(jobs) > checkpointUnitMaxOutput {
				jobsErr = errors.New("systemd pending-job state exceeds its fixed bound")
			}
			group := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(filepath.Clean(held.ControlGroup), string(os.PathSeparator)), "cgroup.procs")
			cgroupProcs, cgroupErr := readCheckpointPlanBrokerCgroupProcs(group)
			if proofErr := verifyCheckpointPlanBrokerStoppedWorkerEmptySample(paths, observed, prior, procErr, jobs, jobsErr, cgroupProcs, cgroupErr, true); proofErr == nil {
				cancel()
				return "", nil
			} else {
				lastCode = planBrokerCPUWorkerEmptyDiagnosticCode(proofErr)
			}
		}
		cancel()
		time.Sleep(100 * time.Millisecond)
	}
	return lastCode, errors.New("cleanup could not prove the exact held worker terminal and old-cgroup state")
}

func waitPlanBrokerCPUInactiveObserved(paths checkpointPlanBrokerPaths, priorInvocation string) (string, error) {
	lastCode := "unavailable"
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		unit, err, stateCode := planBrokerCPUFixtureStoppedStateObserved(context.Background(), paths)
		if err == nil && unit.MainPID == 0 && (unit.Invocation == "" && unit.ControlGroup == "" || unit.Invocation == strings.ToLower(priorInvocation) && unit.ControlGroup != "") {
			if unit.Load == "loaded" && (unit.Sub == "dead" || unit.Sub == "exited") {
				return "", nil
			}
		} else if err != nil {
			lastCode = stateCode
		} else if unit.MainPID != 0 || unit.Load != "loaded" {
			lastCode = "nonzero_pid"
		} else {
			lastCode = "invocation_mismatch"
		}
		time.Sleep(100 * time.Millisecond)
	}
	return lastCode, errors.New("exact transient unit did not become freshly inactive with an empty cgroup")
}

func waitPlanBrokerCPUSocket(path string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("exact broker socket did not appear")
}

func confirmPlanBrokerCPUUnitAbsent(paths checkpointPlanBrokerPaths, unit string) error {
	return confirmPlanBrokerCPUUnitAbsentWithin(paths, unit, time.Now().Add(5*time.Second))
}

func confirmPlanBrokerCPUUnitAbsentWithin(paths checkpointPlanBrokerPaths, unit string, deadline time.Time) error {
	if !planBrokerCPUFixtureUnitBound(paths, unit) {
		return errors.New("fixture unit cleanup target is not canonical")
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if !planBrokerCPUFixtureUnitBound(paths, unit) { return errors.New("fixture unit binding changed before reset-failed") }
	reset := exec.CommandContext(ctx, checkpointFixedSystemctl, "reset-failed", unit)
	reset.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	_ = reset.Run()
	for {
		if ctx.Err() != nil { return errors.New("exact transient unit collection exhausted its shared deadline") }
		if !planBrokerCPUFixtureUnitBound(paths, unit) { return errors.New("fixture unit binding changed before the absence query") }
		query := exec.CommandContext(ctx, checkpointFixedSystemctl, "show", unit, "--property=LoadState", "--value")
		query.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
		output, err := query.CombinedOutput()
		if err == nil && ctx.Err() == nil && bytes.Equal(output, []byte("not-found\n")) { return nil }
		remaining := time.Until(deadline)
		if remaining <= 0 { return errors.New("exact transient unit remains loaded after bounded collection") }
		pause := 25 * time.Millisecond
		if remaining < pause { pause = remaining }
		timer := time.NewTimer(pause)
		select { case <-ctx.Done(): if !timer.Stop() { <-timer.C }; return errors.New("exact transient unit collection exhausted its shared deadline")
		case <-timer.C: }
	}
}

func planBrokerCPUUnitConfirmedAbsent(unit string) bool {
	if unit == "" || filepath.Base(unit) != unit || !strings.HasSuffix(unit, ".service") {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, checkpointFixedSystemctl, "show", unit, "--property=LoadState", "--value")
	command.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	output, err := command.CombinedOutput()
	return err == nil && strings.TrimSpace(string(output)) == "not-found"
}

func makePlanBrokerCPUUnrelatedChild(child **planBrokerCPUParentGuardChild, worker, root string, gid uint32) error {
	if child == nil || !filepath.IsAbs(worker) || filepath.Clean(worker) != worker || !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root)) || filepath.Dir(root) != os.TempDir() || gid == 0 {
		return errors.New("unrelated tagged child inputs are outside the fixed fixture")
	}
	command := exec.Command(worker, "-test.run=^TestCheckpointPlanRelaunchCPUWorker$", "-test.count=1")
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/bin", planBrokerCPUEnv + "=" + planBrokerCPUOptIn, planBrokerCPURole + "=unrelated", planBrokerCPUParentGuardEnv + "=1", "VRAM_PLAN_BROKER_CPU_ROOT=" + root}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = time.Second
	parentGuardWrite, err := startPlanBrokerCPUGuardedChild(command)
	if err != nil {
		return err
	}
	*child = &planBrokerCPUParentGuardChild{cmd: command, parentGuardWrite: parentGuardWrite}
	return nil
}

func planBrokerCPUUnrelatedChildAlive(child *planBrokerCPUParentGuardChild) bool {
	return child != nil && child.cmd != nil && child.cmd.Process != nil && child.parentGuardWrite != nil && child.cmd.Process.Signal(syscall.Signal(0)) == nil
}

func stopPlanBrokerCPUUnrelatedChild(child *planBrokerCPUParentGuardChild) error {
	if child == nil || child.cmd == nil || child.cmd.Process == nil || child.parentGuardWrite == nil {
		return errors.New("unrelated child custody is incomplete")
	}
	killErr := child.cmd.Process.Kill()
	killInitiated := killErr == nil
	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		return errors.New("exact unrelated child could not be terminated")
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- child.cmd.Wait()
	}()
	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-time.After(5 * time.Second):
		return errors.New("exact unrelated child did not reap within its bounded join")
	}
	var exitErr *exec.ExitError
	if !killInitiated || !errors.As(waitErr, &exitErr) {
		return errors.New("unrelated child termination cause is not the initiated exact SIGKILL")
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		return errors.New("unrelated child did not terminate from the initiated exact SIGKILL")
	}
	return child.parentGuardWrite.Close()
}

func planBrokerCPUWorkerStartTicks(paths checkpointPlanBrokerPaths, pid int) (uint64, error) {
	if pid <= 1 {
		return 0, errors.New("worker pid is invalid")
	}
	if ticks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid); err == nil {
		return ticks, nil
	}
	body, err := os.ReadFile(filepath.Join(paths.fixtureRoot, "var", "events", strconv.Itoa(pid)+".json"))
	if err != nil {
		return 0, err
	}
	var event struct {
		PID        int    `json:"pid"`
		StartTicks uint64 `json:"start_ticks"`
	}
	if json.Unmarshal(body, &event) != nil || event.PID != pid || event.StartTicks == 0 {
		return 0, errors.New("worker event does not bind the exact process incarnation")
	}
	return event.StartTicks, nil
}

func observePlanBrokerCPUWorker(ctx context.Context, plan CheckpointLaunchPlan, digest, prior string) (CheckpointManagedBinding, error) {
	var binding CheckpointManagedBinding
	root := filepath.Dir(filepath.Dir(plan.Model.Path))
	configInfo, configErr := os.Stat(filepath.Join(root, "etc", "node-agent.yaml"))
	configStat, configOK := infoSys(configInfo)
	if configErr != nil || !configOK || configStat.Gid == 0 {
		return binding, errors.New("private node principal group is unavailable")
	}
	paths := checkpointPlanBrokerCPUPaths(root, 65534, configStat.Gid)
	if ctx == nil || ctx.Err() != nil || !checkpointPlanBrokerPrivateFixturePathSet(paths) || plan.Placement == nil || digest != sha256Hex(mustJSON(plan)) {
		return binding, errors.New("private CPU observer request is invalid")
	}
	unit, err := planBrokerCPUFixtureUnitState(ctx, paths)
	if err != nil || unit.MainPID <= 1 || unit.Invocation == "" || unit.Invocation == strings.ToLower(prior) || unit.Active != "active" {
		return binding, errors.New("fresh transient worker identity is unavailable")
	}
	active, _, err := readPlanBrokerFile(paths.ActivePlan, checkpointLaunchPlanMaxBytes, 0)
	if err != nil || sha256Hex(active) != digest {
		return binding, errors.New("active plan digest differs from the acknowledged plan")
	}
	var parsed CheckpointLaunchPlan
	if json.Unmarshal(active, &parsed) != nil || parsed.Alias != plan.Alias || parsed.Model.Path != plan.Model.Path {
		return binding, errors.New("active model alias or source differs")
	}
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(unit.MainPID), "exe"))
	if err != nil || filepath.Clean(exe) != filepath.Join(root, "worker") {
		return binding, errors.New("worker executable identity differs from the private fixture image")
	}
	modelInfo, err := os.Stat(plan.Model.Path)
	if err != nil {
		return binding, errors.New("approved worker source is unavailable")
	}
	found := false
	fdDir := filepath.Join("/proc", strconv.Itoa(unit.MainPID), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return binding, errors.New("worker held descriptor table is unavailable")
	}
	for _, entry := range entries {
		fdPath := filepath.Join(fdDir, entry.Name())
		target, linkErr := os.Readlink(fdPath)
		if linkErr == nil && target == plan.Model.Path {
			opened, statErr := os.Stat(fdPath)
			if statErr == nil && os.SameFile(modelInfo, opened) {
				found = true
				break
			}
		}
	}
	if !found {
		return binding, errors.New("worker does not hold the approved model source inode")
	}
	ticks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(unit.MainPID)), unit.MainPID)
	if err != nil || ticks == 0 {
		return binding, errors.New("worker process start incarnation is unavailable")
	}
	physical := plan.Placement.PhysicalIdentity
	if os.Getenv("VRAM_PLAN_BROKER_CPU_PHYSICAL_SUBSTITUTE") == "yes" {
		physical = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	}
	incarnation := sha256Hex([]byte(fmt.Sprintf("%d:%d:%s:%s", unit.MainPID, ticks, digest, unit.Invocation)))
	custody := sha256Hex([]byte(fmt.Sprintf("synthetic-cpu-custody:%d:%d:%s", unit.MainPID, ticks, plan.Model.SHA256)))
	binding = CheckpointManagedBinding{Version: "private-cpu-fixture-v1", CurrentIncarnation: incarnation, PlanSHA256: digest, CustodyBindingSHA256: custody, Alias: plan.Alias,
		Association: CheckpointVerifiedUnitAssociation{Identity: CheckpointLocalIdentity{ServiceUnit: paths.fixtureUnit, PID: unit.MainPID, ProcessStartTicks: ticks, ExecutablePath: exe, ExecutableSHA256: plan.Executable.SHA256, ModelPath: plan.Model.Path, ModelSHA256: plan.Model.SHA256}, Invocation: unit.Invocation, ControlGroup: unit.ControlGroup},
		Placement:   CheckpointDevicePlacement{Backend: plan.Placement.Backend, PhysicalIdentity: physical, RuntimeDeviceToken: plan.Placement.RuntimeDeviceToken, RuntimeVersion: plan.Placement.RuntimeVersion, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	return binding, nil
}

func provePlanBrokerCPUPhysicalSubstitutionRejected(paths checkpointPlanBrokerPaths, plan CheckpointLaunchPlan) error {
	bad := paths
	bad.bindingObserver = func(ctx context.Context, plan CheckpointLaunchPlan, digest, prior string) (CheckpointManagedBinding, error) {
		binding, err := observePlanBrokerCPUWorker(ctx, plan, digest, prior)
		if err == nil {
			binding.Placement.PhysicalIdentity = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		}
		return binding, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_, err := awaitCheckpointPlanBrokerBinding(ctx, bad, plan, sha256Hex(mustJSON(plan)), "old-invocation-id")
	if err == nil {
		return errors.New("substituted physical identity reached the acknowledgement boundary")
	}
	return nil
}

func verifyPlanBrokerCPUHeldSourceEvents(paths checkpointPlanBrokerPaths, victim, urgent CheckpointLaunchPlan, pids ...int) error {
	if len(pids) != 3 {
		return errors.New("three exact worker process identities are required")
	}
	type sourceEvent struct {
		PID            int    `json:"pid"`
		StartTicks     uint64 `json:"start_ticks"`
		Alias          string `json:"alias"`
		ModelPath      string `json:"model_path"`
		ModelSHA256    string `json:"model_sha256"`
		ModelSize      int64  `json:"model_size"`
		ModelDev       uint64 `json:"model_dev"`
		ModelIno       uint64 `json:"model_ino"`
		ExecutablePath string `json:"executable_path"`
		ExecutableSHA  string `json:"executable_sha256"`
		ExecutableDev  uint64 `json:"executable_dev"`
		ExecutableIno  uint64 `json:"executable_ino"`
	}
	var events [3]sourceEvent
	for i, pid := range pids {
		body, err := os.ReadFile(filepath.Join(paths.fixtureRoot, "var", "events", strconv.Itoa(pid)+".json"))
		if err != nil || json.Unmarshal(body, &events[i]) != nil || events[i].PID != pid || events[i].StartTicks == 0 || events[i].ModelSize <= 0 || events[i].ExecutablePath != victim.Executable.Path || events[i].ExecutableSHA != victim.Executable.SHA256 || events[i].ExecutableDev == 0 || events[i].ExecutableIno == 0 {
			return errors.New("exact worker held-source event is incomplete")
		}
	}
	if events[0].Alias != victim.Alias || events[0].ModelPath != victim.Model.Path || events[0].ModelSHA256 != victim.Model.SHA256 || events[1].Alias != urgent.Alias || events[1].ModelPath != urgent.Model.Path || events[1].ModelSHA256 != urgent.Model.SHA256 || events[2].Alias != victim.Alias || events[2].ModelPath != victim.Model.Path || events[2].ModelSHA256 != victim.Model.SHA256 || events[0].ModelDev != events[2].ModelDev || events[0].ModelIno != events[2].ModelIno || events[0].ModelIno == events[1].ModelIno || events[0].ExecutableDev != events[1].ExecutableDev || events[0].ExecutableDev != events[2].ExecutableDev || events[0].ExecutableIno != events[1].ExecutableIno || events[0].ExecutableIno != events[2].ExecutableIno || events[0].ExecutableSHA != events[1].ExecutableSHA || events[0].ExecutableSHA != events[2].ExecutableSHA {
		return errors.New("victim/urgent/victim source or inode linkage differs")
	}
	return nil
}

func assertPlanBrokerCPUOutsideWorkerCgroup(workerCgroup string) error {
	if workerCgroup == "" || !strings.HasPrefix(workerCgroup, "/") || strings.Contains(workerCgroup, "..") {
		return errors.New("worker cgroup identity is malformed")
	}
	body, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(os.Getpid()), "cgroup"))
	if err != nil || len(body) == 0 || len(body) > 16<<10 {
		return errors.New("broker supervisor cgroup identity is unavailable")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && (parts[2] == workerCgroup || strings.HasPrefix(parts[2], strings.TrimSuffix(workerCgroup, "/")+"/")) {
			return errors.New("broker supervisor shares the transient worker cgroup")
		}
	}
	return nil
}

func mustJSON(value any) []byte { body, _ := json.Marshal(value); return body }
