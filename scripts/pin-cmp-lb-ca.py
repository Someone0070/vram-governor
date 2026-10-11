#!/usr/bin/env python3
"""Pin the known LB certificate for the CMP agent without changing its token."""

import os
import pathlib
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone


CONFIG = pathlib.Path('/etc/vram-governor/node-agent.yaml')
STAGED = pathlib.Path('/root/controller-ca-from-lb.pem')
DEST = pathlib.Path('/etc/vram-governor/controller-ca.pem')
EXPECTED = 'EB:87:30:8E:A1:9A:33:A3:0C:E6:B8:FE:55:7B:DB:88:80:1E:15:21:DC:84:F1:0E:AD:C1:22:6D:2F:33:2C:E8'
ANCHOR = 'controller_url: "wss://10.0.0.115:18082/ws/node"'

if os.geteuid() != 0:
    raise SystemExit('run as root')
fingerprint = subprocess.check_output(['openssl', 'x509', '-in', str(STAGED), '-noout', '-fingerprint', '-sha256'], text=True).strip().split('=', 1)[-1]
if fingerprint.upper() != EXPECTED:
    raise SystemExit('LB certificate fingerprint mismatch')
subprocess.run(['openssl', 'verify', '-CAfile', str(STAGED), str(STAGED)], check=True, stdout=subprocess.DEVNULL)
original = CONFIG.read_text()
if original.count(ANCHOR) != 1 or 'controller_ca_file:' in original:
    raise SystemExit('CMP config does not match the expected unpinned state')
stat = CONFIG.stat()
group = __import__('grp').getgrnam('vram-governor').gr_gid
if DEST.exists() or DEST.is_symlink():
    raise SystemExit('destination certificate already exists')
with STAGED.open('rb') as source:
    fd, temporary_cert = tempfile.mkstemp(prefix='.controller-ca-', dir=DEST.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        os.chown(temporary_cert, 0, group)
        os.chmod(temporary_cert, 0o640)
        os.replace(temporary_cert, DEST)
    finally:
        if os.path.exists(temporary_cert):
            os.unlink(temporary_cert)
backup = CONFIG.with_name(CONFIG.name + '.before-lb-ca-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
shutil.copy2(CONFIG, backup)
updated = original.replace(ANCHOR, ANCHOR + '\ncontroller_ca_file: "' + str(DEST) + '"', 1)
fd, temporary_yaml = tempfile.mkstemp(prefix='.node-agent-', dir=CONFIG.parent)
try:
    with os.fdopen(fd, 'w') as output:
        output.write(updated)
        output.flush()
        os.fsync(output.fileno())
    os.chown(temporary_yaml, stat.st_uid, stat.st_gid)
    os.chmod(temporary_yaml, stat.st_mode & 0o777)
    os.replace(temporary_yaml, CONFIG)
finally:
    if os.path.exists(temporary_yaml):
        os.unlink(temporary_yaml)
print('cmp_lb_certificate_pinned=True')
print('config_backup=' + str(backup))
