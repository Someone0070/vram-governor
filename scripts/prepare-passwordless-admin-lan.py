#!/usr/bin/env python3
"""Prepare, but do not activate, the LB's temporary LAN-only Fleet login."""

import os
import pathlib


if os.geteuid() != 0:
    raise SystemExit('run as root on the LB')
source = pathlib.Path('/etc/vram-governor/controller.yaml')
destination = pathlib.Path('/root/controller-passwordless-admin-lan.candidate.yaml')
text = source.read_text()
required = ('production: true', '  development_bypass: false', '  admin_private_cidrs: ["10.0.0.0/24"]')
if any(text.count(value) != 1 for value in required):
    raise SystemExit('live controller security settings do not match expected values')
if 'passwordless_admin_lan:' in text:
    if text.count('  passwordless_admin_lan: false') != 1:
        raise SystemExit('passwordless_admin_lan is already enabled or malformed')
    text = text.replace('  passwordless_admin_lan: false', '  passwordless_admin_lan: true', 1)
else:
    text = text.replace('  development_bypass: false', '  development_bypass: false\n  passwordless_admin_lan: true', 1)
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    output.write(text)
    output.flush()
    os.fsync(output.fileno())
print('candidate_prepared=' + str(destination))
