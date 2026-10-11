#!/usr/bin/env python3
"""Emit only the CMP credential pair from the LB to a protected SSH pipe."""

import hashlib
import json
import os
import pathlib
import re


if os.geteuid() != 0:
    raise SystemExit('run as root')
path = pathlib.Path('/root/vram-governor-controller-credentials.env')
values = {}
for line in path.read_text().splitlines():
    if not line or line.lstrip().startswith('#'):
        continue
    key, sep, value = line.partition('=')
    if sep and key in {'CMP170_NODE_TOKEN', 'VRAM_NODE_COMMAND_SECRET'}:
        values[key] = value.strip().strip('"').strip("'")
token = values.get('CMP170_NODE_TOKEN', '')
secret = values.get('VRAM_NODE_COMMAND_SECRET', '')
if not re.fullmatch(r'[A-Za-z0-9._~+\-]+', token) or len(secret) < 32:
    raise SystemExit('invalid CMP credential pair')
if hashlib.sha256(token.encode()).hexdigest() != '85f2759d6ef8eadac6cd2d454c6bcd5d3c553896c3abfc2823c66da5bd82ad26':
    raise SystemExit('CMP token does not match the active controller identity')
print(json.dumps({'token': token, 'secret': secret}, separators=(',', ':')))
