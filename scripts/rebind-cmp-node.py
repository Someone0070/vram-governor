#!/usr/bin/env python3
"""Atomically bind the CMP agent to the preconfigured LB identity, no secret output."""

import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone


if os.geteuid() != 0:
    raise SystemExit('run as root')
payload = json.load(sys.stdin)
token = payload.get('token', '')
secret = payload.get('secret', '')
if not isinstance(token, str) or not isinstance(secret, str):
    raise SystemExit('invalid credential types')
if hashlib.sha256(token.encode()).hexdigest() != '85f2759d6ef8eadac6cd2d454c6bcd5d3c553896c3abfc2823c66da5bd82ad26':
    raise SystemExit('CMP token does not match the intended controller principal')
if len(secret) < 32 or not re.fullmatch(r'[A-Za-z0-9._~+\-]+', secret):
    raise SystemExit('invalid command signing secret')

base = pathlib.Path('/etc/vram-governor')
env = base / 'node-agent.env'
config = base / 'node-agent.yaml'
old_env = env.read_text()
old_config = config.read_text()
if old_config.count('node_id: "cmp-node"') != 1 or old_config.count('power_control_mode: "manual"') != 1:
    raise SystemExit('CMP config differs from expected pre-bind state')
if old_env.count('VRAM_NODE_TOKEN=') != 1 or old_env.count('VRAM_NODE_COMMAND_SECRET=') != 1:
    raise SystemExit('CMP environment differs from expected pre-bind state')
new_config = old_config.replace('node_id: "cmp-node"', 'node_id: "cmp170-node"', 1)
new_config = new_config.replace('node_name: "cmp-node"', 'node_name: "cmp170-node"', 1)
new_config = new_config.replace('power_control_mode: "manual"', 'power_control_mode: "dont_touch"', 1)
new_env = 'VRAM_NODE_TOKEN=' + token + '\nVRAM_NODE_COMMAND_SECRET=' + secret + '\n'

stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
for target in (env, config):
    shutil.copy2(target, target.with_name(target.name + '.before-lb-bind-' + stamp))

def replace(target: pathlib.Path, content: str) -> None:
    stat = target.stat()
    fd, tmp = tempfile.mkstemp(prefix='.' + target.name + '-', dir=target.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(tmp, stat.st_uid, stat.st_gid)
        os.chmod(tmp, stat.st_mode & 0o777)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

replace(env, new_env)
replace(config, new_config)
print('cmp_node_bound_to_controller=True')
print('node_id=cmp170-node')
print('power_control_mode=dont_touch')
