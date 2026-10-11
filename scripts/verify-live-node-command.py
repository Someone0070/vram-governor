#!/usr/bin/env python3
"""Issue only refresh_capabilities to connected nodes and verify signed results."""

import json
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid


allowed = {'780m-node', 'cmp170-node'}
if len(sys.argv) != 2 or sys.argv[1] not in allowed:
    raise SystemExit('pass exactly one allowlisted node ID')
node_id = sys.argv[1]
values = dict(line.split('=', 1) for line in pathlib.Path('/root/vram-governor-controller-credentials.env').read_text().splitlines() if '=' in line)
base = 'https://10.0.0.115:8443'
context = ssl.create_default_context(cafile='/etc/vram-governor/tls/controller.crt')
headers = {'Authorization': 'Bearer ' + values['ADMIN_TOKEN']}
body = json.dumps({'command': 'refresh_capabilities', 'ttl_seconds': 120}).encode()
request = urllib.request.Request(base + '/admin/api/nodes/' + node_id + '/commands', body,
                                 {**headers, 'Content-Type': 'application/json', 'Idempotency-Key': str(uuid.uuid4())})
with urllib.request.urlopen(request, context=context, timeout=10) as response:
    if response.status != 202:
        raise SystemExit('command was not accepted')
    command = json.load(response)
command_id = command['id']
for _ in range(30):
    request = urllib.request.Request(base + '/admin/api/node-commands?node_id=' + node_id + '&limit=20', headers=headers)
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        rows = json.load(response)
    found = next((row for row in rows if row.get('id') == command_id), None)
    if found and found.get('status') in {'succeeded', 'failed', 'expired'}:
        print('node=' + node_id)
        print('command=refresh_capabilities')
        print('status=' + found['status'])
        print('error=' + str(found.get('error')))
        if found['status'] != 'succeeded':
            raise SystemExit(1)
        print('signed_node_command_verified=True')
        break
    time.sleep(0.5)
else:
    raise SystemExit('command did not settle')
