#!/usr/bin/env python3
"""Read-only CMP enrollment check on the dedicated LB; never print secrets."""

import json
import pathlib
import ssl
import sys
import urllib.request

values = dict(line.split('=', 1) for line in pathlib.Path('/root/vram-governor-controller-credentials.env').read_text().splitlines() if '=' in line)
request = urllib.request.Request('https://10.0.0.115:8443/admin/api/overview', headers={'Authorization': 'Bearer ' + values['ADMIN_TOKEN']})
context = ssl.create_default_context(cafile='/etc/vram-governor/tls/controller.crt')
with urllib.request.urlopen(request, context=context, timeout=10) as response:
    overview = json.load(response)
nodes = overview.get('nodes') or []
connected = sorted(node['id'] for node in nodes if node.get('observed', {}).get('connectivity') == 'connected')
cmp_nodes = [node for node in nodes if node.get('id') == 'cmp170-node']
cmp = cmp_nodes[0] if cmp_nodes else None
cmp_connected = bool(cmp and cmp.get('observed', {}).get('connectivity') == 'connected')
cmp_targets = [target for target in overview.get('targets') or [] if target.get('id', '').startswith('cmp170-node-')]
print('connected_node_ids=' + ','.join(connected))
print('cmp_registered=' + str(bool(cmp)))
print('cmp_connected=' + str(cmp_connected))
print('cmp_targets=' + str(len(cmp_targets)))
if cmp:
    print('cmp_last_seen=' + str(cmp.get('observed', {}).get('last_seen_at')))
    print('cmp_power_control_mode=' + str(cmp.get('desired', {}).get('power_control_mode')))
if '--require-cmp' in sys.argv and not cmp_connected:
    raise SystemExit(1)
