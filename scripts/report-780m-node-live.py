#!/usr/bin/env python3
"""Print only non-secret 780m node readiness facts from the dedicated LB."""
import json
import pathlib
import ssl
import urllib.request

values = dict(line.split('=', 1) for line in pathlib.Path('/root/vram-governor-controller-credentials.env').read_text().splitlines() if '=' in line)
request = urllib.request.Request('https://10.0.0.115:8443/admin/api/overview', headers={'Authorization': 'Bearer ' + values['ADMIN_TOKEN']})
context = ssl.create_default_context(cafile='/etc/vram-governor/tls/controller.crt')
with urllib.request.urlopen(request, context=context, timeout=10) as response:
    overview = json.load(response)
nodes = [node for node in overview['nodes'] if node['id'] == '780m-node']
assert len(nodes) == 1
node = nodes[0]
targets = [target for target in overview['targets'] if target.get('id', '').startswith('780m-node-')]
print('connectivity=' + node['observed']['connectivity'])
print('ready=' + str(node['observed'].get('ready')))
print('accelerators=' + str(len(node.get('accelerators') or [])))
for accelerator in node.get('accelerators') or []:
    print('accelerator=' + accelerator['id'] + ',vendor=' + accelerator['vendor'] + ',memory_kind=' + accelerator.get('memory_kind', '') + ',vram_total_mb=' + str(accelerator['vram_total_mb']))
print('targets=' + str(len(targets)))
for target in targets:
    print('target=' + target['id'] + ',adapter=' + target['adapter'] + ',slots=' + str(target.get('slots')) + ',context_limit=' + str(target.get('context_limit')) + ',capacity_verified=' + str(target.get('capacity_verified')))
    print('target_endpoint=' + str(target.get('endpoint')))
    print('target_models=' + ','.join(target.get('models') or []))
    print('target_capacity_source=' + str(target.get('capacity_source')))
    print('target_lifecycle=' + str(target.get('supports_model_lifecycle')))
print('power_control_mode=' + node['desired']['power_control_mode'])
