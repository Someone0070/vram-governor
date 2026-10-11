#!/usr/bin/env python3
"""Summarize live Fleet control readiness without printing any credentials."""

import json
import pathlib
import ssl
import urllib.request


values = dict(line.split('=', 1) for line in pathlib.Path('/root/vram-governor-controller-credentials.env').read_text().splitlines() if '=' in line)
request = urllib.request.Request('https://10.0.0.115:8443/admin/api/overview', headers={'Authorization': 'Bearer ' + values['ADMIN_TOKEN']})
context = ssl.create_default_context(cafile='/etc/vram-governor/tls/controller.crt')
with urllib.request.urlopen(request, context=context, timeout=10) as response:
    overview = json.load(response)
for node in overview.get('nodes') or []:
    print('node', node.get('id'), 'connectivity=' + str((node.get('observed') or {}).get('connectivity')),
          'scheduling=' + str(node.get('scheduling_state')),
          'power_mode=' + str((node.get('desired') or {}).get('power_control_mode')),
          'agent=' + str((node.get('observed') or {}).get('agent_version')))
for target in overview.get('targets') or []:
    print('target', target.get('id'), 'adapter=' + str(target.get('adapter')),
          'enabled=' + str(target.get('enabled')),
          'endpoint=' + str(target.get('endpoint')),
          'lifecycle=' + str(target.get('supports_model_lifecycle')),
          'reclaim=' + str(target.get('supports_accelerator_reclaim')),
          'profile_switch=' + str(target.get('supports_runtime_profile_switch')),
          'slots=' + str(target.get('slots')),
          'models=' + ','.join(target.get('models') or []),
          'resident=' + ','.join(target.get('resident_models') or []))
for command in (overview.get('node_commands') or [])[-12:]:
    print('command', command.get('node_id'), command.get('command'), command.get('status'),
          'error=' + str(command.get('error')))
print('active_workloads=' + str(sum(row.get('status') in {'queued', 'waiting', 'admitted', 'starting', 'running', 'yielding', 'checkpointing'} for row in overview.get('workloads') or [])))
