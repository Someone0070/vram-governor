#!/usr/bin/env python3
"""Verify the deployed UI and live read-only Qwen target without secrets."""

import json
import pathlib
import re
import ssl
import subprocess
import urllib.request


base = 'https://10.0.0.115:8443'
context = ssl.create_default_context(cafile='/etc/vram-governor/tls/controller.crt')


def get(path, headers=None):
    request = urllib.request.Request(base + path, headers=headers or {})
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        return response.read().decode()


html = get('/admin/')
asset = re.search(r'src="(/ui/assets/admin-[^\"]+\.js)"', html)
if not asset:
    raise SystemExit('admin entry script not found')
bundle = get(asset.group(1))
for marker in ('Loaded now', 'Externally managed runtime:', 'read-only loaded models are shown above'):
    if marker not in bundle:
        raise SystemExit('deployed UI missing marker: ' + marker)

values = dict(line.split('=', 1) for line in pathlib.Path('/root/vram-governor-controller-credentials.env').read_text().splitlines() if '=' in line)
overview = json.loads(get('/admin/api/overview', {'Authorization': 'Bearer ' + values['ADMIN_TOKEN']}))
matches = [target for target in overview['targets'] if target.get('id') == '780m-node-qwen-8095']
if len(matches) != 1:
    raise SystemExit('780m target not present')
target = matches[0]
if target.get('resident_models') != ['/root/models/Qwen3.8-9B-Q5_K_M.gguf'] or target.get('supports_model_lifecycle') is not False:
    raise SystemExit('780m resident model/control state mismatch')
for service in ('vram-governor-controller.service', 'lb-proxy.service'):
    if subprocess.check_output(['systemctl', 'is-active', service], text=True).strip() != 'active':
        raise SystemExit(service + ' is not active')
print('live model visibility verification passed')
