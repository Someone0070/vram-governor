#!/usr/bin/env python3
"""Check that the LB serves the corrected Fleet UI, without login secrets."""

import re
import ssl
import urllib.request


base = 'https://10.0.0.115:8443'
context = ssl.create_default_context(cafile='.cache/controller-ca-cmp.pem')
with urllib.request.urlopen(base + '/admin/', context=context, timeout=10) as response:
    html = response.read().decode()
match = re.search(r'/ui/assets/admin-[A-Za-z0-9_-]+\.js', html)
if not match:
    raise SystemExit('admin app bundle not found')
with urllib.request.urlopen(base + match.group(), context=context, timeout=10) as response:
    script = response.read().decode()
for marker in ('No safe managed model unload is available on this node',
               'advertises a loopback endpoint',
               'cannot load, unload, or resize its runtime process yet'):
    if marker not in script:
        raise SystemExit('updated Fleet control text is missing')
print('live_fleet_ui_clarity_verified=True')
