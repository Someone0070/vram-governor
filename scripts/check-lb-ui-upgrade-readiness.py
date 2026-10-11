#!/usr/bin/env python3
"""Abort a controller UI upgrade while nonterminal work is in flight."""

import json
import pathlib
import ssl
import urllib.request

values = dict(line.split('=', 1) for line in pathlib.Path('/root/vram-governor-controller-credentials.env').read_text().splitlines() if '=' in line)
request = urllib.request.Request('https://10.0.0.115:8443/admin/api/overview', headers={'Authorization': 'Bearer ' + values['ADMIN_TOKEN']})
context = ssl.create_default_context(cafile='/etc/vram-governor/tls/controller.crt')
with urllib.request.urlopen(request, context=context, timeout=10) as response:
    overview = json.load(response)
active = [row for row in overview['workloads'] if row['status'] not in {'succeeded', 'failed', 'cancelled', 'rejected'}]
print('active_workloads=' + str(len(active)))
if active:
    raise SystemExit('controller restart deferred: in-flight workloads present')
print('ui_upgrade_ready=True')
