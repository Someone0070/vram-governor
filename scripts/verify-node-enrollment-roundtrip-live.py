#!/usr/bin/env python3
"""Live enrollment/revocation round-trip; removes only its own unregistered smoke identity."""
import json
import pathlib
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

values = dict(line.split('=', 1) for line in pathlib.Path('/root/vram-governor-controller-credentials.env').read_text().splitlines() if '=' in line)
context = ssl.create_default_context(cafile='/etc/vram-governor/tls/controller.crt')
node_id = 'lb-smoke-' + secrets.token_hex(6)
base = 'https://10.0.0.115:8443'

def call(path, method, token, body=None):
    headers = {'Authorization': 'Bearer ' + token}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(base + path, method=method, headers=headers, data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()

created = False
try:
    status, payload = call('/api/v1/nodes/enroll', 'POST', values['FLEET_ENROLLMENT_TOKEN'], {'node_id': node_id, 'node_name': 'Ephemeral LB smoke test'})
    assert status == 201, f'enrollment HTTP {status}'
    created = True
    node_token = json.loads(payload)['node_token']
    assert len(node_token) == 64
    if '--restart' in sys.argv:
        subprocess.run(['systemctl', 'restart', 'vram-governor-controller.service'], check=True)
        for attempt in range(20):
            try:
                with urllib.request.urlopen(base + '/healthz', context=context, timeout=2) as response:
                    if response.status == 200: break
            except (urllib.error.URLError, TimeoutError):
                time.sleep(0.25)
        else:
            raise RuntimeError('controller did not become healthy after restart')
    assert call('/nodes/' + node_id + '/engines', 'POST', node_token, 'invalid engine body')[0] == 400
    assert call('/nodes/another-node/engines', 'POST', node_token, 'invalid engine body')[0] == 403
    assert call('/admin/api/node-enrollments/' + node_id + '/revoke', 'POST', values['ADMIN_TOKEN'])[0] == 200
    assert call('/nodes/' + node_id + '/engines', 'POST', node_token, 'invalid engine body')[0] == 401
    print('Live self-enrollment, persistence, node binding, and immediate revocation verified.')
finally:
    if created:
        # The smoke identity never registered a node or reported an engine.
        result = subprocess.run(['runuser', '-u', 'vram-governor', '--', 'psql', 'postgresql:///vram_governor?host=/var/run/postgresql', '-v', 'ON_ERROR_STOP=1', '-qAt', '-c', "DELETE FROM node_enrollments WHERE node_id='" + node_id + "' AND node_name='Ephemeral LB smoke test'"], capture_output=True, text=True, check=True)
        assert result.stderr == ''
