#!/usr/bin/env python3
"""Read-only live auth smoke test, except rejected malformed enrollment calls."""
import hashlib
import http.cookiejar
import json
import pathlib
import ssl
import urllib.error
import urllib.request

base = 'https://10.0.0.115:8443'
values = {}
for line in pathlib.Path('/root/vram-governor-controller-credentials.env').read_text().splitlines():
    if '=' in line:
        key, value = line.split('=', 1)
        values[key] = value
for name in ('ADMIN_TOKEN', 'NODE_780M_TOKEN', 'FLEET_ENROLLMENT_TOKEN'):
    assert len(values[name]) >= 32
config = pathlib.Path('/etc/vram-governor/controller.yaml').read_text()
for name in ('NODE_780M_TOKEN', 'FLEET_ENROLLMENT_TOKEN'):
    assert hashlib.sha256(values[name].encode()).hexdigest() in config
context = ssl.create_default_context(cafile='/etc/vram-governor/tls/controller.crt')

def call(path, method='GET', token=None, body=None, opener=None):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if body is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
    try:
        response = (opener.open(req, timeout=10) if opener else urllib.request.urlopen(req, context=context, timeout=10))
        with response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()

assert call('/api/v1/nodes/enroll', 'POST', body={'node_id': 'invalid', 'node_name': 'bad'})[0] == 401
assert call('/api/v1/nodes/enroll', 'POST', values['FLEET_ENROLLMENT_TOKEN'], {'node_id': '../invalid', 'node_name': 'bad'})[0] == 400
assert call('/admin/api/node-enrollments', token=values['FLEET_ENROLLMENT_TOKEN'])[0] == 403
status, data = call('/admin/api/node-enrollments', token=values['ADMIN_TOKEN'])
assert status == 200 and isinstance(json.loads(data)['nodes'], list)
assert call('/nodes', token=values['NODE_780M_TOKEN'])[0] == 403

cookies = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies), urllib.request.HTTPSHandler(context=context))
status, login = call('/auth/session', 'POST', body={'token': values['ADMIN_TOKEN'], 'kind': 'admin'}, opener=opener)
assert status == 200 and json.loads(login)['csrf_token']
assert call('/admin/api/overview', opener=opener)[0] == 200
status, identity = call('/auth/whoami', opener=opener)
assert status == 200 and json.loads(identity)['plane'] == 'admin'
assert call('/api/v1/workloads', opener=opener)[0] == 200
assert call('/admin/', opener=opener)[0] == 200
assert call('/studio/', opener=opener)[0] == 200
assert call('/chat/', opener=opener)[0] == 200
print('Admin across tabs, 780m scope, enrollment authorization, and hash-only config verified.')
