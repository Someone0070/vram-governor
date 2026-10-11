#!/usr/bin/env python3
"""Briefly toggle only idle 780m scheduling via passwordless browser session."""

import http.cookiejar
import json
import pathlib
import ssl
import urllib.request
import uuid


base = 'https://10.0.0.115:8443'
context = ssl.create_default_context(cafile=str(pathlib.Path('.cache/controller-ca-cmp.pem')))
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(jar))

def request(path, payload=None, csrf=None, key=None):
    headers = {}
    if payload is not None:
        headers['Content-Type'] = 'application/json'
    if csrf:
        headers['X-CSRF-Token'] = csrf
    if key:
        headers['Idempotency-Key'] = key
    data = json.dumps(payload).encode() if payload is not None else None
    with opener.open(urllib.request.Request(base + path, data, headers), timeout=10) as response:
        return json.load(response)

session = request('/auth/session', {'token': '', 'kind': 'admin'})
csrf = session['csrf_token']
overview = request('/admin/api/overview')
node = next(row for row in overview['nodes'] if row['id'] == '780m-node')
if node['observed']['connectivity'] != 'connected' or node['scheduling_state'] != 'enabled':
    raise SystemExit('780m must be connected and enabled before safe toggle test')
if any(row['status'] in {'queued', 'waiting', 'admitted', 'starting', 'running', 'yielding', 'checkpointing'} for row in overview['workloads']):
    raise SystemExit('work is active; will not toggle scheduling')

path = '/admin/api/nodes/780m-node/scheduling'
try:
    disabled = request(path, {'state': 'disabled'}, csrf, str(uuid.uuid4()))
    if disabled['scheduling_state'] != 'disabled':
        raise SystemExit('controller did not disable 780m scheduling')
    print('browser_session_scheduling_disable=ok')
finally:
    enabled = request(path, {'state': 'enabled'}, csrf, str(uuid.uuid4()))
    if enabled['scheduling_state'] != 'enabled':
        raise SystemExit('CRITICAL: 780m scheduling was not restored')
print('browser_session_scheduling_restore=ok')
