#!/usr/bin/env python3
"""Verify the temporary Fleet login without printing cookies or CSRF secrets."""

import http.cookiejar
import json
import pathlib
import ssl
import urllib.error
import urllib.request


base = 'https://10.0.0.115:8443'
ca = pathlib.Path('.cache/controller-ca-cmp.pem')
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
    urllib.request.HTTPCookieProcessor(jar),
)

def post_login(kind):
    payload = json.dumps({'token': '', 'kind': kind}).encode()
    request = urllib.request.Request(base + '/auth/session', payload, {'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, {}

status, result = post_login('admin')
assert status == 200 and result.get('principal', {}).get('id') == 'lan-passwordless-admin'
assert result.get('csrf_token') and any(cookie.name == 'vg_admin_session' for cookie in jar)
with opener.open(base + '/admin/api/overview', timeout=10) as response:
    assert response.status == 200
    assert 'nodes' in json.load(response)
print('passwordless_admin_lan_login=ok')
print('admin_session_overview=ok')

status, _ = post_login('ui')
assert status == 401, status
print('blank_ui_login=denied')

anonymous = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
)
try:
    anonymous.open(base + '/admin/api/overview', timeout=10)
except urllib.error.HTTPError as error:
    assert error.code == 401, error.code
else:
    raise AssertionError('anonymous admin API was not denied')
print('anonymous_admin_api=denied')
