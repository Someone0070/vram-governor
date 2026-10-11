#!/usr/bin/env bash
# One-time credential addition on the dedicated LB. Never prints bearer tokens.
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo 'root required' >&2; exit 1; }
python3 - <<'PY'
import hashlib
import os
import pathlib
import secrets
import shutil
import tempfile
from datetime import datetime, timezone

config = pathlib.Path('/etc/vram-governor/controller.yaml')
credentials = pathlib.Path('/root/vram-governor-controller-credentials.env')
source = config.read_text(encoding='utf-8')
existing = credentials.read_text(encoding='utf-8')
if '    - id: "780m-node"' in source or '    - id: "fleet-enrollment"' in source:
    raise SystemExit('credentials already configured; refusing partial rotation')
if 'NODE_780M_TOKEN=' in existing or 'FLEET_ENROLLMENT_TOKEN=' in existing:
    raise SystemExit('root credential file already has new tokens')
anchor = '    - id: "interactive-ui"'
if source.count(anchor) != 1 or '    - id: "cmp170-node"' not in source:
    raise SystemExit('unexpected controller credential layout')
tokens = {'NODE_780M_TOKEN': secrets.token_urlsafe(36), 'FLEET_ENROLLMENT_TOKEN': secrets.token_urlsafe(36)}
def digest(name): return hashlib.sha256(tokens[name].encode()).hexdigest()
addition = '''    - id: "780m-node"
      token_sha256: "{}"
      plane: "node"
      owner_id: "system"
      node_id: "780m-node"
      scopes: ["node:connect", "node:report"]
      adapters: ["llamacpp", "comfy"]
      max_priority: 0
      egress_policy: "local_only"
    - id: "fleet-enrollment"
      token_sha256: "{}"
      plane: "enrollment"
      owner_id: "system"
      scopes: ["node:enroll"]
      adapters: []
      max_priority: 0
      egress_policy: "local_only"
'''.format(digest('NODE_780M_TOKEN'), digest('FLEET_ENROLLMENT_TOKEN'))
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
for path in (config, credentials): shutil.copy2(path, str(path) + '.' + stamp + '.bak')
def replace(path, content):
    fd, temp = tempfile.mkstemp(prefix='.enrollment-', dir=str(path.parent))
    try:
        os.fchmod(fd, path.stat().st_mode & 0o777)
        os.fchown(fd, path.stat().st_uid, path.stat().st_gid)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream: stream.write(content)
        os.replace(temp, path)
    except BaseException:
        try: os.unlink(temp)
        except FileNotFoundError: pass
        raise
replace(credentials, existing.rstrip('\n') + '\n' + ''.join(name + '=' + token + '\n' for name, token in tokens.items()))
replace(config, source.replace(anchor, addition + anchor))
print('Added scoped 780m and fleet-enrollment credential hashes; raw values are in the root-only credential file.')
PY
