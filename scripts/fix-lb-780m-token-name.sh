#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || exit 1
python3 - <<'PY'
import os, pathlib, tempfile
path = pathlib.Path('/root/vram-governor-controller-credentials.env')
source = path.read_text(encoding='utf-8')
old = '780M_NODE_TOKEN='
new = 'NODE_780M_TOKEN='
if source.count(old) != 1 or new in source:
    raise SystemExit('unexpected token key state')
fd, temp = tempfile.mkstemp(prefix='.node-token-', dir=str(path.parent))
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(source.replace(old, new, 1))
    os.replace(temp, path)
except BaseException:
    try: os.unlink(temp)
    except FileNotFoundError: pass
    raise
print('Renamed 780m credential key; token value preserved.')
PY
