#!/usr/bin/env bash
# One-time, dedicated 10.0.0.115 controller provisioning. Run as root on that LB.
# Does not install or modify GPU workers, the old proxy, or any smart-plug relay.
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo 'root required' >&2; exit 1; }
bundle=/root/vram-governor-controller-1.2.1-linux-amd64
garage_binary=/root/garage-v2.4.1
garage_sha=ae49f8de4aaee6b5ca305f7cbdccc8cd8a29b2804aac074649f18bfb83d0a2b6
[[ -f "$bundle/controller.yaml.template" && -x "$bundle/install.sh" ]] || { echo 'staged controller bundle missing' >&2; exit 1; }
[[ -f "$garage_binary" ]] || { echo 'staged Garage binary missing' >&2; exit 1; }
printf '%s  %s\n' "$garage_sha" "$garage_binary" | sha256sum --check --status
[[ ! -e /etc/vram-governor/controller.yaml && ! -e /etc/vram-governor/controller.env ]] || {
  echo 'controller already configured; refusing credential rotation' >&2; exit 1;
}
[[ ! -e /etc/garage/garage.toml && ! -e /etc/garage/garage.env ]] || {
  echo 'Garage already configured; refusing credential rotation' >&2; exit 1;
}
[[ $(readlink /etc/nginx/sites-enabled/default) == /etc/nginx/sites-available/default ]] || {
  echo 'unexpected nginx default site; inspect manually' >&2; exit 1;
}

getent group garage >/dev/null || groupadd --system garage
id garage >/dev/null 2>&1 || useradd --system --gid garage --home-dir /var/lib/garage --shell /usr/sbin/nologin garage
install -m 0755 "$garage_binary" /usr/local/bin/garage
install -d -m 0750 -o root -g garage /etc/garage
install -d -m 0750 -o root -g www-data /etc/garage/tls
install -d -m 0750 -o garage -g garage /var/lib/garage /var/lib/garage/meta /var/lib/garage/data
install -d -m 0755 /etc/systemd/system/vram-governor-controller.service.d

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -subj /CN=127.0.0.1 -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout /etc/garage/tls/s3.key -out /etc/garage/tls/s3.crt >/dev/null 2>&1
chown root:www-data /etc/garage/tls/s3.key /etc/garage/tls/s3.crt
chmod 0640 /etc/garage/tls/s3.key /etc/garage/tls/s3.crt
install -m 0644 /etc/garage/tls/s3.crt /usr/local/share/ca-certificates/vram-governor-garage.crt
update-ca-certificates >/dev/null

python3 - "$bundle/controller.yaml.template" <<'PY'
import hashlib
import os
import pathlib
import re
import secrets
import sys

def create(path, content, mode=0o640):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(content)

tokens = {name: secrets.token_urlsafe(36) for name in (
    'RTX3080_NODE', 'RTX3090_NODE', 'CMP170_NODE', 'INTERACTIVE_UI',
    'WORKFLOW', 'COMFY_MCP', 'SYSTEM_AGENT', 'ADMIN', 'FLEET_ENROLLMENT', 'NODE_780M')}
command_secret = secrets.token_urlsafe(48)
s3_access = 'GK' + secrets.token_hex(16)
s3_secret = secrets.token_hex(32)
rpc_secret = secrets.token_hex(32)
source = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')
replacements = {
    '__ADMIN_PRIVATE_CIDR__': '10.0.0.0/24',
    '__S3_HTTPS_ENDPOINT__': 'https://127.0.0.1:9443',
    '__S3_BUCKET__': 'vram-artifacts',
    '__S3_REGION__': 'garage',
    '__CMP170_MANAGED_HTTPS_ENDPOINT__': 'https://127.0.0.1:9444',
    '__CMP170_VIDEO_MODEL__': 'not-enrolled',
    '__OPENROUTER_MODEL__': 'not-configured',
    '__OPENROUTER_PROVIDER__': 'not-configured',
}
for name, value in tokens.items():
    replacements['__' + name + '_TOKEN_SHA256__'] = hashlib.sha256(value.encode()).hexdigest()
for key, value in replacements.items():
    if key not in source:
        raise RuntimeError('missing template key: ' + key)
    source = source.replace(key, value)
source = source.replace('      enabled: true\n    - id: "openrouter-safety-net"',
                        '      enabled: false\n    - id: "openrouter-safety-net"')
if re.search(r'__[A-Z0-9_]+__', source):
    raise RuntimeError('unrendered controller placeholder')
if 'url: "http://10.0.0.222"\n    control_enabled: false' not in source:
    raise RuntimeError('CMP170 read-only plug guard missing')
if 'id: "cmp170-video-managed"' not in source or '      enabled: false\n    - id: "openrouter-safety-net"' not in source:
    raise RuntimeError('unverified managed target not disabled')
create('/etc/vram-governor/controller.yaml', source)
controller_env = '\n'.join([
    'VRAM_NODE_COMMAND_SECRET=' + command_secret,
    'VRAM_S3_ACCESS_KEY=' + s3_access,
    'VRAM_S3_SECRET_KEY=' + s3_secret,
    'VRAM_S3_SESSION_TOKEN=',
    'VRAM_MANAGED_COMFY_AUTHORIZATION=',
    'OPENROUTER_AUTHORIZATION=',
    'VRAM_WEBHOOK_SIGNING_SECRET=',
]) + '\n'
create('/etc/vram-governor/controller.env', controller_env)
garage_env = '\n'.join([
    'GARAGE_CONFIG_FILE=/etc/garage/garage.toml',
    'GARAGE_DEFAULT_ACCESS_KEY=' + s3_access,
    'GARAGE_DEFAULT_SECRET_KEY=' + s3_secret,
    'GARAGE_DEFAULT_BUCKET=vram-artifacts',
]) + '\n'
create('/etc/garage/garage.env', garage_env)
garage_config = '\n'.join([
    'metadata_dir = "/var/lib/garage/meta"',
    'data_dir = "/var/lib/garage/data"',
    'db_engine = "sqlite"',
    'replication_factor = 1',
    'rpc_bind_addr = "127.0.0.1:3901"',
    'rpc_public_addr = "127.0.0.1:3901"',
    'rpc_secret = "' + rpc_secret + '"',
    '[s3_api]',
    's3_region = "garage"',
    'api_bind_addr = "127.0.0.1:3900"',
]) + '\n'
create('/etc/garage/garage.toml', garage_config)
operator = '\n'.join(name + '_TOKEN=' + value for name, value in tokens.items())
operator += '\nVRAM_NODE_COMMAND_SECRET=' + command_secret + '\n'
create('/root/vram-governor-controller-credentials.env', operator, 0o600)
PY

chown root:vram-governor /etc/vram-governor/controller.yaml /etc/vram-governor/controller.env
chown root:garage /etc/garage/garage.toml /etc/garage/garage.env
chmod 0640 /etc/vram-governor/controller.yaml /etc/vram-governor/controller.env /etc/garage/garage.toml /etc/garage/garage.env

python3 - <<'PY'
from pathlib import Path
Path('/etc/systemd/system/vram-garage.service').write_text('''[Unit]
Description=Private Garage artifact store for VRAM Governor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=garage
Group=garage
EnvironmentFile=/etc/garage/garage.env
ExecStart=/usr/local/bin/garage server --single-node --default-bucket
Restart=on-failure
RestartSec=3
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/garage
RestrictSUIDSGID=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
''')
Path('/etc/nginx/sites-available/vram-garage').write_text('''server {
    listen 127.0.0.1:9443 ssl;
    server_name 127.0.0.1;
    ssl_certificate /etc/garage/tls/s3.crt;
    ssl_certificate_key /etc/garage/tls/s3.key;
    client_max_body_size 8G;
    location / {
        proxy_pass http://127.0.0.1:3900;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_request_buffering off;
        proxy_read_timeout 600s;
    }
}
''')
Path('/etc/systemd/system/vram-governor-controller.service.d/artifact-store.conf').write_text('''[Unit]
Requires=vram-garage.service nginx.service
After=vram-garage.service nginx.service
''')
PY

unlink /etc/nginx/sites-enabled/default
ln -s /etc/nginx/sites-available/vram-garage /etc/nginx/sites-enabled/vram-garage
nginx -t
systemctl daemon-reload
systemctl enable --now vram-garage.service
systemctl enable --now nginx.service
runuser -u vram-governor -- /usr/local/libexec/vram-governor/validate-controller.sh
systemctl enable --now vram-governor-controller.service
echo 'LB provisioning completed; run independent HTTPS, S3 round-trip, and auth checks.'
