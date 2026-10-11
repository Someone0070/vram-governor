# Dedicated controller deployment

The separate controller/load-balancer machine runs the controller API, scheduler,
embedded UI, PostgreSQL authority, and migration tooling. It does not require
WSL and it does not run GPU inference. The RTX 3080, RTX 3090, and CMP170 hosts
run node agents and advertise their runtimes to this controller.

## Bundle path

Source files live in `deploy/controller/`. Build the distributable Linux
archive from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-controller-package.ps1 -Architecture amd64
```

The archive and SHA-256 sidecar are written to `.cache/releases/`. Transfer
both files to the dedicated controller machine and verify the checksum before
extracting the archive.

## Required infrastructure

- A dedicated Linux host with systemd; no NVIDIA runtime or WSL is required.
- PostgreSQL on that host. The template uses peer authentication for the
  `vram-governor` service user and database.
- An HTTPS S3-compatible artifact endpoint. Production mode intentionally
  rejects controller-local filesystem storage.
- A TLS certificate and private key for the controller's stable DNS name or IP.
- Stable LAN name resolution from all three GPU workers to the controller and
  from the controller to the managed CMP170 harness.

Clients use `https://<controller>:8443`; node agents use
`wss://<controller>:8443/ws/node`. Comfy MCP clients use that same controller
host and port with the dedicated MCP credential.

## Prepare credentials and configuration

Copy `controller.yaml.template` and `controller.env.example` to private files.
Replace every `__PLACEHOLDER__`. The installer and service preflight refuse to
start while any placeholder remains.

Generate a different high-entropy raw token for every credential. Put only its
SHA-256 digest in each `token_sha256` field, then deliver the corresponding raw
token to that one client or node through a private channel. For PowerShell:

```powershell
$raw = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($raw))).ToLower()
"raw token: $raw"
"token_sha256: $digest"
```

Set `__ADMIN_PRIVATE_CIDR__` to the narrow management subnet, not the entire
Internet. Keep OpenRouter disabled and quarantined until its exact free-model
allowlist and egress policy have been accepted. The environment file contains
service-to-service secrets and must remain root-readable.

## Install

On the controller host, from the extracted archive:

```bash
sudo ./install.sh
sudo install -m 0640 -o root -g vram-governor controller.crt /etc/vram-governor/tls/controller.crt
sudo install -m 0640 -o root -g vram-governor controller.key /etc/vram-governor/tls/controller.key
sudo ./install.sh --config /root/controller.yaml --environment-file /root/controller.env --no-start
sudo -u vram-governor /usr/local/libexec/vram-governor/apply-migrations.sh
sudo systemctl enable --now vram-governor-controller.service
```

The first installer call creates the service account and directories and
installs examples without starting anything. The configured call validates the
environment and application configuration before installation. Existing
configuration is timestamp-backed-up. `--upgrade` replaces program files while
preserving configuration and durable state.

## Verify and enroll nodes

```bash
sudo -u vram-governor /usr/local/libexec/vram-governor/validate-controller.sh
systemctl --no-pager --full status vram-governor-controller.service
curl --fail --cacert /etc/vram-governor/tls/controller.crt https://127.0.0.1:8443/healthz
journalctl -u vram-governor-controller.service -n 100 --no-pager
```

Install the node-agent bundle separately on each GPU worker. Use the matching
raw node token and the same node-command signing secret, and point every agent
at `wss://<controller>:8443/ws/node`. Confirm the three distinct accelerator
IDs in `/admin/` before enabling managed sharing or client cutover.

The managed CMP170 video target is static because it provides a cooperative
safe-boundary protocol. Native LLM and ComfyUI targets are discovered by their
node agents and must not be duplicated as static targets.

## Removal and recovery

`sudo ./uninstall.sh` disables the service and removes only installed program
files. It deliberately preserves `/etc/vram-governor`, TLS material,
PostgreSQL, installed migrations, and `/var/lib/vram-governor`. Back up the
database and controller configuration before upgrades; database rollback is a
snapshot restore, not reverse migration execution.
