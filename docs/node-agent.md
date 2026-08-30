# Node agent

The node agent opens the controller's `/ws/node` WebSocket outbound, registers
its node identity, and sends heartbeat and nvidia-smi telemetry at the
configured interval. A stable connection resets reconnect backoff; short-lived
connections do not. A failed telemetry sample is skipped so it cannot erase
the controller's last known accelerator inventory.

The bearer credential is scoped to `node:connect`/`node:report` and may be
bound to exactly one node ID. The controller applies that binding to both the
WebSocket and HTTP runtime/profile reports. `wss://` production connections
require `token_env` and a 32-byte-or-longer secret supplied through
`command_signing_secret_env`.

Controller commands carry a node binding, issue/expiry time, idempotency key,
and HMAC signature. The agent durably remembers completed command IDs and
accepts only capability refresh, model load/unload, and accelerator-cache drain operations;
late, replayed, cross-node, unsigned, or unknown commands are rejected.

## Existing llama.cpp discovery

Each `llamacpp.servers` entry identifies an already-running llama-server and
its accelerator index. At registration and every
`capability_refresh_seconds`, the agent reads `/v1/models` and `/slots` to
report model identity, the configured per-slot context, parallel slot count,
busy slots, and a capability fingerprint. `/props`, `context_limit`, and
`slots` are conservative fallbacks for older or locked-down servers. The
advertisement records its source and is marked verified only when `/slots`
supplies both context and slot capacity.

Runtime target IDs are namespaced by node at the controller, so one node
cannot replace another node's target by advertising the same local ID.

## External ComfyUI discovery

When `comfyui.endpoint` is configured, the agent reads the existing server's
`/object_info`, `/system_stats`, and `/queue` endpoints during registration.
It advertises:

- its controller-reachable endpoint and accelerator index;
- installed checkpoint names and node classes;
- ComfyUI version and current queue counts.

Discovery failure does not stop heartbeat service. The control protocol has no
operation for installing custom nodes or changing the external server.

## Still outside the node agent

The llama.cpp runtime driver and measurement probe remain available to the
on-demand probe command. Runtime discovery does not install a server. General
runtime installation/upgrade, process launch, and physical power control stay
outside this release. Model residency and accelerator-cache drain execute on
the owning node; scheduler enable/disable remains authoritative controller
state.

## Durable installation package

Build a self-contained Linux archive on the controller workstation:

```powershell
.\scripts\build-node-agent-package.ps1 -Architecture amd64
```

The archive and SHA-256 sidecar are written to `.cache/releases`. Copy the
archive to a node, extract it, and run `sudo bash ./install.sh`. The guided installer
checks controller and optional ComfyUI reachability, reads secrets without
echo, creates an unprivileged service identity, stores secrets separately from
the YAML, and enables the hardened systemd unit. `sudo bash ./install.sh
--upgrade` replaces only the binary and unit while preserving configuration;
a full reinstall backs up the prior configuration.

The installer places the binary in `/usr/local/bin`, root-owned configuration
in `/etc/vram-governor`, and durable command replay state in
`/var/lib/vram-governor`. `uninstall.sh` preserves that state by default;
`uninstall.sh --purge` explicitly removes it. Each node still requires its own
controller-issued credential and command-signing secret. Signed commands are
restricted to the compiled allowlist; arbitrary shell execution and
software/model installation are intentionally absent.

Validate a built amd64 archive in Linux or WSL with:

```bash
./scripts/verify-node-agent-package.sh .cache/releases/vram-governor-node-agent-1.1.0-linux-amd64.tar.gz
```
