# Connect GPU nodes to the dedicated LB

There is no separate admin password. The Fleet login normally accepts
`ADMIN_TOKEN` from `/root/vram-governor-controller-credentials.env` on
`10.0.0.115`. Read that file locally as root; do not copy the value into
tickets or chat. The admin session also opens Activity and Chat. A normal UI
session cannot open Fleet. For a temporary no-login Fleet UI, set
`auth.passwordless_admin_lan: true` in the controller YAML and restart the
controller. This issues ordinary admin browser sessions only to clients in
`auth.admin_private_cidrs`; it does not make the API or node channel anonymous.
Anyone on that management network can administer the fleet while enabled.
Set the flag back to `false` and restart to revoke these passwordless sessions.

The controller is `wss://10.0.0.115:8443/ws/node`. A TLS-only compatibility
listener at `wss://10.0.0.115:18082/ws/node` now forwards node WebSockets to
that same controller; it is **not** a separate governor or an alternative
admin/API port. Its `/healthz` is available for checks, while other HTTP paths
return 404. The old Comfy test script targeted `10.0.0.186:18082`, which is a
different machine and did not enroll a node with this LB. Verify the live
Machines tab rather than inferring enrollment from a healthy port.

As verified on 2026-09-14, the CMP host is `10.0.0.60`, its agent is upgraded
to 1.2.3, and `cmp170-node` is authenticated over the compatibility listener.
It uses the pinned LB certificate, the controller's pre-issued CMP identity,
and `dont_touch` power mode. The CMP smart plug remains telemetry-only. The
agent advertises one ComfyUI target, but ComfyUI itself currently listens only
on `127.0.0.1:8188`; the LB cannot route inference to that target until the
service has a controller-reachable endpoint and `comfyui.public_endpoint` is
updated accordingly. Do not confuse node connectivity with workload readiness.

Fleet control verification on 2026-09-14: signed `refresh_capabilities`
completed on both connected nodes, and a passwordless browser session toggled
the AMD `780m-node` scheduling OFF then back ON. These prove the browser/session
and signed command paths; they do **not** imply runtime lifecycle control.
`780m-node` currently advertises a direct, externally managed `llama-server`
with four 32k slots and no load/unload or runtime-profile switch. The CMP node
advertises ComfyUI cache reclaim but its public endpoint is loopback-only, and
the separate video worker is not represented as an active governor workload.
The Fleet UI therefore disables its misleading Drain button when no managed
model unload is available and shows the relevant limitation per machine. To
add model/slot controls, the runtime must be put behind an allowlisted managed
launcher or profile-switch harness; merely installing the node agent does not
grant authority to restart `llama-mtp.service` or replace a running model.

New nodes no longer need a controller-side credential edit or restart. The
reusable `FLEET_ENROLLMENT_TOKEN` authorizes a trusted machine to declare its
own ID; the controller returns a unique node-bound token and stores only its
hash. The node becomes active immediately. Fleet → Machines lists
self-enrolled identities and can revoke each one. Treat the enrollment token
as a fleet-wide join key and rotate it if exposed. A revoked ID cannot be
automatically reclaimed; use a new ID or coordinate recovery with an admin.

This is authenticated self-enrollment, not anonymous admission. An arbitrary
token will **not** work: the LB verifies its hash. The older 1.2.1 installer
does not have the fleet-enrollment option; use the 1.2.3 bundle. A non-TTY
install must receive `VRAM_ENROLLMENT_TOKEN` (new ID) **or** `VRAM_NODE_TOKEN`
(pre-issued ID), plus `VRAM_NODE_COMMAND_SECRET`, through a protected
environment or secret channel. Empty values cannot trigger hidden prompts in
a non-interactive SSH command. Do not put these values in command arguments,
chat, or shell history.

For an upgrade on a database that already has older tables, apply only the
new migration:

```bash
runuser -u vram-governor -- /usr/local/libexec/vram-governor/apply-migrations.sh --only 0017_node_enrollments.sql
```

The plain helper mode is for a fresh database and attempts every historical
migration.

These commands are for Linux GPU hosts (including WSL only when systemd and
network reachability are configured). The controller does not need inbound SSH
to the hosts: each agent opens an outbound WSS connection. The LB does need to
reach each advertised LLM/Comfy `public_endpoint` for inference.

## Prepare on the LB

As root on `10.0.0.115`, read
`/root/vram-governor-controller-credentials.env` locally. For each host, use
only its matching `RTX3080_NODE_TOKEN`, `RTX3090_NODE_TOKEN`, or
`CMP170_NODE_TOKEN`, plus the common `VRAM_NODE_COMMAND_SECRET`. Never paste
these into chat, shell history, or a shared file. The rebind helper and agent
archive are staged as:

```text
/root/rebind-node-agent-to-lb.sh
/root/vram-governor-node-agent-1.2.3-linux-amd64.tar.gz
/root/vram-governor-node-agent-1.2.3-linux-amd64.tar.gz.sha256
```

The same helper is in `scripts/rebind-node-agent-to-lb.sh` and the archive is
in `.cache/releases/` in this repository. Transfer the helper and archive to
each GPU host using your usual trusted file-transfer path. The current 1.2.4
archive SHA-256 is
`311f5b83343adfb96450039ad2cc0d506b76124d6dce2ed755cf3a6f8ca2d496`.
For example, from PowerShell in the repository root, if that host accepts SSH:

```powershell
scp .\scripts\rebind-node-agent-to-lb.sh .\.cache\releases\vram-governor-node-agent-1.2.4-linux-amd64.tar.gz <ssh-user>@<NODE_IP>:/tmp/
```

Then run the commands below from `/tmp` on the host. Use its actual SSH user
and LAN IP; no GPU-host address has been assumed by the LB deployment.

## Existing node-agent service

On each host, from the directory containing the transferred files:

```bash
sha256sum vram-governor-node-agent-1.2.4-linux-amd64.tar.gz
tar -xzf vram-governor-node-agent-1.2.4-linux-amd64.tar.gz
sudo bash vram-governor-node-agent-1.2.4-linux-amd64/install.sh --upgrade
sudo bash rebind-node-agent-to-lb.sh rtx3080-node
```

Replace `rtx3080-node` on the last line with exactly `rtx3090-node` or
`cmp170-node` on those hosts. The helper pins the actual LB certificate
fingerprint, verifies HTTPS, backs up the existing node YAML and environment,
changes the controller URL, node ID, and secret bindings, and restarts the
agent. It preserves existing LLM and Comfy discovery entries. It forces
`power_control_mode: dont_touch` on the CMP170 node; it does not toggle the
smart plug. At its hidden prompts, paste the matching node token and common
command-signing secret from the LB root-only file.

## Fresh node-agent service

First trust the pinned LB certificate, then run the packaged guided installer:

```bash
sudo bash rebind-node-agent-to-lb.sh --trust-only
tar -xzf vram-governor-node-agent-1.2.4-linux-amd64.tar.gz
cd vram-governor-node-agent-1.2.4-linux-amd64
sudo bash ./install.sh \
  --controller-url wss://10.0.0.115:8443/ws/node \
  --node-id rtx3080-node --node-name rtx3080 \
  --location local --power-mode manual
```

Use the matching ID/name for 3090. For CMP170, use `--node-id cmp170-node
--node-name cmp170 --power-mode dont_touch`. At the fleet enrollment prompt,
leave the value blank to enter the matching pre-issued node token, then the
common signing secret, without echo. For the 780m machine, use
`--node-id 780m-node` and `NODE_780M_TOKEN` from the LB root-only file. Add
`--comfy-endpoint http://127.0.0.1:8188 --comfy-public-endpoint
http://<NODE_LAN_IP>:8188` only if ComfyUI is already running and the LB can
reach its LAN address. Do not advertise `127.0.0.1` as the public endpoint.

For a new self-enrolled machine, copy
`/etc/vram-governor/tls/controller.crt` from the LB through a trusted channel
and verify its fingerprint. On the machine, unpack the current node-agent
bundle and run its installer as root with
`--controller-ca /path/to/controller.crt`,
`--controller-url wss://10.0.0.115:8443/ws/node`, and a new `--node-id` and
`--node-name`. At the hidden prompts, provide `FLEET_ENROLLMENT_TOKEN` and
`VRAM_NODE_COMMAND_SECRET` from the LB root-only credential file. The
installer saves the returned node-bound token in
`/etc/vram-governor/node-agent.env`, copies the controller certificate, and
starts the service. For a protected non-interactive environment, set
`VRAM_ENROLLMENT_TOKEN` and `VRAM_NODE_COMMAND_SECRET`. Never use `curl -k`
or paste these secrets into chat. The existing 3080/3090/CMP static tokens
remain valid; the separate pre-issued 780m token is also available.

A fresh install starts with `llamacpp.servers: []`; connection alone does not
advertise an LLM. After identifying a real llama.cpp-compatible server and
its reachable LAN endpoint, add it under `llamacpp.servers` in
`/etc/vram-governor/node-agent.yaml` using the relevant template in
`configs/fleet/`, then restart the agent. Do not copy template slot/context
figures as measured capacity without checking the runtime. Existing agent
configs keep their current runtime entries during rebind.
Follow [the existing llama.cpp server setup](llamacpp-node-setup.md) for the
exact discovery, YAML, verification, and managed-control requirements.

For the AMD 780M head node (`10.0.0.165`), agent 1.2.4 reads the Linux
AMDGPU sysfs counters when `nvidia-smi` is absent. The driver exposes
`mem_info_vram_total` and `mem_info_vram_used` in bytes; these are **unified
memory shared with host RAM**, not a separate 16 GiB GPU allocation. Fleet
labels this memory type accordingly. The [Linux kernel AMDGPU sysfs
documentation](https://docs.kernel.org/gpu/amdgpu/driver-misc.html) defines
those counters. The Qwen `:8095` route must be advertised only after its
`/v1/models` and `/slots` endpoints independently confirm its resident model,
context, and parallel slots. Leave context and slot fallback values unset in
the node YAML so a missing runtime measurement does not become a fabricated
4x32k guarantee.

The live 780m node advertises target `780m-node-qwen-8095` at
`http://10.0.0.165:8095` with resident model ID
`/root/models/Qwen3.8-9B-Q5_K_M.gguf`. The agent measures four 32768-token
slots from `/slots`; this target has no model-lifecycle or live context-switch
capability. Clients can query `GET /v1/models` on the LB and submit that model
to `POST /v1/chat/completions` at `https://10.0.0.115:8443` with an
inference-scoped bearer token. Four slots do not mean four *free* slots at
every instant, and the 16 GiB unified-memory figure is not dedicated VRAM.
The root-only `scripts/report-780m-node-live.py` and
`scripts/smoke-780m-qwen-through-lb.py` helpers are staged on the LB.

## CMP node: Comfy and LLM on one accelerator

The CMP node uses one physical accelerator identity,
`cmp170-node-gpu0`, for both targets. This makes scheduler leases,
interruptibility, and slowdown rules apply across LLM and video work. Two
unrelated public servers without that shared identity could double-book the
same GPU.

The deployed boundary is:

- raw ComfyUI, llama.cpp, and the managed harness listen only on CMP loopback
  ports `8188`, `8080`, and `8190`;
- `vram-governor-runtime-tunnel.service` creates encrypted reverse SSH
  forwards on LB loopback ports `9444` (managed Comfy) and `9445` (LLM);
- controller target `cmp170-video-managed` is enabled, while the discovered
  raw `cmp170-node-comfy` target is deliberately disabled;
- the llama.cpp router advertises its model directory with at most one
  resident model and is controlled through signed node commands. The install
  allowlist omits the Qwen 3.5 GGUF files rejected by the currently installed
  llama.cpp build instead of advertising known-unloadable models;
- root-owned systemd/Polkit allowlists expose only `ctx-8k-4`, `ctx-32k-1`,
  and `ctx-32k-2`. The last profile is available policy, not a promise that
  every temporarily installed GPU can fit every model at that capacity.

Adaptive sharing and guarded exploration are enabled on the managed Comfy and
LLM targets, but this does not blindly co-run unknown workloads. Both requests
must explicitly allow slowdown, standalone VRAM envelopes must be measured,
the composed envelope plus reserve must fit, and predicted slowdown must stay
under the target limit. Unknown combinations get only guarded exploration and
are rolled back on VRAM, slowdown, or thermal violations. Locked Comfy MCP
requests remain exclusive; advanced clients use the workload API to declare
slowdown/checkpoint interruptibility and priority.

Reusable deployment files live under `deploy/cmp-runtime/` and
`scripts/cmp-runtime/`. `install-cmp-runtime.sh` installs the harness, router
drop-in, profile allowlist, updated node agent, and tunnel service. Move the
managed-Comfy bearer only through the protected
`export-managed-comfy-token.py | install-managed-comfy-token.py` host-to-host
pipe; never place it on a command line or in chat. Authorize the generated
tunnel public key on the LB with `authorize-runtime-tunnel.sh`, pin the LB SSH
host key, start the tunnel, then configure the static controller target with
`configure-lb-managed-cmp.py`.

The Fleet **Models** tab shows the current resident model and provides direct
Load model, Unload model, and context/slot profile buttons. They use the same
signed node-command API as automation. Clients still use one endpoint,
`https://10.0.0.115:8443`; Comfy MCP clients use `/prompt`, `/history`,
`/queue`, and `/ws`.

## Verify

On each GPU host:

```bash
systemctl is-active vram-governor-node-agent.service
journalctl -u vram-governor-node-agent.service -n 60 --no-pager
curl --fail https://10.0.0.115:8443/healthz
```

On the LB, log into `https://10.0.0.115:8443/admin/` with the `ADMIN_TOKEN`
from its root-only credential file and confirm each distinct node ID is
connected with its intended accelerator and runtime targets. The LB can be
healthy while zero nodes are connected; that is not an inference-ready fleet.
