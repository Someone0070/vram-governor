# Add an existing llama.cpp server to the LB

This is the repeatable setup for a node that **already runs** `llama-server`.
The node agent discovers and advertises that server; it does not install it,
own its systemd unit, or gain model/slot controls merely by connecting. Use
[Connect GPU nodes to the dedicated LB](connect-gpu-nodes-to-lb.md) first to
install and enroll the agent. Keep credentials in the root-protected agent
environment file, never in the YAML or a shell command line.

## 1. Confirm the running server

On the GPU host, identify the service/process that owns the port and check
its actual model and capacity. Substitute the local port as needed:

```bash
systemctl status YOUR_LLAMA_SERVICE.service --no-pager
curl --fail --silent http://127.0.0.1:8095/health
curl --fail --silent http://127.0.0.1:8095/v1/models
curl --fail --silent http://127.0.0.1:8095/slots
```

Record the exact model ID from `/v1/models`, the number of `/slots` entries,
and each entry's `n_ctx`. A healthy server is not enough: if `/slots` is
missing, the LB cannot call its capacity runtime-verified. Do not copy a slot
or context number from an example and present it as a measurement. Confirm
the LB can reach the host's LAN endpoint; `127.0.0.1` is local to each machine
and cannot be the controller-facing address. Restrict the runtime port to
the trusted LAN/controller; this path does not add backend authentication.

## 2. Advertise the existing server

Back up `/etc/vram-governor/node-agent.yaml` on the GPU host. Add one entry
under `llamacpp.servers` (replace addresses, ID, and accelerator index):

```yaml
llamacpp:
  servers:
    - id: "qwen-8095"
      endpoint: "http://127.0.0.1:8095"
      public_endpoint: "http://10.0.0.165:8095"
      accelerator_index: 0
      router_managed: false
      max_resident_models: 1
```

Leave `context_limit`, `slots`, and `runtime_profiles` unset for a fixed
server. Discovery will fill context and slots from `/slots`; a missing or
unreachable measurement must be fixed at the runtime, not hidden with a
fallback. `router_managed: false` is important: setting it to `true` does
not install `/models/load` or `/models/unload` on a standalone server.

Restart only `vram-governor-node-agent.service` after editing its YAML. This
does **not** restart the model server. In the LB admin **Machines** page,
confirm the node and target are connected; in **Models > Loaded now**, confirm
the exact model is shown. The target should report `capacity_source` as
`runtime:/slots` and `capacity_verified: true`. On the LB, `GET /v1/models`
should include the exact model ID and current capacity metadata. A small
request through `POST /v1/chat/completions` proves routing end to end.

## 3. Understand which controls are available

| Server mode | LB can observe and route | LB can load/unload | LB can change slots/context |
| --- | --- | --- | --- |
| Fixed standalone `llama-server` | Yes, after discovery | No | No |
| Lifecycle-capable Ollama/router | Yes | Only after its protocol is verified and allowlisted | Only with verified, locally configured profiles |
| Agent-managed fixed service | Yes | Requires a service-control implementation | Requires fixed profile commands and runtime confirmation |

The current 780M host is the **first row**. Its `llama-mtp.service` starts
`/root/run_mtp.sh` with one Qwen model, `--ctx-size 131072`, and
`--parallel 4`; `/slots` currently reports four 32768-token slots. The
loaded model is visible in Models, but no load/unload or profile-switch
command has been installed for that service. The node's power mode remains
`dont_touch`; model setup does not control the smart plug.

Changing that fixed service manually is maintenance: first stop new LB
admissions and wait for active LB **and direct-to-runtime** clients to finish,
then change its root-owned startup configuration, restart the runtime, check
`/health`, `/v1/models`, and every `/slots` entry, and refresh node
capabilities. A restart clears in-memory state and temporarily interrupts the
port. Do not treat this as a live slot slider or promise zero downtime.

## 4. Requirements before enabling managed switching

The node-agent code already understands signed `switch_runtime_profile`
commands with a local, fixed `switch_command` per allowlisted profile. To
make that safe for a **particular** llama.cpp service, install and test a
root-owned switch helper that refuses unknown models/profiles, checks for
active work, changes only that service's configuration, restarts it, verifies
the measured model/slots/context, and rolls back on failure. The controller
must drain or queue new work while the physical accelerator is switching.
Only then add measured `runtime_profiles` to the node YAML and expose those
profiles to clients. See [Runtime context and slot profiles](ollama-multi-profile.md)
for the existing Ollama-oriented example; its scripts are **not** a tested
installer for `llama-mtp.service`.

Model load/unload is a separate capability. The current node command expects
an actual lifecycle protocol (Ollama or `/models/load` and
`/models/unload` on an allowlisted router). A standalone fixed server does
not provide one, so either deploy and verify a suitable managed runtime or
implement an explicit signed service/model-switch operation with the same
drain, allowlist, verification, and rollback rules. Do not flip
`router_managed` to make the UI show nonfunctional controls.

Future node acceptance is complete only when the exact model, verified
capacity, available controls, and a successful LB request all agree. If a
node is connected with zero targets, it is enrolled but not inference-ready.
