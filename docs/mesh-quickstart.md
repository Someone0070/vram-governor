# Clone-to-mesh setup

Publication status: this installer is currently in the local worktree, not on
GitHub `main`. The clone commands below become usable only after a reviewed
commit containing this installer and its dependent controller/node changes is
pushed. Do not expect the current remote checkout to contain `install-mesh.sh`.

This is the short path for Linux/systemd hosts. There are **three roles**:
the dedicated LB/controller (for example `10.0.0.115`), the always-on head
GPU node (for example the separate 780M machine at `10.0.0.165`), and slave
GPU nodes (3080/3090/CMP rigs). Both GPU roles run the node agent and open an
outbound WSS connection to the LB. Enrollment returns a unique node-bound
credential; the LB does not SSH into the GPU machines.

## What is automated

`install-mesh.sh` lets you select **LB**, **Head GPU node**, or **Slave GPU
node**, builds the
appropriate Go binary from the checked-out source, and invokes the existing
package installer. It preserves installed configuration on `--upgrade` and
refuses an accidental fresh-install overwrite. A GPU-node join bundle carries
the controller certificate and the existing fleet-enrollment and signed-command
secrets without putting them in command arguments. The head defaults to
`location=local` and `power_mode=dont_touch`; a slave defaults to
`location=remote` and `power_mode=manual`. Override those deliberately for
machines such as the CMP rig that must never be power-cycled by the LB.

It does **not** yet provision PostgreSQL, an HTTPS S3-compatible artifact
store, DNS, or a production TLS identity. Those are required for a fresh
controller and depend on the host/network. A fresh controller still needs
prepared YAML and environment files; see
[Dedicated controller deployment](dedicated-controller-deployment.md).
`--dry-run` checks role selection and worker-bundle fingerprint without
building, installing, or starting a service.

## Install or upgrade the dedicated LB

On the controller Linux host, use a trusted GitHub clone or an archive of the
intended commit. Review the checkout before running as root:

```bash
git clone https://github.com/Someone0070/vram-governor.git
cd vram-governor
sudo bash ./install-mesh.sh --role lb --config /root/controller.yaml --environment-file /root/controller.env
```

The interactive form is `sudo bash ./install-mesh.sh`; select **Dedicated LB** and
give those two paths. The existing controller installer validates the files
and service prerequisites. If TLS has not already been installed at the paths
in the controller YAML, add `--tls-cert /root/controller.crt --tls-key
/root/controller.key` to install a supplied pair at the standard paths. The
wrapper applies the historical migrations automatically **only** when the
configuration uses the documented local PostgreSQL URL and the database has
no `nodes` table. Otherwise it leaves the service stopped for a reviewed
migration procedure. For a configured controller, update the checkout and use:

```bash
sudo bash ./install-mesh.sh --role lb --upgrade
```

An upgrade preserves `/etc/vram-governor`, PostgreSQL, TLS files, and durable
state. Take normal backups before upgrading. It does not update or enroll
workers automatically.

## Prepare a GPU-node join bundle

On the controller, once the fleet-enrollment credential is configured and the
controller certificate is in place:

```bash
sudo bash ./scripts/create-node-join-bundle.sh \
  --output /root/lb-worker-join \
  --controller-url wss://CONTROLLER_HOST:8443/ws/node
```

The script reads the root-only controller credential file by default. It
prints the SHA-256 **file digest** of `controller-ca.pem`, but never prints the
enrollment or command secret. Transfer the bundle to the worker via trusted
SSH/SCP or equivalent, preserving private permissions. Communicate/verify the
file digest through a separate trusted channel (this is not the X.509 DER
fingerprint printed by `openssl x509 -fingerprint`). The bundle contains a
fleet-wide join key: keep it out of Git/chat and rotate that key if exposed.

## Join the head or a slave GPU node

On each Linux GPU/compute host:

```bash
git clone https://github.com/Someone0070/vram-governor.git
cd vram-governor
sudo bash ./install-mesh.sh --role head \
  --join-bundle /root/lb-worker-join \
  --expected-fingerprint CERTIFICATE_SHA256 \
  --node-id UNIQUE_NODE_ID \
  --node-name DISPLAY_NAME
```

For a slave, use `--role slave` and a unique ID/name. For the CMP rig, also
pass `--power-mode dont_touch`. The interactive form is
`sudo bash ./install-mesh.sh`; select **Head GPU node** or **Slave GPU node**,
then
enter the bundle path and independently checked fingerprint. The existing
node-agent installer verifies controller HTTPS, self-enrolls with a unique
node-bound token, stores it under `/etc/vram-governor`, and starts the service.
Reusing a revoked ID requires operator recovery or a new ID. For an installed
worker, update the checkout and run:

```bash
sudo bash ./install-mesh.sh --role head --upgrade
```

Use `--role slave --upgrade` on a slave. The older `controller` and `worker`
role names are accepted as aliases for `lb` and `slave`.

The GPU node's runtime still needs to be configured or discovered. Joining the
mesh does not magically install ComfyUI/llama.cpp or declare an unavailable
model. If ComfyUI is already running, provide `--comfy-endpoint` and a
controller-reachable `--comfy-public-endpoint` on first install; never
advertise `127.0.0.1` as a remote public endpoint. See
[Connect GPU nodes](connect-gpu-nodes-to-lb.md) and
[existing llama.cpp server setup](llamacpp-node-setup.md) for runtime setup.

This is not yet a fully automatic greenfield LB installer: PostgreSQL,
production artifact storage, TLS identity, controller configuration, and
network policy still require preparation. The role menu does not manage
models or slot profiles on a fixed inference service. Do not treat a node
appearing in Fleet as proof that it has an inference target.

## Verify

```bash
systemctl --no-pager --full status vram-governor-controller.service
systemctl --no-pager --full status vram-governor-node-agent.service
```

Use the controller Fleet/Machines view to confirm the worker is live. A
healthy controller alone does not prove any worker has joined. Before a real
install, `bash ./install-mesh.sh ... --dry-run` can validate the chosen role,
inputs, and certificate fingerprint. Installer regression checks are in
`scripts/test-mesh-install.sh`.
