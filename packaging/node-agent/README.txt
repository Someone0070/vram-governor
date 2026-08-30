VRAM Governor Node Agent
========================

This package installs one restricted, outbound-only system service on a Linux
GPU node. It reports host, GPU, runtime, queue, and log telemetry to the
controller and executes only compiled, signed, expiring, idempotent commands.
It does not provide the controller with a shell and cannot install models,
custom nodes, packages, or arbitrary software.

Install
-------

  tar -xzf vram-governor-node-agent-*-linux-*.tar.gz
  cd vram-governor-node-agent-*-linux-*
  sudo bash ./install.sh

For a non-interactive install, set VRAM_NODE_TOKEN and
VRAM_NODE_COMMAND_SECRET and pass the documented flags shown by:

  bash ./install.sh --help

Upgrade an existing installation without changing its runtime configuration or
secrets:

  sudo bash ./install.sh --upgrade

A full reinstall backs up the prior configuration and secret file under
/etc/vram-governor before writing the requested settings.

Inspect
-------

  systemctl status vram-governor-node-agent.service
  journalctl -u vram-governor-node-agent.service -f

Uninstall
---------

  sudo bash ./uninstall.sh          # preserves durable replay state
  sudo bash ./uninstall.sh --purge  # removes all agent state and service identity
