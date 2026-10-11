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

For a new node, set VRAM_ENROLLMENT_TOKEN and VRAM_NODE_COMMAND_SECRET.
The installer self-declares over HTTPS and saves a unique node token. For an
existing node, set VRAM_NODE_TOKEN instead. Use --controller-ca FILE when the
controller certificate is not trusted by the node OS. See options with:

  bash ./install.sh --help

Upgrade an existing installation without changing its runtime configuration or
secrets:

  sudo bash ./install.sh --upgrade

A full reinstall backs up the prior configuration and secret file under
/etc/vram-governor before writing the requested settings.

To advertise an already-running standalone llama.cpp server, follow the
included docs/llamacpp-node-setup.md. Enrollment alone advertises no LLM. The guide
explains runtime measurement, LAN endpoints, and why a fixed server cannot
be made load/unload-capable by changing router_managed in the YAML.

Optional runtime-profile assets are bundled under runtime-profile/. They are
not installed automatically because profile slot counts must be benchmarked on
the specific card/model and stock Ollama cannot independently report its
parallel-slot setting. Follow docs/ollama-multi-profile.md in the source repo,
install the helper, unit, and polkit rule as root, then enable runtime_profiles
only after the runtime monitoring endpoint proves context and slot capacity.

Inspect
-------

  systemctl status vram-governor-node-agent.service
  journalctl -u vram-governor-node-agent.service -f

Uninstall
---------

  sudo bash ./uninstall.sh          # preserves durable replay state
  sudo bash ./uninstall.sh --purge  # removes all agent state and service identity
