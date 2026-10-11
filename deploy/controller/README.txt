VRAM Governor dedicated controller bundle
=========================================

This archive belongs on the separate controller/load-balancer machine. Do not
install it as the controller service on the RTX 3080, RTX 3090, or CMP170 GPU
workers; those machines receive the node-agent bundle.

Contents
--------
- vram-governor-controller: Linux controller binary
- controller.yaml.template: production topology and credential template
- controller.env.example: secret environment template
- vram-governor-controller.service: hardened systemd unit
- validate-controller.sh: placeholder, secret, and application config preflight
- apply-migrations.sh and migrations/: ordered PostgreSQL migration helper
- install.sh: safe install/upgrade entrypoint
- uninstall.sh: removes program files while preserving config and data

Quick start
-----------
1. Read docs/dedicated-controller-deployment.md in the source repository.
2. Provision PostgreSQL, an HTTPS S3-compatible bucket, a TLS certificate, and
   DNS/static addressing for this dedicated host.
3. Copy controller.yaml.template and controller.env.example to private working
   files. Replace every __PLACEHOLDER__. Put SHA-256 hashes, never raw client
   tokens, in controller.yaml.
4. Put controller.crt and controller.key in /etc/vram-governor/tls after the
   first installer pass.
5. Run:
     sudo ./install.sh
     sudo ./install.sh --config /root/controller.yaml --environment-file /root/controller.env --no-start
     sudo -u vram-governor /usr/local/libexec/vram-governor/apply-migrations.sh
     sudo systemctl enable --now vram-governor-controller

The validation helper and systemd ExecStartPre refuse unresolved placeholders,
weak node-command secrets, or application-invalid production configuration.
