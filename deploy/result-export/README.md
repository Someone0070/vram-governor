# Final results on the NAS

The controller copies every succeeded workload's final media outputs
(`image/*`, `video/*`, `audio/*`) into a spool directory, named for people:

```text
<spool>/2026-10-12/image-krea2-turbo_fox-1.png
<spool>/2026-10-12/image-krea2-turbo_fox-1.json   # workflow, params (prompt, seed), artifact id
```

Intermediate files (ComfyUI's own output folder on the node, which is scratch)
are never exported. The artifact store stays authoritative; export is best
effort and a failure is only logged.

`vram-result-export-push` (every 30 s) uploads the spool to the NAS with
`smbclient` and deletes each local copy after its upload succeeded. It needs no
kernel mount, so it works in the unprivileged LB container. Files land in
`\\10.0.0.28\models\Outputs\LB\<date>\` (`M:\Outputs\LB` on the desktop).

## Install (LB)

```sh
apt-get install smbclient
install -m 0755 vram-result-export-push /usr/local/libexec/vram-governor/
install -m 0644 vram-result-export-push.service vram-result-export-push.timer /etc/systemd/system/
install -d -o vram-governor -g vram-governor -m 0755 /var/lib/vram-governor/result-export
systemctl daemon-reload && systemctl enable --now vram-result-export-push.timer
```

`/etc/samba/model-sync.cred` (mode 0600, `username=`/`password=` lines) holds
the share account. Controller YAML:

```yaml
workloads:
  result_export:
    dir: /var/lib/vram-governor/result-export
    media_types: [image/*, video/*, audio/*]
```

Override the share, destination folder or credentials file with
`RESULT_EXPORT_SHARE`, `RESULT_EXPORT_DEST` and `RESULT_EXPORT_CREDENTIALS` in a
unit drop-in.
