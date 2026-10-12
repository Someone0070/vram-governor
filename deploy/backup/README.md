# Backups

## Controller (LB): `vram-backup`

Nightly (03:30 UTC) `pg_dump -Fc` of the controller database plus a tarball of
`/etc/vram-governor`, the `vram-*` systemd units and `/etc/samba` (secrets
included: the destination is the private NAS). Each run:

1. restores the dump into a scratch database (`vram_governor_restore_check`)
   and fails unless it has exactly as many tables as the live database;
2. uploads both files to `\10.0.0.28\models\Backups\vram-governor-lb\<date>\`
   with `smbclient` (the LB is an unprivileged container and cannot mount the
   share);
3. keeps the newest 14 of each locally in `/var/backups/vram-governor/daily`.

```sh
install -m 0755 vram-backup /usr/local/libexec/vram-governor/
install -m 0644 vram-backup.service vram-backup.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vram-backup.timer
```

Restore on a fresh controller (stop the controller first):

```sh
runuser -u postgres -- dropdb vram_governor
runuser -u postgres -- createdb -O vram-governor vram_governor
runuser -u postgres -- pg_restore --no-owner --role=vram-governor -d vram_governor < vram_governor-<stamp>.dump
tar -xzf config-<stamp>.tar.gz -C /
systemctl daemon-reload && systemctl start vram-governor-controller
```

## GPU nodes: `vram-node-config-backup`

Nightly (03:45 UTC) tarball of the node agent, router presets, ComfyUI model
paths and VRAM Governor node packs, systemd units and drop-ins, `/etc/fstab`
and `/etc/samba` to `/mnt/models-rw/Backups/<hostname>/` (60 days kept). Model
weights are not included: they live on the NAS. Needs the share's read-write
mount in `/etc/fstab` so it survives reboots.
