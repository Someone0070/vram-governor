# Tasmota smart plugs per rig

The controller can monitor a Sonoff S31/Tasmota plug mapped to a rig's exact
`node_id`. The Operator Console Machines cards show relay state and wall watts;
the rig Telemetry tab shows voltage, current, active/apparent/reactive power, power factor, and
today/yesterday/total kWh. Measurements are read from Tasmota's structured
`/cm?cmnd=Status%200` JSON response, with the `/?m=1` web fragment as a
monitoring fallback. Zero is a real reading rather than "not reported."

The observed device at `10.0.0.43` identifies as a Sonoff S31 running Tasmota
15.6.0 and served those metrics read-only on 2026-09-12. It was ON and showed
0 W / 0 V at that instant. Its `/cm` command endpoint requires a same-device
`Referer` header because `HTTP_API` is disabled. With that header, read-only
`Power` and `Status 0` requests returned valid JSON. On 2026-09-12, an
explicit `Power OFF` command and readback both returned OFF, followed by an
explicit `Power ON` command and readback both returning ON. This was a direct
device test from the workstation, not an end-to-end controller/LB deployment
test. The plug was left ON. Its `HTTP_API` field still reported `0` afterward.
The outlet at `10.0.0.43` is deliberately **not mapped to any rig**.

The user confirmed `10.0.0.222` powers the CMP170 rig. The dedicated
controller template maps it to `cmp170-node` with `control_enabled: false`.
After that template is deployed, the Operator Console can display its live
electrical readings but cannot
switch its relay. A read-only `Status 0` query on 2026-09-12 reported ON,
122 V, 0.657 A, 80 W, and 0.272 kWh today. No relay command was sent.

After confirming which rig an outlet physically feeds, configure one fixed
private IPv4 address per node in the dedicated controller config:

```yaml
smart_plugs:
  - node_id: example-rig-node-id
    url: http://192.168.1.50
    control_enabled: false
```

Set `control_enabled: true` only after the physical rig mapping and explicit
power command have been safely verified on that device. A controller restart applies configuration
changes. Unmapped rigs display "not mapped"; unreachable plugs display an
error, never a stale ON/OFF value.

The admin-only power API is `POST /admin/api/smart-plugs/{node_id}/power` with
an `Idempotency-Key` and an explicit `{"state":"ON"}` or
`{"state":"OFF","acknowledge_hard_power_cut":true}`. It never uses Tasmota's
toggle operation. OFF requires the rig's scheduler to be disabled and no
assigned active workload. It is still a hard AC cut, **not an OS shutdown**:
save work and shut the rig down cleanly first. A separate confirmation in the
UI explains that risk. The node-agent `power_control_mode` must be explicitly `manual`;
all other modes block plug control. ON remains available for a mapped, enabled plug even if
the rig's node agent is offline.

Only configured private IPv4 hosts can be contacted; callers cannot supply a
URL, redirects and environment proxying are disabled, reads are size-limited,
and commands require private-network admin authentication. Successful changes
produce an audit event. Tasmota's documented commands use explicit `Power ON`
and `Power OFF`; this integration requires the device to confirm the requested
state and does not fall back to the web UI's blind toggle endpoint. The
controller sends a same-device `Referer` on these requests; it does not change
Tasmota's `HTTP_API` security setting.
