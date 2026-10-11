# Runtime context and slot profiles

A node can advertise several mutually exclusive capacity profiles for one LLM
endpoint. This supports a runtime such as `8K / 4 slots` during agent fan-out
and `32K / 1 slot` for a later synthesis request without making clients choose
a different load-balancer address.

The controller selects the smallest profile that satisfies
`governor.context_tokens + max_completion_tokens`. A transition occurs only
when the entire physical accelerator is idle. Active LLM, ComfyUI, video, or
other work on that accelerator blocks the transition; the workload remains
queued and receives an ETA instead of disrupting the active job. A failed or
unconfirmed transition is never used for admission.

## Client capacity contract

`GET /v1/models` adds a `governor` object to every model:

```json
{
  "max_context_tokens": 32768,
  "available_context_limits": [8192, 32768],
  "active_context_limits": [8192],
  "capacity_profiles": [
    {"id": "ctx-8k", "context_limit": 8192, "slots": 4},
    {"id": "ctx-32k", "context_limit": 32768, "slots": 1}
  ],
  "current_slots": 4,
  "currently_available_slots": 3,
  "maximum_parallel_slots": 4,
  "max_accelerators": 1,
  "profile_switch_supported": true
}
```

`current_slots` describes the active runtime profile. `currently_available_slots`
subtracts running work. `maximum_parallel_slots` is the largest selectable
profile capacity after applying the model's accelerator ceiling. These are
admission hints, not reservations: clients should limit fan-out to the
currently available value and still handle a queued or fail-fast response
because capacity can change between discovery and submission.

The controller defaults `default_max_accelerators_per_model` to `1`. That does
not limit a model to one request: it may use every slot on one selected card.
An operator can deliberately permit a model on more cards:

```yaml
workloads:
  default_max_accelerators_per_model: 1
  model_capacity_policies:
    - model: small-agent-model
      max_accelerators: 2
```

## Secure node configuration

The controller sends only a target ID and profile ID over the signed node
channel. Each profile ID maps in the node configuration to an exact argv list;
there is no shell evaluation and no controller-provided executable text.

```yaml
llamacpp:
  servers:
    - id: rtx3090-llm
      endpoint: http://127.0.0.1:11434
      accelerator_index: 0
      context_limit: 8192
      slots: 4
      runtime_profiles:
        - id: ctx-8k
          context_limit: 8192
          slots: 4
          switch_command: [/usr/bin/systemctl, start, --wait, "vram-runtime-profile-switch@rtx3090-llm:ctx-8k.service"]
        - id: ctx-32k
          context_limit: 32768
          slots: 1
          switch_command: [/usr/bin/systemctl, start, --wait, "vram-runtime-profile-switch@rtx3090-llm:ctx-32k.service"]
```

The files in `deploy/ollama` provide a hardened service-switch example:

1. Install `switch-runtime-profile.sh` root-owned and mode `0755` at
   `/usr/libexec/vram-governor/`.
2. Install `vram-runtime-profile-switch@.service` under
   `/etc/systemd/system/`.
3. Install the polkit rule under `/etc/polkit-1/rules.d/`, owned by root and
   not writable by the node-agent account.
4. Put profiles under
   `/etc/vram-governor/runtime-profiles/<target>/<profile>.env`, root-owned and
   mode `0644` or stricter. Copy the provided 8K/32K examples and benchmark the
   slot values for each model/card combination before enabling them.
5. Keep the active service environment at
   `/etc/vram-governor/ollama-profiles/<target>.env` and run the existing
   `ollama-profile@<target>.service` instance.

The helper validates both identifiers, refuses symlinks and writable profile
files, accepts only simple environment assignments, copies atomically, and
restarts only the derived allowlisted service instance. Polkit grants the
`vram-governor` user permission only for the switch service family.

Runtime discovery remains the final authority. llama.cpp servers must expose
their `/slots` monitoring endpoint so the node can confirm both context and
parallel slot count after a restart. Stock Ollama does not expose parallel-slot
count through its API, so the sample Ollama helper is staging infrastructure,
not sufficient by itself for verified automatic switching. Keep
`runtime_profiles` disabled for a stock Ollama endpoint until a local monitoring
wrapper reports the effective slot configuration. This fail-closed behavior
prevents the controller from advertising an unverified capacity change.
