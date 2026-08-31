# Ollama multi-profile routing

One Ollama process has one default context/parallelism policy. To keep a
scarce long-context route available while sending smaller requests to a more
efficient multi-slot route, run isolated Ollama services against the same
existing model store and register every service with the node agent.

The included `deploy/ollama/ollama-profile@.service` template does not install
Ollama or download models. Each instance reads an allowlisted environment file
from `/etc/vram-governor/ollama-profiles/<profile>.env` and shares
`/usr/share/ollama/.ollama/models`.

Example node-agent routes:

```yaml
llamacpp:
  servers:
    - id: ollama-short
      endpoint: http://127.0.0.1:11434
      public_endpoint: http://127.0.0.1:11434
      accelerator_index: 0
      context_limit: 2048
      slots: 2
      max_resident_models: 1
      runtime_args: [ollama, profile=short, context=2048, parallel=2]
    - id: ollama-long
      endpoint: http://127.0.0.1:11435
      public_endpoint: http://127.0.0.1:11435
      accelerator_index: 0
      context_limit: 8192
      slots: 1
      max_resident_models: 1
      runtime_args: [ollama, profile=long, context=8192, parallel=1]
```

The scheduler selects the smallest context profile that satisfies a request.
A sticky placement key pins later requests from the same client/session to the
same profile. Both routes retain the same physical accelerator ID, so they can
never be treated as unrelated GPUs. Concurrent use still requires measured
standalone envelopes, explicit `slowdown_allowed` consent on both workloads,
an operator-enabled sharing policy, and either a trusted interference profile
or guarded exploration with sufficient reserve.

Configured context and slot values remain conservative until runtime probing
or live acceptance verifies them. The governor never invents a verified flag
for a value Ollama does not expose through its monitoring API.
