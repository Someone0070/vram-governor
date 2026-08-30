# Model manager foundation + future conversational control agent

Captured from a product steer (2026-08-24): VRAM Governor should also be a **model manager**
— "LM Studio but with more granularity": manually load/unload models in/out of specific GPUs,
OR let the LB do it automatically — and eventually **a conversational agent you can talk to**
that sets things up, monitors, and acts on command or autonomously.

The model-manager foundation is now implemented for external llama.cpp router
targets: durable desired/observed residency, demand loading, safe unloading,
policy controls, transition fencing/audit, and an operator UI/API. Managed
runtime installation and the conversational control agent remain future work.

## Part 1 — Model manager (manual + automatic residency)

### What it is
A UI + API to see, per accelerator, which models are resident, and to control it at fine
granularity: **pin** a model to a specific GPU, load/unload on demand, or hand control to the
scheduler. The "more granular than LM Studio" part is per-accelerator, per-shard control plus
a policy switch per accelerator.

### Already have / already designed
- **Load/unload primitives** — Phase 2 runtime driver: `Launch`, `Stop`, `Sleep(evicted)`,
  `Wake`, KV checkpoint/restore. Manual load/unload is literally these, exposed via API/UI.
- **Desired vs observed state** (§14, decision #30) — the model manager is just desired
  *model residency* per accelerator, reconciled toward observed, exactly like power/pool are.
- **Measured footprint** (Phase 2 probe) — the manager can tell you *before* loading whether
  a model fits a card, and how much VRAM/KV it will take. LM Studio guesses; we measure.
- **Auto/Manual/Off/Don't-touch** modes (§4.2) already exist for *power* — the same shape
  applies to *residency*.

### Hooks to leave in NOW (so Phase 4/5 don't block it)
- **Residency as first-class desired-state at the ACCELERATOR level, not just node.** Today
  desired lives on the Node (`desired_pool`). Add a per-accelerator desired-residency concept:
  a list of desired models/profiles pinned to an accelerator, plus a **residency policy mode**
  (`pinned` / `manual` / `auto`) mirroring the power modes. `auto` = scheduler owns it;
  `pinned` = keep this model here, scheduler may not evict; `manual` = only user actions move
  it. Put the field in the data model even if Phase 4/5 only ever set `auto`.
- **Every load/unload is an owned EngineInstance transition** (decision #18) — the manager
  must never adopt/kill unmanaged PIDs, only surface them. Already the rule; keep it.
- **TransitionPlan (§32) for every residency change**, so a manual "load 27B on GPU2" produces
  the same planned/explainable transition (§31) as a scheduler-driven one — one code path.

## Part 2 — Conversational control agent

### What it is
An LLM you talk to ("load the 9B on the two Ti's and start draining the 3090", "why is the
queue backed up?", "keep the lead responsive tonight but batch overnight") that reads
telemetry and drives the control plane — on command or, when you allow it, autonomously.

### The clean insight: it's the SAME mechanism as `compute_handoff`
The architecture already has **control-plane tools** (§33): tools marked `control: true` that
the agent loop dispatches to the controller's control API instead of to an app handler
(that's how the lead reaches `/control/handoff`). The conversational manager is just an LLM
given a **broader set of control:true tools**:

```
list_nodes / get_telemetry / explain_scheduler_decision
load_model(accelerator, profile) / unload_model / set_residency_policy
drain_node / set_pool / submit_job / pause_job
```

So it needs **no new mechanism** — it's a tool registry over the Phase 1–3 API surface plus
the residency controls from Part 1. And it can be **dogfooded**: the agent is itself a model
served by the pool, managing the pool. VRAM Governor running its own admin.

### Design requirements when we build it
- **Everything auditable.** Every agent action emits a lifecycle Event (§28) and carries the
  §31 explanation. Autonomous actions are logged the same as manual ones.
- **Authority scoping.** The agent gets a scoped control token (§33 auth); autonomy is
  opt-in per capability (e.g. "may drain locals, may NOT power off nodes"). Mirrors the
  Auto/Manual/Don't-touch philosophy — the agent is just another actor bound by node modes
  (a `dont_touch` node is off-limits to the agent too).
- **Confirm-vs-act policy.** Like the interactive-preemption policy (§11), the agent branches:
  read-only queries auto-run; mutating actions either require confirmation or run under a
  standing autonomy grant. Never a blanket "does anything."
- **Grounded in measured data** (`docs/measurement.md`) — the agent answers "will the 27B fit
  on GPU2?" from measured footprints, not guesses.

## Where these land in the roadmap
- **Manual load/unload API + model-manager UI:** implemented for allowlisted external
  llama.cpp router targets. Governor-managed runtime processes remain later work.
- **Automatic residency:** demand loading and conservative idle/quiet-hours unloading are
  implemented. Predictive pre-loading remains deliberately disabled; later learning only
  refines retention and eviction ranking.
- **Conversational agent:** later layer, built on the control-tool registry once the API
  surface is stable. Cheap to add *if* Part 1's hooks (per-accelerator residency + policy mode,
  TransitionPlan for all changes, control-tool registry) are in place first.

## Net: what to do now (no build, just don't paint into a corner)
1. Add per-accelerator **desired residency + residency policy mode** to the data model.
2. Route **all** model load/unload through **TransitionPlan + Events** (one explainable path).
3. Keep the control API tool-shaped and consistent, so a `control: true` tool registry can
   wrap it later with zero rework.
