package workloads

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func TestResidencyAllocateConcurrentResourceFence(t *testing.T) {
	backing := store.NewMemoryStore()
	const workers = 32
	results := make(chan *domain.ResidencyTransition, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			row, _, err := backing.AllocateResidencyTransition(context.Background(), &domain.ResidencyTransition{ID: fmt.Sprintf("alloc-%d", i), IdempotencyKey: fmt.Sprintf("alloc-key-%d", i), TargetID: "node-gpu0", Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "concurrent", Status: domain.ResidencyTransitionPlanned, CreatedAt: time.Now().UTC()})
			if err != nil {
				t.Errorf("allocate %d: %v", i, err)
				return
			}
			results <- row
		}(i)
	}
	wg.Wait()
	close(results)
	seen := make(map[int64]bool, workers)
	for row := range results {
		if row == nil || row.FencingToken <= 0 || seen[row.FencingToken] {
			t.Fatalf("resource fence was not unique and monotonic: row=%+v seen=%v", row, seen)
		}
		seen[row.FencingToken] = true
	}
	if len(seen) != workers {
		t.Fatalf("expected %d allocated transitions, got %d", workers, len(seen))
	}
}

func TestControllerAdapterVerifiesWarmObservation(t *testing.T) {
	target := controllerTarget()
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(_ context.Context, _ string, _ string, args map[string]any, _ string) (map[string]any, error) {
		return map[string]any{"target_id": args["target_id"], "model": args["model"], "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": "warm_ram", "resident": false, "warm_ram": true,
			"warm_model_bytes_verified": true, "warm_model_bytes": int64(4096), "locked_bytes": int64(4096), "released_vram": true}, nil
	}})
	observation, err := adapter.Transition(context.Background(), target, "model", domain.ResidencyWarmRAM)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Tier != domain.ResidencyWarmRAM || !observation.WarmModelBytesVerified || !observation.VRAMReleased || observation.WarmModelBytes != 4096 {
		t.Fatalf("warm observation was not transactionally verified: %+v", observation)
	}
}

// TestControllerAdapterAllResidencyActionsCurrentEnvelope exercises the
// production observation boundary for every lifecycle action.  It keeps the
// desired, inverse, and unrelated third tiers separate and also checks that a
// correlated query is explicitly unchanged rather than being treated as a
// second mutation.
func TestControllerAdapterAllResidencyActionsCurrentEnvelope(t *testing.T) {
	target := controllerTarget()
	identity := "node-1-llama|llamacpp|ollama|ollama-runtime-v1|"
	actions := []struct {
		name, desired, inverse, third string
	}{
		{"load_model", "hot_vram", "cold_disk", "warm_ram"},
		{"unload_model", "cold_disk", "hot_vram", "warm_ram"},
		{"warm_model", "warm_ram", "hot_vram", "cold_disk"},
		{"offload_model", "warm_ram", "cold_disk", "hot_vram"},
		{"demote_model", "warm_ram", "hot_vram", "cold_disk"},
		{"protect_warm_model", "warm_ram", "cold_disk", "hot_vram"},
		{"cleanup_warm_model", "cold_disk", "hot_vram", "warm_ram"},
		{"reverify_warm_model", "warm_ram", "cold_disk", "hot_vram"},
	}
	makeProof := func(action, tier string, changed bool, query bool) map[string]any {
		result := map[string]any{
			"action": action, "target_kind": "llamacpp", "target_id": target.ID, "model": "model", "node_id": "node-1",
			"runtime_identity": identity, "capability_version": target.CapabilityVersion, "capability_revision": target.CapabilityRevision,
			"tier": tier, "resident": tier == "hot_vram", "warm_ram": tier == "warm_ram", "changed": changed,
			"command_id": "mutation-1", "idempotency_key": "mutation-key", "command_fingerprint": "fingerprint", "fingerprint": "fingerprint",
			"original_command_id": "mutation-1", "original_idempotency_key": "mutation-key", "fencing_token": int64(7), "observed_after_fence": int64(7), "reconciled": false,
		}
		if query {
			result["command_id"], result["idempotency_key"] = "query-1", "query-key"
			result["command_fingerprint"], result["fingerprint"] = "query-fingerprint", "query-fingerprint"
			result["expected_fence"] = int64(7)
		}
		switch tier {
		case "cold_disk":
			result["cleaned"], result["warm_entry_absent"], result["warm_release_verified"] = true, true, true
			result["warm_model_bytes"], result["locked_bytes"] = int64(0), int64(0)
		case "warm_ram":
			result["warm_model_bytes_verified"], result["released_vram"], result["oracle"] = true, true, "mincore+mlock"
			result["warm_model_bytes"], result["locked_bytes"] = int64(8), int64(8)
			if action == "protect_warm_model" {
				result["protected"], result["active_references"] = true, int64(2)
			}
		}
		return result
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			for _, tier := range []string{action.desired, action.inverse, action.third} {
				t.Run("mutation/"+tier, func(t *testing.T) {
					result := makeProof(action.name, tier, true, false)
					_, err := observeResidencyResult(result, target, "model", identity, domain.ResidencyTier(action.desired), action.name, 7, "mutation-key")
					if tier == action.desired && err != nil {
						t.Fatalf("desired current proof rejected: %v", err)
					}
					if tier != action.desired && err == nil {
						t.Fatalf("%s tier was accepted as %s evidence", tier, action.desired)
					}
				})
				t.Run("query/"+tier, func(t *testing.T) {
					result := makeProof(action.name, tier, false, true)
					_, err := observeResidencyQueryResult(result, target, "model", identity, domain.ResidencyTier(action.desired), action.name, 7, "query-key")
					if tier == action.desired && err != nil {
						t.Fatalf("desired unchanged query proof rejected: %v", err)
					}
					if tier != action.desired && err == nil {
						t.Fatalf("%s query tier was accepted as %s evidence", tier, action.desired)
					}
				})
			}
		})
	}

	valid := makeProof("warm_model", "warm_ram", true, false)
	badChanged := make(map[string]any, len(valid))
	for key, value := range valid {
		badChanged[key] = value
	}
	badChanged["changed"] = "true"
	if _, err := observeResidencyResult(badChanged, target, "model", identity, domain.ResidencyWarmRAM, "warm_model", 7, "mutation-key"); err == nil {
		t.Fatal("string changed proof was accepted")
	}
	mixed := make(map[string]any, len(valid))
	for key, value := range valid {
		mixed[key] = value
	}
	mixed["cleaned"] = true
	if _, err := observeResidencyResult(mixed, target, "model", identity, domain.ResidencyWarmRAM, "warm_model", 7, "mutation-key"); err == nil {
		t.Fatal("mixed warm/cleanup proof was accepted")
	}
	underflow := make(map[string]any, len(valid))
	for key, value := range valid {
		underflow[key] = value
	}
	underflow["locked_bytes"] = int64(4)
	if _, err := observeResidencyResult(underflow, target, "model", identity, domain.ResidencyWarmRAM, "warm_model", 7, "mutation-key"); err == nil {
		t.Fatal("warm locked-byte underflow was accepted")
	}
	queryChanged := makeProof("load_model", "hot_vram", true, true)
	if _, err := observeResidencyQueryResult(queryChanged, target, "model", identity, domain.ResidencyHotVRAM, "load_model", 7, "query-key"); err == nil {
		t.Fatal("correlated query with changed=true was accepted")
	}
}

// TestControllerAdapterAllResidencyActionsDispatchesThroughTransition proves
// the matrix at the controller boundary, not only in the observation helper:
// transition builds signed-style arguments, dispatches the named action, and
// persists the resulting observation in the durable store.
func TestControllerAdapterAllResidencyActionsDispatchesThroughTransition(t *testing.T) {
	target := controllerTarget()
	identity := "node-1-llama|llamacpp|ollama|ollama-runtime-v1|"
	actions := []struct{ name, desired, inverse, third string }{
		{"load_model", "hot_vram", "cold_disk", "warm_ram"}, {"unload_model", "cold_disk", "hot_vram", "warm_ram"},
		{"warm_model", "warm_ram", "hot_vram", "cold_disk"}, {"offload_model", "warm_ram", "cold_disk", "hot_vram"},
		{"demote_model", "warm_ram", "hot_vram", "cold_disk"}, {"protect_warm_model", "warm_ram", "cold_disk", "hot_vram"},
		{"cleanup_warm_model", "cold_disk", "hot_vram", "warm_ram"}, {"reverify_warm_model", "warm_ram", "cold_disk", "hot_vram"},
	}
	for _, action := range actions {
		for _, scenario := range []struct{ name, tier string }{{"desired", action.desired}, {"inverse", action.inverse}, {"third", action.third}} {
			t.Run(action.name+"/"+scenario.name, func(t *testing.T) {
				backing := store.NewMemoryStore()
				calls := 0
				adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Store: backing, Command: func(_ context.Context, _ string, command string, args map[string]any, idempotency string) (map[string]any, error) {
					calls++
					fence, _ := args["fencing_token"].(int64)
					result := map[string]any{"action": command, "target_kind": "llamacpp", "target_id": target.ID, "model": "model", "node_id": "node-1", "runtime_identity": identity, "capability_version": target.CapabilityVersion, "capability_revision": target.CapabilityRevision, "tier": scenario.tier, "resident": scenario.tier == "hot_vram", "warm_ram": scenario.tier == "warm_ram", "changed": true, "command_id": idempotency + "-command", "idempotency_key": idempotency, "command_fingerprint": "dispatch-fingerprint", "fingerprint": "dispatch-fingerprint", "original_command_id": idempotency + "-command", "original_idempotency_key": idempotency, "fencing_token": fence, "observed_after_fence": fence, "reconciled": false}
					switch scenario.tier {
					case "cold_disk":
						result["cleaned"], result["warm_entry_absent"], result["warm_release_verified"] = true, true, true
						result["warm_model_bytes"], result["locked_bytes"] = int64(0), int64(0)
					case "warm_ram":
						result["warm_model_bytes_verified"], result["released_vram"], result["oracle"] = true, true, "mincore+mlock"
						result["warm_model_bytes"], result["locked_bytes"] = int64(8), int64(8)
					}
					return result, nil
				}})
				_, err := adapter.transition(context.Background(), target, "model", domain.ResidencyTier(action.desired), action.name, action.desired == "warm_ram", "dispatch-"+action.name+"-"+scenario.name, "")
				if scenario.tier == action.desired && err != nil {
					t.Fatalf("desired dispatched transition rejected: %v", err)
				}
				if scenario.tier != action.desired && err == nil {
					t.Fatalf("inverse/third dispatched tier was accepted: tier=%s", scenario.tier)
				}
				if calls == 0 {
					t.Fatal("controller transition did not cross the command dispatch boundary")
				}
			})
		}
	}
}

func TestControllerAdapterAllResidencyActionsDispatchSchemaNegatives(t *testing.T) {
	target := controllerTarget()
	identity := "node-1-llama|llamacpp|ollama|ollama-runtime-v1|"
	actions := []struct{ name, tier string }{
		{"load_model", "hot_vram"}, {"unload_model", "cold_disk"}, {"warm_model", "warm_ram"}, {"offload_model", "warm_ram"},
		{"demote_model", "warm_ram"}, {"protect_warm_model", "warm_ram"}, {"cleanup_warm_model", "cold_disk"}, {"reverify_warm_model", "warm_ram"},
	}
	for _, action := range actions {
		for _, variant := range []string{"changed-type", "mixed-tier", "locked-underflow"} {
			t.Run(action.name+"/"+variant, func(t *testing.T) {
				adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Store: store.NewMemoryStore(), Command: func(_ context.Context, _ string, command string, args map[string]any, idempotency string) (map[string]any, error) {
					fence, _ := args["fencing_token"].(int64)
					result := map[string]any{"action": command, "target_kind": "llamacpp", "target_id": target.ID, "model": "model", "node_id": "node-1", "runtime_identity": identity, "capability_version": target.CapabilityVersion, "capability_revision": target.CapabilityRevision, "tier": action.tier, "resident": action.tier == "hot_vram", "warm_ram": action.tier == "warm_ram", "changed": true, "command_id": idempotency + "-command", "idempotency_key": idempotency, "command_fingerprint": "schema-fingerprint", "fingerprint": "schema-fingerprint", "original_command_id": idempotency + "-command", "original_idempotency_key": idempotency, "fencing_token": fence, "observed_after_fence": fence, "reconciled": false}
					if action.tier == "cold_disk" {
						result["cleaned"], result["warm_entry_absent"], result["warm_release_verified"] = true, true, true
						result["warm_model_bytes"], result["locked_bytes"] = int64(0), int64(0)
					}
					if action.tier == "warm_ram" {
						result["warm_model_bytes_verified"], result["released_vram"], result["oracle"] = true, true, "mincore+mlock"
						result["warm_model_bytes"], result["locked_bytes"] = int64(8), int64(8)
					}
					switch variant {
					case "changed-type":
						result["changed"] = "true"
					case "mixed-tier":
						if action.tier == "cold_disk" {
							result["warm_model_bytes_verified"] = true
						} else {
							result["cleaned"] = true
						}
					case "locked-underflow":
						if action.tier == "warm_ram" {
							result["locked_bytes"] = int64(4)
						} else {
							result["oracle"] = "mincore+mlock"
						}
					}
					return result, nil
				}})
				if _, err := adapter.transition(context.Background(), target, "model", domain.ResidencyTier(action.tier), action.name, action.tier == "warm_ram", "schema-dispatch-"+action.name+"-"+variant, ""); err == nil {
					t.Fatalf("malformed %s proof crossed dispatch and was accepted", variant)
				}
			})
		}
	}
}

func TestObserveResidencyResultExactActionTierProofSchema(t *testing.T) {
	base := func(tier string) map[string]any {
		r := map[string]any{"action": "load_model", "target_id": "node-1-llama", "model": "model", "runtime_identity": "runtime", "tier": tier, "resident": tier == "hot_vram", "warm_ram": tier == "warm_ram", "changed": false}
		switch tier {
		case "cold_disk":
			r["cleaned"], r["warm_entry_absent"], r["warm_release_verified"] = true, true, true
			r["warm_model_bytes"], r["locked_bytes"] = int64(0), int64(0)
		case "warm_ram":
			r["warm_model_bytes_verified"], r["released_vram"], r["oracle"] = true, true, "mincore+mlock"
			r["warm_model_bytes"], r["locked_bytes"] = int64(8), int64(8)
		}
		return r
	}
	for _, tier := range []string{"hot_vram", "cold_disk", "warm_ram"} {
		t.Run(tier, func(t *testing.T) {
			valid := base(tier)
			if got := validateObservedResidencySchema(valid, domain.ResidencyTier(tier)); got != "" {
				t.Fatalf("valid proof rejected: %s", got)
			}
			for name, mutate := range map[string]func(map[string]any){
				"mixed": func(r map[string]any) {
					if tier == "cold_disk" {
						r["oracle"] = "mincore+mlock"
					} else {
						r["cleaned"] = true
					}
				},
				"changed-type": func(r map[string]any) { r["changed"] = "false" },
				"unknown":      func(r map[string]any) { r["extra"] = true },
			} {
				t.Run(name, func(t *testing.T) {
					bad := base(tier)
					mutate(bad)
					if got := validateObservedResidencySchema(bad, domain.ResidencyTier(tier)); got == "" {
						t.Fatal("invalid proof accepted")
					}
				})
			}
		})
	}
}

func TestControllerAdapterRollsBackMismatch(t *testing.T) {
	target := controllerTarget()
	var calls []string
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(_ context.Context, _ string, name string, args map[string]any, _ string) (map[string]any, error) {
		calls = append(calls, name)
		if name == "load_model" {
			return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": "cold_disk", "resident": false, "warm_ram": false}, nil
		}
		return map[string]any{"target_id": args["target_id"], "model": args["model"], "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": "cold_disk", "resident": false, "warm_ram": false}, nil
	}})
	var got *ResidencyAdapterError
	if err := adapter.LoadModel(context.Background(), target, "model"); !errors.As(err, &got) || !got.RollbackAttempted || !got.RollbackSucceeded || got.Code != ResidencyBlockerCommandFailed {
		t.Fatalf("expected rollback-safe mismatch, got %v", err)
	}
	if len(calls) != 2 || calls[1] != "unload_model" {
		t.Fatalf("expected inverse rollback command, calls=%v", calls)
	}
}

func TestControllerAdapterRollbackRestoresAuthoritativeWarmFromTier(t *testing.T) {
	target := controllerTarget()
	backing := store.NewMemoryStore()
	var calls []string
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Store: backing, Command: func(_ context.Context, _ string, name string, args map[string]any, _ string) (map[string]any, error) {
		calls = append(calls, name)
		if name == "load_model" {
			return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": "cold_disk", "resident": false, "warm_ram": false}, nil
		}
		return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": "warm_ram", "resident": false, "warm_ram": true, "warm_model_bytes_verified": true, "warm_model_bytes": int64(4096), "locked_bytes": int64(4096), "released_vram": true}, nil
	}})
	var got *ResidencyAdapterError
	if _, err := adapter.TransitionWithNodeIDFromTier(context.Background(), target, "model", domain.ResidencyWarmRAM, domain.ResidencyHotVRAM, "warm-inverse", "node-1"); !errors.As(err, &got) || !got.RollbackSucceeded {
		t.Fatalf("expected warm inverse rollback, got %v", err)
	}
	if len(calls) != 2 || calls[0] != "load_model" || calls[1] != "offload_model" {
		t.Fatalf("rollback did not restore warm tier: %v", calls)
	}
	rows, err := backing.ListResidencyTransitions(context.Background(), 10)
	rollbackRecorded := false
	for _, row := range rows {
		if row != nil && strings.HasPrefix(row.Reason, "controller-adapter rollback") && row.Status == domain.ResidencyTransitionSucceeded {
			rollbackRecorded = true
		}
	}
	if err != nil || len(rows) != 2 || !rollbackRecorded {
		t.Fatalf("rollback phase was not durably recorded: rows=%+v err=%v", rows, err)
	}
}

func TestControllerAdapterRollbackFailureIsStructured(t *testing.T) {
	target := controllerTarget()
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(_ context.Context, _ string, name string, args map[string]any, _ string) (map[string]any, error) {
		if name == "load_model" {
			return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": "cold_disk", "resident": false, "warm_ram": false}, nil
		}
		return nil, errors.New("rollback transport")
	}})
	var got *ResidencyAdapterError
	if err := adapter.LoadModel(context.Background(), target, "model"); !errors.As(err, &got) || got.Code != ResidencyBlockerRollbackFailed || got.RollbackSucceeded {
		t.Fatalf("expected rollback failure blocker, got %v", err)
	}
}

func TestControllerAdapterKnownPositiveBrokenWarmControl(t *testing.T) {
	target := controllerTarget()
	target.Capabilities.WarmRAMVerified = false
	target.Capabilities.WarmRAMVerification = ""
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		t.Fatal("unverified warm control reached command boundary")
		return nil, nil
	}})
	var got *ResidencyAdapterError
	if err := adapter.OffloadModelToRAM(context.Background(), target, "model"); !errors.As(err, &got) || got.Code != ResidencyBlockerCapabilityUnavailable {
		t.Fatalf("expected warm proof rejection, got %v", err)
	}
}

func TestControllerAdapterDurableGenerationDoesNotReplayEarlierTier(t *testing.T) {
	target := controllerTarget()
	backing := store.NewMemoryStore()
	var fences []int64
	command := func(_ context.Context, _ string, name string, args map[string]any, _ string) (map[string]any, error) {
		fences = append(fences, args["fencing_token"].(int64))
		resident := name == "load_model"
		tier := "cold_disk"
		if resident {
			tier = "hot_vram"
		}
		return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": tier, "resident": resident, "warm_ram": false}, nil
	}
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: command, Store: backing})
	if err := adapter.LoadModel(context.Background(), target, "model"); err != nil {
		t.Fatal(err)
	}
	if err := adapter.UnloadModel(context.Background(), target, "model"); err != nil {
		t.Fatal(err)
	}
	if err := adapter.LoadModel(context.Background(), target, "model"); err != nil {
		t.Fatal(err)
	}
	if len(fences) != 3 || fences[0] != 1 || fences[1] != 2 || fences[2] != 3 {
		t.Fatalf("expected durable generations 1,2,3, got %v", fences)
	}
	rows, err := backing.ListResidencyTransitions(context.Background(), 10)
	if err != nil || len(rows) != 3 {
		t.Fatalf("expected three durable transition rows, rows=%d err=%v", len(rows), err)
	}
}

func TestControllerAdapterDurableReplayRequiresExactObservation(t *testing.T) {
	target := controllerTarget()
	backing := store.NewMemoryStore()
	calls := 0
	command := func(_ context.Context, _ string, name string, args map[string]any, _ string) (map[string]any, error) {
		calls++
		if name != "load_model" {
			t.Fatalf("unexpected replay command %s", name)
		}
		return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": "hot_vram", "resident": true, "warm_ram": false}, nil
	}
	first := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: command, Store: backing})
	if _, err := first.TransitionWithIdempotency(context.Background(), target, "model", domain.ResidencyHotVRAM, "replay-key"); err != nil {
		t.Fatal(err)
	}
	second := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		t.Fatal("durable replay dispatched a second node command")
		return nil, nil
	}, Store: backing})
	observation, err := second.TransitionWithIdempotency(context.Background(), target, "model", domain.ResidencyHotVRAM, "replay-key")
	if err != nil || observation.Tier != domain.ResidencyHotVRAM || observation.FencingToken != 1 || observation.RuntimeIdentity == "" || calls != 1 {
		t.Fatalf("durable replay did not return exact prior observation: observation=%+v calls=%d err=%v", observation, calls, err)
	}
}

func TestControllerAdapterPendingTransitionBlocksAfterRestart(t *testing.T) {
	target := controllerTarget()
	backing := store.NewMemoryStore()
	first := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{TransitionTimeout: 20 * time.Millisecond, PollInterval: time.Millisecond, Store: backing, Command: func(ctx context.Context, _ string, _ string, _ map[string]any, _ string) (map[string]any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	if _, err := first.TransitionWithIdempotency(context.Background(), target, "model", domain.ResidencyHotVRAM, "pending-key"); err == nil {
		t.Fatal("expected bounded pending transition to fail")
	}
	second := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Store: backing, Command: func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		t.Fatal("pending restart dispatched a new command")
		return nil, nil
	}})
	var blocker *ResidencyAdapterError
	if _, err := second.TransitionWithIdempotency(context.Background(), target, "model", domain.ResidencyColdDisk, "new-key"); !errors.As(err, &blocker) || blocker.Code != ResidencyBlockerTransitionBusy {
		t.Fatalf("expected restart pending blocker, got %v", err)
	}
}

func TestResidencyTransitionIdempotencyRejectsCanonicalArgumentMismatch(t *testing.T) {
	backing := store.NewMemoryStore()
	base := &domain.ResidencyTransition{ID: "transition-base", IdempotencyKey: "same-key", TargetID: "target-a", AcceleratorID: "target-a-gpu0", Model: "model-a", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "operator runtime=target-a|llamacpp|ollama|v1|", RequestedBy: "operator", Status: domain.ResidencyTransitionPlanned, FencingToken: 7, CreatedAt: time.Now().UTC()}
	if _, created, err := backing.CreateResidencyTransition(context.Background(), base); err != nil || !created {
		t.Fatalf("create base transition: created=%v err=%v", created, err)
	}
	for _, mutate := range []func(*domain.ResidencyTransition){
		func(value *domain.ResidencyTransition) { value.TargetID = "target-b" },
		func(value *domain.ResidencyTransition) { value.Model = "model-b" },
		func(value *domain.ResidencyTransition) { value.ToTier = domain.ResidencyColdDisk },
		func(value *domain.ResidencyTransition) {
			value.Reason = "operator runtime=target-a|llamacpp|ollama|v2|"
		},
		func(value *domain.ResidencyTransition) { value.FencingToken = 8 },
	} {
		candidate := *base
		mutate(&candidate)
		if _, _, err := backing.CreateResidencyTransition(context.Background(), &candidate); !errors.Is(err, store.ErrResidencyTransitionConflict) {
			t.Fatalf("canonical mismatch was accepted: candidate=%+v err=%v", candidate, err)
		}
	}
}

func TestControllerAdapterResourceQueriesIgnoreUnrelatedHistory(t *testing.T) {
	target := controllerTarget()
	identity := "node-1-llama|llamacpp|ollama|ollama-runtime-v1|"
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	for i := 0; i < 1200; i++ {
		row := &domain.ResidencyTransition{ID: "unrelated-" + strconv.Itoa(i), IdempotencyKey: "unrelated-key-" + strconv.Itoa(i), TargetID: "other-target", AcceleratorID: "other-gpu", Model: "other-model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "noise", Status: domain.ResidencyTransitionSucceeded, FencingToken: 90000 + int64(i), CreatedAt: now.Add(time.Duration(i) * time.Nanosecond)}
		if _, created, err := backing.CreateResidencyTransition(context.Background(), row); err != nil || !created {
			t.Fatalf("unrelated history insert %d: created=%v err=%v", i, created, err)
		}
	}
	base := &domain.ResidencyTransition{ID: "resource-highwater", IdempotencyKey: "resource-highwater-key", TargetID: target.ID, AcceleratorID: target.AcceleratorID, Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "controller-adapter runtime=" + identity + " request=resource-highwater-key", Status: domain.ResidencyTransitionSucceeded, FencingToken: 1234, Error: "observed tier=hot_vram warm_model_bytes=0 locked_bytes=0 released_vram=false runtime=" + identity + " fence=1234", CreatedAt: now}
	if _, created, err := backing.CreateResidencyTransition(context.Background(), base); err != nil || !created {
		t.Fatalf("resource history insert: created=%v err=%v", created, err)
	}
	if got, err := backing.MaxResidencyFencingToken(context.Background(), target.ID, "model"); err != nil || got != 1234 {
		t.Fatalf("resource highwater included unrelated rows: got=%d err=%v", got, err)
	}
	fences := make([]int64, 0, 1)
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Store: backing, Command: func(_ context.Context, _ string, _ string, args map[string]any, _ string) (map[string]any, error) {
		fences = append(fences, args["fencing_token"].(int64))
		return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": identity, "fencing_token": args["fencing_token"], "tier": "hot_vram", "resident": true, "warm_ram": false}, nil
	}})
	if _, err := adapter.TransitionWithIdempotency(context.Background(), target, "model", domain.ResidencyHotVRAM, "resource-next"); err != nil {
		t.Fatal(err)
	}
	if len(fences) != 1 || fences[0] != 1235 {
		t.Fatalf("resource fence did not survive unrelated history: %v", fences)
	}

	pendingStore := store.NewMemoryStore()
	pending := &domain.ResidencyTransition{ID: "resource-pending", IdempotencyKey: durableRequestKey("pending-request"), TargetID: target.ID, AcceleratorID: target.AcceleratorID, Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "controller-adapter runtime=" + identity + " request=pending-request", Status: domain.ResidencyTransitionRunning, FencingToken: 77, CreatedAt: now}
	if _, created, err := pendingStore.CreateResidencyTransition(context.Background(), pending); err != nil || !created {
		t.Fatalf("pending history insert: created=%v err=%v", created, err)
	}
	blocked := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Store: pendingStore, Command: func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		t.Fatal("resource pending query dispatched a new command")
		return nil, nil
	}})
	var blocker *ResidencyAdapterError
	if _, err := blocked.TransitionWithIdempotency(context.Background(), target, "model", domain.ResidencyColdDisk, "other-request"); !errors.As(err, &blocker) || blocker.Code != ResidencyBlockerTransitionBusy {
		t.Fatalf("resource pending state was not preserved: %v", err)
	}
}

func TestResidencyTransitionCASRevisionFenceAndIdentity(t *testing.T) {
	backing := store.NewMemoryStore()
	row := &domain.ResidencyTransition{ID: "cas-transition", IdempotencyKey: "cas-key", TargetID: "target-a", AcceleratorID: "gpu-a", Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "operator", Status: domain.ResidencyTransitionPlanned, FencingToken: 4, CreatedAt: time.Now().UTC()}
	allocated, created, err := backing.AllocateResidencyTransition(context.Background(), row)
	if err != nil || !created || allocated.Revision != 1 {
		t.Fatalf("allocate CAS row: %+v created=%v err=%v", allocated, created, err)
	}
	allocated.Status = domain.ResidencyTransitionRunning
	updated, err := backing.CompareAndSwapResidencyTransition(context.Background(), allocated, 1, domain.ResidencyTransitionPlanned, 4)
	if err != nil || updated.Revision != 2 {
		t.Fatalf("first CAS did not advance revision: %+v err=%v", updated, err)
	}
	stale := *allocated
	stale.Status = domain.ResidencyTransitionSucceeded
	if _, err := backing.CompareAndSwapResidencyTransition(context.Background(), &stale, 1, domain.ResidencyTransitionPlanned, 4); !errors.Is(err, store.ErrResidencyTransitionConflict) {
		t.Fatalf("stale revision was accepted: %v", err)
	}
	identityMismatch := *updated
	identityMismatch.Model = "other-model"
	if _, err := backing.CompareAndSwapResidencyTransition(context.Background(), &identityMismatch, 2, domain.ResidencyTransitionRunning, 4); !errors.Is(err, store.ErrResidencyTransitionConflict) {
		t.Fatalf("canonical identity mutation was accepted: %v", err)
	}
}
