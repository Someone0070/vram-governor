package nodeagent

import "testing"

func TestRouterProfileContextLimitIgnoresModelCappedContext(t *testing.T) {
	profiles := []RuntimeProfileConfig{{ID: "ctx-8k-4", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k-1", ContextLimit: 32768, Slots: 1}}
	cases := []struct{ ctx, slots, want int }{
		{8192, 4, 8192},   // exact profile
		{2048, 4, 8192},   // embedding model capped below ctx-8k-4
		{32768, 1, 32768}, // exact profile
		{2048, 1, 32768},  // capped below ctx-32k-1
		{2048, 2, 2048},   // no profile with 2 slots: unchanged
		{16384, 4, 16384}, // larger than the profile: not a cap, unchanged
	}
	for _, c := range cases {
		if got := routerProfileContextLimit(profiles, c.ctx, c.slots); got != c.want {
			t.Errorf("ctx=%d slots=%d: got %d want %d", c.ctx, c.slots, got, c.want)
		}
	}
	ambiguous := append(profiles, RuntimeProfileConfig{ID: "ctx-16k-4", ContextLimit: 16384, Slots: 4})
	if got := routerProfileContextLimit(ambiguous, 2048, 4); got != 2048 {
		t.Errorf("ambiguous profiles must keep the observation, got %d", got)
	}
}
