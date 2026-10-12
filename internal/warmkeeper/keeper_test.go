package warmkeeper

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

const gib = int64(1) << 30

type fakeNode struct {
	t       *testing.T
	now     time.Time
	free    int64 // MemAvailable before pins
	sizes   map[string]int64
	inode   map[string]uint64
	loaded  string
	locked  map[string]int64
	pinErr  error
	onChunk func() // runs inside abort polling, e.g. to raise pressure mid-pin
	closes  int
}

type fakePin struct {
	n    *fakeNode
	path string
}

func (p *fakePin) Close() error { delete(p.n.locked, p.path); p.n.closes++; return nil }

func newFake(t *testing.T, sizes map[string]int64) *fakeNode {
	return &fakeNode{t: t, now: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC), free: 100 * gib, sizes: sizes, inode: map[string]uint64{}, locked: map[string]int64{}}
}

func (n *fakeNode) avail() int64 {
	a := n.free
	for _, b := range n.locked {
		a -= b
	}
	return a
}

func (n *fakeNode) keeper(cfg Config) *Keeper {
	if cfg.BudgetBytes == 0 {
		cfg.BudgetBytes = 40 * gib
	}
	if cfg.FloorBytes == 0 {
		cfg.FloorBytes = 16 * gib
	}
	cfg.PollEvery, cfg.Cooldown = time.Second, 2*time.Minute
	k := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func(path string, abort func() bool) (Pin, error) {
		if n.pinErr != nil {
			return nil, n.pinErr
		}
		for i := 0; i < 3; i++ {
			if n.onChunk != nil {
				n.onChunk()
			}
			if abort() {
				return nil, ErrAborted
			}
		}
		n.locked[path] = n.sizes[filepath.Base(path)]
		return &fakePin{n: n, path: path}, nil
	})
	k.now = func() time.Time { return n.now }
	k.memAvail = func() (int64, error) { return n.avail(), nil }
	k.stat = func(path string) (FileID, error) {
		return FileID{Path: path, Size: n.sizes[filepath.Base(path)], Inode: n.inode[path]}, nil
	}
	k.router = func(context.Context) ([]RouterModel, error) {
		ids := make([]string, 0, len(n.sizes))
		for id := range n.sizes {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out := []RouterModel{}
		for _, id := range ids {
			out = append(out, RouterModel{ID: id, Loaded: id == n.loaded, Files: []string{"/cache/" + id}})
		}
		return out, nil
	}
	return k
}

// use loads id on the router and advances time far enough for a poll and a
// distinct last-used timestamp, then runs ticks.
func (n *fakeNode) use(k *Keeper, id string, ticks int) {
	n.loaded = id
	for i := 0; i < ticks; i++ {
		n.now = n.now.Add(2 * time.Second)
		k.Tick(context.Background())
	}
}

func pinnedIDs(k *Keeper) []string {
	out := []string{}
	for id := range k.pins {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func TestKeeperPinsRecentModelsWithinBudget(t *testing.T) {
	n := newFake(t, map[string]int64{"big": 20 * gib, "big2": 21 * gib, "small": 4 * gib, "never": 3 * gib})
	k := n.keeper(Config{BudgetBytes: 44 * gib})
	n.use(k, "small", 2)
	n.use(k, "big", 2)
	n.use(k, "big2", 2)
	if got, want := pinnedIDs(k), []string{"big", "big2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pinned %v, want %v (most recent two fill the budget; small no longer fits)", got, want)
	}
	if _, ok := n.locked["/cache/small"]; ok {
		t.Fatal("small should have been released when newer models filled the budget")
	}
	n.use(k, "small", 2)
	// small (4) + big2 (21) fit; big (20) would exceed 44, so it is skipped,
	// never-used models are never pinned.
	if got, want := pinnedIDs(k), []string{"big2", "small"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pinned %v, want %v", got, want)
	}
}

func TestKeeperAlwaysModelsComeFirst(t *testing.T) {
	n := newFake(t, map[string]int64{"embed": 1 * gib, "chat": 30 * gib, "other": 15 * gib})
	k := n.keeper(Config{BudgetBytes: 32 * gib, Always: []string{"embed"}})
	n.use(k, "other", 3)
	n.use(k, "chat", 3)
	if got, want := pinnedIDs(k), []string{"chat", "embed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pinned %v, want %v", got, want)
	}
}

func TestKeeperReleasesUnderPressureAndWaitsOutCooldown(t *testing.T) {
	n := newFake(t, map[string]int64{"a": 10 * gib, "b": 10 * gib})
	k := n.keeper(Config{})
	n.use(k, "a", 2)
	n.use(k, "b", 3)
	if got := pinnedIDs(k); len(got) != 2 {
		t.Fatalf("pinned %v, want both", got)
	}
	n.free = 30 * gib // ComfyUI grabbed memory: 30 - 20 pinned = 10 < 16 floor
	n.use(k, "b", 1)
	if got, want := pinnedIDs(k), []string{"b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after pressure pinned %v, want %v (least recent released first)", got, want)
	}
	n.free = 100 * gib
	n.use(k, "b", 10) // 20 s: still inside the 2 minute cooldown
	if got := pinnedIDs(k); len(got) != 1 {
		t.Fatalf("re-pinned during cooldown: %v", got)
	}
	n.now = n.now.Add(2 * time.Minute)
	n.use(k, "b", 1)
	if got := pinnedIDs(k); len(got) != 2 {
		t.Fatalf("after cooldown pinned %v, want both", got)
	}
}

func TestKeeperNeedsHeadroomAndDoesNotSkipAhead(t *testing.T) {
	n := newFake(t, map[string]int64{"big": 20 * gib, "small": 2 * gib})
	k := n.keeper(Config{HeadroomBytes: 4 * gib})
	n.use(k, "small", 1)
	n.use(k, "big", 1)
	n.free = 38 * gib // big would leave 18 - small 2 = 16; needs 16 + 4
	for _, id := range []string{"small", "big"} {
		delete(n.locked, "/cache/"+id)
		delete(k.pins, id)
	}
	n.use(k, "big", 3)
	if got := pinnedIDs(k); len(got) != 0 {
		t.Fatalf("pinned %v; the higher-priority big model does not fit and must not be skipped", got)
	}
	n.free = 60 * gib
	n.use(k, "big", 3)
	if got, want := pinnedIDs(k), []string{"big", "small"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pinned %v, want %v", got, want)
	}
}

func TestKeeperAbortsPinWhenPressureArrivesMidway(t *testing.T) {
	n := newFake(t, map[string]int64{"a": 10 * gib})
	k := n.keeper(Config{})
	calls := 0
	n.onChunk = func() {
		calls++
		if calls == 2 {
			n.free = 10 * gib
		}
	}
	n.use(k, "a", 1)
	if len(k.pins) != 0 || len(n.locked) != 0 {
		t.Fatalf("aborted pin left state: pins=%v locked=%v", k.pins, n.locked)
	}
	if !k.cooldownUntil.After(n.now) {
		t.Fatal("aborted pin should start the cooldown")
	}
}

func TestKeeperRepinsWhenFileIsReplaced(t *testing.T) {
	n := newFake(t, map[string]int64{"a": 4 * gib})
	k := n.keeper(Config{})
	n.use(k, "a", 2)
	if len(k.pins) != 1 {
		t.Fatal("a not pinned")
	}
	n.inode["/cache/a"] = 99
	n.use(k, "a", 1)
	if n.closes != 1 {
		t.Fatalf("old pin closes = %d, want 1", n.closes)
	}
	n.use(k, "a", 1)
	if len(k.pins) != 1 || k.pins["a"].files[0].Inode != 99 {
		t.Fatalf("a not re-pinned with the new file: %+v", k.pins["a"])
	}
}

func TestKeeperRestoresRecentListAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	n := newFake(t, map[string]int64{"a": 4 * gib, "b": 4 * gib, "c": 4 * gib})
	k := n.keeper(Config{StatePath: filepath.Join(dir, "state.json"), StatusPath: filepath.Join(dir, "status.json")})
	n.use(k, "a", 2)
	n.use(k, "b", 2)
	k.releaseAll("shutdown")
	if len(n.locked) != 0 {
		t.Fatalf("shutdown left locks: %v", n.locked)
	}
	n.loaded = ""
	k2 := n.keeper(Config{StatePath: filepath.Join(dir, "state.json"), StatusPath: filepath.Join(dir, "status.json")})
	k2.loadState()
	n.use(k2, "", 3)
	if got, want := pinnedIDs(k2), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after restart pinned %v, want %v", got, want)
	}
	st := k2.Status()
	if st.PinnedBytes != 8*gib || len(st.Models) != 3 {
		t.Fatalf("status = %+v", st)
	}
}

func TestFetchRouterModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": []any{
			map[string]any{"id": "vl", "status": map[string]any{"value": "loaded", "args": []string{"llama-server", "--model", "/m/vl.gguf", "--mmproj", "/m/vl.mmproj.gguf", "--port", "0"}}},
			map[string]any{"id": "txt", "status": map[string]any{"value": "unloaded", "args": []string{"--model", "/m/txt.gguf"}}},
		}})
	}))
	defer srv.Close()
	got, err := fetchRouterModels(context.Background(), srv.Client(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	want := []RouterModel{{ID: "vl", Loaded: true, Files: []string{"/m/vl.gguf", "/m/vl.mmproj.gguf"}}, {ID: "txt", Files: []string{"/m/txt.gguf"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestParseBytes(t *testing.T) {
	for in, want := range map[string]int64{"44GiB": 44 * gib, "16G": 16 * gib, "512MiB": 512 << 20, "1024": 1024, " 2 TiB ": 2 << 40} {
		got, err := ParseBytes(in)
		if err != nil || got != want {
			t.Errorf("ParseBytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-1G", "1.5G", "G", "12XB", "99999999999T"} {
		if _, err := ParseBytes(bad); err == nil {
			t.Errorf("ParseBytes(%q) accepted", bad)
		}
	}
}
