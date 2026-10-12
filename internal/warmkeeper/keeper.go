// Package warmkeeper keeps recently used llama.cpp router model files pinned
// in host RAM (the Linux page cache) so a model evicted from VRAM reloads from
// memory instead of disk. On CT200 a 19 GiB model loads in ~8 s from the page
// cache and ~40 s from NVMe; without pinning, large ComfyUI model reads push
// LLM files out of the cache between uses.
//
// The keeper is node-local and advisory: it never loads or unloads models and
// gives memory back (least recently used first) as soon as MemAvailable drops
// below the configured floor.
package warmkeeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrAborted is returned by a Pinner when the abort callback stopped a pin.
var ErrAborted = errors.New("pin aborted under memory pressure")

// Pin holds one file's pages locked in memory until Close.
type Pin interface {
	Close() error
}

// Pinner locks a whole file in memory. abort is polled between chunks; when it
// returns true the pinner releases what it locked and returns ErrAborted.
type Pinner func(path string, abort func() bool) (Pin, error)

// FileID identifies the file contents a pin covers; a change means the model
// cache replaced the file and the old pages must be released.
type FileID struct {
	Path  string
	Size  int64
	Mtime int64
	Inode uint64
}

// RouterModel is the subset of the llama.cpp router /models entry the keeper
// needs.
type RouterModel struct {
	ID     string
	Loaded bool
	Files  []string
}

type Config struct {
	RouterURL     string
	BudgetBytes   int64
	FloorBytes    int64 // release pins while MemAvailable is below this
	HeadroomBytes int64 // a new pin must leave MemAvailable >= floor + headroom
	Always        []string
	StatePath     string
	StatusPath    string
	PollEvery     time.Duration
	TickEvery     time.Duration
	Cooldown      time.Duration
}

type model struct {
	ID       string    `json:"id"`
	LastUsed time.Time `json:"last_used"`
	files    []FileID
	bytes    int64
	present  bool
}

type pinned struct {
	files []FileID
	pins  []Pin
	bytes int64
	since time.Time
}

type Keeper struct {
	cfg      Config
	log      *slog.Logger
	pin      Pinner
	memAvail func() (int64, error)
	router   func(context.Context) ([]RouterModel, error)
	stat     func(string) (FileID, error)
	now      func() time.Time

	models        map[string]*model
	pins          map[string]*pinned
	cooldownUntil time.Time
	lastPoll      time.Time
	lastEvent     string
	dirty         bool
}

func New(cfg Config, log *slog.Logger, pin Pinner) *Keeper {
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = 2 * time.Second
	}
	if cfg.TickEvery <= 0 {
		cfg.TickEvery = time.Second
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 2 * time.Minute
	}
	k := &Keeper{cfg: cfg, log: log, pin: pin, memAvail: MemAvailable, stat: statFile, now: time.Now,
		models: map[string]*model{}, pins: map[string]*pinned{}}
	client := &http.Client{Timeout: 3 * time.Second}
	k.router = func(ctx context.Context) ([]RouterModel, error) { return fetchRouterModels(ctx, client, cfg.RouterURL) }
	return k
}

// Run ticks until ctx ends, then releases every pin.
func (k *Keeper) Run(ctx context.Context) error {
	k.loadState()
	t := time.NewTicker(k.cfg.TickEvery)
	defer t.Stop()
	defer k.releaseAll("shutdown")
	for {
		k.Tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Tick performs one reconcile step: observe the router, honour memory
// pressure, drop pins that fell out of the desired set, and add at most one.
func (k *Keeper) Tick(ctx context.Context) {
	now := k.now()
	if k.lastPoll.IsZero() || now.Sub(k.lastPoll) >= k.cfg.PollEvery {
		k.lastPoll = now
		k.observe(ctx, now)
	}
	defer k.writeStatus()
	avail, err := k.memAvail()
	if err != nil {
		k.log.Warn("read MemAvailable failed", "err", err)
		return
	}
	if avail < k.cfg.FloorBytes {
		if victim := k.lowestPriorityPin(); victim != "" {
			k.release(victim, fmt.Sprintf("memory pressure: MemAvailable %s below floor %s", human(avail), human(k.cfg.FloorBytes)))
			k.cooldownUntil = now.Add(k.cfg.Cooldown)
		}
		return
	}
	desired := k.desired()
	want := map[string]bool{}
	for _, id := range desired {
		want[id] = true
	}
	for id, p := range k.pins {
		if !want[id] {
			k.release(id, "no longer in the warm set")
			continue
		}
		if m := k.models[id]; m != nil && !sameFiles(p.files, m.files) {
			k.release(id, "model file changed on disk")
		}
	}
	if now.Before(k.cooldownUntil) {
		return
	}
	for _, id := range desired {
		if _, ok := k.pins[id]; ok {
			continue
		}
		m := k.models[id]
		if avail-m.bytes < k.cfg.FloorBytes+k.cfg.HeadroomBytes {
			return // wait for memory; never skip ahead to a lower-priority model
		}
		k.pinModel(m, now)
		return
	}
}

func (k *Keeper) observe(ctx context.Context, now time.Time) {
	list, err := k.router(ctx)
	if err != nil {
		k.log.Warn("query llama.cpp router failed", "err", err)
		return
	}
	seen := map[string]bool{}
	for _, rm := range list {
		seen[rm.ID] = true
		m := k.models[rm.ID]
		if m == nil {
			m = &model{ID: rm.ID}
			k.models[rm.ID] = m
		}
		files := make([]FileID, 0, len(rm.Files))
		var total int64
		for _, path := range rm.Files {
			id, err := k.stat(path)
			if err != nil {
				files = nil
				break
			}
			files = append(files, id)
			total += id.Size
		}
		m.present = len(files) > 0
		m.files, m.bytes = files, total
		if rm.Loaded && m.present {
			if now.Sub(m.LastUsed) >= time.Second {
				k.dirty = true
			}
			m.LastUsed = now
		}
	}
	for id, m := range k.models {
		if !seen[id] {
			m.present = false
		}
	}
	if k.dirty {
		k.saveState()
	}
}

// desired returns the models to keep pinned in priority order: the configured
// always-warm models, then everything ever loaded, most recent first, as long
// as the running total fits the budget. A model too large for the remaining
// budget is skipped so smaller recent models can still fit.
func (k *Keeper) desired() []string {
	order := make([]*model, 0, len(k.models))
	rank := map[string]int{}
	for i, id := range k.cfg.Always {
		rank[id] = i + 1
	}
	for _, m := range k.models {
		if m.present && m.bytes > 0 && (rank[m.ID] > 0 || !m.LastUsed.IsZero()) {
			order = append(order, m)
		}
	}
	sort.Slice(order, func(i, j int) bool {
		ri, rj := rank[order[i].ID], rank[order[j].ID]
		if (ri > 0) != (rj > 0) {
			return ri > 0
		}
		if ri != rj {
			return ri < rj
		}
		if !order[i].LastUsed.Equal(order[j].LastUsed) {
			return order[i].LastUsed.After(order[j].LastUsed)
		}
		return order[i].ID < order[j].ID
	})
	var used int64
	out := []string{}
	for _, m := range order {
		if used+m.bytes > k.cfg.BudgetBytes {
			continue
		}
		used += m.bytes
		out = append(out, m.ID)
	}
	return out
}

func (k *Keeper) lowestPriorityPin() string {
	desired := k.desired()
	pos := map[string]int{}
	for i, id := range desired {
		pos[id] = i
	}
	victim, worst := "", -1
	for id := range k.pins {
		p, ok := pos[id]
		if !ok {
			return id
		}
		if p > worst {
			victim, worst = id, p
		}
	}
	return victim
}

func (k *Keeper) pinModel(m *model, now time.Time) {
	start := k.now()
	abort := func() bool {
		avail, err := k.memAvail()
		return err != nil || avail < k.cfg.FloorBytes
	}
	p := &pinned{files: append([]FileID(nil), m.files...), bytes: m.bytes, since: now}
	for _, f := range m.files {
		pin, err := k.pin(f.Path, abort)
		if err != nil {
			for _, done := range p.pins {
				_ = done.Close()
			}
			if errors.Is(err, ErrAborted) {
				k.cooldownUntil = k.now().Add(k.cfg.Cooldown)
			}
			k.event(fmt.Sprintf("pin %s failed: %v", m.ID, err))
			k.log.Warn("pin model failed", "model", m.ID, "err", err)
			return
		}
		p.pins = append(p.pins, pin)
	}
	k.pins[m.ID] = p
	k.event(fmt.Sprintf("pinned %s (%s) in %s", m.ID, human(m.bytes), k.now().Sub(start).Round(100*time.Millisecond)))
	k.log.Info("pinned model in RAM", "model", m.ID, "bytes", m.bytes, "took", k.now().Sub(start).String())
}

func (k *Keeper) release(id, reason string) {
	p := k.pins[id]
	if p == nil {
		return
	}
	for _, pin := range p.pins {
		if err := pin.Close(); err != nil {
			k.log.Warn("release pin failed", "model", id, "err", err)
		}
	}
	delete(k.pins, id)
	k.event(fmt.Sprintf("released %s: %s", id, reason))
	k.log.Info("released model pin", "model", id, "bytes", p.bytes, "reason", reason)
}

func (k *Keeper) releaseAll(reason string) {
	for id := range k.pins {
		k.release(id, reason)
	}
	k.writeStatus()
}

func (k *Keeper) event(s string) { k.lastEvent = k.now().UTC().Format(time.RFC3339) + " " + s }

func sameFiles(a, b []FileID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type persisted struct {
	Models []model `json:"models"`
}

func (k *Keeper) loadState() {
	if k.cfg.StatePath == "" {
		return
	}
	b, err := os.ReadFile(k.cfg.StatePath)
	if err != nil {
		return
	}
	var st persisted
	if json.Unmarshal(b, &st) != nil {
		k.log.Warn("ignoring unreadable state file", "path", k.cfg.StatePath)
		return
	}
	for _, m := range st.Models {
		if m.ID != "" {
			k.models[m.ID] = &model{ID: m.ID, LastUsed: m.LastUsed}
		}
	}
}

func (k *Keeper) saveState() {
	k.dirty = false
	if k.cfg.StatePath == "" {
		return
	}
	st := persisted{}
	for _, m := range k.models {
		if !m.LastUsed.IsZero() {
			st.Models = append(st.Models, model{ID: m.ID, LastUsed: m.LastUsed})
		}
	}
	sort.Slice(st.Models, func(i, j int) bool { return st.Models[i].ID < st.Models[j].ID })
	if err := writeFileAtomic(k.cfg.StatePath, st); err != nil {
		k.log.Warn("save state failed", "err", err)
	}
}

// Status is written to StatusPath every tick for operators and the node agent.
type Status struct {
	Updated       time.Time     `json:"updated"`
	BudgetBytes   int64         `json:"budget_bytes"`
	PinnedBytes   int64         `json:"pinned_bytes"`
	FloorBytes    int64         `json:"floor_bytes"`
	MemAvailable  int64         `json:"mem_available_bytes"`
	CooldownUntil *time.Time    `json:"cooldown_until,omitempty"`
	LastEvent     string        `json:"last_event,omitempty"`
	Models        []ModelStatus `json:"models"`
}

type ModelStatus struct {
	ID       string     `json:"id"`
	Bytes    int64      `json:"bytes"`
	Pinned   bool       `json:"pinned"`
	Desired  bool       `json:"desired"`
	LastUsed *time.Time `json:"last_used,omitempty"`
}

func (k *Keeper) Status() Status {
	avail, _ := k.memAvail()
	st := Status{Updated: k.now().UTC(), BudgetBytes: k.cfg.BudgetBytes, FloorBytes: k.cfg.FloorBytes, MemAvailable: avail, LastEvent: k.lastEvent}
	if k.now().Before(k.cooldownUntil) {
		c := k.cooldownUntil.UTC()
		st.CooldownUntil = &c
	}
	want := map[string]bool{}
	for _, id := range k.desired() {
		want[id] = true
	}
	for _, m := range k.models {
		if !m.present && k.pins[m.ID] == nil {
			continue
		}
		ms := ModelStatus{ID: m.ID, Bytes: m.bytes, Pinned: k.pins[m.ID] != nil, Desired: want[m.ID]}
		if !m.LastUsed.IsZero() {
			t := m.LastUsed.UTC()
			ms.LastUsed = &t
		}
		if ms.Pinned {
			st.PinnedBytes += k.pins[m.ID].bytes
		}
		st.Models = append(st.Models, ms)
	}
	sort.Slice(st.Models, func(i, j int) bool { return st.Models[i].ID < st.Models[j].ID })
	return st
}

func (k *Keeper) writeStatus() {
	if k.cfg.StatusPath == "" {
		return
	}
	if err := writeFileAtomic(k.cfg.StatusPath, k.Status()); err != nil {
		k.log.Warn("write status failed", "err", err)
	}
}

func writeFileAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func fetchRouterModels(ctx context.Context, client *http.Client, base string) ([]RouterModel, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/models", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("router /models returned HTTP %d", resp.StatusCode)
	}
	var body struct {
		Data []struct {
			ID     string `json:"id"`
			Status struct {
				Value string   `json:"value"`
				Args  []string `json:"args"`
			} `json:"status"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode router /models: %w", err)
	}
	out := make([]RouterModel, 0, len(body.Data))
	for _, d := range body.Data {
		rm := RouterModel{ID: d.ID, Loaded: d.Status.Value == "loaded" || d.Status.Value == "loading"}
		args := d.Status.Args
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "--model" || args[i] == "-m" || args[i] == "--mmproj" {
				rm.Files = append(rm.Files, args[i+1])
			}
		}
		out = append(out, rm)
	}
	return out, nil
}

// ParseBytes accepts a plain byte count or a number with a KiB/MiB/GiB/TiB
// (or K/M/G/T) suffix.
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mult
			break
		}
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n < 0 || fmt.Sprint(n) != s {
		return 0, fmt.Errorf("invalid byte size %q", s)
	}
	if n > (1<<62)/mult {
		return 0, fmt.Errorf("byte size %q is too large", s)
	}
	return n * mult, nil
}

func human(n int64) string { return fmt.Sprintf("%.1fGiB", float64(n)/(1<<30)) }
