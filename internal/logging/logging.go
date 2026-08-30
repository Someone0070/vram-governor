// Package logging provides a single shared structured-logging setup
// (stdlib log/slog) used by both the controller and the node agent.
package logging

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"
)

type Entry struct {
	Timestamp  time.Time
	Level      string
	Message    string
	Attributes map[string]any
}

type Buffer struct {
	mu      sync.RWMutex
	entries []Entry
	limit   int
}

func (b *Buffer) add(entry Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, entry)
	if len(b.entries) > b.limit {
		b.entries = append([]Entry(nil), b.entries[len(b.entries)-b.limit:]...)
	}
}

func (b *Buffer) Snapshot() []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	rows := make([]Entry, len(b.entries))
	copy(rows, b.entries)
	return rows
}

type bufferedHandler struct {
	slog.Handler
	buffer *Buffer
	attrs  []slog.Attr
}

func (h *bufferedHandler) Handle(ctx context.Context, record slog.Record) error {
	attributes := make(map[string]any)
	for _, attr := range h.attrs {
		attributes[attr.Key] = attr.Value.Any()
	}
	record.Attrs(func(attr slog.Attr) bool {
		attributes[attr.Key] = attr.Value.Any()
		return true
	})
	h.buffer.add(Entry{Timestamp: record.Time.UTC(), Level: record.Level.String(), Message: record.Message, Attributes: attributes})
	return h.Handler.Handle(ctx, record)
}

func (h *bufferedHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &bufferedHandler{Handler: h.Handler.WithAttrs(attrs), buffer: h.buffer, attrs: append(append([]slog.Attr(nil), h.attrs...), attrs...)}
}

func (h *bufferedHandler) WithGroup(name string) slog.Handler {
	return &bufferedHandler{Handler: h.Handler.WithGroup(name), buffer: h.buffer, attrs: append([]slog.Attr(nil), h.attrs...)}
}

// New returns a JSON structured logger writing to stderr at the given level
// ("debug", "info", "warn", "error"; defaults to info on parse failure).
func New(component string, level string) *slog.Logger {
	logger, _ := NewBuffered(component, level, 0)
	return logger
}

// NewBuffered writes normal structured logs and retains a bounded structured
// copy for the authenticated operator console.
func NewBuffered(component string, level string, limit int) (*slog.Logger, *Buffer) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	if limit <= 0 {
		limit = 200
	}
	buffer := &Buffer{limit: limit}
	base := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	h := &bufferedHandler{Handler: base, buffer: buffer}
	return slog.New(h).With("component", component), buffer
}
