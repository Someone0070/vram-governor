package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestModelCapacityRoundTripPreservesExactInt64Bytes(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	want := &ModelCapacity{
		TargetID: "target-16", AcceleratorID: "accel-0", Model: "model-a", ProfileID: "ctx-8k",
		ModelBytes: 10*1024*1024*1024 + 17, ProfileBytes: 512*1024*1024 + 19,
		VRAMReserveBytes: 384*1024*1024 + 23, RuntimeHardCapBytes: 16*1024*1024*1024 - 29,
		RAMBytes: 2*1024*1024*1024 + 31, RAMReserveBytes: 128*1024*1024 + 37,
		Verified: true, UpdatedAt: time.Unix(1712345678, 123).UTC(),
	}
	stored, err := s.UpsertModelCapacity(ctx, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetModelCapacity(ctx, want.TargetID, want.Model, want.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ModelBytes != want.ModelBytes || got.ProfileBytes != want.ProfileBytes || got.VRAMReserveBytes != want.VRAMReserveBytes || got.RuntimeHardCapBytes != want.RuntimeHardCapBytes || got.RAMBytes != want.RAMBytes || got.RAMReserveBytes != want.RAMReserveBytes || got.Revision != stored.Revision || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Fatalf("capacity round trip changed exact bytes: want=%+v got=%+v", want, got)
	}
	if got.FootprintBytes() != want.ModelBytes+want.ProfileBytes {
		t.Fatalf("footprint mismatch: want=%d got=%d", want.ModelBytes+want.ProfileBytes, got.FootprintBytes())
	}
	if _, err := s.UpsertModelCapacity(ctx, &ModelCapacity{TargetID: "target-16", Model: "model-b", ModelBytes: 1, ProfileBytes: 2}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListModelCapacities(ctx, "target-16", "")
	if err != nil || len(rows) != 2 {
		t.Fatalf("capacity listing failed: rows=%v err=%v", rows, err)
	}
}

type fakeCapacityRow struct{ revision uint64 }

func (r fakeCapacityRow) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("fake row expected one destination")
	}
	value, ok := dest[0].(*uint64)
	if !ok {
		return errors.New("fake row expected revision destination")
	}
	*value = r.revision
	return nil
}

type fakeCapacityResult struct{}

func (fakeCapacityResult) LastInsertId() (int64, error) { return 0, nil }
func (fakeCapacityResult) RowsAffected() (int64, error) { return 1, nil }

type fakeCapacityTx struct {
	queryCalls    int
	execCalls     int
	commitCalls   int
	rollback      int
	failExec      bool
	pending       bool
	committed     bool
	revisionArg   any
	committedRows int
}

func (tx *fakeCapacityTx) QueryRowContext(context.Context, string, ...any) modelCapacityRow {
	tx.queryCalls++
	tx.pending = true // first statement stages the INSERT/UPSERT, not durable state
	return fakeCapacityRow{revision: 7}
}

func (tx *fakeCapacityTx) ExecContext(_ context.Context, _ string, args ...any) (sql.Result, error) {
	tx.execCalls++
	if tx.failExec {
		return nil, errors.New("injected json revision write failure")
	}
	if len(args) == 0 {
		return nil, errors.New("revision update omitted arguments")
	}
	tx.revisionArg = args[len(args)-1]
	tx.pending = true
	return fakeCapacityResult{}, nil
}

func (tx *fakeCapacityTx) Commit() error {
	tx.commitCalls++
	tx.committed = true
	if tx.pending {
		tx.committedRows++
	}
	return nil
}

func (tx *fakeCapacityTx) Rollback() error {
	tx.rollback++
	if !tx.committed {
		tx.pending = false
		tx.committedRows = 0
	}
	return nil
}

func TestPostgresModelCapacityUpsertUsesOneTransaction(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		failExec bool
		wantErr  bool
	}{
		{name: "commit", wantErr: false},
		{name: "rollback on JSON revision failure", failExec: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &fakeCapacityTx{failExec: tc.failExec}
			p := &PostgresWorkloadStore{modelCapacityBeginTx: func(context.Context) (modelCapacityTx, error) { return tx, nil }}
			capacity := &ModelCapacity{TargetID: "target", Model: "model", ModelBytes: 17, ProfileBytes: 19, UpdatedAt: time.Now().UTC(), ObservedAt: time.Now().UTC()}
			got, err := p.UpsertModelCapacity(ctx, capacity)
			if (err != nil) != tc.wantErr {
				t.Fatalf("upsert error=%v wantErr=%t", err, tc.wantErr)
			}
			if tx.queryCalls != 1 || tx.execCalls != 1 || tx.rollback != 1 {
				t.Fatalf("transaction statements mismatch: tx=%+v", tx)
			}
			if tc.wantErr {
				if tx.commitCalls != 0 || tx.committed || tx.pending {
					t.Fatalf("failed second write left partial state: tx=%+v", tx)
				}
				return
			}
			if tx.commitCalls != 1 || !tx.committed || !tx.pending || tx.committedRows != 1 || got == nil || got.Revision != 7 || tx.revisionArg != uint64(7) {
				t.Fatalf("successful transaction did not commit one CAS revision: tx=%+v got=%+v", tx, got)
			}
		})
	}
}
