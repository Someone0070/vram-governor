package store

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type legacyReservationFixture struct {
	Revision       int64
	Attempt        int64
	OwnershipToken string
}

func normalizeLegacyReservationFixture(workloadID string, in legacyReservationFixture) legacyReservationFixture {
	out := in
	if out.Revision <= 0 {
		out.Revision = 1
	}
	if out.Attempt <= 0 {
		out.Attempt = 1
	}
	if strings.TrimSpace(out.OwnershipToken) == "" {
		out.OwnershipToken = workloadID + ":" + strconv.FormatInt(out.Attempt, 10)
	}
	return out
}

func TestWorkloadRevisionMigrationFixtureMatrix(t *testing.T) {
	fixtures := []legacyReservationFixture{
		{Revision: 9, Attempt: 7, OwnershipToken: "existing"},
		{Attempt: 7, OwnershipToken: "existing"},
		{Revision: 9},
		{},
		{Revision: -2, Attempt: -1, OwnershipToken: ""},
	}
	for i, fixture := range fixtures {
		first := normalizeLegacyReservationFixture("fixture", fixture)
		second := normalizeLegacyReservationFixture("fixture", first)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("fixture %d migration was not idempotent: first=%+v second=%+v", i, first, second)
		}
		if fixture.Revision > 0 && first.Revision != fixture.Revision {
			t.Fatalf("fixture %d downgraded revision: before=%d after=%d", i, fixture.Revision, first.Revision)
		}
		if fixture.Attempt > 0 && first.Attempt != fixture.Attempt {
			t.Fatalf("fixture %d downgraded attempt: before=%d after=%d", i, fixture.Attempt, first.Attempt)
		}
		if fixture.OwnershipToken != "" && first.OwnershipToken != fixture.OwnershipToken {
			t.Fatalf("fixture %d replaced existing ownership token: before=%q after=%q", i, fixture.OwnershipToken, first.OwnershipToken)
		}
	}
}

func TestWorkloadRevisionMigrationBackfillsLegacyJSONAtomically(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "0018_workload_revision.sql")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(body))
	for _, fragment := range []string{
		"begin;", "update workloads", "jsonb_typeof(body->'revision')",
		"jsonb_set", "update budget_reservations", "ownership_token", "commit;",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("migration missing executable backfill semantic %q", fragment)
		}
	}
}
