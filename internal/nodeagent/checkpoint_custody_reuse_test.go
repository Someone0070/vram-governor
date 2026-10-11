package nodeagent

import (
	"context"
	"strings"
	"testing"
)

func TestCheckpointCustodyReuseRejectsUnboundedAndForgedSourceRequests(t *testing.T) {
	s := &CheckpointCustodyStore{maxBytes: 32}
	if _, err := s.PrepareReusable(context.Background(), CheckpointCustodySource{Path: "/tmp/model", ApprovedSHA256: "not-a-digest", ExpectedBytes: 1}); err == nil {
		t.Fatal("accepted malformed reusable allowlist digest")
	}
	if _, err := s.PrepareReusable(context.Background(), CheckpointCustodySource{Path: "/tmp/model", ApprovedSHA256: strings.Repeat("a", 64), ExpectedBytes: 33}); err == nil {
		t.Fatal("accepted reusable source above explicit byte quota")
	}
	if _, err := s.PrepareReusable(context.Background(), CheckpointCustodySource{Path: "/tmp/model", ApprovedSHA256: strings.Repeat("a", 64), ExpectedBytes: 1}); err == nil {
		t.Fatal("accepted reusable source without an initialized custody store")
	}
}
