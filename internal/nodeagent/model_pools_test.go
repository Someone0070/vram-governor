package nodeagent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadModelPoolsKeepsValidPoolsOfAdvertisedModels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pools.json")
	if err := os.WriteFile(path, []byte(`{"a":{"pool_tokens":40000,"slots":4,"max_request_tokens":32768},"b":{"pool_tokens":0,"slots":4,"max_request_tokens":1},"gone":{"pool_tokens":9,"slots":1,"max_request_tokens":9}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	pools := readModelPools(path, []string{"a", "b"})
	if len(pools) != 1 || pools["a"].PoolTokens != 40000 || pools["a"].Slots != 4 || pools["a"].MaxRequestTokens != 32768 {
		t.Fatalf("pools = %+v", pools)
	}
	if readModelPools(filepath.Join(t.TempDir(), "missing.json"), []string{"a"}) != nil || readModelPools("", []string{"a"}) != nil {
		t.Fatal("a missing or unset file must advertise no pools")
	}
}
