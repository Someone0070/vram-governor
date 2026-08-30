package nodeagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAgentConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node-agent.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNodeConfigRequiresCredentialsAndSafeWSSSecrets(t *testing.T) {
	if _, err := LoadConfig(writeAgentConfig(t, "controller_url: ws://127.0.0.1/ws/node\nnode_id: node-a\n")); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("credential-free node config was accepted: %v", err)
	}
	t.Setenv("TEST_NODE_TOKEN", "node-token")
	t.Setenv("TEST_NODE_COMMAND", strings.Repeat("s", 32))
	config, err := LoadConfig(writeAgentConfig(t, `controller_url: wss://controller.example/ws/node
token_env: TEST_NODE_TOKEN
node_id: node-a
command_signing_secret_env: TEST_NODE_COMMAND
`))
	if err != nil || config.Token != "node-token" || len(config.CommandSigningSecret) != 32 {
		t.Fatalf("valid wss node config rejected: %+v err=%v", config, err)
	}
	if _, err := LoadConfig(writeAgentConfig(t, `controller_url: wss://controller.example/ws/node
token: literal
node_id: node-a
command_signing_secret_env: TEST_NODE_COMMAND
`)); err == nil || !strings.Contains(err.Error(), "token_env") {
		t.Fatalf("literal production node token was accepted: %v", err)
	}
}

func TestNodeConfigRejectsReconnectStormSettings(t *testing.T) {
	_, err := LoadConfig(writeAgentConfig(t, `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
reconnect_min_seconds: 10
reconnect_max_seconds: 2
`))
	if err == nil || !strings.Contains(err.Error(), "reconnect_max_seconds") {
		t.Fatalf("unsafe reconnect range accepted: %v", err)
	}
}
