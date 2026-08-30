package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSampleControllerConfigParsesResidencyPolicy(t *testing.T) {
	config, err := LoadConfig("../../configs/controller.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if config.Workloads.Residency.Enabled == nil || !*config.Workloads.Residency.Enabled {
		t.Fatal("sample config should enable residency reconciliation")
	}
	if config.Workloads.Residency.IdleUnloadSeconds != 900 || config.Workloads.Residency.MinResidencySeconds != 300 {
		t.Fatalf("unexpected residency defaults: %+v", config.Workloads.Residency)
	}
}

func TestDevelopmentTLSRequiresCertificateAndKeyTogether(t *testing.T) {
	valid := `listen_addr: ":8443"
tls_cert_file: "controller.crt"
tls_key_file: "controller.key"
auth:
  credentials: []
workloads:
  artifact_store:
    type: "filesystem"
`
	if _, err := LoadConfig(writeConfig(t, valid)); err != nil {
		t.Fatalf("development TLS configuration was rejected: %v", err)
	}

	missingKey := strings.Replace(valid, "tls_key_file: \"controller.key\"\n", "", 1)
	if _, err := LoadConfig(writeConfig(t, missingKey)); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("unpaired development TLS certificate was accepted: %v", err)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func productionConfig(adminCIDR string) string {
	return `production: true
listen_addr: ":8443"
tls_cert_file: "controller.crt"
tls_key_file: "controller.key"
database_url: "postgres://controller@example/controller"
auth:
  command_signing_secret_env: "TEST_NODE_COMMAND_SECRET"
  admin_private_cidrs: ["` + adminCIDR + `"]
  credentials:
    - id: "operator"
      token_sha256: "` + strings.Repeat("ab", 32) + `"
      plane: "admin"
      owner_id: "ops"
      scopes: ["*"]
      adapters: ["*"]
      max_priority: 100
      egress_policy: "cloud_allowed"
workloads:
  artifact_store:
    type: "s3"
    endpoint: "https://objects.example.test"
    bucket: "vram"
    access_key_env: "TEST_S3_ACCESS"
    secret_key_env: "TEST_S3_SECRET"
`
}

func TestProductionConfigRequiresPrivateAdminNetworkAndCommandSecret(t *testing.T) {
	t.Setenv("TEST_NODE_COMMAND_SECRET", strings.Repeat("s", 32))
	if _, err := LoadConfig(writeConfig(t, productionConfig("10.10.0.0/16"))); err != nil {
		t.Fatalf("valid production security configuration rejected: %v", err)
	}
	if _, err := LoadConfig(writeConfig(t, productionConfig("0.0.0.0/0"))); err == nil || !strings.Contains(err.Error(), "private or loopback") {
		t.Fatalf("public admin network was not rejected: %v", err)
	}
	t.Setenv("TEST_NODE_COMMAND_SECRET", "short")
	if _, err := LoadConfig(writeConfig(t, productionConfig("10.10.0.0/16"))); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("weak production command secret was not rejected: %v", err)
	}
}

func TestProductionConfigRejectsDevelopmentBypass(t *testing.T) {
	t.Setenv("TEST_NODE_COMMAND_SECRET", strings.Repeat("s", 32))
	body := strings.Replace(productionConfig("10.10.0.0/16"), "auth:\n", "auth:\n  development_bypass: true\n", 1)
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "development_bypass") {
		t.Fatalf("production development bypass was not rejected: %v", err)
	}
}

func TestCredentialValidationRejectsInvalidPlaneAndDigest(t *testing.T) {
	body := `auth:
  credentials:
    - id: "bad"
      token_sha256: "not-a-digest"
      plane: "side-door"
      owner_id: "owner"
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil {
		t.Fatal("invalid credential plane and digest were accepted")
	}
}
