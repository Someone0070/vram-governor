package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPrepareControllerCheckConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.yaml")
	body := []byte("listen_addr: \":9443\"\nauth:\n  credentials: []\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	cfg, checked, err := prepareController([]string{"-config", path, "-check-config"}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !checked {
		t.Fatal("check-config did not stop before service startup")
	}
	if cfg.ListenAddr != ":9443" || !strings.Contains(stdout.String(), "configuration valid") {
		t.Fatalf("unexpected check result: addr=%q output=%q", cfg.ListenAddr, stdout.String())
	}
}

func TestPrepareControllerRejectsUnexpectedArguments(t *testing.T) {
	if _, _, err := prepareController([]string{"unexpected"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unexpected positional argument was accepted")
	}
}

func TestPrepareControllerDefaultsResidencyContractAndSingleAccelerator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(path, []byte("auth:\n  credentials: []\nworkloads:\n  capacity:\n    vram_total_bytes: 1000\n    vram_reserve_bytes: 100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, checked, err := prepareController([]string{"-config", path, "-check-config"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil || !checked {
		t.Fatalf("contract config rejected: checked=%v err=%v", checked, err)
	}
	if cfg.Workloads.MaxAcceleratorsPerWorkload != 1 || cfg.Workloads.CapabilityVersion == "" || cfg.Workloads.Capacity.VRAMHardCapBytes != 1000 {
		t.Fatalf("unsafe or implicit defaults: %+v", cfg.Workloads)
	}
}

func TestDedicatedControllerTemplateMaterializesAsProductionConfig(t *testing.T) {
	templatePath := filepath.Join("..", "..", "deploy", "controller", "controller.yaml.template")
	body, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	replacements := map[string]string{
		"__ADMIN_PRIVATE_CIDR__":            "10.42.0.0/24",
		"__S3_HTTPS_ENDPOINT__":             "https://objects.example.test",
		"__S3_BUCKET__":                     "vram-artifacts",
		"__S3_REGION__":                     "us-east-1",
		"__CMP170_MANAGED_HTTPS_ENDPOINT__": "https://cmp170.example.test:8190",
		"__CMP170_VIDEO_MODEL__":            "video-model.safetensors",
		"__OPENROUTER_MODEL__":              "example/free-model",
		"__OPENROUTER_PROVIDER__":           "example",
	}
	digest := strings.Repeat("ab", 32)
	placeholder := regexp.MustCompile(`__[A-Z0-9_]+__`)
	materialized := placeholder.ReplaceAllStringFunc(string(body), func(value string) string {
		if replacement, ok := replacements[value]; ok {
			return replacement
		}
		if strings.HasSuffix(value, "_TOKEN_SHA256__") {
			return digest
		}
		return value
	})
	if unresolved := placeholder.FindString(materialized); unresolved != "" {
		t.Fatalf("test does not know how to materialize %s", unresolved)
	}
	path := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(path, []byte(materialized), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VRAM_NODE_COMMAND_SECRET", strings.Repeat("s", 32))
	var stdout bytes.Buffer
	cfg, checked, err := prepareController([]string{"-config", path, "-check-config"}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !checked || !cfg.Production || cfg.Workloads.ArtifactStore.Type != "s3" {
		t.Fatalf("unexpected materialized config: checked=%v production=%v artifacts=%q", checked, cfg.Production, cfg.Workloads.ArtifactStore.Type)
	}
}
