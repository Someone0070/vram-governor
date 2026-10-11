//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func checkpointReuseChargedBytes(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			return 0, infoErr
		}
		total += info.Size()
	}
	return total, nil
}

func TestCheckpointCustodyReuseFreshProcessesNoCopy(t *testing.T) {
	if fixture := os.Getenv("CHECKPOINT_CUSTODY_REUSE_FIXTURE_PROCESS"); fixture != "" {
		runCheckpointCustodyReuseFixtureProcess(t, fixture)
		return
	}
	root := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if root == "" {
		t.Skip("kernel provisioning not requested")
	}
	base := filepath.Join(root, "reuse-fresh-processes")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	modelPath := filepath.Join(base, "source.gguf")
	payload := []byte("authenticated reusable immutable model fixture\n")
	if err := os.WriteFile(modelPath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	results := make([]checkpointReuseFixtureResult, 3)
	for i := range results {
		resultPath := filepath.Join(base, fmt.Sprintf("process-%d.json", i))
		copyPath := filepath.Join(base, fmt.Sprintf("process-%d.copy-bytes", i))
		cmd := exec.Command(os.Args[0], "-test.run=^TestCheckpointCustodyReuseFreshProcessesNoCopy$")
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_REUSE_FIXTURE_PROCESS="+strconv.Itoa(i), "CHECKPOINT_CUSTODY_REUSE_RESULT="+resultPath, "CHECKPOINT_CUSTODY_REUSE_COPY_RESULT="+copyPath)
		output, err := runCheckpointCustodyReuseChild(cmd, 60*time.Second)
		if err != nil {
			t.Fatalf("fresh reuse fixture process %d failed: %v: %s", i, err, output)
		}
		raw, err := os.ReadFile(resultPath)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &results[i]); err != nil {
			t.Fatal(err)
		}
		copyBytes, err := os.ReadFile(copyPath)
		if err != nil {
			t.Fatal(err)
		}
		want := "0"
		if i == 0 {
			want = strconv.Itoa(len(payload))
		}
		if strings.TrimSpace(string(copyBytes)) != want {
			t.Fatalf("actual copy branch bytes for process %d = %q, want %q", i, copyBytes, want)
		}
	}
	for i, result := range results {
		if result.ModelPath == "" || result.ExecutablePath == "" || result.Inode == 0 || result.Device == 0 || result.Size != int64(len(payload)) || result.Nonce == "" || result.PID <= 0 || result.StartTicks == 0 || result.BootID == "" || !result.TerminalSettled || !result.ReceiptRemoved || !result.ExecutableRemoved {
			t.Fatalf("fixture process %d omitted authenticated lifecycle evidence: %+v", i, result)
		}
		if i > 0 && (result.Device != results[0].Device || result.Inode != results[0].Inode || result.ModelPath != results[0].ModelPath) {
			t.Fatalf("fixture process %d did not reuse the retained model inode: first=%+v got=%+v", i, results[0], result)
		}
		for j := 0; j < i; j++ {
			if result.Nonce == results[j].Nonce {
				t.Fatalf("fresh launch nonce was reused by fixture processes %d and %d", j, i)
			}
			if result.ExecutablePath == results[j].ExecutablePath {
				t.Fatalf("fresh launcher executable staging path was reused by fixture processes %d and %d", j, i)
			}
		}
	}
	models := filepath.Join(base, "custody", "models")
	entries, err := os.ReadDir(models)
	if err != nil || len(entries) != 2 {
		t.Fatalf("retained reusable model and bounded record were not the only model entries: count=%d err=%v", len(entries), err)
	}
	var charged int64
	for _, entry := range entries {
		info, e := entry.Info()
		if e != nil {
			t.Fatal(e)
		}
		charged += info.Size()
	}
	if charged < int64(len(payload)) || charged > int64(len(payload))+custodyMaxReuseRecordBytes {
		t.Fatalf("disk quota charge must count the retained model once plus bounded metadata: %d", charged)
	}
}

type checkpointReuseFixtureResult struct {
	ModelPath         string `json:"model_path"`
	ExecutablePath    string `json:"executable_path"`
	Device            uint64 `json:"device"`
	Inode             uint64 `json:"inode"`
	Size              int64  `json:"size"`
	Nonce             string `json:"nonce"`
	PID               int    `json:"pid"`
	StartTicks        uint64 `json:"start_ticks"`
	BootID            string `json:"boot_id"`
	TerminalSettled   bool   `json:"terminal_settled"`
	ReceiptRemoved    bool   `json:"receipt_removed"`
	ExecutableRemoved bool   `json:"executable_removed"`
}

func runCheckpointCustodyReuseFixtureProcess(t *testing.T, index string) {
	t.Helper()
	root := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	base := filepath.Join(root, "reuse-fresh-processes")
	payload, err := os.ReadFile(filepath.Join(base, "source.gguf"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	sourceSHA := hex.EncodeToString(sum[:])
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 128 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	copyPath := os.Getenv("CHECKPOINT_CUSTODY_REUSE_COPY_RESULT")
	copySeen := false
	store.reuseCopyBytesTest = func(n int64) {
		copySeen = true
		if err := os.WriteFile(copyPath, []byte(strconv.FormatInt(n, 10)), 0600); err != nil {
			t.Errorf("record actual copy branch bytes: %v", err)
		}
	}
	prepareCtx, prepareCancel := context.WithTimeout(context.Background(), 30*time.Second)
	model, err := store.PrepareReusable(prepareCtx, CheckpointCustodySource{Path: filepath.Join(base, "source.gguf"), ApprovedSHA256: sourceSHA, ExpectedBytes: int64(len(payload))})
	prepareCancel()
	if err != nil {
		t.Fatal(err)
	}
	if !copySeen {
		if err = os.WriteFile(copyPath, []byte("0"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executableSHA := sha256.Sum256(executableBytes)
	cmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr)
	launch, err := store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "reuse-fixture-" + index, ExpectedExecutableSHA256: hex.EncodeToString(executableSHA[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err = launch.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForCustodyEndpoint(addr, 5*time.Second) {
		_ = launch.Abort()
		t.Fatal("CPU fixture child did not bind its process-local endpoint")
	}
	commitCtx, commitCancel := context.WithTimeout(context.Background(), 20*time.Second)
	err = launch.Commit(commitCtx)
	commitCancel()
	if err != nil {
		_ = stopCustodyTestChild(launch)
		t.Fatalf("commit fresh launch receipt: %v", err)
	}
	binding, valid, verifyErr := store.VerifyBinding(context.Background(), "http://"+addr, checkpointIdentityServiceUnit)
	if verifyErr != nil || !valid || binding.ArtifactDevice != model.identity.Device || binding.ArtifactInode != model.identity.Inode || binding.VerityDigest != model.identity.VerityDigest || binding.Nonce != launch.nonce {
		t.Fatalf("fresh launch receipt did not bind the reusable model pin: valid=%v binding=%+v err=%v", valid, binding, verifyErr)
	}
	receiptPath := custodyReceiptPath(store.root, launch.nonce)
	result := checkpointReuseFixtureResult{ModelPath: model.path, ExecutablePath: launch.executablePath, Nonce: launch.nonce}
	var pin syscall.Stat_t
	if err = syscall.Fstat(int(model.modelPin.Fd()), &pin); err != nil {
		t.Fatal(err)
	}
	result.Device, result.Inode, result.Size = uint64(pin.Dev), pin.Ino, pin.Size
	var signed custodySignedReceipt
	if err = json.Unmarshal(launch.receiptRaw, &signed); err != nil {
		t.Fatal(err)
	}
	result.PID, result.StartTicks, result.BootID = signed.Receipt.PID, signed.Receipt.StartTicks, signed.Receipt.BootID
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_ = launch.WaitContext(waitCtx)
	waitCancel()
	if !launch.reaped {
		t.Fatal("fresh CPU fixture child was not exactly reaped")
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = launch.ReleaseTerminal(cleanupCtx)
	cleanupCancel()
	if err != nil {
		t.Fatalf("settle exact terminal receipt and executable cleanup: %v", err)
	}
	launch.mu.Lock()
	result.TerminalSettled = launch.reaped && launch.committed && launch.released && launch.terminal
	launch.mu.Unlock()
	if _, err = os.Lstat(receiptPath); errors.Is(err, os.ErrNotExist) {
		result.ReceiptRemoved = true
	}
	if _, err = os.Lstat(launch.executablePath); errors.Is(err, os.ErrNotExist) {
		result.ExecutableRemoved = true
	}
	modelAfter, err := openCheckpointCustodyArtifact(model.path)
	if err != nil {
		t.Fatalf("terminal cleanup removed reusable model: %v", err)
	}
	modelAfter.Close()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(os.Getenv("CHECKPOINT_CUSTODY_REUSE_RESULT"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointCustodyReuseRejectsOrphansAndTampering(t *testing.T) {
	root := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if root == "" {
		t.Skip("kernel provisioning not requested")
	}
	for _, name := range []string{"missing-record-existing-stage", "wrong-source-key", "bad-signature", "replaced-inode", "partial-stage", "verity-substitution", "symlink", "fifo", "hardlink", "metadata-symlink", "metadata-fifo", "metadata-hardlink", "canonical-duplicate", "canonical-case", "canonical-trailing", "canonical-null", "wrong-approved-hash", "source-content-changed", "model-temp-sync-failure", "record-temp-sync-failure", "model-temp-replacement", "record-temp-replacement", "model-temp-successful-substitution", "record-temp-successful-substitution", "reserve-quota", "unknown-orphan-charged", "stale-handle", "failed-begin-retains-cache", "failed-begin-after-executable-stage", "failed-commit-retains-charge", "unknown-reap-retains-charge"} {
		t.Run(name, func(t *testing.T) {
			base := filepath.Join(root, "reuse-fault-"+name)
			if err := os.Mkdir(base, 0700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(base, "source.gguf")
			payload := []byte("authenticated cache fault fixture\n")
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(payload)
			digest := hex.EncodeToString(sum[:])
			quota := int64(64 << 20)
			if name == "reserve-quota" || name == "unknown-orphan-charged" {
				quota = int64(len(payload)) + custodyMaxReuseRecordBytes + 128
				if name == "unknown-orphan-charged" {
					quota = int64(len(payload)) + custodyMaxReuseRecordBytes + 256
				}
			}
			store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: quota, ReserveBytes: 256})
			if err != nil {
				t.Fatal(err)
			}
			if name == "reserve-quota" {
				if _, err = store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))}); err == nil {
					t.Fatal("cache copy exceeded the staging reserve quota")
				}
				return
			}
			if name == "wrong-approved-hash" {
				if _, err = store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: strings.Repeat("0", 64), ExpectedBytes: int64(len(payload))}); err == nil {
					t.Fatal("source with the wrong approved digest was staged")
				}
				return
			}
			if name == "source-content-changed" {
				model, prepareErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
				if prepareErr != nil {
					t.Fatal(prepareErr)
				}
				if err = model.Discard(context.Background()); err != nil {
					t.Fatal(err)
				}
				changed := append([]byte(nil), payload...)
				changed[0] ^= 1
				if err = os.WriteFile(source, changed, 0600); err != nil {
					t.Fatal(err)
				}
				if _, reuseErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))}); reuseErr == nil {
					t.Fatal("same-inode source byte changes passed authenticated cache hit")
				}
				return
			}
			if strings.HasPrefix(name, "model-temp-") || strings.HasPrefix(name, "record-temp-") {
				key, keyErr := reusableCheckpointKey(source, digest, int64(len(payload)))
				if keyErr != nil {
					t.Fatal(keyErr)
				}
				modelTemp := reusableModelPath(store, key) + ".tmp"
				if name == "model-temp-sync-failure" {
					store.reuseModelSyncTest = func() error { return errors.New("injected model temp sync failure") }
				}
				if name == "record-temp-sync-failure" {
					store.reuseRecordSyncTest = func() error { return errors.New("injected record temp sync failure") }
				}
				if name == "model-temp-replacement" || name == "record-temp-replacement" || name == "model-temp-successful-substitution" || name == "record-temp-successful-substitution" {
					store.cleanupBeforeCaptureTest = func(original, _ string) {
						if !strings.Contains(filepath.Base(original), ".tmp") {
							return
						}
						if _, statErr := os.Lstat(original + ".preserved-original"); statErr == nil {
							return
						}
						if renameErr := os.Rename(original, original+".preserved-original"); renameErr != nil {
							t.Errorf("preserve exact temp inode before replacement: %v", renameErr)
							return
						}
						if writeErr := os.WriteFile(original, []byte("unknown replacement; preserve"), 0600); writeErr != nil {
							t.Errorf("install pre-capture temp replacement: %v", writeErr)
						}
					}
					if name == "model-temp-replacement" {
						store.reuseAfterCopyTest = func(string) error { return errors.New("force exact temp cleanup") }
					}
					if name == "model-temp-successful-substitution" {
						store.reuseAfterCopyTest = func(temp string) error {
							if err := os.Rename(temp, temp+".preserved-original"); err != nil {
								return err
							}
							return os.WriteFile(temp, []byte("unknown replacement; preserve"), 0600)
						}
					}
					if name == "record-temp-replacement" {
						store.reuseRecordBeforePublishTest = func(string) error { return errors.New("force exact record temp cleanup") }
					}
					if name == "record-temp-successful-substitution" {
						store.reuseRecordBeforePublishTest = func(temp string) error {
							if err := os.Rename(temp, temp+".preserved-original"); err != nil {
								return err
							}
							return os.WriteFile(temp, []byte("unknown replacement; preserve"), 0600)
						}
					}
				}
				if prepared, prepareErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))}); prepareErr == nil {
					_ = prepared.Discard(context.Background())
					t.Fatal("injected reusable temporary failure unexpectedly succeeded")
				}
				if name == "model-temp-replacement" || name == "model-temp-successful-substitution" {
					info, statErr := os.Stat(modelTemp)
					if statErr != nil || info.Size() != int64(len("unknown replacement; preserve")) {
						t.Fatalf("pre-capture replacement was not preserved: info=%v err=%v", info, statErr)
					}
					if name == "model-temp-successful-substitution" {
						if _, stageErr := os.Lstat(reusableModelPath(store, key)); !errors.Is(stageErr, os.ErrNotExist) {
							t.Fatalf("substituted model inode was published as approved staged content: %v", stageErr)
						}
					}
				}
				if name == "record-temp-replacement" || name == "record-temp-successful-substitution" {
					entries, readErr := os.ReadDir(filepath.Join(store.root, "models"))
					if readErr != nil {
						t.Fatal(readErr)
					}
					preserved := false
					for _, entry := range entries {
						if strings.HasSuffix(entry.Name(), ".preserved-original") || strings.HasPrefix(entry.Name(), ".tmp-reuse-") {
							if entry.Type().IsRegular() && entry.Name() != key+".gguf" {
								preserved = true
							}
						}
					}
					if !preserved {
						t.Fatal("record temp replacement evidence was not preserved")
					}
				}
				if name == "record-temp-successful-substitution" {
					if _, statErr := os.Lstat(reusableRecordPath(store, key)); !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("substituted record inode was published as signed metadata: %v", statErr)
					}
				}
				if name == "record-temp-sync-failure" {
					if _, statErr := os.Stat(reusableModelPath(store, key)); statErr != nil {
						t.Fatalf("failed record sync should retain staged model as fail-closed orphan: %v", statErr)
					}
					if _, reuseErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))}); reuseErr == nil {
						t.Fatal("missing signed record after record sync failure was silently republished")
					}
				}
				return
			}
			if name == "failed-begin-retains-cache" {
				model, prepareErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
				if prepareErr != nil {
					t.Fatal(prepareErr)
				}
				badCommand := exec.Command(filepath.Join(base, "missing-executable"), "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
				_, beginErr := store.Begin(model, CheckpointCustodyLaunchRequest{Command: badCommand, Endpoint: "http://127.0.0.1:3333", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "failed-reusable-begin", ExpectedExecutableSHA256: strings.Repeat("a", 64)})
				if beginErr == nil {
					t.Fatal("failed Begin unexpectedly issued a launch handle")
				}
				if err = model.Discard(context.Background()); err != nil {
					t.Fatal(err)
				}
				if _, err = os.Stat(model.path); err != nil {
					t.Fatalf("failed Begin cleanup deleted reusable cache bytes: %v", err)
				}
				return
			}
			if name == "failed-begin-after-executable-stage" {
				model, prepareErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
				if prepareErr != nil {
					t.Fatal(prepareErr)
				}
				executable, exeErr := os.Executable()
				if exeErr != nil {
					t.Fatal(exeErr)
				}
				exeBytes, exeErr := os.ReadFile(executable)
				if exeErr != nil {
					t.Fatal(exeErr)
				}
				exeSHA := sha256.Sum256(exeBytes)
				store.beginAfterStageTest = func(string) error { return errors.New("injected post-stage Begin failure") }
				cmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
				if _, beginErr := store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://127.0.0.1:3333", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "failed-staged-begin", ExpectedExecutableSHA256: hex.EncodeToString(exeSHA[:])}); beginErr == nil {
					t.Fatal("post-stage Begin unexpectedly succeeded")
				}
				if model.failedExecutableFD == nil {
					t.Fatal("post-stage Begin did not retain exact executable cleanup authority")
				}
				replaced := false
				failedPath := model.failedExecutablePath
				store.cleanupBeforeCaptureTest = func(original, _ string) {
					if original != failedPath || replaced {
						return
					}
					replaced = true
					if renameErr := os.Rename(original, original+".retry-original"); renameErr != nil {
						t.Errorf("preserve staged executable inode for retry: %v", renameErr)
						return
					}
					if writeErr := os.WriteFile(original, []byte("unknown executable replacement"), 0600); writeErr != nil {
						t.Errorf("install staged executable replacement: %v", writeErr)
					}
				}
				if err = model.Discard(context.Background()); err == nil {
					t.Fatal("failed executable cleanup removed an unverified path replacement")
				}
				replacement, statErr := os.ReadFile(failedPath)
				if statErr != nil || string(replacement) != "unknown executable replacement" {
					t.Fatalf("failed executable cleanup did not preserve replacement: %q %v", replacement, statErr)
				}
				if err = os.Remove(failedPath); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(failedPath+".retry-original", failedPath); err != nil {
					t.Fatal(err)
				}
				if err = model.Discard(context.Background()); err != nil {
					t.Fatalf("retry exact staged executable cleanup: %v", err)
				}
				if _, err = os.Stat(model.path); err != nil {
					t.Fatalf("post-stage Begin cleanup deleted retained cache: %v", err)
				}
				charged, chargeErr := checkpointReuseChargedBytes(filepath.Join(base, "custody", "models"))
				if chargeErr != nil || charged < int64(len(payload)) {
					t.Fatalf("post-stage Begin lost reusable cache quota charge: bytes=%d err=%v", charged, chargeErr)
				}
				return
			}
			if name == "failed-commit-retains-charge" {
				model, prepareErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
				if prepareErr != nil {
					t.Fatal(prepareErr)
				}
				probe, probeErr := net.Listen("tcp", "127.0.0.1:0")
				if probeErr != nil {
					t.Fatal(probeErr)
				}
				addr := probe.Addr().String()
				_ = probe.Close()
				executable, exeErr := os.Executable()
				if exeErr != nil {
					t.Fatal(exeErr)
				}
				exeBytes, exeErr := os.ReadFile(executable)
				if exeErr != nil {
					t.Fatal(exeErr)
				}
				exeSHA := sha256.Sum256(exeBytes)
				cmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
				cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
				cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr)
				launch, beginErr := store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "reuse-failed-commit", ExpectedExecutableSHA256: hex.EncodeToString(exeSHA[:])})
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				cleanupSettled := false
				defer func() {
					if cleanupSettled {
						return
					}
					if !launch.reaped {
						_ = stopCustodyTestChild(launch)
					}
					cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
					_ = launch.ReleaseTerminal(cleanupCtx)
					cleanupCancel()
				}()
				if beginErr = launch.Start(); beginErr != nil || !waitForCustodyEndpoint(addr, 5*time.Second) {
					_ = launch.Abort()
					t.Fatalf("start reusable Commit-failure CPU child: %v", beginErr)
				}
				launch.receiptPinFailureTest = true
				commitCtx, commitCancel := context.WithTimeout(context.Background(), 20*time.Second)
				commitErr := launch.Commit(commitCtx)
				commitCancel()
				if commitErr == nil {
					_ = stopCustodyTestChild(launch)
					t.Fatal("injected reusable receipt-pin failure did not reject Commit")
				}
				receiptPath := custodyReceiptPath(store.root, launch.nonce)
				if releaseErr := launch.ReleaseTerminal(context.Background()); releaseErr == nil {
					_ = stopCustodyTestChild(launch)
					t.Fatal("unreaped failed Commit released per-launch custody")
				}
				if _, statErr := os.Stat(launch.executablePath); statErr != nil {
					_ = stopCustodyTestChild(launch)
					t.Fatalf("unconfirmed failed Commit lost executable custody: %v", statErr)
				}
				if _, statErr := os.Stat(model.path); statErr != nil {
					_ = stopCustodyTestChild(launch)
					t.Fatalf("failed Commit deleted reusable cache: %v", statErr)
				}
				if _, statErr := os.Lstat(receiptPath); !errors.Is(statErr, os.ErrNotExist) {
					_ = stopCustodyTestChild(launch)
					t.Fatalf("receipt-pin failure unexpectedly published a receipt: %v", statErr)
				}
				if reapErr := stopCustodyTestChild(launch); !errors.Is(reapErr, context.DeadlineExceeded) {
					t.Fatalf("failed Commit exact child reap did not settle under timeout: %v", reapErr)
				}
				launch.mu.Lock()
				reaped, terminal := launch.reaped, launch.terminal
				launch.mu.Unlock()
				if !reaped || !terminal {
					t.Fatalf("failed Commit did not reach exact terminal state: reaped=%t terminal=%t", reaped, terminal)
				}
				if err = launch.ReleaseTerminal(context.Background()); err != nil {
					t.Fatalf("settle reusable failed Commit terminal cleanup: %v", err)
				}
				cleanupSettled = true
				if _, statErr := os.Lstat(launch.executablePath); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("settled failed Commit retained launch executable: %v", statErr)
				}
				if _, statErr := os.Lstat(receiptPath); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("settled failed Commit retained receipt: %v", statErr)
				}
				if _, statErr := os.Stat(model.path); statErr != nil {
					t.Fatalf("terminal failed Commit removed reusable cache: %v", statErr)
				}
				charged, chargeErr := checkpointReuseChargedBytes(filepath.Join(store.root, "models"))
				if chargeErr != nil || charged < int64(len(payload)) || charged > int64(len(payload))+custodyMaxReuseRecordBytes {
					t.Fatalf("failed Commit cache charge not retained exactly once: bytes=%d err=%v", charged, chargeErr)
				}
				for _, dir := range []string{"launchers", "receipts"} {
					entries, readErr := os.ReadDir(filepath.Join(store.root, dir))
					if readErr != nil || len(entries) != 0 {
						t.Fatalf("settled failed Commit retained %s artifacts: entries=%v err=%v", dir, entries, readErr)
					}
				}
				return
			}
			if name == "unknown-reap-retains-charge" {
				model, prepareErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
				if prepareErr != nil {
					t.Fatal(prepareErr)
				}
				probe, probeErr := net.Listen("tcp", "127.0.0.1:0")
				if probeErr != nil {
					t.Fatal(probeErr)
				}
				addr := probe.Addr().String()
				_ = probe.Close()
				executable, exeErr := os.Executable()
				if exeErr != nil {
					t.Fatal(exeErr)
				}
				exeBytes, exeErr := os.ReadFile(executable)
				if exeErr != nil {
					t.Fatal(exeErr)
				}
				exeSHA := sha256.Sum256(exeBytes)
				cmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
				cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
				cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr)
				launch, beginErr := store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "unknown-reap-reuse", ExpectedExecutableSHA256: hex.EncodeToString(exeSHA[:])})
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				if beginErr = launch.Start(); beginErr != nil || !waitForCustodyEndpoint(addr, 5*time.Second) {
					_ = launch.Abort()
					t.Fatalf("start CPU child for unknown reap control: %v", beginErr)
				}
				if beginErr = launch.Commit(context.Background()); beginErr != nil {
					_ = stopCustodyTestChild(launch)
					t.Fatal(beginErr)
				}
				receiptPath := custodyReceiptPath(store.root, launch.nonce)
				launch.waitUnknownTest = true
				waitCtx, waitCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				_ = launch.WaitContext(waitCtx)
				waitCancel()
				if releaseErr := launch.ReleaseTerminal(context.Background()); releaseErr == nil {
					t.Fatal("unknown child reap gained terminal deletion authority")
				}
				if _, statErr := os.Stat(model.path); statErr != nil {
					t.Fatalf("unknown reap deleted retained reusable model: %v", statErr)
				}
				if _, statErr := os.Stat(receiptPath); statErr != nil {
					t.Fatalf("unknown reap removed receipt evidence: %v", statErr)
				}
				if _, statErr := os.Stat(launch.executablePath); statErr != nil {
					t.Fatalf("unknown reap removed executable evidence: %v", statErr)
				}
				again, reuseErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
				if reuseErr != nil {
					t.Fatalf("unknown reap made authenticated model cache unreadable: %v", reuseErr)
				}
				if discardErr := again.Discard(context.Background()); discardErr != nil {
					t.Fatal(discardErr)
				}
				return
			}
			model, err := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
			if err != nil {
				t.Fatal(err)
			}
			path, recordPath := model.path, reusableRecordPath(store, model.reuseKey)
			if err = model.Discard(context.Background()); err != nil {
				t.Fatal(err)
			}
			if name == "unknown-orphan-charged" {
				metadata, statErr := os.Stat(recordPath)
				if statErr != nil {
					t.Fatal(statErr)
				}
				orphanBytes := int64(custodyMaxReuseRecordBytes) - metadata.Size() + 1
				orphan := filepath.Join(store.root, "models", "unknown-orphan.bin")
				if err = os.WriteFile(orphan, make([]byte, orphanBytes), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err = store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))}); err == nil {
					t.Fatal("unknown orphan bytes were omitted from retained model quota")
				}
				if _, err = os.Stat(orphan); err != nil {
					t.Fatalf("quota failure deleted ambiguous orphan evidence: %v", err)
				}
				return
			}
			switch name {
			case "missing-record-existing-stage":
				if err = os.Remove(recordPath); err != nil {
					t.Fatal(err)
				}
			case "wrong-source-key", "bad-signature":
				raw, readErr := os.ReadFile(recordPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				var signed custodySignedReuseRecord
				if err = json.Unmarshal(raw, &signed); err != nil {
					t.Fatal(err)
				}
				if name == "wrong-source-key" {
					signed.Record.Key = strings.Repeat("f", 64)
					_, privateKey, keyErr := loadCustodyKey(store)
					if keyErr != nil {
						t.Fatal(keyErr)
					}
					payload, _ := json.Marshal(signed.Record)
					signed.Signature = hex.EncodeToString(ed25519.Sign(privateKey, payload))
				} else {
					signed.Signature = strings.Repeat("0", ed25519.SignatureSize*2)
				}
				corrupt, _ := json.Marshal(signed)
				if err = os.WriteFile(recordPath, corrupt, 0600); err != nil {
					t.Fatal(err)
				}
			case "replaced-inode":
				if err = os.Rename(path, path+".orphan"); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, payload, 0600); err != nil {
					t.Fatal(err)
				}
			case "partial-stage":
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, payload[:len(payload)/2], 0600); err != nil {
					t.Fatal(err)
				}
			case "verity-substitution":
				raw, readErr := os.ReadFile(recordPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				var signed custodySignedReuseRecord
				if err = json.Unmarshal(raw, &signed); err != nil {
					t.Fatal(err)
				}
				signed.Record.Staged.VerityDigest = strings.Repeat("0", fsVerityDigestSize*2)
				_, privateKey, keyErr := loadCustodyKey(store)
				if keyErr != nil {
					t.Fatal(keyErr)
				}
				recordPayload, _ := json.Marshal(signed.Record)
				signed.Signature = hex.EncodeToString(ed25519.Sign(privateKey, recordPayload))
				resigned, _ := json.Marshal(signed)
				if err = os.WriteFile(recordPath, resigned, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(source, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err = os.Link(path, path+".extra-link"); err != nil {
					t.Fatal(err)
				}
			case "metadata-symlink", "metadata-fifo", "metadata-hardlink":
				if err = os.Remove(recordPath); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "metadata-symlink":
					err = os.Symlink(path, recordPath)
				case "metadata-fifo":
					err = unix.Mkfifo(recordPath, 0600)
				case "metadata-hardlink":
					err = os.Link(path, recordPath)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "canonical-duplicate", "canonical-case", "canonical-trailing", "canonical-null":
				raw, readErr := os.ReadFile(recordPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				switch name {
				case "canonical-duplicate":
					raw = append(raw[:len(raw)-1], []byte(`,"record":{}}`)...)
				case "canonical-case":
					raw = append([]byte(`{"Record":`), raw[len(`{"record":`):]...)
				case "canonical-trailing":
					raw = append(raw, []byte(" {}")...)
				case "canonical-null":
					raw = []byte("null")
				}
				if err = os.WriteFile(recordPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "stale-handle":
				cmd := exec.Command(filepath.Join(base, "unused-executable"), "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
				if _, err = store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://127.0.0.1:3333", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "stale-reusable-handle", ExpectedExecutableSHA256: strings.Repeat("a", 64)}); err == nil {
					t.Fatal("discarded single-use preparation produced a second launch")
				}
				fresh, freshErr := store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
				if freshErr != nil {
					t.Fatalf("discarded handle prevented a fresh reusable preparation: %v", freshErr)
				}
				if fresh.modelPin == nil || fresh == model {
					t.Fatal("fresh preparation did not issue a distinct one-use pin")
				}
				if err = fresh.Discard(context.Background()); err != nil {
					t.Fatal(err)
				}
				return
			}
			if _, err = store.PrepareReusable(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))}); err == nil {
				t.Fatal("corrupt, orphaned, or substituted cache state was accepted")
			}
		})
	}
}

func TestCheckpointCustodyReuseConcurrentPreparationCopiesOnce(t *testing.T) {
	if fixture := os.Getenv("CHECKPOINT_CUSTODY_REUSE_CONCURRENT_PROCESS"); fixture != "" {
		runCheckpointCustodyReuseConcurrentFixtureProcess(t, fixture)
		return
	}
	root := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if root == "" {
		t.Skip("kernel provisioning not requested")
	}
	base := filepath.Join(root, "reuse-concurrent")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "source.gguf")
	payload := []byte("serialized concurrent reusable source\n")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 64 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatalf("preinitialize shared custody root before child races: %v", err)
	}
	var children [2]*exec.Cmd
	var childOutput [2]boundedCheckpointReuseOutput
	var childStarted, childWaited [2]bool
	defer func() {
		for i, child := range children {
			if child != nil && childStarted[i] && !childWaited[i] && child.Process != nil && child.ProcessState == nil {
				_ = child.Process.Kill()
			}
		}
		for i, child := range children {
			if child != nil && childStarted[i] && !childWaited[i] {
				_ = child.Wait()
				childWaited[i] = true
			}
		}
	}()
	for i := range children {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCheckpointCustodyReuseConcurrentPreparationCopiesOnce$")
		cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_REUSE_CONCURRENT_PROCESS="+strconv.Itoa(i), "CHECKPOINT_CUSTODY_REUSE_CONCURRENT_BASE="+base)
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		cmd.Stdout, cmd.Stderr = &childOutput[i], &childOutput[i]
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		children[i] = cmd
		childStarted[i] = true
	}
	for i := range children {
		if err = waitForReuseFile(filepath.Join(base, fmt.Sprintf("ready-%d", i)), 10*time.Second); err != nil {
			t.Fatalf("%v; child0=%s; child1=%s", err, childOutput[0].String(), childOutput[1].String())
		}
	}
	if err = os.WriteFile(filepath.Join(base, "go"), []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, child := range children {
		index := 0
		if child == children[1] {
			index = 1
		}
		if waitErr := waitCheckpointCustodyReuseChild(child, 60*time.Second, &childOutput[index]); waitErr != nil {
			childWaited[index] = true
			t.Fatalf("cross-process reusable preparation failed: %v: %s", waitErr, childOutput[index].String())
		}
		childWaited[index] = true
	}
	var identities [2]checkpointReuseConcurrentResult
	var copied [2]string
	for i := range identities {
		raw, readErr := os.ReadFile(filepath.Join(base, fmt.Sprintf("result-%d.json", i)))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err = json.Unmarshal(raw, &identities[i]); err != nil {
			t.Fatal(err)
		}
		bytes, readErr := os.ReadFile(filepath.Join(base, fmt.Sprintf("copy-%d", i)))
		if readErr != nil {
			t.Fatal(readErr)
		}
		copied[i] = strings.TrimSpace(string(bytes))
	}
	wantBytes := strconv.Itoa(len(payload))
	if !((copied[0] == wantBytes && copied[1] == "0") || (copied[1] == wantBytes && copied[0] == "0")) {
		t.Fatalf("distinct-process copy branches=%v, want exactly one source copy", copied)
	}
	if identities[0].Device != identities[1].Device || identities[0].Inode == 0 || identities[0].Inode != identities[1].Inode {
		t.Fatalf("separate stores did not serialize to the one cache inode: %+v", identities)
	}
	lockFD, err := unix.Open(filepath.Join(store.root, "custody.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(lockFD)
	if err = unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	lockCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err = store.PrepareReusable(lockCtx, CheckpointCustodySource{Path: source, ApprovedSHA256: hex.EncodeToString(sum[:]), ExpectedBytes: int64(len(payload))}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("process-lock timeout did not fail closed: %v", err)
	}
}

type checkpointReuseConcurrentResult struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func waitForReuseFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for cross-process reuse rendezvous %s", path)
}

func runCheckpointCustodyReuseChild(cmd *exec.Cmd, timeout time.Duration) ([]byte, error) {
	var output boundedCheckpointReuseOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	}
	if err := cmd.Start(); err != nil {
		return []byte(output.String()), err
	}
	err := waitCheckpointCustodyReuseChild(cmd, timeout, &output)
	return []byte(output.String()), err
}

type boundedCheckpointReuseOutput struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	truncated bool
}

func (b *boundedCheckpointReuseOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	const maximum = 64 << 10
	remaining := maximum - b.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buffer.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buffer.Write(p)
		}
	} else {
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedCheckpointReuseOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		return b.buffer.String() + "\n[child output truncated]"
	}
	return b.buffer.String()
}

func waitCheckpointCustodyReuseChild(cmd *exec.Cmd, timeout time.Duration, output *boundedCheckpointReuseOutput) error {
	if cmd == nil || cmd.Process == nil || timeout <= 0 {
		return errors.New("bounded reuse child wait lacks process or timeout")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		_ = cmd.Process.Kill()
		waitErr := <-done
		return fmt.Errorf("reuse fixture child exceeded %s and was killed/reaped: %v; output=%s", timeout, waitErr, output.String())
	}
}

func runCheckpointCustodyReuseConcurrentFixtureProcess(t *testing.T, index string) {
	t.Helper()
	base := os.Getenv("CHECKPOINT_CUSTODY_REUSE_CONCURRENT_BASE")
	i, err := strconv.Atoi(index)
	if err != nil || i < 0 || i > 1 {
		t.Fatal("invalid reuse process index")
	}
	if err = os.WriteFile(filepath.Join(base, "ready-"+index), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = waitForReuseFile(filepath.Join(base, "go"), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join(base, "source.gguf"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 64 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	copyObserved := false
	store.reuseCopyBytesTest = func(n int64) {
		copyObserved = true
		_ = os.WriteFile(filepath.Join(base, "copy-"+index), []byte(strconv.FormatInt(n, 10)), 0600)
	}
	prepareCtx, prepareCancel := context.WithTimeout(context.Background(), 30*time.Second)
	model, err := store.PrepareReusable(prepareCtx, CheckpointCustodySource{Path: filepath.Join(base, "source.gguf"), ApprovedSHA256: hex.EncodeToString(sum[:]), ExpectedBytes: int64(len(payload))})
	prepareCancel()
	if err != nil {
		t.Fatal(err)
	}
	if !copyObserved {
		if err = os.WriteFile(filepath.Join(base, "copy-"+index), []byte("0"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(int(model.modelPin.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(checkpointReuseConcurrentResult{Device: uint64(stat.Dev), Inode: stat.Ino})
	if err = os.WriteFile(filepath.Join(base, "result-"+index+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	discardCtx, discardCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = model.Discard(discardCtx)
	discardCancel()
	if err != nil {
		t.Fatal(err)
	}
}
