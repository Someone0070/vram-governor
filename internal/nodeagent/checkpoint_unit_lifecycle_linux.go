//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"vram-governor/internal/safefile"
	"vram-governor/internal/wsproto"
)

type checkpointOwnedStopServer struct {
	listener        net.Listener
	private         ed25519.PrivateKey
	public          ed25519.PublicKey
	secret          string
	configSHA256    string
	config          *Config
	plan            *PinnedCheckpointLaunchPlan
	launch          *CheckpointControlledLaunch
	waitDone        <-chan struct{}
	waitErr         *error
	mu              sync.Mutex
	active          bool
	ackDone         chan struct{}
	ackOnce         sync.Once
	ackErr          error
	observation     *checkpointOwnedStopObservation
	connections     chan struct{}
	paths           checkpointOwnedStopPaths
	waiterReady     bool
	unitObserver    func(context.Context) (checkpointFixedUnitState, error)
	bindingObserver func(context.Context) (CheckpointManagedBinding, error)
	dropReply       func() bool
	afterIntent     func()
	// testDiagnostic is an unexported, bounded observation seam for the local
	// durability fixture. Production leaves it nil; wire replies remain generic.
	testDiagnostic func(stage, cause string)
}

func (s *checkpointOwnedStopServer) reportTestDiagnostic(stage string, err error, fallback string) {
	if s.testDiagnostic == nil {
		return
	}
	cause := fallback
	if err != nil {
		cause = err.Error()
	}
	for _, sensitive := range []string{s.secret, string(s.private)} {
		if sensitive != "" {
			cause = strings.ReplaceAll(cause, sensitive, "[redacted]")
		}
	}
	cause = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, cause)
	if runes := []rune(cause); len(runes) > 256 {
		cause = string(runes[:256])
	}
	s.testDiagnostic(stage, cause)
}

func readPinnedRootStopPublicKey(path string) ([]byte, error) {
	return readPinnedRootStopPublicKeyAt(path, fixedCheckpointOwnedStopPaths())
}

func readPinnedRootStopPublicKeyAt(path string, paths checkpointOwnedStopPaths) ([]byte, error) {
	if path != paths.PublicKey {
		return nil, errors.New("root stop public key path is not fixed by its internal path set")
	}
	if err := checkpointOwnedStopPathChainAt(path, paths, true); err != nil {
		return nil, err
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !statOK || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) || info.Size() != ed25519.PublicKeySize*2 {
		return nil, errors.New("root stop public key file is not a bounded regular file")
	}
	_, groupID, principalErr := checkpointOwnedStopPrincipal(paths)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if principalErr != nil || !ok || stat.Uid != 0 || stat.Gid != groupID || info.Mode().Perm() != 0o640 {
		return nil, errors.New("root stop public key ownership or mode is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(f, ed25519.PublicKeySize*2+1))
	after, statErr := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || len(body) != ed25519.PublicKeySize*2 || statErr != nil || pathErr != nil || !os.SameFile(info, after) || !os.SameFile(info, pathInfo) || !sameCheckpointFileSnapshot(info, after) || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("root stop public key is truncated")
	}
	if err := checkpointOwnedStopPathChainAt(path, paths, true); err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(string(body))
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != string(body) {
		return nil, errors.New("root stop public key encoding is invalid")
	}
	return key, nil
}

func checkpointOwnedStopPathChain(path string, public bool) error {
	return checkpointOwnedStopPathChainAt(path, fixedCheckpointOwnedStopPaths(), public)
}

func checkpointOwnedStopPathChainAt(path string, paths checkpointOwnedStopPaths, public bool) error {
	clean := filepath.Clean(path)
	if clean != path || !filepath.IsAbs(path) || paths.TrustedRoot == "" || !filepath.IsAbs(paths.TrustedRoot) || filepath.Clean(paths.TrustedRoot) != paths.TrustedRoot || !strings.HasPrefix(path, paths.TrustedRoot+string(os.PathSeparator)) {
		return errors.New("owned stop state path is not canonical")
	}
	for current := filepath.Dir(path); current != paths.TrustedRoot; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("owned stop state parent is unavailable or linked")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("owned stop state parent ownership or mode is unsafe")
		}
	}
	rootInfo, rootErr := os.Lstat(paths.TrustedRoot)
	rootStat, rootOK := infoSys(rootInfo)
	if rootErr != nil || !rootOK || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootStat.Uid != 0 || rootInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("owned stop trusted root is unavailable or writable by an untrusted principal")
	}
	allowedDirectory := filepath.Dir(paths.PrivateKey)
	if public {
		allowedDirectory = filepath.Dir(paths.PublicKey)
	}
	if public && !strings.HasPrefix(path, allowedDirectory+string(os.PathSeparator)) {
		return errors.New("owned stop public path is outside its fixed directory")
	}
	if !public && !strings.HasPrefix(path, allowedDirectory+string(os.PathSeparator)) {
		return errors.New("owned stop private path is outside its fixed directory")
	}
	return nil
}

func ensureCheckpointOwnedStopKeys() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	return ensureCheckpointOwnedStopKeysAt(fixedCheckpointOwnedStopPaths())
}

func ensureCheckpointOwnedStopKeysAt(paths checkpointOwnedStopPaths) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privateDir, publicDir := filepath.Dir(paths.PrivateKey), filepath.Dir(paths.PublicKey)
	if err := ensureCheckpointOwnedStopDirectoryAt(privateDir, 0o700, 0, 0, paths, false); err != nil {
		return nil, nil, err
	}
	_, expectedGroup, principalErr := checkpointOwnedStopPrincipal(paths)
	if principalErr != nil {
		return nil, nil, principalErr
	}
	groupID := int(expectedGroup)
	if groupID < 0 {
		return nil, nil, errors.New("owned stop node group is invalid")
	}
	if err := ensureCheckpointOwnedStopDirectoryAt(publicDir, 0o750, 0, groupID, paths, true); err != nil {
		return nil, nil, err
	}
	if err := ensureCheckpointOwnedStopDirectoryAt(paths.ReceiptDir, 0o750, 0, groupID, paths, true); err != nil {
		return nil, nil, err
	}
	privateBody, privateErr := readCheckpointOwnedStopKeyAt(paths.PrivateKey, false, paths)
	publicBody, publicErr := readCheckpointOwnedStopKeyAt(paths.PublicKey, true, paths)
	if errors.Is(privateErr, os.ErrNotExist) && errors.Is(publicErr, os.ErrNotExist) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if err := writeCheckpointOwnedStopKeyAt(paths.PrivateKey, hex.EncodeToString(private), 0o600, 0, paths, false); err != nil {
			return nil, nil, err
		}
		if err := writeCheckpointOwnedStopKeyAt(paths.PublicKey, hex.EncodeToString(public), 0o640, groupID, paths, true); err != nil {
			return nil, nil, err
		}
		return private, public, nil
	}
	if privateErr != nil || publicErr != nil {
		return nil, nil, errors.New("owned stop signing key pair is incomplete or invalid")
	}
	private, err := hex.DecodeString(string(privateBody))
	if err != nil || len(private) != ed25519.PrivateKeySize || hex.EncodeToString(private) != string(privateBody) {
		return nil, nil, errors.New("owned stop private key encoding is invalid")
	}
	public, err := hex.DecodeString(string(publicBody))
	if err != nil || len(public) != ed25519.PublicKeySize || !bytes.Equal(ed25519.PrivateKey(private).Public().(ed25519.PublicKey), public) {
		return nil, nil, errors.New("owned stop public key does not match its private key")
	}
	return ed25519.PrivateKey(private), ed25519.PublicKey(public), nil
}

func ensureCheckpointOwnedStopDirectory(path string, mode os.FileMode, uid, gid int) error {
	return ensureCheckpointOwnedStopDirectoryAt(path, mode, uid, gid, fixedCheckpointOwnedStopPaths(), strings.HasPrefix(path, checkpointFixedStopPublicDir))
}

func ensureCheckpointOwnedStopDirectoryAt(path string, mode os.FileMode, uid, gid int, paths checkpointOwnedStopPaths, public bool) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("owned stop directory is not a real directory")
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return checkpointOwnedStopPathChainAt(filepath.Join(path, ".check"), paths, public)
}

func readCheckpointOwnedStopKey(path string, public bool) ([]byte, error) {
	return readCheckpointOwnedStopKeyAt(path, public, fixedCheckpointOwnedStopPaths())
}

func readCheckpointOwnedStopKeyAt(path string, public bool, paths checkpointOwnedStopPaths) ([]byte, error) {
	if err := checkpointOwnedStopPathChainAt(path, paths, public); err != nil {
		return nil, err
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	_, statOK := info.Sys().(*syscall.Stat_t)
	wantGroup := uint32(0)
	if public {
		_, wantGroup, err = checkpointOwnedStopPrincipal(paths)
		if err != nil || (wantGroup == 0 && !paths.principalPinned) {
			return nil, errors.New("owned stop node group is unavailable")
		}
	}
	if !statOK || validateCheckpointOwnedStopKeyMetadata(info, public, wantGroup) != nil {
		return nil, errors.New("owned stop key file metadata is invalid")
	}
	wantSize := int64(ed25519.PrivateKeySize * 2)
	if public {
		wantSize = int64(ed25519.PublicKeySize * 2)
	}
	body, err := io.ReadAll(io.LimitReader(f, wantSize+1))
	after, statErr := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || int64(len(body)) != wantSize || statErr != nil || pathErr != nil || !os.SameFile(info, after) || !os.SameFile(info, pathInfo) || !sameCheckpointFileSnapshot(info, after) || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("owned stop key changed during held-descriptor read")
	}
	if err := checkpointOwnedStopPathChainAt(path, paths, public); err != nil {
		return nil, err
	}
	return body, nil
}

func validateCheckpointOwnedStopKeyMetadata(info os.FileInfo, public bool, groupID uint32) error {
	if info == nil {
		return errors.New("owned stop key metadata is absent")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	wantMode := os.FileMode(0o600)
	wantSize := int64(ed25519.PrivateKeySize * 2)
	wantGID := uint32(0)
	if public {
		wantMode = 0o640
		wantSize = int64(ed25519.PublicKeySize * 2)
		wantGID = groupID
	}
	if !ok || stat.Uid != 0 || stat.Gid != wantGID || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) || info.Mode().Perm() != wantMode || info.Size() != wantSize {
		return errors.New("owned stop key metadata does not match the root-only contract")
	}
	return nil
}

func writeCheckpointOwnedStopKey(path, content string, mode os.FileMode, gid int) error {
	public := strings.HasPrefix(path, checkpointFixedStopPublicDir)
	return writeCheckpointOwnedStopKeyAt(path, content, mode, gid, fixedCheckpointOwnedStopPaths(), public)
}

func writeCheckpointOwnedStopKeyAt(path, content string, mode os.FileMode, gid int, paths checkpointOwnedStopPaths, public bool) error {
	if err := checkpointOwnedStopPathChainAt(filepath.Join(filepath.Dir(path), ".check"), paths, public); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".owned-stop-key-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmpInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return err
	}
	defer removeOwnedStopTemporary(tmpPath, tmpInfo)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chown(0, gid); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.WriteString(tmp, content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	current, err := os.Lstat(tmpPath)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(tmpInfo, current) {
		return errors.New("owned stop key temporary path changed before publication")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, tmpPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	published, err := os.Lstat(path)
	if err != nil || !os.SameFile(tmpInfo, published) || published.Mode()&os.ModeSymlink != 0 {
		return errors.New("owned stop key publication identity changed")
	}
	return syncCommandStateDir(filepath.Dir(path))
}

func removeOwnedStopTemporary(path string, held os.FileInfo) {
	if held == nil {
		return
	}
	current, err := os.Lstat(path)
	if err == nil && current.Mode()&os.ModeSymlink == 0 && os.SameFile(held, current) {
		_ = os.Remove(path)
	}
}

func ownedStopReceiptFilename(commandID string) string {
	sum := sha256.Sum256([]byte(commandID))
	return hex.EncodeToString(sum[:]) + ".json"
}

func invokeOwnedStopSupervisorPlatform(ctx context.Context, request ownedStopRequest) ([]byte, error) {
	return invokeOwnedStopSupervisorAt(ctx, request, fixedCheckpointOwnedStopPaths().Socket)
}

func invokeOwnedStopSupervisorAt(ctx context.Context, request ownedStopRequest, socket string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || len(request.Command) == 0 || len(request.Command) > checkpointOwnedStopMaxFrame || len(request.PinnedPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("owned stop supervisor request is invalid")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, err
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("owned stop control socket is not Unix")
	}
	if err := unixConn.CloseWrite(); err != nil {
		return nil, err
	}
	var reply ownedStopReply
	decoder := json.NewDecoder(io.LimitReader(conn, checkpointOwnedStopMaxFrame+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reply); err != nil || len(reply.Receipt) > 16<<10 {
		return nil, errors.New("owned stop supervisor reply is malformed")
	}
	if reply.Error != "" || len(reply.Receipt) == 0 {
		return nil, errors.New("owned stop supervisor did not produce a durable acknowledgement")
	}
	return reply.Receipt, nil
}

func observeOwnedStopReceiptPlatform(ctx context.Context, root string, originalWire, publicKey []byte, secret string) ([]byte, error) {
	return observeOwnedStopReceiptAt(ctx, root, originalWire, publicKey, secret, fixedCheckpointOwnedStopPaths())
}

func observeOwnedStopReceiptAt(ctx context.Context, root string, originalWire, publicKey []byte, secret string, paths checkpointOwnedStopPaths) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || root != paths.ReceiptDir || len(publicKey) != ed25519.PublicKeySize || len(originalWire) == 0 || len(originalWire) > checkpointOwnedStopMaxFrame {
		return nil, errors.New("owned stop receipt observation inputs are invalid")
	}
	var original wsproto.CommandPayload
	if err := json.Unmarshal(originalWire, &original); err != nil || original.Command != "llm_displacement_stop" || !wsproto.VerifyCommand(original, []byte(secret)) {
		return nil, errors.New("owned stop original command is not authenticated")
	}
	currentKey, err := readPinnedRootStopPublicKeyAt(paths.PublicKey, paths)
	if err != nil || !bytes.Equal(currentKey, publicKey) {
		return nil, errors.New("owned stop root acknowledgement key changed from the pinned intent")
	}
	canonical, err := wsproto.CanonicalCommandEnvelope(original)
	if err != nil || !bytes.Equal(canonical, originalWire) {
		return nil, errors.New("owned stop original envelope is not canonical")
	}
	path := filepath.Join(root, ownedStopReceiptFilename(original.ID))
	if err := checkpointOwnedStopPathChainAt(path, paths, true); err != nil {
		return nil, err
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !singleCheckpointLink(info) || info.Mode().Perm() != 0o640 || info.Size() <= 0 || info.Size() > 16<<10 {
		return nil, errors.New("owned stop receipt file metadata is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	_, groupID, principalErr := checkpointOwnedStopPrincipal(paths)
	if !ok || stat.Uid != 0 || principalErr != nil || stat.Gid != groupID {
		return nil, errors.New("owned stop receipt ownership is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	after, statErr := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || int64(len(body)) != info.Size() || statErr != nil || pathErr != nil || !os.SameFile(info, after) || !os.SameFile(info, pathInfo) || !sameCheckpointFileSnapshot(info, after) || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("owned stop receipt read was incomplete")
	}
	if err := checkpointOwnedStopPathChainAt(path, paths, true); err != nil {
		return nil, err
	}
	if err := verifyOwnedStopReceipt(body, ed25519.PublicKey(publicKey), originalWire, secret); err != nil {
		return nil, err
	}
	var receipt ownedStopReceipt
	if json.Unmarshal(body, &receipt) != nil {
		return nil, errors.New("owned stop receipt is malformed")
	}
	canonicalReceipt, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(body, canonicalReceipt) {
		return nil, errors.New("owned stop receipt bytes are not canonical")
	}
	if err := syncOwnedStopReceiptDirectory(paths); err != nil {
		return nil, errors.New("owned stop receipt directory durability could not be re-established")
	}
	afterSync, statErr := f.Stat()
	pathAfterSync, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !os.SameFile(info, afterSync) || !os.SameFile(info, pathAfterSync) || !sameCheckpointFileSnapshot(info, afterSync) || pathAfterSync.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("owned stop receipt identity changed during directory durability check")
	}
	if err := checkpointOwnedStopPathChainAt(path, paths, true); err != nil {
		return nil, err
	}
	currentPublicKey, err := readPinnedRootStopPublicKeyAt(paths.PublicKey, paths)
	if err != nil || !bytes.Equal(currentPublicKey, publicKey) {
		return nil, errors.New("root stop public-key pin changed during receipt durability check")
	}
	return body, nil
}

func syncOwnedStopReceiptDirectory(paths checkpointOwnedStopPaths) error {
	path := paths.ReceiptDir
	if path == "" || filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return errors.New("owned stop receipt directory path is invalid")
	}
	if err := checkpointOwnedStopPathChainAt(filepath.Join(path, ".check"), paths, true); err != nil {
		return err
	}
	_, groupID, err := checkpointOwnedStopPrincipal(paths)
	if err != nil {
		return err
	}
	if paths.syncReceiptDir != nil {
		if err := paths.syncReceiptDir(path); err != nil {
			return err
		}
	}
	before, err := os.Lstat(path)
	stat, ok := infoSys(before)
	if err != nil || !ok || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || stat.Gid != groupID || before.Mode().Perm() != 0o750 {
		return errors.New("owned stop receipt directory metadata is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || uint64(opened.Dev) != uint64(stat.Dev) || opened.Ino != stat.Ino || opened.Uid != 0 || opened.Gid != groupID || opened.Mode&0o777 != 0o750 {
		return errors.New("owned stop receipt directory descriptor changed")
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	afterStat, afterOK := infoSys(after)
	if err != nil || !afterOK || !os.SameFile(before, after) || afterStat.Dev != stat.Dev || afterStat.Ino != stat.Ino || after.Mode().Perm() != 0o750 {
		return errors.New("owned stop receipt directory changed after fsync")
	}
	return checkpointOwnedStopPathChainAt(filepath.Join(path, ".check"), paths, true)
}

func loadOwnedStopNodeConfig() (*Config, string, error) {
	return loadOwnedStopNodeConfigAt(fixedCheckpointOwnedStopPaths())
}

func loadOwnedStopNodeConfigAt(paths checkpointOwnedStopPaths) (*Config, string, error) {
	configBody, err := readOwnedStopRootFileAt(paths.NodeConfig, 1<<20, paths)
	if err != nil {
		return nil, "", err
	}
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(configBody))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, "", errors.New("fixed node-agent YAML is malformed or contains unknown fields")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, "", errors.New("fixed node-agent YAML contains more than one document")
	}
	if cfg.NodeID == "" || !checkpointLaunchAliasRE.MatchString(cfg.NodeID) || cfg.CommandStatePath != paths.NodeState || cfg.CommandSigningSecret != "" || cfg.CommandSigningSecretEnv != "VRAM_NODE_COMMAND_SECRET" {
		return nil, "", errors.New("fixed node-agent identity or command-state contract is invalid")
	}
	secret, err := readFixedNodeCommandSecretAt(paths)
	if err != nil || len(secret) < 32 {
		return nil, "", errors.New("fixed command signing credential is unavailable or too short")
	}
	cfg.CommandSigningSecret = secret
	seen := make(map[string]struct{}, len(cfg.LlamaCPP.Servers))
	for _, server := range cfg.LlamaCPP.Servers {
		if server.ID == "" || !checkpointLaunchAliasRE.MatchString(server.ID) {
			return nil, "", errors.New("fixed node-agent target ID is invalid")
		}
		if _, duplicate := seen[server.ID]; duplicate {
			return nil, "", errors.New("fixed node-agent target ID is duplicated")
		}
		seen[server.ID] = struct{}{}
	}
	return &cfg, sha256Hex(configBody), nil
}

func readOwnedStopRootFile(path string, maximum int64) ([]byte, error) {
	return readOwnedStopRootFileAt(path, maximum, fixedCheckpointOwnedStopPaths())
}

func readOwnedStopRootFileAt(path string, maximum int64, paths checkpointOwnedStopPaths) ([]byte, error) {
	if maximum <= 0 || filepath.Clean(path) != path || !filepath.IsAbs(path) || !strings.HasPrefix(path, paths.ConfigRoot+string(os.PathSeparator)) {
		return nil, errors.New("fixed root config path is invalid")
	}
	for parent := filepath.Dir(path); parent != paths.ConfigRoot; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		stat, ok := func() (*syscall.Stat_t, bool) { s, ok := infoSys(info); return s, ok }()
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return nil, errors.New("fixed root config parent ownership or mode is unsafe")
		}
	}
	rootInfo, rootErr := os.Lstat(paths.ConfigRoot)
	rootStat, rootOK := infoSys(rootInfo)
	if rootErr != nil || !rootOK || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootStat.Uid != 0 || rootInfo.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("fixed root config directory is unavailable or writable by an untrusted principal")
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || !singleCheckpointLink(before) || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("fixed root config is not a bounded regular file")
	}
	stat, ok := infoSys(before)
	if !ok || stat.Uid != 0 || before.Mode().Perm() != 0o640 {
		return nil, errors.New("fixed root config ownership or mode is invalid")
	}
	_, groupID, principalErr := checkpointOwnedStopPrincipal(paths)
	if principalErr != nil || stat.Gid != groupID {
		return nil, errors.New("fixed root config group is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || int64(len(body)) != before.Size() {
		return nil, errors.New("fixed root config read was incomplete")
	}
	after, err := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, pathInfo) || !sameCheckpointFileSnapshot(before, after) || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("fixed root config changed during held-descriptor read")
	}
	return body, nil
}

func readFixedNodeCommandSecret() (string, error) {
	return readFixedNodeCommandSecretAt(fixedCheckpointOwnedStopPaths())
}

func readFixedNodeCommandSecretAt(paths checkpointOwnedStopPaths) (string, error) {
	body, err := readOwnedStopRootFileAt(paths.NodeEnv, 64<<10, paths)
	if err != nil {
		return "", err
	}
	values := make(map[string]string, 2)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "VRAM_NODE_TOKEN" && key != "VRAM_NODE_COMMAND_SECRET") || !ownedStopEnvCredentialRE.MatchString(value) {
			return "", errors.New("fixed node-agent environment has an unsupported or nonliteral entry")
		}
		if _, duplicate := values[key]; duplicate {
			return "", errors.New("fixed node-agent environment duplicates a credential")
		}
		values[key] = value
	}
	secret, secretOK := values["VRAM_NODE_COMMAND_SECRET"]
	_, tokenOK := values["VRAM_NODE_TOKEN"]
	if !secretOK || !tokenOK {
		return "", errors.New("fixed node-agent credentials are incomplete")
	}
	return secret, nil
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func checkpointOwnedStopPrincipal(paths checkpointOwnedStopPaths) (uint32, uint32, error) {
	if paths.principalPinned {
		return paths.NodeUID, paths.NodeGID, nil
	}
	account, err := user.Lookup("vram-governor")
	if err != nil {
		return 0, 0, err
	}
	group, err := user.LookupGroup("vram-governor")
	if err != nil {
		return 0, 0, err
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(group.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return 0, 0, errors.New("fixed node-agent principal is invalid")
	}
	return uint32(uid), uint32(gid), nil
}

func sameCheckpointFileSnapshot(a, b os.FileInfo) bool {
	if a == nil || b == nil || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	as, aok := infoSys(a)
	bs, bok := infoSys(b)
	return aok && bok && as.Dev == bs.Dev && as.Ino == bs.Ino && as.Mtim == bs.Mtim && as.Ctim == bs.Ctim
}

func decodeStrictCanonicalState(body []byte, envelope *commandStateEnvelope) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(envelope); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("node command state has a trailing JSON value")
	}
	canonical, err := json.MarshalIndent(*envelope, "", "  ")
	if err != nil || !bytes.Equal(canonical, body) {
		return errors.New("node command state is not canonical JSON")
	}
	return nil
}

func readOwnedStopBounded(path string, maximum int64, _ bool) ([]byte, os.FileInfo, error) {
	return readOwnedStopBoundedAt(path, maximum, fixedCheckpointOwnedStopPaths())
}

func readOwnedStopBoundedAt(path string, maximum int64, paths checkpointOwnedStopPaths) ([]byte, os.FileInfo, error) {
	if maximum <= 0 || maximum > 64<<20 || filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return nil, nil, errors.New("owned stop file path or bound is invalid")
	}
	if path != paths.NodeState && path != paths.NodeState+".journal" {
		return nil, nil, errors.New("owned stop node state path is not fixed")
	}
	uid, gid, principalErr := checkpointOwnedStopPrincipal(paths)
	if principalErr != nil {
		return nil, nil, errors.New("fixed node-agent principal is invalid")
	}
	parent := filepath.Dir(path)
	if parent != paths.StateDir {
		return nil, nil, errors.New("fixed node state parent is not the pinned directory")
	}
	parentInfo, parentErr := os.Lstat(parent)
	parentStat, parentOK := infoSys(parentInfo)
	if parentErr != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || !parentOK || parentStat.Uid != uid || parentStat.Gid != gid || parentInfo.Mode().Perm()&0o022 != 0 {
		return nil, nil, errors.New("fixed node state parent ownership or mode is unsafe")
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) || info.Size() < 0 || info.Size() > maximum {
		return nil, nil, errors.New("owned stop file is not a bounded single-link regular file")
	}
	stat, ok := infoSys(info)
	if !ok || stat.Uid != uid || stat.Gid != gid || info.Mode().Perm() != 0o600 {
		return nil, nil, errors.New("owned stop file principal is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || int64(len(body)) != info.Size() {
		return nil, nil, errors.New("owned stop file read was incomplete")
	}
	after, err := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) || !sameCheckpointFileSnapshot(info, after) || !os.SameFile(info, after) {
		return nil, nil, errors.New("owned stop path changed during held-descriptor read")
	}
	return body, info, nil
}

func verifyOwnedStopJournalReadOnly(cfg *Config, state commandStatePayload, stateHash string, paths checkpointOwnedStopPaths) error {
	path := cfg.CommandStatePath + ".journal"
	body, _, err := readOwnedStopBoundedAt(path, 64<<20, paths)
	if err != nil {
		return errors.New("durable node command journal is unavailable")
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return errors.New("node command journal is not a complete newline-terminated append log")
	}
	var previous string
	var sequence uint64
	var prepared *commandStateJournalRecord
	var committed *commandStateJournalRecord
	for _, line := range bytes.Split(body[:len(body)-1], []byte{'\n'}) {
		if len(line) == 0 {
			return errors.New("node command journal contains an empty record")
		}
		if rejectDuplicateJSONKeys(line) != nil {
			return errors.New("node command journal has duplicate JSON keys")
		}
		var record commandStateJournalRecord
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil || record.StateHash == "" || (record.Phase != "prepared" && record.Phase != "committed") || record.HMAC == "" {
			return errors.New("node command journal contains an unresolved or malformed record")
		}
		canonicalRecord, marshalErr := json.Marshal(record)
		if marshalErr != nil || !bytes.Equal(canonicalRecord, line) {
			return errors.New("node command journal record is not canonical JSON")
		}
		mac := hmac.New(sha256.New, []byte("node-command-state-journal-v1:"+cfg.CommandSigningSecret))
		unsigned := record
		unsigned.HMAC = ""
		material, _ := json.Marshal(unsigned)
		_, _ = mac.Write(material)
		if !hmac.Equal([]byte(record.HMAC), []byte(hex.EncodeToString(mac.Sum(nil)))) {
			return errors.New("node command journal authentication or chain failed")
		}
		if record.Phase == "prepared" {
			if prepared != nil || record.Sequence != sequence+1 || record.PrevHash != previous {
				return errors.New("node command journal prepare chain failed")
			}
			copy := record
			prepared = &copy
			continue
		}
		if prepared == nil || record.Sequence != prepared.Sequence || record.StateHash != prepared.StateHash || record.PrevHash != prepared.PrevHash || record.PrevHash != previous {
			return errors.New("node command journal commit does not match its prepare")
		}
		previous = journalDigest(record)
		sequence = record.Sequence
		copy := record
		committed = &copy
		prepared = nil
	}
	if prepared != nil || committed == nil || committed.Sequence != state.JournalSequence || committed.StateHash != stateHash || state.JournalPrevHash != committed.PrevHash {
		return errors.New("node command journal does not anchor the exact pending state")
	}
	return nil
}

func verifyOwnedStopNodeIntent(ctx context.Context, request ownedStopRequest, expectedConfigSHA256 string) (*Config, wsproto.CommandPayload, pendingCommand, error) {
	return verifyOwnedStopNodeIntentAt(ctx, request, expectedConfigSHA256, fixedCheckpointOwnedStopPaths())
}

func verifyOwnedStopNodeIntentAt(ctx context.Context, request ownedStopRequest, expectedConfigSHA256 string, paths checkpointOwnedStopPaths) (*Config, wsproto.CommandPayload, pendingCommand, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("owned stop verification context is unavailable")
	}
	cfg, configSHA256, err := loadOwnedStopNodeConfigAt(paths)
	if err != nil {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, err
	}
	if expectedConfigSHA256 != "" && configSHA256 != expectedConfigSHA256 {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("root-pinned node configuration changed during service lifetime")
	}
	if len(request.Command) == 0 || len(request.Command) > checkpointOwnedStopMaxFrame || len(request.PinnedPublicKey) != ed25519.PublicKeySize {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("owned stop request frame or pinned key is invalid")
	}
	var command wsproto.CommandPayload
	if err := json.Unmarshal(request.Command, &command); err != nil || command.Command != "llm_displacement_stop" || command.NodeID != cfg.NodeID || command.ID == "" || command.IdempotencyKey == "" || !wsproto.VerifyCommand(command, []byte(cfg.CommandSigningSecret)) {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("owned stop command HMAC or node identity is invalid")
	}
	canonical, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil || !bytes.Equal(canonical, request.Command) {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("owned stop command wire is not canonical")
	}
	if err := wsproto.ValidateOwnedStopCommandArgs(command.Command, command.Args); err != nil {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, err
	}
	material, err := wsproto.CommandSigningMaterialForOwnedStop(command)
	if err != nil || sha256Hex(material) != request.SigningSHA256 {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("owned stop signing-material digest does not match")
	}
	now := time.Now().UTC()
	if !now.Before(command.ExpiresAt) || command.IssuedAt.After(now) || request.RecoveryEpoch != command.Args["recovery_epoch"] {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("owned stop command expiry or recovery epoch is invalid")
	}
	public, err := readPinnedRootStopPublicKeyAt(paths.PublicKey, paths)
	if err != nil || !bytes.Equal(public, request.PinnedPublicKey) {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("owned stop intent did not pin the active root acknowledgement key")
	}
	if _, err := os.Lstat(cfg.CommandStatePath + ".recovery"); err == nil {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node command state has an unresolved recovery marker")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node recovery marker cannot be inspected")
	}
	stateBody, _, err := readOwnedStopBoundedAt(cfg.CommandStatePath, 32<<20, paths)
	if err != nil {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, err
	}
	var envelope commandStateEnvelope
	if rejectDuplicateJSONKeys(stateBody) != nil || decodeStrictCanonicalState(stateBody, &envelope) != nil || envelope.Version != commandStateVersion || envelope.Checksum == "" || envelope.State.Results == nil || envelope.State.Pending == nil || envelope.State.Fences == nil || envelope.State.OwnedStopOperations == nil || envelope.State.RecoveryEpoch != request.RecoveryEpoch || envelope.State.JournalSequence == 0 {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node command state envelope is incomplete")
	}
	encoded, err := json.Marshal(envelope.State)
	if err != nil || sha256Hex(encoded) != envelope.Checksum {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node command state checksum is invalid")
	}
	if err := verifyOwnedStopJournalReadOnly(cfg, envelope.State, envelope.Checksum, paths); err != nil {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, err
	}
	pending, ok := envelope.State.Pending[command.ID]
	if !ok || pending.Command != command.Command || pending.CommandID != command.ID || pending.IdempotencyKey != command.IdempotencyKey || pending.Token != int64FromArg(command.Args["fencing_token"]) || !bytes.Equal(pending.OriginalEnvelope, request.Command) || pending.SigningMaterialSHA256 != request.SigningSHA256 || pending.StopRecoveryEpoch != request.RecoveryEpoch || !bytes.Equal(pending.PinnedRootStopPublicKey, request.PinnedPublicKey) {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node command state does not contain the exact pending signed envelope")
	}
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	resourceFence := ownedStopFenceKey(accelerator)
	if envelope.State.Fences[resourceFence] != pending.Token {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node durable accelerator fence does not match the pending intent")
	}
	server, targetOK := func() (LlamaCPPServerConfig, bool) {
		for _, candidate := range cfg.LlamaCPP.Servers {
			if command.Args["target_id"] == cfg.NodeID+"-"+candidate.ID {
				return candidate, true
			}
		}
		return LlamaCPPServerConfig{}, false
	}()
	if !targetOK || strings.TrimSpace(server.ID) == "" {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("owned stop target is not the fixed local node target")
	}
	normalizedArgs := make(map[string]any, len(command.Args)+1)
	for key, value := range command.Args {
		normalizedArgs[key] = value
	}
	normalizedArgs["resource"] = "owned-stop:" + accelerator
	semanticFingerprint := wsproto.ResidencyCommandFingerprint(command.NodeID, command.Command, command.IdempotencyKey, normalizedArgs)
	var manifest pendingOperationManifest
	manifestRaw := []byte(pending.ManifestJSON)
	if rejectDuplicateJSONKeys(manifestRaw) != nil {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node pending operation manifest has duplicate fields")
	}
	manifestDecoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	manifestDecoder.DisallowUnknownFields()
	if manifestDecoder.Decode(&manifest) != nil {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node pending operation manifest is malformed")
	}
	canonicalManifest, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonicalManifest, manifestRaw) || manifest.Action != command.Command || manifest.NodeID != cfg.NodeID || manifest.CommandID != command.ID || manifest.IdempotencyKey != command.IdempotencyKey || manifest.Fingerprint != semanticFingerprint || pending.Fingerprint != semanticFingerprint || manifest.TargetKind != "llamacpp" || manifest.TargetID != command.Args["target_id"] || manifest.Model != "owned-stop:"+accelerator || manifest.FencingToken != pending.Token || !reflect.DeepEqual(manifest.Args, normalizedArgs) {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node pending operation manifest does not bind every original argument")
	}
	if envelope.State.CommandFingerprints["id:"+command.ID] != semanticFingerprint || envelope.State.CommandFingerprints[command.IdempotencyKey] != semanticFingerprint {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node command fingerprint aliases do not bind the pending envelope")
	}
	operationID := fmt.Sprint(command.Args["operation_id"])
	stepID := fmt.Sprint(command.Args["step_id"])
	operation, ok := envelope.State.OwnedStopOperations[accelerator]
	step, stepOK := operation.Steps[stepID]
	if !ok || !stepOK || !operation.UsedOperationIDs[operationID] || operation.OperationID != operationID || operation.AcceleratorID != accelerator || operation.Fence != pending.Token || operation.RecoveryEpoch != request.RecoveryEpoch || step.Status != "pending" || step.CommandID != command.ID || step.IdempotencyKey != command.IdempotencyKey || step.EnvelopeSHA256 != sha256Hex(request.Command) || !bytes.Equal(step.PinnedRootStopPublicKey, request.PinnedPublicKey) {
		return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("node durable operation-step journal does not match the exact pending stop")
	}
	for id, other := range envelope.State.Pending {
		if id == command.ID || other.Command != "llm_displacement_stop" {
			continue
		}
		var manifest pendingOperationManifest
		if json.Unmarshal([]byte(other.ManifestJSON), &manifest) == nil && manifest.Args["accelerator_id"] == accelerator {
			return nil, wsproto.CommandPayload{}, pendingCommand{}, errors.New("another pending owned stop already holds this accelerator")
		}
	}
	return cfg, command, pending, nil
}

func startCheckpointOwnedStopServer(plan *PinnedCheckpointLaunchPlan, launch *CheckpointControlledLaunch) (*checkpointOwnedStopServer, error) {
	if os.Geteuid() != 0 || plan == nil || launch == nil {
		return nil, errors.New("owned stop receiver requires the fixed root supervisor")
	}
	paths := fixedCheckpointOwnedStopPaths()
	uid, gid, principalErr := checkpointOwnedStopPrincipal(paths)
	if principalErr != nil {
		return nil, errors.New("fixed node-agent identity could not be pinned")
	}
	paths.NodeUID, paths.NodeGID = uid, gid
	paths.principalPinned = true
	cfg, configSHA256, err := loadOwnedStopNodeConfigAt(paths)
	if err != nil {
		return nil, err
	}
	private, public, err := ensureCheckpointOwnedStopKeysAt(paths)
	if err != nil {
		return nil, err
	}
	runtimeInfo, err := os.Lstat(filepath.Dir(paths.Socket))
	if err != nil || !runtimeInfo.IsDir() || runtimeInfo.Mode()&os.ModeSymlink != 0 || runtimeInfo.Mode().Perm() != 0o750 {
		return nil, errors.New("owned stop runtime directory is not the fixed private systemd directory")
	}
	runtimeStat, ok := runtimeInfo.Sys().(*syscall.Stat_t)
	if !ok || runtimeStat.Uid != 0 || runtimeStat.Gid != paths.NodeGID {
		return nil, errors.New("owned stop runtime directory ownership is invalid")
	}
	if current, err := os.Lstat(paths.Socket); err == nil {
		currentStat, ok := current.Sys().(*syscall.Stat_t)
		if !ok || current.Mode()&os.ModeSocket == 0 || current.Mode()&os.ModeSymlink != 0 || currentStat.Uid != 0 {
			return nil, errors.New("existing owned stop socket path is not a stale root socket")
		}
		if err := os.Remove(paths.Socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: paths.Socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chown(paths.Socket, 0, int(paths.NodeGID)); err != nil {
		listener.Close()
		return nil, err
	}
	if err := os.Chmod(paths.Socket, 0o660); err != nil {
		listener.Close()
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	server := &checkpointOwnedStopServer{listener: listener, private: private, public: public, secret: cfg.CommandSigningSecret, configSHA256: configSHA256, config: cfg, plan: plan, launch: launch, ackDone: make(chan struct{}), connections: make(chan struct{}, 4), paths: paths, unitObserver: readCheckpointOwnedStopUnit, bindingObserver: ObserveCheckpointManagedLocalBinding}
	return server, nil
}

func (s *checkpointOwnedStopServer) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *checkpointOwnedStopServer) isActive() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func (s *checkpointOwnedStopServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		select {
		case s.connections <- struct{}{}:
			go func() {
				defer func() { <-s.connections }()
				s.handleConnection(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (s *checkpointOwnedStopServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	if !s.ownedStopPeer(conn) {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	raw, err := io.ReadAll(io.LimitReader(conn, checkpointOwnedStopMaxFrame+1))
	if err != nil || len(raw) == 0 || len(raw) > checkpointOwnedStopMaxFrame || rejectDuplicateJSONKeys(raw) != nil {
		_ = json.NewEncoder(conn).Encode(ownedStopReply{Error: "invalid request frame"})
		return
	}
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request ownedStopRequest
	if err := decoder.Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(ownedStopReply{Error: "invalid request frame"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		_ = json.NewEncoder(conn).Encode(ownedStopReply{Error: "request frame has trailing data"})
		return
	}
	canonicalRequest, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonicalRequest, raw) {
		_ = json.NewEncoder(conn).Encode(ownedStopReply{Error: "request frame is not canonical"})
		return
	}
	receipt, err := s.handleStop(request)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(ownedStopReply{Error: "owned stop remains pending"})
		return
	}
	if s.dropReply != nil && s.dropReply() {
		return
	}
	_ = json.NewEncoder(conn).Encode(ownedStopReply{Receipt: receipt})
}

func (s *checkpointOwnedStopServer) ownedStopPeer(conn net.Conn) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}
	var credential *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || controlErr != nil || credential == nil {
		return false
	}
	uid, _, err := checkpointOwnedStopPrincipal(s.paths)
	return err == nil && credential.Uid == uid
}

type checkpointOwnedStopObservation struct {
	command         wsproto.CommandPayload
	workerPID       int
	workerTicks     uint64
	supervisorPID   int
	supervisorTicks uint64
	unit            checkpointFixedUnitState
	binding         CheckpointManagedBinding
	originalWire    []byte
	requestHash     string
}

func (s *checkpointOwnedStopServer) handleStop(request ownedStopRequest) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.waiterReady || s.waitDone == nil || s.waitErr == nil {
		return nil, errors.New("single owned waiter is not registered")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer stopCancel()
	var requestCommand wsproto.CommandPayload
	if rejectDuplicateJSONKeys(request.Command) != nil || json.Unmarshal(request.Command, &requestCommand) != nil || requestCommand.ExpiresAt.IsZero() {
		return nil, errors.New("owned stop request does not contain one exact expiring command")
	}
	if requestCommand.ExpiresAt.Before(time.Now().Add(25 * time.Second)) {
		var cancel context.CancelFunc
		stopCtx, cancel = context.WithDeadline(stopCtx, requestCommand.ExpiresAt)
		defer cancel()
	}
	cfg, command, pending, err := verifyOwnedStopNodeIntentAt(stopCtx, request, s.configSHA256, s.paths)
	if err != nil || cfg.NodeID != s.config.NodeID || cfg.CommandSigningSecret != s.secret {
		fallback := "loaded node identity or command credential differs from the fixed supervisor"
		s.reportTestDiagnostic("pre-barrier-node-intent", err, fallback)
		return nil, errors.New("root receiver could not verify the durable node intent")
	}
	if s.afterIntent != nil {
		// The test-only barrier runs without the receiver mutex so a forged
		// competing frame can be exercised while this verified intent is held.
		s.mu.Unlock()
		s.afterIntent()
		s.mu.Lock()
	}
	requestHash := sha256Hex(request.Command)
	receiptPath := filepath.Join(s.paths.ReceiptDir, ownedStopReceiptFilename(command.ID))
	if err := checkpointOwnedStopPathChainAt(receiptPath, s.paths, true); err != nil {
		return nil, err
	}
	if _, statErr := os.Lstat(receiptPath); statErr == nil {
		existing, observeErr := observeOwnedStopReceiptAt(stopCtx, s.paths.ReceiptDir, request.Command, request.PinnedPublicKey, s.secret, s.paths)
		if observeErr != nil {
			return nil, errors.New("existing owned stop receipt is present but cannot be authenticated")
		}
		s.markOwnedStopAcknowledged()
		return existing, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, errors.New("owned stop receipt path cannot be inspected")
	}
	if s.active && (s.observation == nil || s.observation.requestHash != requestHash) {
		return nil, errors.New("another owned stop operation is already active")
	}
	if !s.active {
		if err := s.plan.Recheck(stopCtx); err != nil {
			return nil, errors.New("pinned fixed plan changed before owned stop")
		}
		observation, err := s.observeOwnedStop(stopCtx, command, pending, requestHash)
		if err != nil {
			return nil, err
		}
		s.launch.mu.Lock()
		pidfd, started, reaped := s.launch.pidfd, s.launch.started, s.launch.reaped
		if !started || reaped || pidfd < 0 || s.launch.cmd == nil || s.launch.cmd.Process == nil || s.launch.cmd.Process.Pid != observation.workerPID {
			s.launch.mu.Unlock()
			return nil, errors.New("held owned pidfd differs from the fresh managed worker")
		}
		signalErr := unix.PidfdSendSignal(pidfd, syscall.SIGTERM, nil, 0)
		s.launch.mu.Unlock()
		if signalErr != nil {
			return nil, errors.New("owned worker termination signal was not confirmed")
		}
		s.active = true
		s.observation = &observation
	}
	observation := s.observation
	select {
	case <-s.waitDone:
	case <-stopCtx.Done():
		return nil, errors.New("owned worker exact reap exceeded its bound")
	}
	s.launch.mu.Lock()
	reaped, terminal := s.launch.reaped, s.launch.terminal
	s.launch.mu.Unlock()
	if !reaped || !terminal {
		return nil, errors.New("owned worker exact reap or terminal custody is unproven")
	}
	if s.waitErr != nil && !ownedStopExpectedWaitResult(*s.waitErr) {
		return nil, errors.New("owned worker lifetime ended with an unexpected exit status")
	}
	if err := s.plan.Recheck(stopCtx); err != nil {
		return nil, errors.New("pinned fixed plan drifted before owned stop acknowledgement")
	}
	if _, _, _, err := verifyOwnedStopNodeIntentAt(stopCtx, request, s.configSHA256, s.paths); err != nil {
		return nil, errors.New("durable node intent changed before owned stop acknowledgement")
	}
	unitObserver := s.unitObserver
	if unitObserver == nil {
		unitObserver = readCheckpointOwnedStopUnit
	}
	unit, err := unitObserver(stopCtx)
	if err != nil || unit.Invocation != observation.unit.Invocation || unit.ControlGroup != observation.unit.ControlGroup || unit.Active != "active" || unit.Sub != "running" {
		return nil, errors.New("fixed supervisor lifetime or invocation drifted after worker exit")
	}
	supervisorTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(observation.supervisorPID)), observation.supervisorPID)
	if err != nil || supervisorTicks != observation.supervisorTicks {
		return nil, errors.New("root supervisor incarnation changed before acknowledgement")
	}
	if _, err := readCheckpointCgroupMembership(stopCtx, filepath.Join("/proc", strconv.Itoa(observation.supervisorPID), "cgroup"), observation.unit.ControlGroup); err != nil {
		return nil, errors.New("root supervisor left the fixed service cgroup")
	}
	releaseCtx, cancel := context.WithTimeout(stopCtx, 20*time.Second)
	releaseErr := s.launch.ReleaseTerminal(releaseCtx)
	cancel()
	if releaseErr != nil {
		return nil, errors.New("custody terminal release remains unconfirmed")
	}
	signedAt := time.Now().UTC()
	if signedAt.Before(command.IssuedAt) || !signedAt.Before(command.ExpiresAt) {
		return nil, errors.New("owned stop command validity window closed before root acknowledgement")
	}
	receipt := ownedStopReceipt{Version: 1, NodeID: command.NodeID, OperationID: fmt.Sprint(command.Args["operation_id"]), StepID: fmt.Sprint(command.Args["step_id"]), CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, OriginalEnvelopeSHA256: sha256Hex(request.Command), SigningMaterialSHA256: request.SigningSHA256, RecoveryEpoch: request.RecoveryEpoch, AcceleratorID: fmt.Sprint(command.Args["accelerator_id"]), FencingToken: int64FromArg(command.Args["fencing_token"]), TargetID: fmt.Sprint(command.Args["target_id"]), WorkloadID: fmt.Sprint(command.Args["workload_id"]), WorkloadRevision: int64FromArg(command.Args["workload_revision"]), Model: fmt.Sprint(command.Args["model"]), ModelAlias: fmt.Sprint(command.Args["model_alias"]), LocalCheckpointBinding: observation.binding.CurrentIncarnation, ManagedCurrentIncarnation: observation.binding.CurrentIncarnation, ManagedPlanSHA256: observation.binding.PlanSHA256, CustodyBindingSHA256: observation.binding.CustodyBindingSHA256, SnapshotName: fmt.Sprint(command.Args["snapshot_name"]), SnapshotDigest: fmt.Sprint(command.Args["snapshot_digest"]), SupervisorPID: observation.supervisorPID, SupervisorStartTicks: observation.supervisorTicks, WorkerPID: observation.workerPID, WorkerStartTicks: observation.workerTicks, InvocationID: observation.unit.Invocation, ControlGroup: observation.unit.ControlGroup, SignalSent: true, ReleaseTerminal: true, SignedAt: signedAt.Format(time.RFC3339Nano)}
	unsigned, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	receipt.Signature = hex.EncodeToString(ed25519.Sign(s.private, ownedStopReceiptSigningMaterial(unsigned)))
	receiptRaw, err := json.Marshal(receipt)
	if err != nil || len(receiptRaw) > 16<<10 {
		return nil, errors.New("owned stop receipt could not be encoded within bound")
	}
	groupID := int(s.paths.NodeGID)
	if groupID < 0 {
		return nil, errors.New("owned stop receipt group is unavailable")
	}
	if err := writeOwnedStopReceiptAt(receiptRaw, groupID, s.paths); err != nil {
		return nil, errors.New("owned stop receipt could not be durably published")
	}
	if err := verifyOwnedStopReceipt(receiptRaw, s.public, request.Command, s.secret); err != nil {
		return nil, errors.New("durable root receipt failed local validation")
	}
	verifiedReceipt, err := observeOwnedStopReceiptAt(stopCtx, s.paths.ReceiptDir, request.Command, request.PinnedPublicKey, s.secret, s.paths)
	if err != nil || !bytes.Equal(verifiedReceipt, receiptRaw) {
		return nil, errors.New("published root receipt could not be re-observed as durable exact bytes")
	}
	s.markOwnedStopAcknowledged()
	return receiptRaw, nil
}

func (s *checkpointOwnedStopServer) markOwnedStopAcknowledged() {
	if s == nil || s.ackDone == nil {
		return
	}
	s.ackOnce.Do(func() {
		s.ackErr = nil
		close(s.ackDone)
	})
}

func ownedStopExpectedWaitResult(waitErr error) bool {
	if waitErr == nil {
		return true
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGTERM
}

func ownedStopWaitResultAfterDurableAck(waitErr, ackErr error) bool {
	return ackErr == nil && ownedStopExpectedWaitResult(waitErr)
}

func writeOwnedStopReceipt(raw []byte, gid int) error {
	return writeOwnedStopReceiptAt(raw, gid, fixedCheckpointOwnedStopPaths())
}

func writeOwnedStopReceiptAt(raw []byte, gid int, paths checkpointOwnedStopPaths) error {
	if len(raw) == 0 || len(raw) > 16<<10 || gid < 0 {
		return errors.New("owned stop receipt publication is outside its bound")
	}
	path := filepath.Join(paths.ReceiptDir, ownedStopReceiptFilenameFromReceipt(raw))
	if err := checkpointOwnedStopPathChainAt(path, paths, true); err != nil {
		return err
	}
	if existing, err := safefile.OpenReadOnlyNoFollow(path); err == nil {
		defer existing.Close()
		body, readErr := io.ReadAll(io.LimitReader(existing, (16<<10)+1))
		if readErr == nil && bytes.Equal(body, raw) {
			return nil
		}
		return errors.New("owned stop receipt path already contains different bytes")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(paths.ReceiptDir, ".owned-stop-receipt-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmpInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return err
	}
	defer removeOwnedStopTemporary(tmpPath, tmpInfo)
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chown(0, gid); err != nil {
		_ = tmp.Close()
		return err
	}
	if n, err := tmp.Write(raw); err != nil || n != len(raw) {
		_ = tmp.Close()
		if err != nil {
			return err
		}
		return errors.New("owned stop receipt write was incomplete")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	current, err := os.Lstat(tmpPath)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(tmpInfo, current) {
		return errors.New("owned stop receipt temporary path changed before publication")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, tmpPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	published, err := os.Lstat(path)
	if err != nil || !os.SameFile(tmpInfo, published) || published.Mode()&os.ModeSymlink != 0 {
		return errors.New("owned stop receipt publication identity changed")
	}
	return syncOwnedStopReceiptDirectory(paths)
}

func ownedStopReceiptFilenameFromReceipt(raw []byte) string {
	var receipt ownedStopReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.CommandID == "" {
		return "invalid.json"
	}
	return ownedStopReceiptFilename(receipt.CommandID)
}

func readCheckpointOwnedStopUnit(ctx context.Context) (checkpointFixedUnitState, error) {
	if ctx == nil {
		return checkpointFixedUnitState{}, errors.New("owned stop unit observation context is required")
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, checkpointFixedSystemctl, "show", checkpointIdentityServiceUnit, "--property=MainPID", "--property=InvocationID", "--property=ControlGroup", "--property=ActiveState", "--property=SubState")
	command.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	output := &checkpointUnitOutput{max: checkpointUnitMaxOutput}
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return checkpointFixedUnitState{}, errors.New("read fixed owned stop unit state failed")
	}
	if len(output.Bytes()) == 0 {
		return checkpointFixedUnitState{}, errors.New("fixed owned stop unit state is empty or oversized")
	}
	values := make(map[string]string, 5)
	for _, line := range strings.Split(strings.TrimSuffix(string(output.Bytes()), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || value == "" || values[key] != "" {
			return checkpointFixedUnitState{}, errors.New("fixed owned stop unit state is malformed")
		}
		switch key {
		case "MainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState":
			values[key] = value
		default:
			return checkpointFixedUnitState{}, errors.New("fixed owned stop unit state has an unexpected field")
		}
	}
	if len(values) != 5 {
		return checkpointFixedUnitState{}, errors.New("fixed owned stop unit state is incomplete")
	}
	pid, err := strconv.Atoi(values["MainPID"])
	if err != nil || pid < 0 || !checkpointInvocationIDRE.MatchString(strings.ToLower(values["InvocationID"])) || strings.EqualFold(values["InvocationID"], strings.Repeat("0", 32)) || !validCheckpointCgroupPath(values["ControlGroup"]) || (values["ActiveState"] != "active" && values["ActiveState"] != "activating") || values["SubState"] == "" {
		return checkpointFixedUnitState{}, errors.New("fixed owned stop unit identity is invalid")
	}
	return checkpointFixedUnitState{MainPID: pid, Invocation: strings.ToLower(values["InvocationID"]), ControlGroup: values["ControlGroup"], Active: values["ActiveState"], Sub: values["SubState"]}, nil
}

func verifyOwnedStopSnapshot(ctx context.Context, name, want string) error {
	return verifyOwnedStopSnapshotAt(ctx, name, want, checkpointFixedSnapshotRoot)
}

func verifyOwnedStopSnapshotAt(ctx context.Context, name, want, snapshotRoot string) error {
	if ctx == nil || ctx.Err() != nil || name == "" || strings.ContainsAny(name, `/\\`+"\x00\r\n") || strings.Contains(name, "..") || !strings.HasSuffix(name, ".kv") || !checkpointSHA256RE.MatchString(want) {
		return errors.New("owned stop snapshot identity is invalid")
	}
	path := filepath.Join(snapshotRoot, name)
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || !singleCheckpointLink(before) || before.Size() <= 0 || before.Size() > 1<<34 || before.Mode().Perm()&0o077 != 0 {
		return errors.New("owned stop snapshot is not a bounded private regular file")
	}
	hash := sha256.New()
	buffer := make([]byte, 1<<20)
	var read int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := f.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			read += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	after, err := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, pathInfo) || !sameCheckpointFileSnapshot(before, after) || read != before.Size() {
		return errors.New("owned stop snapshot changed during held-descriptor verification")
	}
	if hex.EncodeToString(hash.Sum(nil)) != want {
		return errors.New("owned stop snapshot digest differs from signed intent")
	}
	return ctx.Err()
}

func (s *checkpointOwnedStopServer) observeOwnedStop(ctx context.Context, command wsproto.CommandPayload, pending pendingCommand, requestHash string) (checkpointOwnedStopObservation, error) {
	if ctx == nil || ctx.Err() != nil {
		return checkpointOwnedStopObservation{}, errors.New("owned stop observation context is unavailable")
	}
	spec := s.plan.Spec()
	if err := wsproto.ValidateOwnedStopCommandArgs(command.Command, command.Args); err != nil || spec.Version != checkpointLaunchPlanVersion2 || spec.Placement == nil || command.Args["model_alias"] != spec.Alias || command.Args["accelerator_id"] != spec.Placement.PhysicalIdentity {
		return checkpointOwnedStopObservation{}, errors.New("owned stop signed identity differs from the immutable fixed plan")
	}
	var server *LlamaCPPServerConfig
	for i := range s.config.LlamaCPP.Servers {
		candidate := &s.config.LlamaCPP.Servers[i]
		if command.Args["target_id"] == s.config.NodeID+"-"+candidate.ID {
			server = candidate
			break
		}
	}
	endpoint := "http://" + net.JoinHostPort(spec.Endpoint.Host, strconv.Itoa(spec.Endpoint.Port))
	if server == nil || strings.TrimRight(server.Endpoint, "/") != endpoint {
		return checkpointOwnedStopObservation{}, errors.New("owned stop target is not the exact fixed local worker")
	}
	bindingObserver := s.bindingObserver
	if bindingObserver == nil {
		bindingObserver = ObserveCheckpointManagedLocalBinding
	}
	binding, err := bindingObserver(ctx)
	if err != nil || binding.Alias != spec.Alias || binding.Association.Identity.PID <= 1 || binding.Association.Custody.BindingSHA256 == "" {
		return checkpointOwnedStopObservation{}, errors.New("fresh root-local managed binding or custody receipt is unavailable")
	}
	wantBinding := strings.TrimPrefix(fmt.Sprint(command.Args["local_checkpoint_binding"]), "sha256:")
	if !strings.EqualFold(binding.CurrentIncarnation, wantBinding) || !checkpointSHA256RE.MatchString(binding.CurrentIncarnation) || !checkpointSHA256RE.MatchString(binding.CustodyBindingSHA256) || !strings.EqualFold(binding.CustodyBindingSHA256, binding.Association.Custody.BindingSHA256) || binding.Placement.PhysicalIdentity != spec.Placement.PhysicalIdentity {
		return checkpointOwnedStopObservation{}, errors.New("fresh managed binding or physical accelerator differs from signed intent")
	}
	unitObserver := s.unitObserver
	if unitObserver == nil {
		unitObserver = readCheckpointOwnedStopUnit
	}
	unit, err := unitObserver(ctx)
	if err != nil || unit.MainPID != binding.Association.Identity.PID || unit.Active != "active" || unit.Sub != "running" {
		return checkpointOwnedStopObservation{}, errors.New("fixed unit MainPID does not identify the fresh managed worker")
	}
	workerTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(unit.MainPID)), unit.MainPID)
	if err != nil || workerTicks != binding.Association.Identity.ProcessStartTicks {
		return checkpointOwnedStopObservation{}, errors.New("managed worker start incarnation is unavailable")
	}
	supervisorPID := os.Getpid()
	supervisorTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(supervisorPID)), supervisorPID)
	if err != nil || supervisorTicks == 0 {
		return checkpointOwnedStopObservation{}, errors.New("root supervisor start incarnation is unavailable")
	}
	if err := verifyOwnedStopSnapshotAt(ctx, fmt.Sprint(command.Args["snapshot_name"]), strings.TrimPrefix(fmt.Sprint(command.Args["snapshot_digest"]), "sha256:"), s.paths.SnapshotRoot); err != nil {
		return checkpointOwnedStopObservation{}, errors.New("signed snapshot reference is not an exact local snapshot")
	}
	original, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil || !bytes.Equal(original, pending.OriginalEnvelope) {
		return checkpointOwnedStopObservation{}, errors.New("pending original command no longer matches the exact envelope")
	}
	return checkpointOwnedStopObservation{command: command, workerPID: unit.MainPID, workerTicks: workerTicks, supervisorPID: supervisorPID, supervisorTicks: supervisorTicks, unit: unit, binding: binding, originalWire: original, requestHash: requestHash}, nil
}
