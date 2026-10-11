//go:build linux

package nodeagent

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"vram-governor/internal/safefile"
)

func readPinnedPlanBrokerPublicKeyAt(path string, paths checkpointPlanBrokerPaths) ([]byte, error) {
	if path != paths.PublicKey || (path != checkpointPlanBrokerPublicKeyPath && !checkpointPlanBrokerPrivateFixturePath(path, paths, "var/public/ed25519.pub")) {
		return nil, errors.New("root plan broker public key path is not fixed")
	}
	if err := checkpointPlanBrokerRootDir(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	stat, ok := infoSys(before)
	if err != nil || !ok || stat.Uid != 0 || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o644 || before.Size() != ed25519.PublicKeySize*2 || stat.Nlink != 1 {
		return nil, errors.New("root plan broker public key metadata is unsafe")
	}
	body, err := io.ReadAll(io.LimitReader(f, ed25519.PublicKeySize*2+1))
	after, statErr := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || len(body) != ed25519.PublicKeySize*2 || statErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, pathInfo) || !sameCheckpointFileSnapshot(before, after) {
		return nil, errors.New("root plan broker public key changed during held read")
	}
	key, err := hex.DecodeString(string(body))
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != string(body) {
		return nil, errors.New("root plan broker public key encoding is invalid")
	}
	return key, nil
}
