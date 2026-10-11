//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	custodyEnableVerityIOC  = 0x40806685
	custodyMeasureVerityIOC = 0xc0046686
	custodyVeritySHA256     = 1
	fsVerityDigestSize      = 32
)

func openCheckpointCustodyPlatform(cfg CheckpointCustodyConfig) (*CheckpointCustodyStore, error) {
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, err
	}
	root = filepath.Clean(root)
	if _, err = os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(root, 0700); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, errors.New("custody root must be a real mode-0700 directory")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return nil, errors.New("custody root must be owned by the current local principal")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return nil, errors.New("custody root is not canonical")
	}
	for _, name := range []string{"models", "receipts"} {
		p := filepath.Join(root, name)
		if err = os.Mkdir(p, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm() != 0700 {
			return nil, errors.New("custody private subdirectory is unsafe")
		}
		if st, ok := i.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
			return nil, errors.New("custody subdirectory has unexpected owner")
		}
	}
	launchers := filepath.Join(root, "launchers")
	if err = os.Mkdir(launchers, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	li, le := os.Lstat(launchers)
	if le != nil || !li.IsDir() || li.Mode()&os.ModeSymlink != 0 || li.Mode().Perm() != 0700 {
		return nil, errors.New("custody launcher directory is unsafe")
	}
	if st, ok := li.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return nil, errors.New("custody launcher directory has unexpected owner")
	}
	store := &CheckpointCustodyStore{root: root, maxBytes: cfg.MaxArtifactBytes, maxStagingBytes: cfg.MaxStagingBytes, reserve: cfg.ReserveBytes}
	paths := []string{root, filepath.Join(root, "models"), launchers, filepath.Join(root, "receipts")}
	ids := [][2]*uint64{{&store.rootDevice, &store.rootInode}, {&store.modelsDevice, &store.modelsInode}, {&store.launchersDevice, &store.launchersInode}, {&store.receiptsDevice, &store.receiptsInode}}
	for i, p := range paths {
		info, e := os.Stat(p)
		if e != nil {
			return nil, e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, errors.New("custody directory identity unavailable")
		}
		*ids[i][0] = uint64(st.Dev)
		*ids[i][1] = st.Ino
	}
	return store, nil
}

func ensureCheckpointCustodyKey(ctx context.Context, s *CheckpointCustodyStore) error {
	unlock, err := lockCustodyProcess(ctx, s)
	if err != nil {
		return err
	}
	defer unlock()
	privPath, pubPath := filepath.Join(s.root, "signing.key"), filepath.Join(s.root, "signing.pub")
	priv, pErr := readPrivateCustodyFile(privPath, ed25519.PrivateKeySize)
	pub, uErr := readPrivateCustodyFile(pubPath, ed25519.PublicKeySize)
	if pErr == nil && uErr == nil {
		if !ed25519.PrivateKey(priv).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pub)) {
			return errors.New("custody local keypair does not match")
		}
		return nil
	}
	if !errors.Is(pErr, os.ErrNotExist) || !errors.Is(uErr, os.ErrNotExist) {
		return errors.New("custody signing key files are incomplete or unsafe")
	}
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err = writeCustodyAtomic(s.root, privPath, priv); err != nil {
		return err
	}
	return writeCustodyAtomic(s.root, pubPath, pub)
}

func readPrivateCustodyFile(path string, size int) ([]byte, error) {
	return readPrivateCustodyFileContext(context.Background(), path, size)
}

func readPrivateCustodyFileContext(ctx context.Context, path string, size int) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("private file read context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("private file descriptor unavailable")
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !i.Mode().IsRegular() || i.Mode().Perm() != 0600 {
		return nil, errors.New("private key or receipt has unsafe mode/type")
	}
	if st, ok := i.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() || st.Nlink != 1 {
		return nil, errors.New("private file has unexpected owner")
	}
	b, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, r: f}, int64(size)+1))
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if (size <= ed25519.PrivateKeySize && len(b) != size) || (size > ed25519.PrivateKeySize && (len(b) == 0 || len(b) > size)) {
		return nil, errors.New("local custody key has invalid size")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("private file path changed during read")
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	fdStat, fdok := i.Sys().(*syscall.Stat_t)
	if !ok || !fdok || pathStat.Dev != fdStat.Dev || pathStat.Ino != fdStat.Ino {
		return nil, errors.New("private file path no longer names opened inode")
	}
	return b, nil
}

func openCheckpointCustodyArtifact(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("artifact descriptor unavailable")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("custody artifact is not a regular file")
	}
	return f, nil
}

func lockCustodyProcess(ctx context.Context, s *CheckpointCustodyStore) (func(), error) {
	if ctx == nil {
		return nil, errors.New("custody lock context is required")
	}
	if err := validateCustodyDirectories(s); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(s.root, "custody.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if int(st.Uid) != os.Getuid() || st.Nlink != 1 || st.Mode&0777 != 0600 {
		unix.Close(fd)
		return nil, errors.New("custody process lock is unsafe")
	}
	for {
		if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			unix.Close(fd)
			return nil, err
		}
		t := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			unix.Close(fd)
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
}

func writeCustodyAtomic(root, path string, data []byte) error {
	tmp, err := os.OpenFile(filepath.Join(root, ".tmp-"+hex.EncodeToString(mustRandom(12))), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, name, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	d, err := os.Open(root)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func mustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func reusableCheckpointKey(sourcePath, digest string, size int64) (string, error) {
	keyInput, err := json.Marshal(struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}{sourcePath, strings.ToLower(digest), size})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(keyInput)
	return hex.EncodeToString(sum[:]), nil
}

func reusableRecordPath(s *CheckpointCustodyStore, key string) string {
	return filepath.Join(s.root, "models", key+".reuse.json")
}

func reusableModelPath(s *CheckpointCustodyStore, key string) string {
	return filepath.Join(s.root, "models", key+".gguf")
}

func prepareReusableCheckpointCustodyPlatform(ctx context.Context, s *CheckpointCustodyStore, src CheckpointCustodySource) (*CheckpointPreparedModel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := filepath.Abs(src.Path)
	if err != nil {
		return nil, err
	}
	canonical = filepath.Clean(canonical)
	resolved, err := filepath.EvalSymlinks(canonical)
	if err != nil || resolved != canonical {
		return nil, errors.New("approved reusable source must be canonical and symlink-free")
	}
	in, err := openCheckpointCustodyArtifact(canonical)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != src.ExpectedBytes {
		return nil, errors.New("approved reusable source size or type mismatch")
	}
	key, err := reusableCheckpointKey(canonical, src.ApprovedSHA256, src.ExpectedBytes)
	if err != nil {
		return nil, err
	}
	unlock, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	processUnlock, err := lockCustodyProcess(ctx, s)
	if err != nil {
		return nil, err
	}
	defer processUnlock()
	if err = validateCustodyDirectories(s); err != nil {
		return nil, err
	}
	modelsDir := filepath.Join(s.root, "models")
	modelPath, recordPath := reusableModelPath(s, key), reusableRecordPath(s, key)
	_, modelErr := os.Lstat(modelPath)
	_, recordErr := os.Lstat(recordPath)
	modelExists := modelErr == nil
	recordExists := recordErr == nil
	if modelErr != nil && !errors.Is(modelErr, os.ErrNotExist) || recordErr != nil && !errors.Is(recordErr, os.ErrNotExist) {
		return nil, errors.New("reusable cache path cannot be inspected safely")
	}
	if modelExists != recordExists {
		return nil, errors.New("reusable cache has an orphaned model or missing signed record")
	}
	var staged int64
	for _, dir := range []string{modelsDir, filepath.Join(s.root, "launchers")} {
		entries, e := checkpointReadDirNamesBounded(dir, 4096)
		if e != nil {
			return nil, e
		}
		for _, entry := range entries {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			if strings.HasSuffix(entry, ".tmp") || strings.HasPrefix(entry, ".tmp-") || strings.HasPrefix(entry, ".cleanup-") {
				return nil, errors.New("custody staging directory contains an unexpected entry")
			}
			fi, e := os.Lstat(filepath.Join(dir, entry))
			if e != nil || !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("custody staging entry is unsafe")
			}
			if !custodyQuotaFits(staged, fi.Size(), 0, s.maxStagingBytes) {
				return nil, errors.New("custody staging quota is already exceeded")
			}
			staged += fi.Size()
		}
	}
	if !custodyQuotaFits(staged, 0, s.reserve, s.maxStagingBytes) {
		return nil, errors.New("retained custody staging bytes exceed quota or reserve")
	}
	if modelExists {
		if err = validateReusableOriginalSource(ctx, canonical, in, src, true); err != nil {
			return nil, err
		}
		modelPin, identity, verifyErr := openAndVerifyReusableCache(ctx, s, canonical, src, key, modelPath, recordPath)
		if verifyErr != nil {
			return nil, verifyErr
		}
		return &CheckpointPreparedModel{store: s, path: modelPath, identity: identity, reusable: true, reuseKey: key, modelPin: modelPin}, nil
	}

	// Existing unknowns and orphan files stay in the quota total. Metadata is
	// reserved before copying so publication cannot exceed the configured bound.
	if !custodyQuotaFits(staged, src.ExpectedBytes+custodyMaxReuseRecordBytes, s.reserve, s.maxStagingBytes) {
		return nil, errors.New("reusable model and bounded record plus reserve exceed custody staging quota")
	}
	var free unix.Statfs_t
	if err = unix.Statfs(s.root, &free); err != nil {
		return nil, err
	}
	if uint64(src.ExpectedBytes+custodyMaxReuseRecordBytes+s.reserve) > free.Bavail*uint64(free.Bsize) {
		return nil, errors.New("reusable cache quota plus reserve exceeds available disk space")
	}
	tmp := modelPath + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	var tmpCleanup custodyCleanupState
	defer func() {
		if !tmpCleanup.Removed {
			_ = captureAndRemoveCustodyPath(context.Background(), s, tmp, out, &tmpCleanup, func(*os.File) error { return nil }, func() error { return syncCustodyStoreDir(s, modelsDir) })
		}
		_ = out.Close()
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(contextReader{ctx, in}, src.ExpectedBytes+1))
	if s.reuseCopyBytesTest != nil {
		s.reuseCopyBytesTest(n)
	}
	if err != nil {
		return nil, err
	}
	if n != src.ExpectedBytes || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(src.ApprovedSHA256) {
		return nil, errors.New("approved reusable source changed or SHA-256 mismatched")
	}
	if err = validateReusableOriginalSource(ctx, canonical, in, src, false); err != nil {
		return nil, err
	}
	if s.reuseAfterCopyTest != nil {
		if err = s.reuseAfterCopyTest(tmp); err != nil {
			return nil, err
		}
	}
	if s.reuseModelSyncTest != nil {
		err = s.reuseModelSyncTest()
	}
	if err == nil {
		err = out.Sync()
	}
	if err != nil {
		return nil, err
	}
	if err = verifyCustodyEntryAgainstHeld(tmp, out); err != nil {
		return nil, errors.New("reusable copied temporary path no longer names the exact copied inode")
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, modelPath, unix.RENAME_NOREPLACE); err != nil {
		return nil, err
	}
	tmpCleanup.Removed, tmpCleanup.Synced = true, true
	if err = syncCustodyStoreDir(s, modelsDir); err != nil {
		return nil, err
	}
	modelPin, err := openCheckpointCustodyArtifact(modelPath)
	if err != nil {
		return nil, err
	}
	if err = verifyCustodyHeldRegular(modelPin, out); err != nil {
		modelPin.Close()
		return nil, errors.New("published reusable model path differs from the exact copied inode")
	}
	if err = out.Close(); err != nil {
		modelPin.Close()
		return nil, err
	}
	if err = enableAndMeasureVerity(int(modelPin.Fd())); err != nil {
		modelPin.Close()
		return nil, fmt.Errorf("fs-verity is required for reusable custody source: %w", err)
	}
	if err = unix.Fsync(int(modelPin.Fd())); err == nil {
		err = syncCustodyStoreDir(s, modelsDir)
	}
	if err != nil {
		modelPin.Close()
		return nil, err
	}
	identity, err := reusableStagedIdentity(modelPath, modelPin, src)
	if err != nil {
		modelPin.Close()
		return nil, err
	}
	_, privateKey, err := loadCustodyKey(s)
	if err != nil {
		modelPin.Close()
		return nil, err
	}
	record := custodyReuseRecord{Version: custodyReuseRecordVersion, KeyID: custodyKeyID(privateKey.Public().(ed25519.PublicKey)), Key: key, SourcePath: canonical, SourceSHA256: strings.ToLower(src.ApprovedSHA256), SourceSize: src.ExpectedBytes, Staged: identity}
	if err = publishReusableRecord(s, record, privateKey); err != nil {
		modelPin.Close()
		return nil, err
	}
	return &CheckpointPreparedModel{store: s, path: modelPath, identity: identity, reusable: true, reuseKey: key, modelPin: modelPin}, nil
}

func validateReusableOriginalSource(ctx context.Context, path string, held *os.File, src CheckpointCustodySource, verifyBytes bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("approved reusable source path changed during staging")
	}
	current, err := openCheckpointCustodyArtifact(path)
	if err != nil {
		return err
	}
	defer current.Close()
	var pinned, live syscall.Stat_t
	if err = syscall.Fstat(int(held.Fd()), &pinned); err != nil {
		return err
	}
	if err = syscall.Fstat(int(current.Fd()), &live); err != nil {
		return err
	}
	if live.Mode&syscall.S_IFMT != syscall.S_IFREG || pinned.Dev != live.Dev || pinned.Ino != live.Ino || live.Size != src.ExpectedBytes {
		return errors.New("approved reusable source path no longer names the copied inode")
	}
	if verifyBytes {
		if _, err = held.Seek(0, io.SeekStart); err != nil {
			return err
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(contextReader{ctx, held}, src.ExpectedBytes+1))
		if copyErr != nil {
			return copyErr
		}
		if n != src.ExpectedBytes || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(src.ApprovedSHA256) {
			return errors.New("approved reusable source bytes changed after approval")
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return nil
}

func reusableStagedIdentity(path string, held *os.File, src CheckpointCustodySource) (custodySourceIdentity, error) {
	info, err := held.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != src.ExpectedBytes {
		return custodySourceIdentity{}, errors.New("sealed reusable model has an unexpected type or size")
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(int(held.Fd()), &stat); err != nil || stat.Nlink != 1 || uint64(stat.Uid) != uint64(os.Getuid()) || stat.Mode&0777 != 0600 {
		return custodySourceIdentity{}, errors.New("sealed reusable model inode is not private and single-linked")
	}
	verity, err := measureVerity(int(held.Fd()))
	if err != nil {
		return custodySourceIdentity{}, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return custodySourceIdentity{}, errors.New("sealed reusable model path is not canonical")
	}
	return custodySourceIdentity{CanonicalPath: path, Device: uint64(stat.Dev), Inode: stat.Ino, Size: info.Size(), SHA256: strings.ToLower(src.ApprovedSHA256), VerityDigest: verity}, nil
}

func publishReusableRecord(s *CheckpointCustodyStore, record custodyReuseRecord, privateKey ed25519.PrivateKey) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	signed := custodySignedReuseRecord{Record: record, Signature: hex.EncodeToString(ed25519.Sign(privateKey, payload))}
	raw, err := json.Marshal(signed)
	if err != nil || len(raw) > custodyMaxReuseRecordBytes {
		return errors.New("reusable cache record exceeds its bounded metadata size")
	}
	dir := filepath.Join(s.root, "models")
	tmp := filepath.Join(dir, ".tmp-reuse-"+hex.EncodeToString(mustRandom(12)))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	var tmpCleanup custodyCleanupState
	defer func() {
		if !tmpCleanup.Removed {
			_ = captureAndRemoveCustodyPath(context.Background(), s, tmp, f, &tmpCleanup, func(*os.File) error { return nil }, func() error { return syncCustodyStoreDir(s, dir) })
		}
		_ = f.Close()
	}()
	if s.reuseRecordBeforePublishTest != nil {
		if err = s.reuseRecordBeforePublishTest(tmp); err != nil {
			return err
		}
	}
	if _, err = f.Write(raw); err == nil {
		if s.reuseRecordSyncTest != nil {
			err = s.reuseRecordSyncTest()
		}
		if err == nil {
			err = f.Sync()
		}
	}
	if err != nil {
		return err
	}
	if err = verifyCustodyEntryAgainstHeld(tmp, f); err != nil {
		return errors.New("reusable signed-record temporary path no longer names its exact inode")
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, reusableRecordPath(s, record.Key), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	tmpCleanup.Removed, tmpCleanup.Synced = true, true
	if err = verifyCustodyEntryAgainstHeld(reusableRecordPath(s, record.Key), f); err != nil {
		return errors.New("published reusable signed-record path differs from its exact written inode")
	}
	if closeErr := f.Close(); closeErr != nil {
		return closeErr
	}
	return syncCustodyStoreDir(s, dir)
}

func openAndVerifyReusableCache(ctx context.Context, s *CheckpointCustodyStore, sourcePath string, src CheckpointCustodySource, key, modelPath, recordPath string) (*os.File, custodySourceIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, custodySourceIdentity{}, err
	}
	raw, err := readPrivateCustodyFileContext(ctx, recordPath, custodyMaxReuseRecordBytes)
	if err != nil {
		return nil, custodySourceIdentity{}, err
	}
	var signed custodySignedReuseRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&signed); err != nil {
		return nil, custodySourceIdentity{}, errors.New("reusable cache record is malformed")
	}
	if err = dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, custodySourceIdentity{}, errors.New("reusable cache record has trailing data")
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, custodySourceIdentity{}, errors.New("reusable cache record is not canonical")
	}
	pub, _, err := loadCustodyKey(s)
	if err != nil {
		return nil, custodySourceIdentity{}, err
	}
	record := signed.Record
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, custodySourceIdentity{}, err
	}
	sig, err := hex.DecodeString(signed.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || hex.EncodeToString(sig) != signed.Signature || !ed25519.Verify(pub, payload, sig) {
		return nil, custodySourceIdentity{}, errors.New("reusable cache record signature is invalid")
	}
	wantSHA := strings.ToLower(src.ApprovedSHA256)
	if record.Version != custodyReuseRecordVersion || record.KeyID != custodyKeyID(pub) || record.Key != key || record.SourcePath != sourcePath || record.SourceSHA256 != wantSHA || record.SourceSize != src.ExpectedBytes || record.Staged.CanonicalPath != modelPath || record.Staged.Size != src.ExpectedBytes || record.Staged.SHA256 != wantSHA || !custodyDigestRE.MatchString(record.Staged.VerityDigest) {
		return nil, custodySourceIdentity{}, errors.New("reusable cache record does not bind the requested source and stage")
	}
	modelPin, err := openCheckpointCustodyArtifact(modelPath)
	if err != nil {
		return nil, custodySourceIdentity{}, err
	}
	if err = validateReusableStageIdentity(modelPin, record.Staged); err != nil {
		modelPin.Close()
		return nil, custodySourceIdentity{}, err
	}
	return modelPin, record.Staged, nil
}

func validateReusableStageIdentity(held *os.File, want custodySourceIdentity) error {
	info, err := held.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != want.Size {
		return errors.New("reusable model stage type or size changed")
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(int(held.Fd()), &stat); err != nil || uint64(stat.Dev) != want.Device || stat.Ino != want.Inode || stat.Size != want.Size || stat.Nlink != 1 || uint64(stat.Uid) != uint64(os.Getuid()) || stat.Mode&0777 != 0600 {
		return errors.New("reusable model stage inode identity changed")
	}
	verity, err := measureVerity(int(held.Fd()))
	if err != nil || verity != want.VerityDigest {
		return errors.New("reusable model stage has no matching fs-verity identity")
	}
	return nil
}

func prepareCheckpointCustodyPlatform(ctx context.Context, s *CheckpointCustodyStore, src CheckpointCustodySource) (*CheckpointPreparedModel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := filepath.Abs(src.Path)
	if err != nil {
		return nil, err
	}
	canonical = filepath.Clean(canonical)
	resolved, err := filepath.EvalSymlinks(canonical)
	if err != nil || resolved != canonical {
		return nil, errors.New("approved source must be canonical and symlink-free")
	}
	in, err := openCheckpointCustodyArtifact(canonical)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != src.ExpectedBytes {
		return nil, errors.New("approved source size or type mismatch")
	}
	unlock, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	processUnlock, err := lockCustodyProcess(ctx, s)
	if err != nil {
		return nil, err
	}
	defer processUnlock()
	modelsDir := filepath.Join(s.root, "models")
	var staged int64
	for _, dir := range []string{modelsDir, filepath.Join(s.root, "launchers")} {
		entries, e := checkpointReadDirNamesBounded(dir, 4096)
		if e != nil {
			return nil, e
		}
		for _, entry := range entries {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			if strings.HasSuffix(entry, ".tmp") {
				return nil, errors.New("custody staging directory contains an unexpected entry")
			}
			fi, e := os.Lstat(filepath.Join(dir, entry))
			if e != nil || !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("custody staging entry is unsafe")
			}
			if !custodyQuotaFits(staged, fi.Size(), 0, s.maxStagingBytes) {
				return nil, errors.New("custody staging quota is already exceeded")
			}
			staged += fi.Size()
		}
	}
	if !custodyQuotaFits(staged, src.ExpectedBytes, s.reserve, s.maxStagingBytes) {
		return nil, errors.New("model bytes plus configured reserve exceed custody staging quota")
	}
	var free unix.Statfs_t
	if err = unix.Statfs(s.root, &free); err != nil {
		return nil, err
	}
	if uint64(src.ExpectedBytes+s.reserve) > free.Bavail*uint64(free.Bsize) {
		return nil, errors.New("custody staging quota plus reserve exceeds available disk space")
	}
	name := hex.EncodeToString(mustRandom(16))
	final := filepath.Join(s.root, "models", name+".gguf")
	tmp := final + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(tmp)
			os.Remove(final)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(contextReader{ctx, in}, src.ExpectedBytes+1))
	if err != nil {
		return nil, err
	}
	if n != src.ExpectedBytes {
		return nil, errors.New("approved source changed or exceeded exact byte bound")
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(src.ApprovedSHA256) {
		return nil, errors.New("approved source SHA-256 mismatch")
	}
	if err = out.Sync(); err != nil {
		return nil, err
	}
	if err = out.Close(); err != nil {
		return nil, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, final, unix.RENAME_NOREPLACE); err != nil {
		return nil, err
	}
	stageDir, err := os.Open(modelsDir)
	if err != nil {
		return nil, err
	}
	err = stageDir.Sync()
	stageDir.Close()
	if err != nil {
		return nil, err
	}
	f, err := openCheckpointCustodyArtifact(final)
	if err != nil {
		return nil, err
	}
	if err = enableAndMeasureVerity(int(f.Fd())); err != nil {
		f.Close()
		return nil, fmt.Errorf("fs-verity is required for immutable custody source: %w", err)
	}
	if err = unix.Fsync(int(f.Fd())); err != nil {
		f.Close()
		return nil, err
	}
	stageDir, err = os.Open(modelsDir)
	if err != nil {
		f.Close()
		return nil, err
	}
	err = stageDir.Sync()
	stageDir.Close()
	if err != nil {
		f.Close()
		return nil, err
	}
	verity, err := measureVerity(int(f.Fd()))
	if err != nil {
		f.Close()
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	var dst syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &dst); err != nil {
		f.Close()
		return nil, err
	}
	path2, err := filepath.EvalSymlinks(final)
	if err != nil || path2 != final {
		f.Close()
		return nil, errors.New("staged model pathname changed")
	}
	ok = true
	return &CheckpointPreparedModel{store: s, path: final, modelPin: f, identity: custodySourceIdentity{CanonicalPath: final, Device: uint64(dst.Dev), Inode: dst.Ino, Size: fi.Size(), SHA256: strings.ToLower(src.ApprovedSHA256), VerityDigest: verity}}, nil
}

func validatePreparedCheckpointPlatform(m *CheckpointPreparedModel, held *os.File) error {
	if m == nil || m.store == nil {
		return errors.New("prepared model authority unavailable")
	}
	if err := validateCustodyDirectories(m.store); err != nil {
		return err
	}
	f, err := openCheckpointCustodyArtifact(m.path)
	if err != nil {
		return err
	}
	defer f.Close()
	var st syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if uint64(st.Dev) != m.identity.Device || st.Ino != m.identity.Inode || st.Size != m.identity.Size || st.Nlink != 1 {
		return errors.New("prepared immutable artifact identity changed before launch")
	}
	v, err := measureVerity(int(f.Fd()))
	if err != nil || v != m.identity.VerityDigest {
		return errors.New("prepared fs-verity identity changed before launch")
	}
	if held != nil {
		var pinned syscall.Stat_t
		if err = syscall.Fstat(int(held.Fd()), &pinned); err != nil || pinned.Dev != st.Dev || pinned.Ino != st.Ino || pinned.Size != st.Size || pinned.Nlink != 1 {
			return errors.New("held model descriptor no longer pins the prepared artifact")
		}
		pinnedVerity, measureErr := measureVerity(int(held.Fd()))
		if measureErr != nil || pinnedVerity != m.identity.VerityDigest {
			return errors.New("held model descriptor has no matching fs-verity identity")
		}
	}
	resolved, err := filepath.EvalSymlinks(m.path)
	if err != nil || resolved != m.path {
		return errors.New("prepared model path is no longer canonical")
	}
	return nil
}

func validateCheckpointLaunchExecutablePlatform(path, want string, held *os.File) error {
	if held == nil || path == "" {
		return errors.New("held executable descriptor is unavailable")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("staged executable path is no longer canonical")
	}
	f, err := openCheckpointCustodyArtifact(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var st, pinned syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if err = syscall.Fstat(int(held.Fd()), &pinned); err != nil || pinned.Dev != st.Dev || pinned.Ino != st.Ino || pinned.Size != st.Size || pinned.Nlink != 1 || st.Mode&0111 == 0 {
		return errors.New("executable path no longer names the pinned immutable launch image")
	}
	verity, err := measureVerity(int(held.Fd()))
	if err != nil || verity == "" {
		return errors.New("held executable descriptor lost fs-verity protection")
	}
	if !custodyDigestRE.MatchString(want) {
		return errors.New("expected executable digest is invalid")
	}
	return nil
}

func retainCheckpointChildPlatform(pid int) (int, error) {
	if pid <= 1 {
		return -1, errors.New("controlled child PID invalid")
	}
	return unix.PidfdOpen(pid, 0)
}
func duplicateCheckpointChildPlatform(fd int) (int, error) {
	if fd < 0 {
		return -1, errors.New("controlled child pidfd unavailable for commit")
	}
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
}
func closeCheckpointChildPlatform(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}
func killCheckpointChildPlatform(fd int) error {
	return unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0)
}

func releaseCheckpointExecutablePlatform(store *CheckpointCustodyStore, path string, held *os.File, state *custodyCleanupState) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return releaseCheckpointExecutableContextPlatform(ctx, store, path, held, state)
}

func releaseCheckpointExecutableContextPlatform(ctx context.Context, store *CheckpointCustodyStore, path string, held *os.File, state *custodyCleanupState) error {
	if ctx == nil {
		return errors.New("executable cleanup context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || filepath.Dir(path) != filepath.Join(store.root, "launchers") {
		return errors.New("staged executable cleanup path is outside its validated private directory")
	}
	if err := validateCustodyDirectories(store); err != nil {
		return err
	}
	syncDir := func() error { return syncCustodyStoreDir(store, filepath.Join(store.root, "launchers")) }
	settled, err := settleAlreadyUnlinkedCheckpointExecutable(ctx, store, path, held, state, syncDir)
	if err != nil || settled {
		return err
	}
	return captureAndRemoveCustodyPath(ctx, store, path, held, state, nil, syncDir)
}

// settleAlreadyUnlinkedCheckpointExecutable accepts only an already-unlinked
// exact executable pin. It never removes a pathname: a replacement at the
// original name is preserved and reported as an error.
func settleAlreadyUnlinkedCheckpointExecutable(ctx context.Context, store *CheckpointCustodyStore, path string, held *os.File, state *custodyCleanupState, syncDir func() error) (bool, error) {
	if ctx == nil || store == nil || held == nil || state == nil || state.Removed || state.Captured {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return true, err
	}
	var pinned syscall.Stat_t
	if err := syscall.Fstat(int(held.Fd()), &pinned); err != nil {
		return false, err
	}
	if pinned.Mode&syscall.S_IFMT != syscall.S_IFREG || pinned.Uid != uint32(os.Getuid()) || uint64(pinned.Dev) != store.launchersDevice || pinned.Nlink != 0 {
		return false, nil
	}
	dirPath, base := filepath.Dir(path), filepath.Base(path)
	dirFD, err := unix.Open(dirPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return true, err
	}
	defer unix.Close(dirFD)
	var parent unix.Stat_t
	if err = unix.Fstat(dirFD, &parent); err != nil || uint64(parent.Dev) != store.launchersDevice || parent.Ino != store.launchersInode || uint32(parent.Uid) != uint32(os.Getuid()) || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&0777 != 0700 {
		return true, errors.New("unlinked executable parent is not the original private directory")
	}
	checkAbsent := func() error {
		var entry unix.Stat_t
		entryErr := unix.Fstatat(dirFD, base, &entry, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(entryErr, unix.ENOENT) {
			return nil
		}
		if entryErr != nil {
			return entryErr
		}
		return errors.New("staged executable path now names another object; preserving it")
	}
	if err = checkAbsent(); err != nil {
		return true, err
	}
	if err = ctx.Err(); err != nil {
		return true, err
	}
	if syncDir != nil {
		if err = syncDir(); err != nil {
			return true, err
		}
	}
	if err = ctx.Err(); err != nil {
		return true, err
	}
	if err = checkAbsent(); err != nil {
		return true, err
	}
	if err = syscall.Fstat(int(held.Fd()), &pinned); err != nil || pinned.Mode&syscall.S_IFMT != syscall.S_IFREG || pinned.Uid != uint32(os.Getuid()) || uint64(pinned.Dev) != store.launchersDevice || pinned.Nlink != 0 {
		return true, errors.New("held executable pin changed while settling already-unlinked cleanup")
	}
	state.Removed = true
	state.Synced = true
	return true, nil
}

func captureAndRemoveCustodyPath(ctx context.Context, store *CheckpointCustodyStore, path string, held *os.File, state *custodyCleanupState, verify func(*os.File) error, syncDir func() error) error {
	if ctx == nil || store == nil || path == "" || held == nil || state == nil {
		return errors.New("bounded custody cleanup lacks context, path, inode pin, or retry state")
	}
	if syncDir == nil {
		syncDir = func() error { return syncCustodyDir(filepath.Dir(path)) }
	}
	if state.Removed {
		if state.Synced {
			return nil
		}
		if err := syncDir(); err != nil {
			return err
		}
		state.Synced = true
		return nil
	}
	dirPath, base := filepath.Dir(path), filepath.Base(path)
	var wantDev, wantIno uint64
	switch dirPath {
	case filepath.Join(store.root, "models"):
		wantDev, wantIno = store.modelsDevice, store.modelsInode
	case filepath.Join(store.root, "receipts"):
		wantDev, wantIno = store.receiptsDevice, store.receiptsInode
	case filepath.Join(store.root, "launchers"):
		wantDev, wantIno = store.launchersDevice, store.launchersInode
	default:
		return errors.New("custody cleanup parent is outside a validated private directory")
	}
	dirFD, err := unix.Open(dirPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	var parent unix.Stat_t
	if err = unix.Fstat(dirFD, &parent); err != nil || uint64(parent.Dev) != wantDev || parent.Ino != wantIno || uint32(parent.Uid) != uint32(os.Getuid()) || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&0777 != 0700 {
		return errors.New("custody cleanup parent descriptor is not the original private directory")
	}
	if !state.Captured {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = verifyCustodyHeldRegular(held, held); err != nil {
			return err
		}
		if err = verifyCustodyEntryAgainstHeld(path, held); err != nil {
			return err
		}
		raw := make([]byte, 16)
		if _, err = rand.Read(raw); err != nil {
			return err
		}
		state.CaptureName = ".cleanup-" + hex.EncodeToString(raw)
		if dirPath == filepath.Join(store.root, "receipts") {
			state.CaptureName += ".json"
		}
		if store != nil && store.cleanupBeforeCaptureTest != nil {
			store.cleanupBeforeCaptureTest(path, filepath.Join(dirPath, state.CaptureName))
		}
		if err = ctx.Err(); err != nil {
			state.CaptureName = ""
			return err
		}
		if err = unix.Renameat2(dirFD, base, dirFD, state.CaptureName, unix.RENAME_NOREPLACE); err != nil {
			state.CaptureName = ""
			return err
		}
		state.Captured = true
		if store != nil && store.cleanupAfterCaptureTest != nil {
			store.cleanupAfterCaptureTest(path, filepath.Join(dirPath, state.CaptureName))
		}
		if err = syncDir(); err != nil {
			return err
		}
	}
	nameHex := strings.TrimPrefix(state.CaptureName, ".cleanup-")
	if dirPath == filepath.Join(store.root, "receipts") {
		nameHex = strings.TrimSuffix(nameHex, ".json")
	}
	if len(nameHex) != 32 || !strings.HasPrefix(state.CaptureName, ".cleanup-") || dirPath == filepath.Join(store.root, "receipts") && !strings.HasSuffix(state.CaptureName, ".json") {
		return errors.New("custody retry state contains an invalid private capture name")
	}
	if _, err = hex.DecodeString(nameHex); err != nil {
		return errors.New("custody retry state contains a malformed private capture name")
	}
	if err = syncDir(); err != nil {
		return err
	}
	capturedFD, err := unix.Openat(dirFD, state.CaptureName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	captured := os.NewFile(uintptr(capturedFD), filepath.Join(dirPath, state.CaptureName))
	if captured == nil {
		unix.Close(capturedFD)
		return errors.New("captured custody descriptor unavailable")
	}
	defer captured.Close()
	if err = verifyCustodyHeldRegular(captured, held); err == nil && verify != nil {
		err = verify(captured)
	}
	if err != nil {
		restoreErr := unix.Renameat2(dirFD, state.CaptureName, dirFD, base, unix.RENAME_NOREPLACE)
		if restoreErr == nil {
			state.Captured = false
			state.CaptureName = ""
			_ = syncDir()
		}
		return errors.Join(errors.New("captured custody entry is not the original pinned object"), err, restoreErr)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = verifyCustodyEntryAgainstHeld(filepath.Join(dirPath, state.CaptureName), held); err != nil {
		return err
	}
	if err = unix.Unlinkat(dirFD, state.CaptureName, 0); err != nil {
		return err
	}
	state.Captured = false
	state.Removed = true
	if err = syncDir(); err != nil {
		return err
	}
	state.Synced = true
	state.CaptureName = ""
	return nil
}

func verifyCustodyHeldRegular(candidate, held *os.File) error {
	var a, b syscall.Stat_t
	if err := syscall.Fstat(int(candidate.Fd()), &a); err != nil {
		return err
	}
	if err := syscall.Fstat(int(held.Fd()), &b); err != nil {
		return err
	}
	if a.Mode&syscall.S_IFMT != syscall.S_IFREG || a.Dev != b.Dev || a.Ino != b.Ino || a.Size != b.Size || a.Uid != b.Uid || a.Mode&0777 != b.Mode&0777 || a.Nlink != 1 {
		return errors.New("captured entry identity differs from original held inode")
	}
	return nil
}

func verifyCustodyEntryAgainstHeld(path string, held *os.File) error {
	f, err := openCheckpointCustodyArtifact(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return verifyCustodyHeldRegular(f, held)
}

func validateCustodyDirectories(s *CheckpointCustodyStore) error {
	paths := []string{s.root, filepath.Join(s.root, "models"), filepath.Join(s.root, "launchers"), filepath.Join(s.root, "receipts")}
	devs := []uint64{s.rootDevice, s.modelsDevice, s.launchersDevice, s.receiptsDevice}
	inos := []uint64{s.rootInode, s.modelsInode, s.launchersInode, s.receiptsInode}
	for n, p := range paths {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm() != 0700 {
			return errors.New("custody private directory changed or is unsafe")
		}
		resolved, e := filepath.EvalSymlinks(p)
		if e != nil || resolved != p {
			return errors.New("custody directory path is no longer canonical")
		}
		if st, ok := i.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() || uint64(st.Dev) != devs[n] || st.Ino != inos[n] {
			return errors.New("custody directory owner or inode changed")
		}
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func checkpointReadDirNamesBounded(path string, limit int) ([]string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	if dir == nil {
		unix.Close(fd)
		return nil, errors.New("directory descriptor unavailable")
	}
	defer dir.Close()
	names, err := dir.Readdirnames(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > limit {
		return nil, errors.New("directory entry count exceeds bound")
	}
	return names, nil
}

func checkpointVerityEnableArgument(fd int) ([128]byte, error) {
	var arg [128]byte
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return arg, err
	}
	if fs.Bsize < 1024 {
		return arg, errors.New("filesystem block size is below the fs-verity minimum")
	}
	blockSize := uint64(os.Getpagesize())
	if uint64(fs.Bsize) < blockSize {
		blockSize = uint64(fs.Bsize)
	}
	if blockSize < 1024 || blockSize&(blockSize-1) != 0 || blockSize > uint64(^uint32(0)) {
		return arg, errors.New("filesystem and page sizes do not permit a supported fs-verity block size")
	}
	*(*uint32)(unsafe.Pointer(&arg[0])) = 1
	*(*uint32)(unsafe.Pointer(&arg[4])) = custodyVeritySHA256
	*(*uint32)(unsafe.Pointer(&arg[8])) = uint32(blockSize)
	return arg, nil
}

func enableAndMeasureVerity(fd int) error {
	if _, err := measureVerity(fd); err == nil {
		return nil
	}
	arg, err := checkpointVerityEnableArgument(fd)
	if err != nil {
		return err
	}
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(custodyEnableVerityIOC), uintptr(unsafe.Pointer(&arg[0])))
	if e != 0 {
		return e
	}
	_, err = measureVerity(fd)
	return err
}
func measureVerity(fd int) (string, error) {
	buf := make([]byte, 4+64)
	*(*uint16)(unsafe.Pointer(&buf[0])) = custodyVeritySHA256
	*(*uint16)(unsafe.Pointer(&buf[2])) = 64
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(custodyMeasureVerityIOC), uintptr(unsafe.Pointer(&buf[0])))
	if e != 0 {
		return "", e
	}
	if *(*uint16)(unsafe.Pointer(&buf[0])) != custodyVeritySHA256 || *(*uint16)(unsafe.Pointer(&buf[2])) != fsVerityDigestSize {
		return "", errors.New("fs-verity digest algorithm or size is unsupported")
	}
	return hex.EncodeToString(buf[4 : 4+fsVerityDigestSize]), nil
}

func beginCheckpointCustodyPlatform(ctx context.Context, s *CheckpointCustodyStore, m *CheckpointPreparedModel, req CheckpointCustodyLaunchRequest) (*CheckpointControlledLaunch, error) {
	if err := validatePreparedCheckpointPlatform(m, m.modelPin); err != nil {
		return nil, err
	}
	modelFD, err := openCheckpointCustodyArtifact(m.path)
	if err != nil {
		return nil, err
	}
	if err = validatePreparedCheckpointPlatform(m, modelFD); err != nil {
		modelFD.Close()
		return nil, err
	}
	boot, err := checkpointReadBounded(checkpointCustodyBootIDPath(), 128)
	if err != nil {
		modelFD.Close()
		return nil, err
	}
	bootID := strings.TrimSpace(string(boot))
	if bootID == "" {
		modelFD.Close()
		return nil, errors.New("kernel boot ID is unavailable")
	}
	now, err := checkpointBootTimeNS()
	if err != nil {
		modelFD.Close()
		return nil, err
	}
	nonce, err := custodyNewNonce()
	if err != nil {
		modelFD.Close()
		return nil, err
	}
	executablePath, executableFD, err := custodyStageExecutable(ctx, s, req.Command.Path, req.ExpectedExecutableSHA256)
	if err != nil {
		modelFD.Close()
		if executableFD != nil {
			m.mu.Lock()
			m.failedExecutablePath, m.failedExecutableFD = executablePath, executableFD
			m.failedExecutableCleanup = custodyCleanupState{}
			m.mu.Unlock()
		}
		return nil, err
	}
	if s.beginAfterStageTest != nil {
		if err = s.beginAfterStageTest(executablePath); err != nil {
			modelFD.Close()
			m.mu.Lock()
			m.failedExecutablePath, m.failedExecutableFD = executablePath, executableFD
			m.failedExecutableCleanup = custodyCleanupState{}
			m.mu.Unlock()
			return nil, err
		}
	}
	if err = ctx.Err(); err != nil {
		modelFD.Close()
		m.mu.Lock()
		m.failedExecutablePath, m.failedExecutableFD = executablePath, executableFD
		m.failedExecutableCleanup = custodyCleanupState{}
		m.mu.Unlock()
		return nil, err
	}
	req.Command.Path = "/proc/self/fd/3"
	req.Command.ExtraFiles = []*os.File{executableFD, modelFD}
	return &CheckpointControlledLaunch{store: s, model: m, cmd: req.Command, modelFD: modelFD, executableFD: executableFD, executablePath: executablePath, permit: &struct{}{}, pidfd: -1, commitPIDFD: -1, bootID: bootID, preBootNS: now, nonce: nonce, endpoint: req.Endpoint, unit: req.ServiceUnit, alias: req.ActualAlias, expectedExecutableSHA256: strings.ToLower(req.ExpectedExecutableSHA256)}, nil
}

func custodyStageExecutable(ctx context.Context, s *CheckpointCustodyStore, path, want string) (stagedPath string, pinnedFD *os.File, stageErr error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", nil, errors.New("controlled executable must have a fixed absolute path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return "", nil, errors.New("controlled executable path must be canonical and symlink-free")
	}
	f, err := openCheckpointCustodyArtifact(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 1<<30 {
		return "", nil, errors.New("controlled executable type or size is invalid")
	}
	elfFile, err := elf.NewFile(f)
	if err != nil || elfFile.Type != elf.ET_EXEC && elfFile.Type != elf.ET_DYN {
		return "", nil, errors.New("controlled executable must be a supported ELF image")
	}
	unlock, err := s.acquire(ctx)
	if err != nil {
		return "", nil, err
	}
	defer unlock()
	processUnlock, err := lockCustodyProcess(ctx, s)
	if err != nil {
		return "", nil, err
	}
	defer processUnlock()
	var staged int64
	for _, dir := range []string{filepath.Join(s.root, "models"), filepath.Join(s.root, "launchers")} {
		entries, e := checkpointReadDirNamesBounded(dir, 4096)
		if e != nil {
			return "", nil, e
		}
		for _, entry := range entries {
			if err = ctx.Err(); err != nil {
				return "", nil, err
			}
			fi, e := os.Lstat(filepath.Join(dir, entry))
			if e != nil || !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 || strings.HasSuffix(entry, ".tmp") {
				return "", nil, errors.New("custody staging entry is unsafe")
			}
			if !custodyQuotaFits(staged, fi.Size(), 0, s.maxStagingBytes) {
				return "", nil, errors.New("custody staging quota is already exceeded")
			}
			staged += fi.Size()
		}
	}
	if !custodyQuotaFits(staged, st.Size(), s.reserve, s.maxStagingBytes) {
		return "", nil, errors.New("executable bytes plus configured reserve exceed custody staging quota")
	}
	var free unix.Statfs_t
	if err = unix.Statfs(s.root, &free); err != nil {
		return "", nil, err
	}
	if uint64(st.Size()+s.reserve) > free.Bavail*uint64(free.Bsize) {
		return "", nil, errors.New("executable staging quota plus reserve exceeds available disk space")
	}
	name := hex.EncodeToString(mustRandom(16))
	final := filepath.Join(s.root, "launchers", name+".elf")
	tmp := final + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", nil, err
	}
	published := false
	defer func() {
		out.Close()
		if !published {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return "", nil, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(contextReader{ctx, f}, st.Size()+1))
	if err != nil || n != st.Size() || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(want) {
		return "", nil, errors.New("controlled executable staged bytes failed exact SHA-256 validation")
	}
	if err = out.Chmod(0500); err != nil {
		return "", nil, err
	}
	if err = out.Sync(); err != nil {
		return "", nil, err
	}
	if err = out.Close(); err != nil {
		return "", nil, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, final, unix.RENAME_NOREPLACE); err != nil {
		return "", nil, err
	}
	published = true
	fd, err := openCheckpointCustodyArtifact(final)
	if err != nil {
		return "", nil, err
	}
	fail := true
	defer func() {
		if fail {
			stagedPath, pinnedFD = final, fd
		}
	}()
	if err = syncCustodyStoreDir(s, filepath.Join(s.root, "launchers")); err != nil {
		return "", nil, err
	}
	if s.stageExecutableAfterPinTest != nil {
		if err = s.stageExecutableAfterPinTest(final); err != nil {
			return "", nil, err
		}
	}
	if err = enableAndMeasureVerity(int(fd.Fd())); err != nil {
		return "", nil, fmt.Errorf("fs-verity is required for immutable executable: %w", err)
	}
	if err = unix.Fsync(int(fd.Fd())); err != nil {
		return "", nil, err
	}
	if err = syncCustodyStoreDir(s, filepath.Join(s.root, "launchers")); err != nil {
		return "", nil, err
	}
	var dst syscall.Stat_t
	if err = syscall.Fstat(int(fd.Fd()), &dst); err != nil || dst.Nlink != 1 || dst.Size != st.Size() {
		return "", nil, errors.New("immutable executable descriptor identity is invalid")
	}
	actual := sha256.New()
	if _, err = io.Copy(actual, io.LimitReader(fd, st.Size()+1)); err != nil || hex.EncodeToString(actual.Sum(nil)) != strings.ToLower(want) {
		return "", nil, errors.New("immutable executable descriptor hash changed")
	}
	if _, err = fd.Seek(0, io.SeekStart); err != nil {
		return "", nil, err
	}
	fail = false
	return final, fd, nil
}

func commitCheckpointCustodyPlatform(ctx context.Context, l *CheckpointControlledLaunch) error {
	if l.commitTestEntered != nil {
		close(l.commitTestEntered)
	}
	if l.commitTestBarrier != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.commitTestBarrier:
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCustodyDirectories(l.store); err != nil {
		return err
	}
	pid := l.cmd.Process.Pid
	if pid <= 1 {
		return errors.New("controlled process PID invalid")
	}
	pidfd := l.commitPIDFD
	if pidfd < 0 {
		return errors.New("controlled child pidfd authority was not retained at Start")
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return err
	}
	var err error
	boot, err := checkpointReadBounded(checkpointCustodyBootIDPath(), 128)
	if err != nil || strings.TrimSpace(string(boot)) != l.bootID {
		return errors.New("boot identity changed during controlled launch")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	start, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	var info custodyProcessFacts
	if l.controlledSource {
		argvSHA256, argvErr := custodyArgvDigest(l.controlledArgv)
		if argvErr != nil {
			return errors.New("fixed controlled argv digest is invalid")
		}
		executableSource, identityErr := custodyPinnedExecutableIdentity(l.executablePath, l.executableFD, l.expectedExecutableSHA256)
		if identityErr != nil {
			return identityErr
		}
		info, err = custodyLiveControlledProcess(ctx, pid, l.model.identity, l.model.modelPin, executableSource, l.executableFD, l.endpoint, l.expectedExecutableSHA256, argvSHA256, l.controlledModelArgument)
	} else {
		info, err = custodyLiveProcess(ctx, pid, l.model.identity, l.endpoint, l.expectedExecutableSHA256)
	}
	if err != nil {
		return err
	}
	startAfter, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil || startAfter != start {
		return errors.New("controlled process incarnation changed during commit")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	var finalFacts custodyProcessFacts
	if l.controlledSource {
		argvSHA256, argvErr := custodyArgvDigest(l.controlledArgv)
		if argvErr != nil {
			return errors.New("fixed controlled argv digest is invalid")
		}
		executableSource, identityErr := custodyPinnedExecutableIdentity(l.executablePath, l.executableFD, l.expectedExecutableSHA256)
		if identityErr != nil {
			return identityErr
		}
		finalFacts, err = custodyLiveControlledProcess(ctx, pid, l.model.identity, l.model.modelPin, executableSource, l.executableFD, l.endpoint, l.expectedExecutableSHA256, argvSHA256, l.controlledModelArgument)
	} else {
		finalFacts, err = custodyLiveProcess(ctx, pid, l.model.identity, l.endpoint, l.expectedExecutableSHA256)
	}
	if err != nil || finalFacts != info {
		return errors.New("controlled process facts changed during commit")
	}
	unlockStore, err := l.store.acquire(ctx)
	if err != nil {
		return err
	}
	defer unlockStore()
	if err = ctx.Err(); err != nil {
		return err
	}
	unlockProcess, err := lockCustodyProcess(ctx, l.store)
	if err != nil {
		return err
	}
	defer unlockProcess()
	if err = ctx.Err(); err != nil {
		return err
	}
	pub, priv, err := loadCustodyKey(l.store)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	rec := custodyReceipt{Version: 1, KeyID: custodyKeyID(pub), Nonce: l.nonce, BootID: l.bootID, PrelaunchBootNS: l.preBootNS, StartBootNS: l.startBootNS, StartedBootNS: l.startedBootNS, PID: pid, StartTicks: start, ServiceUnit: l.unit, UnitAssociation: "label-only-unverified", Endpoint: info.endpoint, SocketInode: info.socketInode, ExecutablePath: info.exePath, ExecutableSHA256: info.exeSHA, ActualAlias: l.alias, Source: l.model.identity}
	if l.controlledSource {
		argvSHA256, digestErr := custodyArgvDigest(l.controlledArgv)
		if digestErr != nil || l.controlledModelArgument != "/proc/self/fd/4" {
			return errors.New("fixed controlled argv identity is unavailable")
		}
		rec.Version = 2
		rec.EvidenceKind = "controlled-source-fs-verity-v2"
		rec.ModelArgument = l.controlledModelArgument
		rec.ArgvSHA256 = argvSHA256
		var executableIdentity custodySourceIdentity
		executableIdentity, err = custodyPinnedExecutableIdentity(l.executablePath, l.executableFD, l.expectedExecutableSHA256)
		if err != nil {
			return err
		}
		// Retain the immutable staged executable tuple before WaitContext is
		// allowed to settle and close the launch-time descriptor. Terminal
		// receipt cleanup authenticates this private captured tuple after reap.
		l.controlledExecutableIdentity = executableIdentity
		l.controlledExecutablePinned = true
		rec.Executable = &executableIdentity
	}
	b, err := custodyReceiptBytes(rec)
	if err != nil {
		return err
	}
	signed := custodySignedReceipt{Receipt: rec, Signature: hex.EncodeToString(ed25519.Sign(priv, b))}
	raw, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	shouldAbort := l.waitStarted
	l.mu.Unlock()
	if shouldAbort || ctx.Err() != nil {
		return errors.New("controlled child custody publication canceled by reap or context")
	}
	path := custodyReceiptPath(l.store.root, l.nonce)
	receiptsDir := filepath.Join(l.store.root, "receipts")
	tmpPath := filepath.Join(receiptsDir, ".receipt-"+hex.EncodeToString(mustRandom(12)))
	fd, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	keepPin := false
	defer func() {
		if !keepPin {
			_ = fd.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err = fd.Chmod(0600); err == nil {
		_, err = fd.Write(raw)
	}
	if err == nil {
		err = fd.Sync()
	}
	if err != nil {
		return err
	}
	var receiptStat syscall.Stat_t
	if err = syscall.Fstat(int(fd.Fd()), &receiptStat); err != nil {
		return err
	}
	if receiptStat.Mode&syscall.S_IFMT != syscall.S_IFREG || int(receiptStat.Uid) != os.Getuid() || receiptStat.Nlink != 1 || receiptStat.Size != int64(len(raw)) || receiptStat.Mode&0777 != 0600 {
		return errors.New("staged custody receipt inode is unsafe")
	}
	if l.receiptPinFailureTest {
		return errors.New("test receipt pin acquisition failure before publication")
	}
	pinned := make([]byte, len(raw))
	n, readErr := fd.ReadAt(pinned, 0)
	if readErr != nil && !errors.Is(readErr, io.EOF) || n != len(raw) || !bytes.Equal(pinned, raw) {
		return errors.New("published receipt changed before original inode pin")
	}
	l.receiptPin, l.receiptRaw = fd, raw
	l.receiptDevice, l.receiptInode = uint64(receiptStat.Dev), receiptStat.Ino
	if err = validatePinnedCustodyReceipt(l); err != nil {
		l.receiptPin = nil
		l.receiptRaw = nil
		return err
	}
	if err = ctx.Err(); err != nil {
		l.receiptPin, l.receiptRaw = nil, nil
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmpPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		l.receiptPin, l.receiptRaw = nil, nil
		return err
	}
	keepPin = true
	l.receiptPublished = true
	if err = syncCustodyStoreDir(l.store, receiptsDir); err != nil {
		return err
	}
	return nil
}

type custodyProcessFacts struct {
	endpoint, exePath, exeSHA string
	socketInode               uint64
}

func custodyLiveProcess(ctx context.Context, pid int, src custodySourceIdentity, endpoint, expectedExe string) (custodyProcessFacts, error) {
	return custodyLiveProcessMode(ctx, pid, src, endpoint, expectedExe, true)
}

func custodyLiveProcessMode(ctx context.Context, pid int, src custodySourceIdentity, endpoint, expectedExe string, requireMapping bool) (custodyProcessFacts, error) {
	if err := ctx.Err(); err != nil {
		return custodyProcessFacts{}, err
	}
	_, host, port, err := parseCheckpointIdentityEndpoint(endpoint)
	if err != nil {
		return custodyProcessFacts{}, err
	}
	listeners, err := checkpointMatchingListeners(ctx, "/proc", host, port)
	if err != nil || len(listeners) != 1 {
		return custodyProcessFacts{}, errors.New("endpoint does not have exactly one local listener")
	}
	if err = ctx.Err(); err != nil {
		return custodyProcessFacts{}, err
	}
	owned, err := custodyOwnsSocket(ctx, pid, listeners[0].inode)
	if err != nil || !owned {
		return custodyProcessFacts{}, errors.New("listener socket is not owned by controlled process")
	}
	if requireMapping {
		err = custodyHasMapping(ctx, pid, src)
	}
	if err != nil {
		return custodyProcessFacts{}, err
	}
	if err = ctx.Err(); err != nil {
		return custodyProcessFacts{}, err
	}
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return custodyProcessFacts{}, err
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return custodyProcessFacts{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(contextReader{ctx, f}, custodyMaxExecutableVerifyBytes+1))
	if err != nil || n > custodyMaxExecutableVerifyBytes {
		return custodyProcessFacts{}, errors.New("executable hashing failed or exceeded limit")
	}
	exe := hex.EncodeToString(h.Sum(nil))
	if exe != expectedExe {
		return custodyProcessFacts{}, errors.New("controlled executable SHA-256 mismatch")
	}
	return custodyProcessFacts{endpoint: endpoint, exePath: exePath, exeSHA: exe, socketInode: listeners[0].inode}, nil
}

func custodyLiveControlledProcess(ctx context.Context, pid int, src custodySourceIdentity, preparedPin *os.File, executableSource custodySourceIdentity, executablePin *os.File, endpoint, expectedExe, expectedArgvSHA256, modelArgument string) (custodyProcessFacts, error) {
	if preparedPin == nil || executablePin == nil || modelArgument != "/proc/self/fd/4" {
		return custodyProcessFacts{}, errors.New("controlled source authority or descriptor model argument is unavailable")
	}
	if !custodyDigestRE.MatchString(expectedArgvSHA256) {
		return custodyProcessFacts{}, errors.New("controlled argv digest is malformed")
	}
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	cmdline, err := checkpointReadBounded(filepath.Join(proc, "cmdline"), 16<<10)
	if err != nil || len(cmdline) == 0 || cmdline[len(cmdline)-1] != 0 {
		return custodyProcessFacts{}, errors.New("controlled child argv is unreadable or malformed")
	}
	parts := strings.Split(string(cmdline[:len(cmdline)-1]), "\x00")
	gotArgv, err := custodyArgvDigest(parts)
	if err != nil || gotArgv != expectedArgvSHA256 {
		return custodyProcessFacts{}, errors.New("controlled child argv differs from the fixed launch identity")
	}
	facts, err := custodyLiveProcessMode(ctx, pid, src, endpoint, expectedExe, false)
	if err != nil {
		return custodyProcessFacts{}, err
	}
	fdPath := filepath.Join(proc, "fd", "4")
	fd, err := unix.Open(fdPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return custodyProcessFacts{}, errors.New("controlled child model descriptor four is not openable")
	}
	defer unix.Close(fd)
	var child, pinned syscall.Stat_t
	if err = syscall.Fstat(fd, &child); err != nil || syscall.Fstat(int(preparedPin.Fd()), &pinned) != nil || child.Mode&syscall.S_IFMT != syscall.S_IFREG || child.Nlink != 1 || child.Dev != pinned.Dev || child.Ino != pinned.Ino || child.Size != pinned.Size || uint64(child.Dev) != src.Device || child.Ino != src.Inode || child.Size != src.Size {
		return custodyProcessFacts{}, errors.New("live child descriptor four differs from the immutable prepared source pin")
	}
	childVerity, childErr := measureVerity(fd)
	pinnedVerity, pinErr := measureVerity(int(preparedPin.Fd()))
	if childErr != nil || pinErr != nil || childVerity != src.VerityDigest || pinnedVerity != src.VerityDigest {
		return custodyProcessFacts{}, errors.New("live child descriptor four lacks the pinned fs-verity source identity")
	}
	if executableSource.CanonicalPath != facts.exePath || executableSource.SHA256 != expectedExe {
		return custodyProcessFacts{}, errors.New("controlled receipt executable identity differs from the pinned launch image")
	}
	liveExe, err := os.Open(filepath.Join(proc, "exe"))
	if err != nil {
		return custodyProcessFacts{}, errors.New("controlled live executable inode cannot be opened")
	}
	var liveExeStat, pinnedExeStat syscall.Stat_t
	statErr := syscall.Fstat(int(liveExe.Fd()), &liveExeStat)
	pinnedErr := syscall.Fstat(int(executablePin.Fd()), &pinnedExeStat)
	liveExeVerity, verityErr := measureVerity(int(liveExe.Fd()))
	pinExeVerity, pinVerityErr := measureVerity(int(executablePin.Fd()))
	_ = liveExe.Close()
	if statErr != nil || pinnedErr != nil || verityErr != nil || pinVerityErr != nil || liveExeStat.Mode&syscall.S_IFMT != syscall.S_IFREG || liveExeStat.Dev != pinnedExeStat.Dev || liveExeStat.Ino != pinnedExeStat.Ino || liveExeStat.Size != pinnedExeStat.Size || uint64(liveExeStat.Dev) != executableSource.Device || liveExeStat.Ino != executableSource.Inode || liveExeStat.Size != executableSource.Size || liveExeVerity != executableSource.VerityDigest || pinExeVerity != executableSource.VerityDigest {
		return custodyProcessFacts{}, errors.New("controlled live executable differs from the pinned immutable staged inode and verity")
	}
	cmdlineAfter, err := checkpointReadBounded(filepath.Join(proc, "cmdline"), 16<<10)
	if err != nil || !bytes.Equal(cmdline, cmdlineAfter) {
		return custodyProcessFacts{}, errors.New("controlled child argv changed during descriptor verification")
	}
	return facts, nil
}

func custodyPinnedExecutableIdentity(path string, pin *os.File, expectedSHA string) (custodySourceIdentity, error) {
	if path == "" || pin == nil || !custodyDigestRE.MatchString(expectedSHA) {
		return custodySourceIdentity{}, errors.New("pinned executable identity request is incomplete")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(pin.Fd()), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Mode&0111 == 0 || st.Size <= 0 || st.Size > custodyMaxExecutableVerifyBytes {
		return custodySourceIdentity{}, errors.New("pinned executable inode is invalid")
	}
	verity, err := measureVerity(int(pin.Fd()))
	if err != nil || verity == "" {
		return custodySourceIdentity{}, errors.New("pinned executable has no fs-verity identity")
	}
	return custodySourceIdentity{CanonicalPath: path, Device: uint64(st.Dev), Inode: st.Ino, Size: st.Size, SHA256: strings.ToLower(expectedSHA), VerityDigest: verity}, nil
}

func openCustodyReceiptSource(src custodySourceIdentity) (*os.File, error) {
	if src.CanonicalPath == "" || src.Size <= 0 || !custodyDigestRE.MatchString(src.SHA256) || !custodyDigestRE.MatchString(src.VerityDigest) {
		return nil, errors.New("controlled receipt source identity is malformed")
	}
	f, err := openCheckpointCustodyArtifact(src.CanonicalPath)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || uint64(st.Dev) != src.Device || st.Ino != src.Inode || st.Size != src.Size {
		f.Close()
		return nil, errors.New("controlled receipt source inode changed")
	}
	verity, err := measureVerity(int(f.Fd()))
	if err != nil || verity != src.VerityDigest {
		f.Close()
		return nil, errors.New("controlled receipt source verity changed")
	}
	return f, nil
}

func openCustodyReceiptExecutable(src custodySourceIdentity) (*os.File, error) {
	f, err := openCustodyReceiptSource(src)
	if err != nil {
		return nil, err
	}
	identity, err := custodyPinnedExecutableIdentity(src.CanonicalPath, f, src.SHA256)
	if err != nil || identity != src {
		f.Close()
		return nil, errors.New("controlled receipt executable pin identity changed")
	}
	return f, nil
}
func custodyOwnsSocket(ctx context.Context, pid int, inode uint64) (bool, error) {
	entries, err := checkpointReadDirNamesBounded(fmt.Sprintf("/proc/%d/fd", pid), checkpointFDLimit)
	if err != nil {
		return false, err
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	needle := fmt.Sprintf("socket:[%d]", inode)
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		link, er := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, e))
		if er == nil && link == needle {
			return true, nil
		}
	}
	return false, nil
}
func custodyHasMapping(ctx context.Context, pid int, src custodySourceIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := checkpointReadBounded(fmt.Sprintf("/proc/%d/maps", pid), checkpointProcMaxRead)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	type span struct{ start, end uint64 }
	var spans []span
	for i, line := range strings.Split(string(b), "\n") {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		f := strings.Fields(line)
		if len(f) < 6 || f[1] != "r--p" || filepath.Clean(strings.ReplaceAll(f[5], "\\040", " ")) != src.CanonicalPath {
			continue
		}
		devParts := strings.Split(f[3], ":")
		if len(devParts) != 2 {
			continue
		}
		major, e1 := strconv.ParseUint(devParts[0], 16, 32)
		minor, e2 := strconv.ParseUint(devParts[1], 16, 32)
		inode, e3 := strconv.ParseUint(f[4], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || inode != src.Inode || uint64(unix.Mkdev(uint32(major), uint32(minor))) != src.Device {
			continue
		}
		rng := strings.Split(f[0], "-")
		if len(rng) != 2 {
			continue
		}
		lo, e1 := strconv.ParseUint(rng[0], 16, 64)
		hi, e2 := strconv.ParseUint(rng[1], 16, 64)
		off, e3 := strconv.ParseUint(f[2], 16, 64)
		if e1 == nil && e2 == nil && e3 == nil && lo < hi {
			spans = append(spans, span{start: off, end: off + hi - lo})
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	found := false
	covered := uint64(0)
	for _, s := range spans {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.start > covered {
			break
		}
		if s.end > covered {
			covered = s.end
		}
		if covered >= uint64(src.Size) {
			found = true
			break
		}
	}
	if !found {
		return errors.New("full readable private mapping of prepared immutable source is absent")
	}
	return nil
}

func removeCheckpointCustodyReceiptPlatform(ctx context.Context, l *CheckpointControlledLaunch) error {
	if ctx == nil {
		return errors.New("receipt cleanup context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if l == nil || l.store == nil || len(l.nonce) != 64 || !custodyDigestRE.MatchString(l.nonce) {
		return nil
	}
	if !l.receiptPublished {
		return nil
	}
	if l.receiptSettled {
		return nil
	}
	if err := validateCustodyDirectories(l.store); err != nil {
		return err
	}
	path := custodyReceiptPath(l.store.root, l.nonce)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if !l.receiptCleanup.Removed && !l.receiptCleanup.Captured {
			return errors.New("published receipt disappeared before pinned cleanup")
		}
		if l.receiptCleanup.Captured {
			err = nil
		}
		if l.receiptCleanup.Removed && !l.receiptCleanup.Synced {
			err = syncCustodyStoreDir(l.store, filepath.Join(l.store.root, "receipts"))
		}
		if err != nil {
			return err
		}
		if l.receiptCleanup.Removed {
			l.receiptCleanup.Synced = true
			l.receiptSettled = true
			if l.receiptPin != nil {
				_ = l.receiptPin.Close()
				l.receiptPin = nil
			}
			return nil
		}
	} else if err != nil {
		return err
	} else if !l.receiptCleanup.Captured && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600) {
		return errors.New("custody cancellation found an unsafe receipt path")
	}
	if l.receiptPin == nil || validatePinnedCustodyReceipt(l) != nil {
		return errors.New("custody cancellation has no verified original receipt pin")
	}
	syncDir := func() error { return syncCustodyStoreDir(l.store, filepath.Join(l.store.root, "receipts")) }
	if err = captureAndRemoveCustodyPath(ctx, l.store, path, l.receiptPin, &l.receiptCleanup, func(*os.File) error {
		return validatePinnedCustodyReceipt(l)
	}, syncDir); err != nil {
		return err
	}
	l.receiptSettled = true
	_ = l.receiptPin.Close()
	l.receiptPin = nil
	return nil
}

func discardCheckpointCustodySourcePlatform(ctx context.Context, m *CheckpointPreparedModel) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCustodyDirectories(m.store); err != nil {
		return err
	}
	unlock, err := m.store.acquire(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	processUnlock, err := lockCustodyProcess(ctx, m.store)
	if err != nil {
		return err
	}
	defer processUnlock()
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = validateCustodyDirectories(m.store); err != nil {
		return err
	}
	if m.failedExecutableFD != nil {
		if err = releaseCheckpointExecutableContextPlatform(ctx, m.store, m.failedExecutablePath, m.failedExecutableFD, &m.failedExecutableCleanup); err != nil {
			return err
		}
		_ = m.failedExecutableFD.Close()
		m.failedExecutableFD = nil
		m.failedExecutablePath = ""
	}
	if err = verifyPinnedCustodyModel(m); err != nil {
		return err
	}
	syncDir := func() error { return syncCustodyStoreDir(m.store, filepath.Join(m.store.root, "models")) }
	return captureAndRemoveCustodyPath(ctx, m.store, m.path, m.modelPin, &m.discardCleanup, func(*os.File) error {
		return verifyPinnedCustodyModel(m)
	}, syncDir)
}

func discardReusableCheckpointModelPlatform(ctx context.Context, m *CheckpointPreparedModel) error {
	if ctx == nil || m == nil || m.store == nil || !m.reusable {
		return errors.New("reusable prepared model authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCustodyDirectories(m.store); err != nil {
		return err
	}
	unlock, err := m.store.acquire(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	processUnlock, err := lockCustodyProcess(ctx, m.store)
	if err != nil {
		return err
	}
	defer processUnlock()
	if err = ctx.Err(); err != nil {
		return err
	}
	if m.failedExecutableFD != nil {
		if m.failedExecutableCleanup.Removed && !m.failedExecutableCleanup.Synced {
			if _, pathErr := os.Lstat(m.failedExecutablePath); pathErr == nil || !errors.Is(pathErr, os.ErrNotExist) {
				return errors.New("failed executable cleanup found a replacement at its original path; preserving it")
			}
		}
		if err = releaseCheckpointExecutableContextPlatform(ctx, m.store, m.failedExecutablePath, m.failedExecutableFD, &m.failedExecutableCleanup); err != nil {
			return err
		}
		if m.failedExecutableCleanup.Removed && m.failedExecutableCleanup.Synced {
			if _, pathErr := os.Lstat(m.failedExecutablePath); pathErr == nil || !errors.Is(pathErr, os.ErrNotExist) {
				return errors.New("failed executable path was replaced during cleanup; preserving it")
			}
		}
		_ = m.failedExecutableFD.Close()
		m.failedExecutableFD = nil
		m.failedExecutablePath = ""
		m.failedExecutableCleanup = custodyCleanupState{}
	}
	return validatePreparedCheckpointPlatform(m, m.modelPin)
}

func releaseCheckpointCustodyTerminalPlatform(ctx context.Context, l *CheckpointControlledLaunch) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCustodyDirectories(l.store); err != nil {
		return err
	}
	unlock, err := l.store.acquire(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	processUnlock, err := lockCustodyProcess(ctx, l.store)
	if err != nil {
		return err
	}
	defer processUnlock()
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = validateCustodyDirectories(l.store); err != nil {
		return err
	}
	if l.modelCleanup.Removed {
		if err = verifyPinnedCustodyModel(l.model); err != nil {
			return err
		}
	} else if l.modelCleanup.Captured {
		if err = verifyPinnedCustodyModel(l.model); err != nil {
			return err
		}
	} else if err = validatePreparedCheckpointPlatform(l.model, l.model.modelPin); err != nil {
		return err
	}
	if l.receiptPublished && !l.receiptSettled {
		if err = validatePinnedCustodyReceipt(l); err != nil {
			return err
		}
	}
	// Validate both original objects before the first unlink. Retry state records
	// which unlink was attempted so an uncertain directory sync cannot lie about
	// both objects still existing.
	if l.receiptPublished && !l.receiptCleanup.Removed && !l.receiptSettled {
		if !l.receiptCleanup.Captured {
			if err = verifyCustodyReceiptPath(l); err != nil {
				return err
			}
		}
	}
	if !l.modelCleanup.Removed && !l.modelCleanup.Captured {
		if err = verifyCustodyModelPath(l.model); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if cleanupErr := l.cleanupExecutableBounded(ctx); cleanupErr != nil {
		return cleanupErr
	}
	if l.receiptPublished && !l.receiptSettled {
		if err = removeCheckpointCustodyReceiptPlatform(ctx, l); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if l.model.reusable {
		if err = verifyCustodyModelPath(l.model); err != nil {
			return err
		}
		if l.receiptPin != nil {
			_ = l.receiptPin.Close()
			l.receiptPin = nil
		}
		if l.model.modelPin != nil {
			_ = l.model.modelPin.Close()
			l.model.modelPin = nil
		}
		return nil
	}
	syncDir := func() error { return syncCustodyStoreDir(l.store, filepath.Join(l.store.root, "models")) }
	if err = captureAndRemoveCustodyPath(ctx, l.store, l.model.path, l.model.modelPin, &l.modelCleanup, func(*os.File) error {
		return verifyPinnedCustodyModel(l.model)
	}, syncDir); err != nil {
		return err
	}
	if l.receiptPin != nil {
		_ = l.receiptPin.Close()
		l.receiptPin = nil
	}
	if l.model.modelPin != nil {
		_ = l.model.modelPin.Close()
		l.model.modelPin = nil
	}
	return nil
}

func verifyCustodyModelPath(m *CheckpointPreparedModel) error {
	if err := verifyPinnedCustodyModel(m); err != nil {
		return err
	}
	f, err := openCheckpointCustodyArtifact(m.path)
	if err != nil {
		return err
	}
	defer f.Close()
	var pathStat, pinStat syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &pathStat); err != nil {
		return err
	}
	if err = syscall.Fstat(int(m.modelPin.Fd()), &pinStat); err != nil {
		return err
	}
	if pathStat.Dev != pinStat.Dev || pathStat.Ino != pinStat.Ino || pathStat.Size != pinStat.Size || pathStat.Nlink != 1 || pinStat.Nlink != 1 || uint32(pathStat.Uid) != uint32(os.Getuid()) || pathStat.Mode&0777 != 0600 {
		return errors.New("staged model path no longer names the original private inode")
	}
	return nil
}

func verifyPinnedCustodyModel(m *CheckpointPreparedModel) error {
	if m == nil || m.modelPin == nil {
		return errors.New("original model inode pin is unavailable")
	}
	var pin syscall.Stat_t
	if err := syscall.Fstat(int(m.modelPin.Fd()), &pin); err != nil {
		return err
	}
	if uint64(pin.Dev) != m.identity.Device || pin.Ino != m.identity.Inode || pin.Size != m.identity.Size || uint64(pin.Uid) != uint64(os.Getuid()) || pin.Mode&syscall.S_IFMT != syscall.S_IFREG || pin.Mode&0777 != 0600 {
		return errors.New("pinned model inode identity changed")
	}
	v, err := measureVerity(int(m.modelPin.Fd()))
	if err != nil || v != m.identity.VerityDigest {
		return errors.New("original staged model fs-verity identity changed")
	}
	return nil
}

func verifyCustodyReceiptPath(l *CheckpointControlledLaunch) error {
	if l.receiptPin == nil || len(l.receiptRaw) == 0 {
		return errors.New("original signed receipt pin is unavailable")
	}
	path := custodyReceiptPath(l.store.root, l.nonce)
	f, err := openCheckpointCustodyArtifact(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var st syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if uint64(st.Dev) != l.receiptDevice || st.Ino != l.receiptInode || st.Nlink != 1 || st.Size != int64(len(l.receiptRaw)) || uint32(st.Uid) != uint32(os.Getuid()) || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0777 != 0600 {
		return errors.New("receipt path no longer names the original signed receipt inode")
	}
	return validatePinnedCustodyReceipt(l)
}

func decodeStrictJSONValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("receipt JSON nesting exceeds its bound")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{':
			object := make(map[string]any)
			for dec.More() {
				keyToken, keyErr := dec.Token()
				key, valid := keyToken.(string)
				if keyErr != nil || !valid {
					return nil, errors.New("receipt JSON object key is malformed")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("receipt JSON contains duplicate key %q", key)
				}
				value, valueErr := decodeStrictJSONValue(dec, depth+1)
				if valueErr != nil {
					return nil, valueErr
				}
				object[key] = value
			}
			end, endErr := dec.Token()
			if endErr != nil || end != json.Delim('}') {
				return nil, errors.New("receipt JSON object is unterminated")
			}
			return object, nil
		case '[':
			var array []any
			for dec.More() {
				value, valueErr := decodeStrictJSONValue(dec, depth+1)
				if valueErr != nil {
					return nil, valueErr
				}
				array = append(array, value)
			}
			end, endErr := dec.Token()
			if endErr != nil || end != json.Delim(']') {
				return nil, errors.New("receipt JSON array is unterminated")
			}
			return array, nil
		default:
			return nil, errors.New("receipt JSON contains an unexpected delimiter")
		}
	}
	return tok, nil
}

func strictControlledReceiptJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := decodeStrictJSONValue(dec, 0)
	if err != nil {
		return err
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("controlled receipt has trailing JSON data")
	}
	root, ok := value.(map[string]any)
	if !ok || !exactJSONKeys(root, "receipt", "signature") {
		return errors.New("controlled receipt envelope has unknown or missing fields")
	}
	receipt, ok := root["receipt"].(map[string]any)
	if !ok {
		return errors.New("controlled receipt payload is not an object")
	}
	for key := range receipt {
		if strings.EqualFold(key, "version") && key != "version" {
			return errors.New("controlled receipt uses a noncanonical version field")
		}
	}
	if !exactJSONKeys(receipt, "version", "key_id", "nonce", "boot_id", "prelaunch_boot_ns", "start_boot_ns", "started_boot_ns", "pid", "start_ticks", "service_unit", "unit_association", "endpoint", "socket_inode", "executable_path", "executable_sha256", "actual_alias", "source", "evidence_kind", "model_argument", "argv_sha256", "executable") {
		return errors.New("controlled receipt payload has unknown or missing fields")
	}
	source, sourceOK := receipt["source"].(map[string]any)
	executable, executableOK := receipt["executable"].(map[string]any)
	if !sourceOK || !exactJSONKeys(source, "canonical_path", "device", "inode", "size", "sha256", "verity_digest") || !executableOK || !exactJSONKeys(executable, "canonical_path", "device", "inode", "size", "sha256", "verity_digest") {
		return errors.New("controlled receipt source or executable identity fields are malformed")
	}
	for _, object := range []map[string]any{root, receipt, source, executable} {
		for _, field := range object {
			if field == nil {
				return errors.New("controlled receipt contains a null field")
			}
		}
	}
	if _, ok := root["signature"].(string); !ok {
		return errors.New("controlled receipt signature is not a string")
	}
	if version, ok := receipt["version"].(json.Number); !ok || version.String() != "2" {
		return errors.New("controlled receipt version is not canonical v2")
	}
	return nil
}

func exactJSONKeys(object map[string]any, expected ...string) bool {
	if len(object) != len(expected) {
		return false
	}
	wanted := make(map[string]struct{}, len(expected))
	for _, key := range expected {
		wanted[key] = struct{}{}
	}
	for key := range object {
		if _, ok := wanted[key]; !ok {
			return false
		}
		delete(wanted, key)
	}
	return len(wanted) == 0
}

func validatePinnedCustodyReceipt(l *CheckpointControlledLaunch) error {
	if l.receiptPin == nil || len(l.receiptRaw) == 0 {
		return errors.New("original signed receipt pin is unavailable")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(l.receiptPin.Fd()), &st); err != nil {
		return err
	}
	if uint64(st.Dev) != l.receiptDevice || st.Ino != l.receiptInode || st.Size != int64(len(l.receiptRaw)) || uint64(st.Uid) != uint64(os.Getuid()) || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0777 != 0600 {
		return errors.New("pinned signed receipt inode changed")
	}
	raw := make([]byte, len(l.receiptRaw))
	n, err := l.receiptPin.ReadAt(raw, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if n != len(raw) || !bytes.Equal(raw, l.receiptRaw) {
		return errors.New("pinned signed receipt bytes changed")
	}
	var signed custodySignedReceipt
	if err = json.Unmarshal(raw, &signed); err != nil {
		return err
	}
	pub, _, err := loadCustodyKey(l.store)
	if err != nil {
		return err
	}
	payload, err := custodyReceiptBytes(signed.Receipt)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(pub, payload, sig) {
		return errors.New("original receipt signature is invalid")
	}
	r := signed.Receipt
	versionOK := r.Version == 1 && r.EvidenceKind == "" && r.ModelArgument == "" && r.ArgvSHA256 == "" && r.Executable == nil
	if l.controlledSource {
		argvSHA256, digestErr := custodyArgvDigest(l.controlledArgv)
		versionOK = r.Version == 2 && r.Executable != nil && r.EvidenceKind == "controlled-source-fs-verity-v2" && r.ModelArgument == l.controlledModelArgument && r.ArgvSHA256 == argvSHA256 && l.controlledModelArgument == "/proc/self/fd/4" && digestErr == nil
		if versionOK {
			versionOK = l.controlledExecutablePinned && *r.Executable == l.controlledExecutableIdentity
		}
	}
	if !versionOK || r.KeyID != custodyKeyID(pub) || r.Nonce != l.nonce || r.BootID != l.bootID || r.Source != l.model.identity || r.PID != l.cmd.Process.Pid || r.Endpoint != l.endpoint || r.ServiceUnit != l.unit || r.ExecutablePath != l.executablePath || r.ExecutableSHA256 != l.expectedExecutableSHA256 || r.ActualAlias != l.alias {
		return errors.New("signed receipt does not identify this exact launch and source")
	}
	return nil
}

func syncCustodyDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func syncCustodyStoreDir(s *CheckpointCustodyStore, path string) error {
	if s != nil && s.syncTest != nil {
		return s.syncTest(path)
	}
	return syncCustodyDir(path)
}

func verifyCheckpointCustodyPlatform(ctx context.Context, s *CheckpointCustodyStore, endpoint, unit string) (bool, error) {
	_, ok, err := verifyCheckpointCustodyBindingPlatform(ctx, s, endpoint, unit)
	return ok, err
}

func verifyCheckpointCustodyBindingPlatform(ctx context.Context, s *CheckpointCustodyStore, endpoint, unit string) (CheckpointCustodyVerification, bool, error) {
	if ctx == nil {
		return CheckpointCustodyVerification{}, false, errors.New("custody verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return CheckpointCustodyVerification{}, false, err
	}
	if err := validateCustodyDirectories(s); err != nil {
		return CheckpointCustodyVerification{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return CheckpointCustodyVerification{}, false, err
	}
	canonical, _, _, parseErr := parseCheckpointIdentityEndpoint(endpoint)
	if parseErr != nil {
		return CheckpointCustodyVerification{}, false, parseErr
	}
	endpoint = canonical
	if unit != checkpointIdentityServiceUnit {
		return CheckpointCustodyVerification{}, false, nil
	}
	receiptDir := filepath.Join(s.root, "receipts")
	if err := ctx.Err(); err != nil {
		return CheckpointCustodyVerification{}, false, err
	}
	dirFD, err := unix.Open(receiptDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return CheckpointCustodyVerification{}, false, err
	}
	dir := os.NewFile(uintptr(dirFD), receiptDir)
	if dir == nil {
		unix.Close(dirFD)
		return CheckpointCustodyVerification{}, false, errors.New("receipt directory descriptor unavailable")
	}
	defer dir.Close()
	var dirStat unix.Stat_t
	if err = unix.Fstat(dirFD, &dirStat); err != nil || uint64(dirStat.Dev) != s.receiptsDevice || dirStat.Ino != s.receiptsInode {
		return CheckpointCustodyVerification{}, false, errors.New("receipt directory identity changed")
	}
	if err = ctx.Err(); err != nil {
		return CheckpointCustodyVerification{}, false, err
	}
	entries, readErr := dir.Readdirnames(custodyMaxReceiptCount + 1)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return CheckpointCustodyVerification{}, false, readErr
	}
	if len(entries) > custodyMaxReceiptCount {
		return CheckpointCustodyVerification{}, false, errors.New("custody receipt count exceeds bound")
	}
	if err = ctx.Err(); err != nil {
		return CheckpointCustodyVerification{}, false, err
	}
	sort.Strings(entries)
	pubRaw, err := readPrivateCustodyFileContext(ctx, filepath.Join(s.root, "signing.pub"), ed25519.PublicKeySize)
	if err != nil {
		return CheckpointCustodyVerification{}, false, err
	}
	pub := ed25519.PublicKey(pubRaw)
	var aggregateReceiptBytes int64
	liveCandidates := 0
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		if !strings.HasSuffix(entry, ".json") {
			continue
		}
		if aggregateReceiptBytes >= custodyMaxReceiptVerifyBytes {
			return CheckpointCustodyVerification{}, false, errors.New("custody receipt aggregate verification-work budget exceeded")
		}
		p := filepath.Join(receiptDir, entry)
		raw, e := readPrivateCustodyFileContext(ctx, p, custodyMaxReceiptBytes)
		if e != nil {
			if ctx.Err() != nil {
				return CheckpointCustodyVerification{}, false, ctx.Err()
			}
			return CheckpointCustodyVerification{}, false, e
		}
		aggregateReceiptBytes += int64(len(raw))
		if aggregateReceiptBytes > custodyMaxReceiptVerifyBytes {
			return CheckpointCustodyVerification{}, false, errors.New("custody receipt aggregate verification-work budget exceeded")
		}
		if s.verifyTestAfterReceiptRead != nil {
			s.verifyTestAfterReceiptRead(entry)
		}
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		var signed custodySignedReceipt
		jsonErr := json.Unmarshal(raw, &signed)
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		if jsonErr != nil {
			continue
		}
		r := signed.Receipt
		if r.Version == 2 && strictControlledReceiptJSON(raw) != nil {
			continue
		}
		if r.Endpoint != endpoint || r.ServiceUnit != unit || r.KeyID != custodyKeyID(pub) || entry != r.Nonce+".json" {
			continue
		}
		b, e := custodyReceiptBytes(r)
		if e != nil {
			continue
		}
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		if len(signed.Signature) != ed25519.SignatureSize*2 {
			continue
		}
		sig, e := hex.DecodeString(signed.Signature)
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		if e != nil || !ed25519.Verify(pub, b, sig) {
			continue
		}
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		legacyReceipt := r.Version == 1 && r.EvidenceKind == "" && r.ModelArgument == "" && r.ArgvSHA256 == "" && r.Executable == nil
		controlledReceipt := r.Version == 2 && r.EvidenceKind == "controlled-source-fs-verity-v2" && r.ModelArgument == "/proc/self/fd/4" && custodyDigestRE.MatchString(r.ArgvSHA256) && r.Executable != nil && r.Executable.CanonicalPath == r.ExecutablePath && r.Executable.SHA256 == r.ExecutableSHA256 && custodyDigestRE.MatchString(r.Executable.VerityDigest)
		if r.UnitAssociation != "label-only-unverified" || (!legacyReceipt && !controlledReceipt) || r.PrelaunchBootNS <= 0 || r.StartBootNS < r.PrelaunchBootNS || r.StartedBootNS < r.StartBootNS {
			continue
		}
		nowBoot, clockErr := checkpointBootTimeNS()
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		if clockErr != nil || r.StartedBootNS > nowBoot {
			continue
		}
		currentBoot, bootErr := checkpointReadBounded(checkpointCustodyBootIDPath(), 128)
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		if bootErr != nil || r.BootID != strings.TrimSpace(string(currentBoot)) {
			continue
		}
		start, e := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(r.PID)), r.PID)
		if ctx.Err() != nil {
			return CheckpointCustodyVerification{}, false, ctx.Err()
		}
		if e != nil || start != r.StartTicks {
			continue
		}
		liveCandidates++
		if liveCandidates > custodyMaxLiveVerifyCandidates {
			return CheckpointCustodyVerification{}, false, errors.New("custody live-process candidate verification budget exceeded")
		}
		var f custodyProcessFacts
		if controlledReceipt {
			pin, pinErr := openCustodyReceiptSource(r.Source)
			if pinErr != nil {
				if ctx.Err() != nil {
					return CheckpointCustodyVerification{}, false, ctx.Err()
				}
				continue
			}
			exePin, exeErr := openCustodyReceiptExecutable(*r.Executable)
			if exeErr != nil {
				pin.Close()
				if ctx.Err() != nil {
					return CheckpointCustodyVerification{}, false, ctx.Err()
				}
				continue
			}
			f, e = custodyLiveControlledProcess(ctx, r.PID, r.Source, pin, *r.Executable, exePin, r.Endpoint, r.ExecutableSHA256, r.ArgvSHA256, r.ModelArgument)
			exePin.Close()
			pin.Close()
		} else {
			f, e = custodyLiveProcess(ctx, r.PID, r.Source, r.Endpoint, r.ExecutableSHA256)
		}
		if e != nil || f.socketInode != r.SocketInode || f.exePath != r.ExecutablePath {
			if ctx.Err() != nil {
				return CheckpointCustodyVerification{}, false, ctx.Err()
			}
			continue
		}
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		fd, e := openCheckpointCustodyArtifact(r.Source.CanonicalPath)
		if e != nil {
			if ctx.Err() != nil {
				return CheckpointCustodyVerification{}, false, ctx.Err()
			}
			continue
		}
		fi, e := fd.Stat()
		if e != nil {
			fd.Close()
			if ctx.Err() != nil {
				return CheckpointCustodyVerification{}, false, ctx.Err()
			}
			continue
		}
		var st syscall.Stat_t
		e = syscall.Fstat(int(fd.Fd()), &st)
		v, ve := measureVerity(int(fd.Fd()))
		fd.Close()
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		if e != nil || ve != nil || !fi.Mode().IsRegular() || fi.Size() != r.Source.Size || uint64(st.Dev) != r.Source.Device || st.Ino != r.Source.Inode || v != r.Source.VerityDigest {
			continue
		}
		startAfter, e := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(r.PID)), r.PID)
		if ctx.Err() != nil {
			return CheckpointCustodyVerification{}, false, ctx.Err()
		}
		if e != nil || startAfter != r.StartTicks {
			continue
		}
		var final custodyProcessFacts
		if controlledReceipt {
			pin, pinErr := openCustodyReceiptSource(r.Source)
			if pinErr != nil {
				if ctx.Err() != nil {
					return CheckpointCustodyVerification{}, false, ctx.Err()
				}
				continue
			}
			exePin, exeErr := openCustodyReceiptExecutable(*r.Executable)
			if exeErr != nil {
				pin.Close()
				if ctx.Err() != nil {
					return CheckpointCustodyVerification{}, false, ctx.Err()
				}
				continue
			}
			final, e = custodyLiveControlledProcess(ctx, r.PID, r.Source, pin, *r.Executable, exePin, r.Endpoint, r.ExecutableSHA256, r.ArgvSHA256, r.ModelArgument)
			exePin.Close()
			pin.Close()
		} else {
			final, e = custodyLiveProcess(ctx, r.PID, r.Source, r.Endpoint, r.ExecutableSHA256)
		}
		if e != nil || final != f {
			if ctx.Err() != nil {
				return CheckpointCustodyVerification{}, false, ctx.Err()
			}
			continue
		}
		if err = ctx.Err(); err != nil {
			return CheckpointCustodyVerification{}, false, err
		}
		binding := CheckpointCustodyVerification{EvidenceKind: r.EvidenceKind, ModelArgument: r.ModelArgument, ArgvSHA256: r.ArgvSHA256, Nonce: r.Nonce, Endpoint: r.Endpoint, ServiceUnit: r.ServiceUnit, UnitAssociation: r.UnitAssociation, BootID: r.BootID, PID: r.PID, ProcessStartTicks: r.StartTicks, ListenerSocketInode: r.SocketInode, ExecutablePath: r.ExecutablePath, ExecutableSHA256: r.ExecutableSHA256, ActualAlias: r.ActualAlias, ArtifactPath: r.Source.CanonicalPath, ArtifactDevice: r.Source.Device, ArtifactInode: r.Source.Inode, ArtifactSize: r.Source.Size, ArtifactSHA256: r.Source.SHA256, VerityDigest: r.Source.VerityDigest, PrelaunchBootNS: r.PrelaunchBootNS, StartBootNS: r.StartBootNS, StartedBootNS: r.StartedBootNS}
		if controlledReceipt {
			binding.ExecutableDevice = r.Executable.Device
			binding.ExecutableInode = r.Executable.Inode
			binding.ExecutableSize = r.Executable.Size
			binding.ExecutableVerityDigest = r.Executable.VerityDigest
		}
		material, _ := json.Marshal(binding)
		sum := sha256.Sum256(material)
		binding.BindingSHA256 = hex.EncodeToString(sum[:])
		return binding, true, nil
	}
	if err = ctx.Err(); err != nil {
		return CheckpointCustodyVerification{}, false, err
	}
	return CheckpointCustodyVerification{}, false, nil
}
func checkpointBootTimeNS() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(checkpointCustodyClockID(), &ts); err != nil {
		return 0, err
	}
	return ts.Nano(), nil
}

func checkpointCustodyClockID() int32     { return unix.CLOCK_BOOTTIME }
func checkpointCustodyBootIDPath() string { return "/proc/sys/kernel/random/boot_id" }

func loadCustodyKey(s *CheckpointCustodyStore) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	a, e := readPrivateCustodyFile(filepath.Join(s.root, "signing.pub"), ed25519.PublicKeySize)
	if e != nil {
		return nil, nil, e
	}
	b, e := readPrivateCustodyFile(filepath.Join(s.root, "signing.key"), ed25519.PrivateKeySize)
	if e != nil {
		return nil, nil, e
	}
	return ed25519.PublicKey(a), ed25519.PrivateKey(b), nil
}
