//go:build windows

package comfyharness

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var kernelLockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
var kernelUnlockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")

func singleLinkFile(path string, expected os.FileInfo) bool {
	if expected == nil || !expected.Mode().IsRegular() {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(expected, opened) {
		return false
	}
	var details syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &details); err != nil {
		return false
	}
	return details.NumberOfLinks == 1
}

func acquireStateLock(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil && (before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || !singleLinkFile(path, before)) {
		return nil, fmt.Errorf("state lock is not a single-link regular file")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*os.File, error) { _ = file.Close(); return nil, cause }
	opened, err := file.Stat()
	after, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || opened.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() || !os.SameFile(opened, after) || !singleLinkFile(path, opened) {
		return fail(fmt.Errorf("state lock changed while opening or is not single-link"))
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("restrict state lock permissions: %w", err))
	}
	var overlapped syscall.Overlapped
	result, _, callErr := kernelLockFileEx.Call(uintptr(file.Fd()), 0x1|0x2, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		return fail(fmt.Errorf("state directory is already owned: %w", callErr))
	}
	if err := file.Truncate(0); err != nil {
		_ = unlockStateHandle(file, &overlapped)
		return fail(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = unlockStateHandle(file, &overlapped)
		return fail(err)
	}
	if _, err := fmt.Fprintf(file, "%d %s\n", os.Getpid(), newID()); err != nil {
		_ = unlockStateHandle(file, &overlapped)
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		_ = unlockStateHandle(file, &overlapped)
		return fail(err)
	}
	// The lock stays associated with this open file handle until Close releases it.
	return file, nil
}

func unlockStateHandle(file *os.File, overlapped *syscall.Overlapped) error {
	result, _, callErr := kernelUnlockFileEx.Call(uintptr(file.Fd()), 0, 1, 0, uintptr(unsafe.Pointer(overlapped)))
	if result == 0 {
		return callErr
	}
	return nil
}

func releaseStateLock(file *os.File) error {
	if file == nil {
		return nil
	}
	var overlapped syscall.Overlapped
	unlockErr := unlockStateHandle(file, &overlapped)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
