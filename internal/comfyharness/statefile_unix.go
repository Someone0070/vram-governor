//go:build !windows

package comfyharness

import (
	"fmt"
	"os"
	"reflect"
	"syscall"
)

func singleLinkFile(_ string, info os.FileInfo) bool {
	if info == nil || info.Sys() == nil {
		return false
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() {
		return false
	}
	links := value.FieldByName("Nlink")
	if !links.IsValid() {
		return false
	}
	switch links.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return links.Uint() == 1
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return links.Int() == 1
	default:
		return false
	}
}

func acquireStateLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	fail := func(cause error) (*os.File, error) { _ = file.Close(); return nil, cause }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !singleLinkFile(path, info) {
		return fail(fmt.Errorf("state lock is not a private single-link regular file"))
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := file.Chmod(0o600); err != nil {
			return fail(fmt.Errorf("restrict state lock permissions: %w", err))
		}
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(err)
	}
	if err := file.Truncate(0); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return fail(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return fail(err)
	}
	if _, err := fmt.Fprintf(file, "%d %s\n", os.Getpid(), newID()); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return fail(err)
	}
	return file, nil
}

func releaseStateLock(file *os.File) error {
	if file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
