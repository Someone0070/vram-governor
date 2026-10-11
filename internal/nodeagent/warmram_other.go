//go:build !linux

package nodeagent

import "errors"

func syncCommandStateDir(string) error { return nil }

type warmFileIdentity struct {
	Dev, Ino uint64
	Size     int64
	Mtime    int64
	Hash     string
}
type unsupportedWarmPin struct{}
type warmRAMPin interface {
	Close() error
	ResidentBytes() int64
	LockedBytes() int64
}

func warmRAMOSSupported() bool            { return false }
func warmRAMOracle() string               { return "unsupported" }
func warmRAMMemlockLimit() (int64, error) { return 0, ErrWarmRAMUnsupported }
func warmFileIdentityAt(string) (warmFileIdentity, error) {
	return warmFileIdentity{}, ErrWarmRAMUnsupported
}
func warmSecureFileIdentity(string, []string) (warmFileIdentity, error) {
	return warmFileIdentity{}, ErrWarmRAMUnsupported
}
func pinWarmModelFile(string, []string) (warmRAMPin, warmFileIdentity, error) {
	return nil, warmFileIdentity{}, ErrWarmRAMUnsupported
}
func pinWarmModelFileExpected(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
	return nil, warmFileIdentity{}, ErrWarmRAMUnsupported
}
func warmRAMSnapshot(WarmRAMPolicy) (int64, int64, int64, int64, float64, error) {
	return 0, 0, 0, 0, 0, ErrWarmRAMUnsupported
}

func warmRAMOOMEvents(string) (int64, error)    { return 0, ErrWarmRAMUnsupported }
func warmRAMCgroupMax(string) (int64, error)    { return 0, ErrWarmRAMUnsupported }
func (unsupportedWarmPin) Close() error         { return errors.New("warm RAM pin is unsupported") }
func (unsupportedWarmPin) ResidentBytes() int64 { return 0 }
func (unsupportedWarmPin) LockedBytes() int64   { return 0 }
