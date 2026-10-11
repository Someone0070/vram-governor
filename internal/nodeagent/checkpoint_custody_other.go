//go:build !linux

package nodeagent

import (
	"context"
	"errors"
	"os"
)

func checkpointBootTimeNS() (int64, error) {
	return 0, errors.New("CLOCK_BOOTTIME custody is unsupported on this platform")
}
func checkpointCustodyClockID() int32     { return -1 }
func checkpointCustodyBootIDPath() string { return "" }
func validatePreparedCheckpointPlatform(*CheckpointPreparedModel, *os.File) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}
func validateCheckpointLaunchExecutablePlatform(string, string, *os.File) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}
func retainCheckpointChildPlatform(int) (int, error) {
	return -1, errors.New("checkpoint custody is unsupported on this platform")
}
func duplicateCheckpointChildPlatform(int) (int, error) {
	return -1, errors.New("checkpoint custody is unsupported on this platform")
}
func closeCheckpointChildPlatform(int) {}
func killCheckpointChildPlatform(int) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}
func releaseCheckpointExecutablePlatform(*CheckpointCustodyStore, string, *os.File, *custodyCleanupState) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}
func releaseCheckpointExecutableContextPlatform(context.Context, *CheckpointCustodyStore, string, *os.File, *custodyCleanupState) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}

func openCheckpointCustodyPlatform(CheckpointCustodyConfig) (*CheckpointCustodyStore, error) {
	return nil, errors.New("checkpoint custody requires Linux fs-verity and process identity support")
}

func ensureCheckpointCustodyKey(context.Context, *CheckpointCustodyStore) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}
func prepareCheckpointCustodyPlatform(context.Context, *CheckpointCustodyStore, CheckpointCustodySource) (*CheckpointPreparedModel, error) {
	return nil, errors.New("checkpoint custody is unsupported on this platform")
}
func prepareReusableCheckpointCustodyPlatform(context.Context, *CheckpointCustodyStore, CheckpointCustodySource) (*CheckpointPreparedModel, error) {
	return nil, errors.New("reusable checkpoint custody is unsupported on this platform")
}
func beginCheckpointCustodyPlatform(context.Context, *CheckpointCustodyStore, *CheckpointPreparedModel, CheckpointCustodyLaunchRequest) (*CheckpointControlledLaunch, error) {
	return nil, errors.New("checkpoint custody is unsupported on this platform")
}
func commitCheckpointCustodyPlatform(context.Context, *CheckpointControlledLaunch) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}
func removeCheckpointCustodyReceiptPlatform(context.Context, *CheckpointControlledLaunch) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}
func discardCheckpointCustodySourcePlatform(context.Context, *CheckpointPreparedModel) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}
func discardReusableCheckpointModelPlatform(context.Context, *CheckpointPreparedModel) error {
	return errors.New("reusable checkpoint custody is unsupported on this platform")
}
func releaseCheckpointCustodyTerminalPlatform(context.Context, *CheckpointControlledLaunch) error {
	return errors.New("checkpoint custody is unsupported on this platform")
}
func verifyCheckpointCustodyPlatform(context.Context, *CheckpointCustodyStore, string, string) (bool, error) {
	return false, errors.New("checkpoint custody is unsupported on this platform")
}
func verifyCheckpointCustodyBindingPlatform(context.Context, *CheckpointCustodyStore, string, string) (CheckpointCustodyVerification, bool, error) {
	return CheckpointCustodyVerification{}, false, errors.New("checkpoint custody is unsupported on this platform")
}
