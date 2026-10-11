//go:build windows

package safefile

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Windows has no O_NOFOLLOW flag. CreateFile's OPEN_REPARSE_POINT flag opens
// the final path component itself when it is a reparse point instead of
// following it. We then inspect that same handle before handing it to the
// caller, so a path replacement cannot turn the check into a different open.
func openReadOnlyNoFollow(path string) (*os.File, error) {
	if hook := beforeOpenReadOnlyNoFollowHook; hook != nil {
		hook()
	}
	windowsPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("open safe file %q: %w", path, err)
	}
	handle, err := windows.CreateFile(
		windowsPath,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open safe file %q: %w", path, err)
	}
	closeHandle := true
	defer func() {
		if closeHandle {
			_ = windows.CloseHandle(handle)
		}
	}()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, fmt.Errorf("open safe file %q: inspect opened handle: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("open safe file %q: final path component is a reparse point", path)
	}

	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		return nil, fmt.Errorf("open safe file %q: handle could not be wrapped", path)
	}
	closeHandle = false
	return f, nil
}
