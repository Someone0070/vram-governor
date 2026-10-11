// Package safefile contains the small set of filesystem-opening primitives
// used at security-sensitive snapshot boundaries.
package safefile

import (
	"errors"
	"os"
)

// beforeOpenReadOnlyNoFollowHook is a package-local test seam. Windows tests
// use it to replace a path immediately before the handle is created, making a
// check-then-open implementation's race deterministic. It is nil in normal
// operation.
var beforeOpenReadOnlyNoFollowHook func()

// OpenReadOnlyNoFollow opens path for reading while refusing to follow a
// symlink in the final path component on platforms that provide that
// primitive. Callers must validate the returned descriptor (type, link count,
// permissions, size, and identity) before consuming it; the returned handle
// is the descriptor that was opened.
//
// There is intentionally no flags argument and no ordinary os.Open fallback:
// callers that need this security boundary cannot accidentally opt out of the
// no-follow policy. Unsupported operating systems fail closed.
func OpenReadOnlyNoFollow(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("safe file path is empty")
	}
	return openReadOnlyNoFollow(path)
}
