//go:build linux

package securefs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openRootNoSymlink obtains an fd for every path component with O_NOFOLLOW.
// A configured root (or any parent) must not be redirected through a symlink,
// including during an adversarial rename/symlink swap after Manager.New.
// os.OpenRoot(path) by itself follows a symlink that *is* the root path.
func openRootNoSymlink(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("root path must be absolute")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = syscall.Close(fd) }()
	for _, part := range strings.Split(filepath.Clean(path), string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, fmt.Errorf("unsafe symlink or unavailable root component %q: %w", part, openErr)
		}
		_ = syscall.Close(fd)
		fd = next
	}
	// The directory fd remains open until OpenRoot has obtained its own fd.
	// /proc/self/fd is required, not an optional unverified fallback.
	return os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", fd))
}
