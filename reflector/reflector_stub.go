//go:build !linux

package reflector

import (
	"errors"
	"io"
	"runtime"
)

// Start returns an unsupported-OS error on non-Linux platforms.
func Start(ifaceName string) (io.Closer, error) {
	return StartWithEvents(ifaceName, nil)
}

// StartWithEvents returns an unsupported-OS error on non-Linux platforms.
func StartWithEvents(ifaceName string, handler EventHandler) (io.Closer, error) {
	return nil, errors.New("eBPF reflector is only supported on linux (current OS: " + runtime.GOOS + ")")
}
