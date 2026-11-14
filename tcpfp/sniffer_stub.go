//go:build !linux

package tcpfp

import (
	"context"
	"fmt"
	"runtime"
)

// StartSniffer is only supported on Linux; on other operating systems it returns an error.
func StartSniffer(ctx context.Context, ifaceName string, port uint16, store *Store) error {
	return fmt.Errorf("tcpfp: raw socket sniffer is unsupported on %s", runtime.GOOS)
}
