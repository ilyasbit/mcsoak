//go:build linux

package tcpfp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// StartSniffer captures raw Ethernet frames on ifaceName (or all interfaces if empty)
// using an AF_PACKET socket and records matching TCP SYN fingerprints into store.
// If port > 0, only SYN packets destined for port are recorded.
// It exits cleanly and returns nil when ctx is cancelled.
func StartSniffer(ctx context.Context, ifaceName string, port uint16, store *Store) error {
	if store == nil {
		return errors.New("tcpfp: store must not be nil")
	}
	if ctx.Err() != nil {
		return nil
	}

	proto := htons(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(proto))
	if err != nil {
		return fmt.Errorf("tcpfp: open AF_PACKET socket: %w", err)
	}
	defer unix.Close(fd)

	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("tcpfp: lookup interface %q: %w", ifaceName, err)
		}
		sll := &unix.SockaddrLinklayer{
			Protocol: proto,
			Ifindex:  iface.Index,
		}
		if err := unix.Bind(fd, sll); err != nil {
			return fmt.Errorf("tcpfp: bind AF_PACKET socket to %q: %w", ifaceName, err)
		}
	}

	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	buf := make([]byte, 65536)

	for {
		if ctx.Err() != nil {
			return nil
		}

		n, err := unix.Poll(pfd, 200)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("tcpfp: poll AF_PACKET socket: %w", err)
		}
		if n == 0 || pfd[0].Revents&unix.POLLIN == 0 {
			continue
		}

		nr, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return fmt.Errorf("tcpfp: recvfrom AF_PACKET socket: %w", err)
		}

		fp, err := ParseEthernetSYN(buf[:nr])
		if err != nil {
			continue
		}
		if port > 0 && fp.DstPort != port {
			continue
		}
		store.Record(*fp)
	}
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
