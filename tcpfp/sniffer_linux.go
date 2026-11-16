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

	insns := buildTCPSYNBPF(port)
	fprog := unix.SockFprog{
		Len:    uint16(len(insns)),
		Filter: &insns[0],
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return fmt.Errorf("tcpfp: attach BPF filter: %w", err)
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

func buildTCPSYNBPF(port uint16) []unix.SockFilter {
	const (
		ldhAbs  = unix.BPF_LD | unix.BPF_H | unix.BPF_ABS
		ldbAbs  = unix.BPF_LD | unix.BPF_B | unix.BPF_ABS
		ldxMsh  = unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH
		ldbInd  = unix.BPF_LD | unix.BPF_B | unix.BPF_IND
		ldhInd  = unix.BPF_LD | unix.BPF_H | unix.BPF_IND
		aluAndK = unix.BPF_ALU | unix.BPF_AND | unix.BPF_K
		jmpJeqK = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jmpJset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		retK    = unix.BPF_RET | unix.BPF_K
	)

	if port > 0 {
		p := uint32(port)
		return []unix.SockFilter{
			// 0: EtherType
			{Code: ldhAbs, K: 12},
			// 1: IPv4 -> 2; else -> 12 (IPv6)
			{Code: jmpJeqK, Jt: 0, Jf: 10, K: ethTypeIPv4},
			// 2: IPv4 protocol == TCP
			{Code: ldbAbs, K: 23},
			// 3: TCP -> 4; else -> 21 (drop)
			{Code: jmpJeqK, Jt: 0, Jf: 17, K: ipProtoTCP},
			// 4: IPv4 flags & fragment offset
			{Code: ldhAbs, K: 20},
			// 5: fragmented -> 21 (drop); else -> 6
			{Code: jmpJset, Jt: 15, Jf: 0, K: 0x1fff},
			// 6: X = IPv4 header length
			{Code: ldxMsh, K: 14},
			// 7: TCP flags at 14 + X + 13
			{Code: ldbInd, K: 27},
			// 8: mask SYN | ACK
			{Code: aluAndK, K: tcpFlagSYN | tcpFlagACK},
			// 9: pure SYN -> 10; else -> 21 (drop)
			{Code: jmpJeqK, Jt: 0, Jf: 11, K: tcpFlagSYN},
			// 10: TCP dst port at 14 + X + 2
			{Code: ldhInd, K: 16},
			// 11: port match -> 20 (accept); else -> 21 (drop)
			{Code: jmpJeqK, Jt: 8, Jf: 9, K: p},
			// 12: IPv6 -> 13; else -> 21 (drop)
			{Code: jmpJeqK, Jt: 0, Jf: 8, K: ethTypeIPv6},
			// 13: IPv6 Next Header == TCP
			{Code: ldbAbs, K: 20},
			// 14: TCP -> 15; else -> 21 (drop)
			{Code: jmpJeqK, Jt: 0, Jf: 6, K: ipProtoTCP},
			// 15: IPv6 TCP flags at 14 + 40 + 13
			{Code: ldbAbs, K: 67},
			// 16: mask SYN | ACK
			{Code: aluAndK, K: tcpFlagSYN | tcpFlagACK},
			// 17: pure SYN -> 18; else -> 21 (drop)
			{Code: jmpJeqK, Jt: 0, Jf: 3, K: tcpFlagSYN},
			// 18: IPv6 TCP dst port at 14 + 40 + 2
			{Code: ldhAbs, K: 56},
			// 19: port match -> 20 (accept); else -> 21 (drop)
			{Code: jmpJeqK, Jt: 0, Jf: 1, K: p},
			// 20: accept
			{Code: retK, K: 0x40000},
			// 21: drop
			{Code: retK, K: 0},
		}
	}

	return []unix.SockFilter{
		// 0: EtherType
		{Code: ldhAbs, K: 12},
		// 1: IPv4 -> 2; else -> 10 (IPv6)
		{Code: jmpJeqK, Jt: 0, Jf: 8, K: ethTypeIPv4},
		// 2: IPv4 protocol == TCP
		{Code: ldbAbs, K: 23},
		// 3: TCP -> 4; else -> 17 (drop)
		{Code: jmpJeqK, Jt: 0, Jf: 13, K: ipProtoTCP},
		// 4: IPv4 flags & fragment offset
		{Code: ldhAbs, K: 20},
		// 5: fragmented -> 17 (drop); else -> 6
		{Code: jmpJset, Jt: 11, Jf: 0, K: 0x1fff},
		// 6: X = IPv4 header length
		{Code: ldxMsh, K: 14},
		// 7: TCP flags at 14 + X + 13
		{Code: ldbInd, K: 27},
		// 8: mask SYN | ACK
		{Code: aluAndK, K: tcpFlagSYN | tcpFlagACK},
		// 9: pure SYN -> 16 (accept); else -> 17 (drop)
		{Code: jmpJeqK, Jt: 6, Jf: 7, K: tcpFlagSYN},
		// 10: IPv6 -> 11; else -> 17 (drop)
		{Code: jmpJeqK, Jt: 0, Jf: 6, K: ethTypeIPv6},
		// 11: IPv6 Next Header == TCP
		{Code: ldbAbs, K: 20},
		// 12: TCP -> 13; else -> 17 (drop)
		{Code: jmpJeqK, Jt: 0, Jf: 4, K: ipProtoTCP},
		// 13: IPv6 TCP flags at 14 + 40 + 13
		{Code: ldbAbs, K: 67},
		// 14: mask SYN | ACK
		{Code: aluAndK, K: tcpFlagSYN | tcpFlagACK},
		// 15: pure SYN -> 16 (accept); else -> 17 (drop)
		{Code: jmpJeqK, Jt: 0, Jf: 1, K: tcpFlagSYN},
		// 16: accept
		{Code: retK, K: 0x40000},
		// 17: drop
		{Code: retK, K: 0},
	}
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
