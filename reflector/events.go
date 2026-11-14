package reflector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const pulseEventSize = 32

// PulseEvent represents a pulse packet telemetry record emitted by the XDP reflector ring buffer.
type PulseEvent struct {
	TimestampNs uint64
	SrcAddr     netip.Addr
	SrcPort     uint16
	Proto       uint8
	IPVersion   uint8
	Flags       uint8
}

// EventHandler is invoked for each decoded PulseEvent read from the BPF ring buffer.
type EventHandler func(PulseEvent)

// DecodePulseEvent decodes a raw 32-byte ring buffer record into a PulseEvent.
func DecodePulseEvent(raw []byte) (PulseEvent, error) {
	if len(raw) < pulseEventSize {
		return PulseEvent{}, fmt.Errorf("pulse event too short: got %d bytes, want %d", len(raw), pulseEventSize)
	}

	ts := binary.LittleEndian.Uint64(raw[0:8])
	srcPort := binary.LittleEndian.Uint16(raw[24:26])
	proto := raw[26]
	ipVer := raw[27]
	flags := raw[28]

	var addr netip.Addr
	switch ipVer {
	case 4:
		var b4 [4]byte
		copy(b4[:], raw[8:12])
		addr = netip.AddrFrom4(b4)
	case 6:
		var b16 [16]byte
		copy(b16[:], raw[8:24])
		addr = netip.AddrFrom16(b16)
	default:
		return PulseEvent{}, errors.New("unsupported IP version in pulse event")
	}

	return PulseEvent{
		TimestampNs: ts,
		SrcAddr:     addr,
		SrcPort:     srcPort,
		Proto:       proto,
		IPVersion:   ipVer,
		Flags:       flags,
	}, nil
}
