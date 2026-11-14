package reflector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
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

// StatsSnapshot holds an immutable point-in-time view of reflector pulse statistics.
type StatsSnapshot struct {
	TotalPulses uint64    `json:"total_pulses"`
	UDPPulses   uint64    `json:"udp_pulses"`
	TCPPulses   uint64    `json:"tcp_pulses"`
	IPv4Pulses  uint64    `json:"ipv4_pulses"`
	IPv6Pulses  uint64    `json:"ipv6_pulses"`
	LastPulseAt time.Time `json:"last_pulse_at,omitempty"`
	RecentIPs   []string  `json:"recent_ips,omitempty"`
}

// StatsTracker aggregates pulse telemetry events in a thread-safe manner.
type StatsTracker struct {
	mu          sync.RWMutex
	maxRecent   int
	totalPulses uint64
	udpPulses   uint64
	tcpPulses   uint64
	ipv4Pulses  uint64
	ipv6Pulses  uint64
	lastPulseAt time.Time
	recentIPs   []string
	seenIPs     map[string]struct{}
}

// NewStatsTracker creates a StatsTracker retaining at most maxRecent unique recent source IPs.
func NewStatsTracker(maxRecent int) *StatsTracker {
	if maxRecent < 0 {
		maxRecent = 0
	}
	return &StatsTracker{
		maxRecent: maxRecent,
		seenIPs:   make(map[string]struct{}),
	}
}

// Record updates pulse counters and recent source IP tracking for a single PulseEvent.
func (st *StatsTracker) Record(ev PulseEvent) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.totalPulses++
	switch ev.Proto {
	case 17:
		st.udpPulses++
	case 6:
		st.tcpPulses++
	}
	switch ev.IPVersion {
	case 4:
		st.ipv4Pulses++
	case 6:
		st.ipv6Pulses++
	}
	st.lastPulseAt = time.Now().UTC()

	if st.maxRecent > 0 && ev.SrcAddr.IsValid() {
		ipStr := ev.SrcAddr.String()
		if _, exists := st.seenIPs[ipStr]; exists {
			// Move existing IP to the end as most recent.
			for i, existing := range st.recentIPs {
				if existing == ipStr {
					st.recentIPs = append(st.recentIPs[:i], st.recentIPs[i+1:]...)
					break
				}
			}
		} else if len(st.recentIPs) >= st.maxRecent {
			oldest := st.recentIPs[0]
			st.recentIPs = st.recentIPs[1:]
			delete(st.seenIPs, oldest)
		}
		st.seenIPs[ipStr] = struct{}{}
		st.recentIPs = append(st.recentIPs, ipStr)
	}
}

// Snapshot returns a copy of the aggregated pulse statistics, optionally including recent source IPs.
func (st *StatsTracker) Snapshot(includeIPs bool) StatsSnapshot {
	st.mu.RLock()
	defer st.mu.RUnlock()

	snap := StatsSnapshot{
		TotalPulses: st.totalPulses,
		UDPPulses:   st.udpPulses,
		TCPPulses:   st.tcpPulses,
		IPv4Pulses:  st.ipv4Pulses,
		IPv6Pulses:  st.ipv6Pulses,
		LastPulseAt: st.lastPulseAt,
	}
	if includeIPs && len(st.recentIPs) > 0 {
		snap.RecentIPs = make([]string, len(st.recentIPs))
		copy(snap.RecentIPs, st.recentIPs)
	}
	return snap
}
