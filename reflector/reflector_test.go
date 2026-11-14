package reflector

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestStartInvalidInterface(t *testing.T) {
	closer, err := Start("nonexistent_iface_9999")
	if err == nil {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatal("expected error for nonexistent interface, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent_iface_9999") && !strings.Contains(err.Error(), "only supported on linux") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestStartWithEventsInvalidInterface(t *testing.T) {
	closer, err := StartWithEvents("nonexistent_iface_9999", func(PulseEvent) {})
	if err == nil {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatal("expected error for nonexistent interface, got nil")
	}
}

func TestDecodePulseEventIPv4(t *testing.T) {
	raw := make([]byte, pulseEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 123456789)
	copy(raw[8:12], []byte{203, 0, 113, 42})
	binary.LittleEndian.PutUint16(raw[24:26], 54321)
	raw[26] = 17 // IPPROTO_UDP
	raw[27] = 4
	raw[28] = 0x00

	ev, err := DecodePulseEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.TimestampNs != 123456789 {
		t.Fatalf("TimestampNs = %d, want 123456789", ev.TimestampNs)
	}
	if ev.SrcAddr != netip.MustParseAddr("203.0.113.42") {
		t.Fatalf("SrcAddr = %v, want 203.0.113.42", ev.SrcAddr)
	}
	if ev.SrcPort != 54321 || ev.Proto != 17 || ev.IPVersion != 4 || ev.Flags != 0 {
		t.Fatalf("unexpected event fields: %+v", ev)
	}
}

func TestDecodePulseEventIPv6(t *testing.T) {
	raw := make([]byte, pulseEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 987654321)
	wantIP := netip.MustParseAddr("2001:db8::1")
	b16 := wantIP.As16()
	copy(raw[8:24], b16[:])
	binary.LittleEndian.PutUint16(raw[24:26], 44444)
	raw[26] = 6 // IPPROTO_TCP
	raw[27] = 6
	raw[28] = 0x02 // SYN

	ev, err := DecodePulseEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.SrcAddr != wantIP {
		t.Fatalf("SrcAddr = %v, want %v", ev.SrcAddr, wantIP)
	}
	if ev.SrcPort != 44444 || ev.Proto != 6 || ev.IPVersion != 6 || ev.Flags != 0x02 {
		t.Fatalf("unexpected event fields: %+v", ev)
	}
}

func TestDecodePulseEventErrors(t *testing.T) {
	if _, err := DecodePulseEvent(make([]byte, pulseEventSize-1)); err == nil {
		t.Fatal("expected error for short buffer, got nil")
	}
	badVer := make([]byte, pulseEventSize)
	badVer[27] = 5
	if _, err := DecodePulseEvent(badVer); err == nil {
		t.Fatal("expected error for unsupported IP version, got nil")
	}
}

func TestStatsTracker(t *testing.T) {
	st := NewStatsTracker(2)

	st.Record(PulseEvent{SrcAddr: netip.MustParseAddr("192.0.2.1"), Proto: 17, IPVersion: 4})
	st.Record(PulseEvent{SrcAddr: netip.MustParseAddr("2001:db8::1"), Proto: 6, IPVersion: 6})
	st.Record(PulseEvent{SrcAddr: netip.MustParseAddr("192.0.2.2"), Proto: 17, IPVersion: 4})
	// Re-recording 2001:db8::1 should move it to most recent without evicting 192.0.2.2.
	st.Record(PulseEvent{SrcAddr: netip.MustParseAddr("2001:db8::1"), Proto: 6, IPVersion: 6})

	snapNoIPs := st.Snapshot(false)
	if snapNoIPs.TotalPulses != 4 || snapNoIPs.UDPPulses != 2 || snapNoIPs.TCPPulses != 2 {
		t.Fatalf("unexpected proto counts: %+v", snapNoIPs)
	}
	if snapNoIPs.IPv4Pulses != 2 || snapNoIPs.IPv6Pulses != 2 {
		t.Fatalf("unexpected IP version counts: %+v", snapNoIPs)
	}
	if snapNoIPs.LastPulseAt.IsZero() {
		t.Fatal("expected LastPulseAt to be set")
	}
	if len(snapNoIPs.RecentIPs) != 0 {
		t.Fatalf("expected RecentIPs to be empty when includeIPs=false, got %v", snapNoIPs.RecentIPs)
	}

	snapWithIPs := st.Snapshot(true)
	if len(snapWithIPs.RecentIPs) != 2 {
		t.Fatalf("expected 2 recent IPs, got %v", snapWithIPs.RecentIPs)
	}
	if snapWithIPs.RecentIPs[0] != "192.0.2.2" || snapWithIPs.RecentIPs[1] != "2001:db8::1" {
		t.Fatalf("unexpected RecentIPs order: %v", snapWithIPs.RecentIPs)
	}
	// Mutating returned slice must not affect tracker state.
	snapWithIPs.RecentIPs[0] = "mutated"
	snapCheck := st.Snapshot(true)
	if snapCheck.RecentIPs[0] != "192.0.2.2" {
		t.Fatalf("RecentIPs slice was not copied: %v", snapCheck.RecentIPs)
	}
}

func TestStatsTrackerConcurrent_Race(t *testing.T) {
	st := NewStatsTracker(8)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			addr := netip.AddrFrom4([4]byte{198, 51, 100, byte(id + 1)})
			for i := 0; i < 50; i++ {
				st.Record(PulseEvent{SrcAddr: addr, Proto: 17, IPVersion: 4})
				_ = st.Snapshot(i%2 == 0)
			}
		}(g)
	}
	wg.Wait()

	snap := st.Snapshot(true)
	if snap.TotalPulses != 400 || snap.UDPPulses != 400 || snap.IPv4Pulses != 400 {
		t.Fatalf("unexpected concurrent totals: %+v", snap)
	}
	if len(snap.RecentIPs) != 8 {
		t.Fatalf("expected 8 unique recent IPs, got %d", len(snap.RecentIPs))
	}
}
