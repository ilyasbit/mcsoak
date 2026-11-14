package tcpfp

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func buildIPv4TCPSYN(srcIP string, ttl uint8, srcPort, dstPort, win uint16, flags byte, opts []byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, optEOL)
	}
	tcpLen := 20 + len(opts)
	totLen := 20 + tcpLen
	pkt := make([]byte, totLen)

	// IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totLen))
	pkt[8] = ttl
	pkt[9] = ipProtoTCP
	copy(pkt[12:16], net.ParseIP(srcIP).To4())
	copy(pkt[16:20], net.ParseIP("10.0.0.1").To4())

	// TCP header
	seg := pkt[20:]
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	seg[12] = byte((tcpLen / 4) << 4)
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], win)
	copy(seg[20:], opts)
	return pkt
}

func buildIPv6TCPSYN(srcIP string, hopLimit uint8, win uint16, opts []byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, optEOL)
	}
	tcpLen := 20 + len(opts)
	pkt := make([]byte, 40+tcpLen)

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpLen))
	pkt[6] = ipProtoTCP
	pkt[7] = hopLimit
	copy(pkt[8:24], net.ParseIP(srcIP).To16())
	copy(pkt[24:40], net.ParseIP("fd00::1").To16())

	seg := pkt[40:]
	binary.BigEndian.PutUint16(seg[0:2], 51234)
	binary.BigEndian.PutUint16(seg[2:4], 9443)
	seg[12] = byte((tcpLen / 4) << 4)
	seg[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(seg[14:16], win)
	copy(seg[20:], opts)
	return pkt
}

func linuxSYNOptions() []byte {
	return []byte{
		optMSS, 4, 0x05, 0xb4, // MSS 1460
		optSACKPerm, 2,
		optTimestamp, 10, 0, 0, 0, 1, 0, 0, 0, 0,
		optNOP,
		optWScale, 3, 7,
	}
}

func windowsSYNOptions() []byte {
	return []byte{
		optMSS, 4, 0x05, 0xb4,
		optNOP,
		optWScale, 3, 8,
		optNOP, optNOP,
		optSACKPerm, 2,
	}
}

func TestParseIPv4SYN_OSProfiles(t *testing.T) {
	macOpts := []byte{
		optMSS, 4, 0x05, 0xb4,
		optNOP,
		optWScale, 3, 6,
		optNOP, optNOP,
		optTimestamp, 10, 0, 0, 0, 1, 0, 0, 0, 0,
		optSACKPerm, 2,
	}

	tests := []struct {
		name   string
		pkt    []byte
		wantOS OSProfile
		wantWS uint8
	}{
		{
			name:   "linux",
			pkt:    buildIPv4TCPSYN("192.0.2.10", 60, 40000, 9443, 64240, tcpFlagSYN, linuxSYNOptions()),
			wantOS: OSLinux,
			wantWS: 7,
		},
		{
			name:   "windows",
			pkt:    buildIPv4TCPSYN("192.0.2.20", 120, 50000, 9443, 64240, tcpFlagSYN, windowsSYNOptions()),
			wantOS: OSWindows,
			wantWS: 8,
		},
		{
			name:   "macos",
			pkt:    buildIPv4TCPSYN("192.0.2.30", 64, 51000, 9443, 65535, tcpFlagSYN, macOpts),
			wantOS: OSMacOS,
			wantWS: 6,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fp, err := ParseIPSYN(tc.pkt)
			if err != nil {
				t.Fatalf("ParseIPSYN failed: %v", err)
			}
			if fp.OS != tc.wantOS {
				t.Errorf("OS = %q, want %q", fp.OS, tc.wantOS)
			}
			if fp.MSS != 1460 {
				t.Errorf("MSS = %d, want 1460", fp.MSS)
			}
			if fp.WindowScale != tc.wantWS {
				t.Errorf("WindowScale = %d, want %d", fp.WindowScale, tc.wantWS)
			}
			if fp.Signature == "" || fp.TCPOptions == "" {
				t.Errorf("expected non-empty signature and tcp_options, got sig=%q opts=%q", fp.Signature, fp.TCPOptions)
			}
		})
	}
}

func TestParseIPv6AndEthernetSYN(t *testing.T) {
	ip6 := buildIPv6TCPSYN("2001:db8::42", 62, 64240, linuxSYNOptions())
	eth := make([]byte, ethHeaderLen+len(ip6))
	binary.BigEndian.PutUint16(eth[12:14], ethTypeIPv6)
	copy(eth[ethHeaderLen:], ip6)

	fp, err := ParseEthernetSYN(eth)
	if err != nil {
		t.Fatalf("ParseEthernetSYN failed: %v", err)
	}
	if fp.IPVersion != 6 {
		t.Errorf("IPVersion = %d, want 6", fp.IPVersion)
	}
	if fp.TargetIP != "2001:db8::42" {
		t.Errorf("TargetIP = %q, want 2001:db8::42", fp.TargetIP)
	}
	if fp.OS != OSLinux {
		t.Errorf("OS = %q, want %q", fp.OS, OSLinux)
	}
}

func TestParseSYN_RejectsInvalidPackets(t *testing.T) {
	synAck := buildIPv4TCPSYN("192.0.2.1", 64, 64240, 1234, 443, tcpFlagSYN|tcpFlagACK, nil)
	if _, err := ParseIPSYN(synAck); !errors.Is(err, ErrNotSYN) {
		t.Errorf("expected ErrNotSYN for SYN-ACK, got %v", err)
	}

	udpPkt := buildIPv4TCPSYN("192.0.2.1", 64, 64240, 1234, 443, tcpFlagSYN, nil)
	udpPkt[9] = 17
	if _, err := ParseIPSYN(udpPkt); !errors.Is(err, ErrNotTCP) {
		t.Errorf("expected ErrNotTCP for UDP, got %v", err)
	}

	if _, err := ParseIPSYN([]byte{0x45, 0x00}); !errors.Is(err, ErrTooShort) {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestStoreAndHTTPHandler_Race(t *testing.T) {
	store := NewStore(16)
	srv := httptest.NewServer(store.Handler())
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := fmt.Sprintf("198.51.100.%d", idx%20)
			pkt := buildIPv4TCPSYN(ip, 64, 64240, uint16(10000+idx), 9443, tcpFlagSYN, linuxSYNOptions())
			if _, err := store.RecordPacket(pkt); err != nil {
				t.Errorf("RecordPacket failed: %v", err)
			}
			store.Lookup(ip)
		}(i)
	}
	wg.Wait()

	if store.Len() > 16 {
		t.Fatalf("store exceeded capacity: %d", store.Len())
	}

	pkt := buildIPv4TCPSYN("203.0.113.5", 128, 64240, 44444, 9443, tcpFlagSYN, windowsSYNOptions())
	if _, err := store.RecordPacket(pkt); err != nil {
		t.Fatalf("RecordPacket failed: %v", err)
	}

	resp, err := http.Get(srv.URL + "/check?ip=203.0.113.5")
	if err != nil {
		t.Fatalf("GET /check failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got Fingerprint
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if got.OS != OSWindows || got.TargetIP != "203.0.113.5" {
		t.Errorf("unexpected fingerprint response: %+v", got)
	}

	missResp, err := http.Get(srv.URL + "/check?ip=203.0.113.99")
	if err != nil {
		t.Fatalf("GET /check miss failed: %v", err)
	}
	defer missResp.Body.Close()
	if missResp.StatusCode != http.StatusNotFound {
		t.Errorf("miss status = %d, want 404", missResp.StatusCode)
	}
}
