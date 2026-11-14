package mcsoak

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ilyasbit/mcsoak/reflector"
	"github.com/ilyasbit/mcsoak/tcpfp"
	"github.com/quic-go/quic-go/http3"
)

func TestFingerprintInProcessStore(t *testing.T) {
	srv, fpStore, _, _ := newTestServer("")
	fpStore.Record(tcpfp.Fingerprint{
		TargetIP:   "203.0.113.42",
		SrcPort:    54321,
		DstPort:    8443,
		OS:         "Linux 6.x",
		TCPOptions: "mss:1460,sackOK,ts,nop,wscale:7",
	})

	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/fp?ip=203.0.113.42")
	if err != nil {
		t.Fatalf("failed request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var fp tcpfp.Fingerprint
	if err := json.NewDecoder(resp.Body).Decode(&fp); err != nil {
		t.Fatalf("failed to decode fingerprint response: %v", err)
	}
	if fp.OS != "Linux 6.x" {
		t.Errorf("expected os Linux 6.x, got %q", fp.OS)
	}

	resp404, err := http.Get(ts.URL + "/fp?ip=198.51.100.1")
	if err != nil {
		t.Fatalf("failed 404 request: %v", err)
	}
	defer resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404 for unknown IP, got %d", resp404.StatusCode)
	}
}

func TestDNSAndReflectorStatsRoutes(t *testing.T) {
	srv, _, _, stats := newTestServer("")
	stats.Record(reflector.PulseEvent{Proto: 17, IPVersion: 4})
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/dns")
	if err != nil {
		t.Fatalf("failed GET /dns: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /dns, got %d", resp.StatusCode)
	}

	var reg struct {
		SessionID string `json:"session_id"`
		FQDN      string `json:"fqdn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatalf("failed to decode /dns: %v", err)
	}
	if reg.SessionID == "" || !strings.Contains(reg.FQDN, "sight.muterconn.com") {
		t.Fatalf("unexpected /dns response: %+v", reg)
	}

	chkResp, err := http.Get(ts.URL + "/dns/check?id=" + reg.SessionID)
	if err != nil {
		t.Fatalf("failed GET /dns/check: %v", err)
	}
	defer chkResp.Body.Close()
	if chkResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /dns/check, got %d", chkResp.StatusCode)
	}

	statsResp, err := http.Get(ts.URL + "/reflector/stats?ips=true")
	if err != nil {
		t.Fatalf("failed GET /reflector/stats: %v", err)
	}
	defer statsResp.Body.Close()
	if statsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /reflector/stats, got %d", statsResp.StatusCode)
	}
	var snap reflector.StatsSnapshot
	if err := json.NewDecoder(statsResp.Body).Decode(&snap); err != nil {
		t.Fatalf("failed to decode /reflector/stats: %v", err)
	}
	if snap.TotalPulses != 1 || snap.UDPPulses != 1 {
		t.Fatalf("unexpected reflector stats: %+v", snap)
	}
}

func TestTokenAuthMiddleware(t *testing.T) {
	const secret = "super-secret-soak-token"
	srv, _, _, _ := newTestServer(secret)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	// /health must bypass auth
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected /health 200 without token, got %d", resp.StatusCode)
	}

	protected := []string{"/echo", "/asn", "/fp", "/dns", "/reflector/stats"}
	for _, ep := range protected {
		r, err := http.Get(ts.URL + ep)
		if err != nil {
			t.Fatalf("request %s failed: %v", ep, err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for %s without token, got %d", ep, r.StatusCode)
		}

		req, _ := http.NewRequest(http.MethodGet, ts.URL+ep, nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		r2, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %s failed: %v", ep, err)
		}
		r2.Body.Close()
		if r2.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for %s with wrong token, got %d", ep, r2.StatusCode)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rOK, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bearer request failed: %v", err)
	}
	rOK.Body.Close()
	if rOK.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with valid Bearer token, got %d", rOK.StatusCode)
	}

	rQuery, err := http.Get(ts.URL + "/reflector/stats?token=" + secret)
	if err != nil {
		t.Fatalf("query token request failed: %v", err)
	}
	rQuery.Body.Close()
	if rQuery.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with valid ?token= param, got %d", rQuery.StatusCode)
	}
}

func TestIPBasedTLSSANs(t *testing.T) {
	t.Setenv("SOAK_PUBLIC_IPV4", "198.51.100.77")
	t.Setenv("SOAK_PUBLIC_IPV6", "2001:db8::77")

	tlsConfig, err := LoadOrGenerateTLS("", "")
	if err != nil {
		t.Fatalf("LoadOrGenerateTLS failed: %v", err)
	}
	if len(tlsConfig.Certificates) == 0 || len(tlsConfig.Certificates[0].Certificate) == 0 {
		t.Fatal("expected generated certificate")
	}

	leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	wantIPs := map[string]bool{
		"127.0.0.1":     false,
		"::1":           false,
		"198.51.100.77": false,
		"2001:db8::77":  false,
	}
	for _, ip := range leaf.IPAddresses {
		if _, ok := wantIPs[ip.String()]; ok {
			wantIPs[ip.String()] = true
		}
	}
	for ip, found := range wantIPs {
		if !found {
			t.Errorf("expected IP SAN %s in certificate, got %v", ip, leaf.IPAddresses)
		}
	}

	hasLocalhost := false
	for _, dnsName := range leaf.DNSNames {
		if dnsName == "localhost" {
			hasLocalhost = true
		}
	}
	if !hasLocalhost {
		t.Errorf("expected localhost DNS SAN, got %v", leaf.DNSNames)
	}

	hasH3 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h3" {
			hasH3 = true
		}
	}
	if !hasH3 {
		t.Errorf("expected h3 in NextProtos, got %v", tlsConfig.NextProtos)
	}
}

func TestHTTP3EndToEnd(t *testing.T) {
	tlsConfig, err := LoadOrGenerateTLS("", "")
	if err != nil {
		t.Fatalf("LoadOrGenerateTLS failed: %v", err)
	}

	srv, _, _, _ := newTestServer("")
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer udpConn.Close()

	h3Srv := &http3.Server{
		Handler:   srv.Routes(),
		TLSConfig: http3.ConfigureTLSConfig(tlsConfig),
	}
	defer h3Srv.Close()

	go func() {
		_ = h3Srv.Serve(udpConn)
	}()

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}
	defer tr.Close()

	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://%s/echo", udpConn.LocalAddr().String())
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("HTTP/3 GET /echo failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("expected HTTP/3 (ProtoMajor 3), got %s", resp.Proto)
	}

	var echo EchoResponse
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode echo failed: %v", err)
	}
	if echo.ClientIP == "" {
		t.Errorf("expected non-empty client_ip")
	}
}

func mmdbEncodeString(s string) []byte {
	n := len(s)
	var out []byte
	if n < 29 {
		out = append(out, byte((2<<5)|n))
	} else {
		out = append(out, byte((2<<5)|29), byte(n-29))
	}
	return append(out, s...)
}

func mmdbEncodeUint32(v uint32) []byte {
	if v == 0 {
		return []byte{6 << 5}
	}
	var buf [4]byte
	buf[0] = byte(v >> 24)
	buf[1] = byte(v >> 16)
	buf[2] = byte(v >> 8)
	buf[3] = byte(v)
	i := 0
	for i < 4 && buf[i] == 0 {
		i++
	}
	size := 4 - i
	out := []byte{byte((6 << 5) | size)}
	return append(out, buf[i:]...)
}

func buildTestASNMMDB(t *testing.T, asn uint32, isp string) string {
	t.Helper()
	var data []byte
	// 1-node tree (6 bytes for 24-bit records); record 17 => data offset 0.
	data = append(data, 0, 0, 17, 0, 0, 17)
	// 16-byte data section separator
	data = append(data, make([]byte, 16)...)
	// Data record at offset 0: map with 2 entries
	data = append(data, byte((7<<5)|2))
	data = append(data, mmdbEncodeString("autonomous_system_number")...)
	data = append(data, mmdbEncodeUint32(asn)...)
	data = append(data, mmdbEncodeString("autonomous_system_organization")...)
	data = append(data, mmdbEncodeString(isp)...)

	// Metadata marker + map (6 entries)
	data = append(data, []byte("\xab\xcd\xefMaxMind.com")...)
	data = append(data, byte((7<<5)|6))
	data = append(data, mmdbEncodeString("node_count")...)
	data = append(data, mmdbEncodeUint32(1)...)
	data = append(data, mmdbEncodeString("record_size")...)
	data = append(data, mmdbEncodeUint32(24)...)
	data = append(data, mmdbEncodeString("ip_version")...)
	data = append(data, mmdbEncodeUint32(4)...)
	data = append(data, mmdbEncodeString("database_type")...)
	data = append(data, mmdbEncodeString("GeoLite2-ASN")...)
	data = append(data, mmdbEncodeString("binary_format_major_version")...)
	data = append(data, mmdbEncodeUint32(2)...)
	data = append(data, mmdbEncodeString("binary_format_minor_version")...)
	data = append(data, mmdbEncodeUint32(0)...)

	path := t.TempDir() + "/test_asn.mmdb"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test mmdb: %v", err)
	}
	return path
}

func TestASNLookupAndHandlers(t *testing.T) {
	var nilLookup *ASNLookup
	if _, ok := nilLookup.Lookup(netip.MustParseAddr("1.1.1.1")); ok {
		t.Fatal("expected nil ASNLookup.Lookup to return false")
	}
	if err := nilLookup.Close(); err != nil {
		t.Fatalf("expected nil ASNLookup.Close to return nil, got %v", err)
	}

	if _, err := OpenASNLookup("/nonexistent/path/missing.mmdb"); err == nil {
		t.Fatal("expected error for missing mmdb path")
	}

	mmdbPath := buildTestASNMMDB(t, 13335, "Cloudflare, Inc.")
	lookup, err := OpenASNLookup(mmdbPath)
	if err != nil {
		t.Fatalf("OpenASNLookup failed: %v", err)
	}
	defer lookup.Close()

	info, ok := lookup.Lookup(netip.MustParseAddr("1.1.1.1"))
	if !ok {
		t.Fatal("expected ASN lookup match for 1.1.1.1")
	}
	if info.ASN != 13335 || info.ISP != "Cloudflare, Inc." {
		t.Fatalf("unexpected ASNInfo: %+v", info)
	}

	srv := NewServer(ServerConfig{
		ASNLookup: lookup,
	})
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	echoResp, err := http.Get(ts.URL + "/echo")
	if err != nil {
		t.Fatalf("GET /echo failed: %v", err)
	}
	defer echoResp.Body.Close()
	if echoResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /echo, got %d", echoResp.StatusCode)
	}
	var echo EchoResponse
	if err := json.NewDecoder(echoResp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode /echo failed: %v", err)
	}
	if echo.ASN != 13335 || echo.ISP != "Cloudflare, Inc." {
		t.Fatalf("expected ASN=13335 ISP='Cloudflare, Inc.' in /echo, got asn=%d isp=%q", echo.ASN, echo.ISP)
	}

	asnResp, err := http.Get(ts.URL + "/asn?ip=1.1.1.1")
	if err != nil {
		t.Fatalf("GET /asn failed: %v", err)
	}
	defer asnResp.Body.Close()
	if asnResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /asn, got %d", asnResp.StatusCode)
	}
	var asnBody struct {
		IP  string `json:"ip"`
		ASN uint32 `json:"asn"`
		ISP string `json:"isp"`
	}
	if err := json.NewDecoder(asnResp.Body).Decode(&asnBody); err != nil {
		t.Fatalf("decode /asn failed: %v", err)
	}
	if asnBody.IP != "1.1.1.1" || asnBody.ASN != 13335 || asnBody.ISP != "Cloudflare, Inc." {
		t.Fatalf("unexpected /asn response: %+v", asnBody)
	}

	badResp, err := http.Get(ts.URL + "/asn?ip=not-an-ip")
	if err != nil {
		t.Fatalf("GET /asn invalid ip failed: %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid ip, got %d", badResp.StatusCode)
	}
}
