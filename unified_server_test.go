package mcsoak

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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
	t.Setenv("MCSOAK_PUBLIC_IPV4", "198.51.100.77")
	t.Setenv("MCSOAK_PUBLIC_IPV6", "2001:db8::77")

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
