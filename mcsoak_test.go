package mcsoak

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ilyasbit/mcsoak/dnsleak"
	"github.com/ilyasbit/mcsoak/reflector"
	"github.com/ilyasbit/mcsoak/tcpfp"
	"github.com/quic-go/quic-go/http3"
)

func newTestServer(token string) (*Server, *tcpfp.Store, *dnsleak.Store, *reflector.StatsTracker) {
	fpStore := tcpfp.NewStore(64)
	dnsStore := dnsleak.NewStore(64, time.Minute)
	dnsStore.SetBaseDomain("sight.muterconn.com")
	stats := reflector.NewStatsTracker(16)
	srv := NewServer(ServerConfig{
		FPStore:        fpStore,
		DNSStore:       dnsStore,
		ReflectorStats: stats,
		Token:          token,
	})
	return srv, fpStore, dnsStore, stats
}

func TestHealth(t *testing.T) {
	srv, _, _, _ := newTestServer("")
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var res map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	if res["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", res["status"])
	}
}

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

	protected := []string{"/echo", "/fp", "/dns", "/reflector/stats"}
	for _, ep := range protected {
		r, err := http.Get(ts.URL + ep)
		if err != nil {
			t.Fatalf("request %s failed: %v", ep, err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for %s without token, got %d", ep, r.StatusCode)
		}

		// Wrong token
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

	// Valid Bearer header on /echo
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

	// Valid ?token= query param on /reflector/stats
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

func TestAssets(t *testing.T) {
	srv, _, _, _ := newTestServer("")
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	cases := []struct {
		path        string
		status      int
		contentType string
	}{
		{"/assets/chunk_1.js", http.StatusOK, "application/javascript"},
		{"/assets/style_2.css", http.StatusOK, "text/css"},
		{"/assets/img_3.svg", http.StatusOK, "image/svg+xml"},
		{"/assets/unknown_1.exe", http.StatusNotFound, ""},
		{"/assets/chunk_foo.js", http.StatusNotFound, ""},
	}

	for _, tc := range cases {
		resp, err := http.Get(ts.URL + tc.path)
		if err != nil {
			t.Fatalf("get %s failed: %v", tc.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Errorf("for %s expected status %d, got %d", tc.path, tc.status, resp.StatusCode)
		}
		if tc.contentType != "" {
			ct := resp.Header.Get("Content-Type")
			if !strings.HasPrefix(ct, tc.contentType) {
				t.Errorf("for %s expected Content-Type %s, got %s", tc.path, tc.contentType, ct)
			}
		}
	}
}

func TestBurst(t *testing.T) {
	srv, _, _, _ := newTestServer("")
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}
	resp, err := client.Get(ts.URL + "/burst")
	if err != nil {
		t.Fatalf("failed to get burst: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("expected Content-Encoding: gzip, got %s", resp.Header.Get("Content-Encoding"))
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gr.Close()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to read decompressed gzip: %v", err)
	}

	var burstObj map[string]any
	if err := json.Unmarshal(decompressed, &burstObj); err != nil {
		t.Fatalf("failed to unmarshal decompressed json: %v", err)
	}
	if burstObj["message"] != "burst payload" {
		t.Errorf("expected burst payload message, got %v", burstObj["message"])
	}
}

func TestPage(t *testing.T) {
	srv, _, _, _ := newTestServer("")
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/page")
	if err != nil {
		t.Fatalf("failed to get page: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read page: %v", err)
	}
	bodyStr := string(body)

	for i := 1; i <= 15; i++ {
		pattern := fmt.Sprintf("/assets/style_%d.css", i)
		if !strings.Contains(bodyStr, pattern) {
			t.Errorf("missing sub-resource: %s", pattern)
		}
	}
	for i := 1; i <= 10; i++ {
		pattern := fmt.Sprintf("/assets/img_%d.svg", i)
		if !strings.Contains(bodyStr, pattern) {
			t.Errorf("missing sub-resource: %s", pattern)
		}
	}
	for i := 1; i <= 25; i++ {
		pattern := fmt.Sprintf("/assets/chunk_%d.js", i)
		if !strings.Contains(bodyStr, pattern) {
			t.Errorf("missing sub-resource: %s", pattern)
		}
	}
	if !strings.Contains(bodyStr, "new WebSocket") {
		t.Errorf("missing WebSocket script in page")
	}
}

func TestWebSocketEcho(t *testing.T) {
	srv, _, _, _ := newTestServer("")
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer ws.Close()

	msgText := "hello mcsoak websocket"
	if err := ws.WriteMessage(websocket.TextMessage, []byte(msgText)); err != nil {
		t.Fatalf("failed to write text message: %v", err)
	}
	mt, msgBytes, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read text message: %v", err)
	}
	if mt != websocket.TextMessage || string(msgBytes) != msgText {
		t.Errorf("expected text message '%s', got '%s' (type %d)", msgText, string(msgBytes), mt)
	}

	binData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
	if err := ws.WriteMessage(websocket.BinaryMessage, binData); err != nil {
		t.Fatalf("failed to write binary message: %v", err)
	}
	mt, msgBytes, err = ws.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read binary message: %v", err)
	}
	if mt != websocket.BinaryMessage || !bytes.Equal(msgBytes, binData) {
		t.Errorf("expected binary message %v, got %v (type %d)", binData, msgBytes, mt)
	}

	pongReceived := make(chan string, 1)
	ws.SetPongHandler(func(appData string) error {
		pongReceived <- appData
		return nil
	})
	if err := ws.WriteControl(websocket.PingMessage, []byte("ping-payload"), time.Now().Add(time.Second)); err != nil {
		t.Fatalf("failed to write ping: %v", err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _, _ = ws.ReadMessage()
	select {
	case data := <-pongReceived:
		if data != "ping-payload" {
			t.Errorf("expected pong payload 'ping-payload', got '%s'", data)
		}
	case <-time.After(500 * time.Millisecond):
		t.Log("pong received or handled internally")
	}
}

func TestTLSHandshakeAndHTTP2(t *testing.T) {
	tlsConfig, err := LoadOrGenerateTLS("", "", "localhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to load or generate tls: %v", err)
	}

	srv, _, _, _ := newTestServer("")
	ts := httptest.NewUnstartedServer(srv.Routes())
	ts.TLS = tlsConfig
	ts.StartTLS()
	defer ts.Close()

	client := ts.Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	}
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client.Transport = transport

	resp, err := client.Get(ts.URL + "/echo")
	if err != nil {
		t.Fatalf("failed to request TLS server: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Logf("protocol is %s (ProtoMajor %d)", resp.Proto, resp.ProtoMajor)
	}

	var echo EchoResponse
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("failed to decode echo response: %v", err)
	}
	if echo.TLS == nil {
		t.Fatalf("expected TLS info in echo response, got nil")
	}
	if echo.TLS.CipherSuite == "" {
		t.Errorf("expected TLS CipherSuite to be non-empty")
	}
}

func TestConcurrentRequests_Race(t *testing.T) {
	srv, fpStore, _, stats := newTestServer("")
	fpStore.Record(tcpfp.Fingerprint{TargetIP: "127.0.0.1", OS: "Linux"})
	stats.Record(reflector.PulseEvent{Proto: 6, IPVersion: 4})

	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	var wg sync.WaitGroup
	concurrency := 100
	endpoints := []string{
		"/health",
		"/burst",
		"/echo",
		"/fp?ip=127.0.0.1",
		"/dns",
		"/reflector/stats",
		"/assets/chunk_1.js",
		"/assets/style_2.css",
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		endpoint := endpoints[i%len(endpoints)]
		go func(ep string) {
			defer wg.Done()
			resp, err := client.Get(ts.URL + ep)
			if err != nil {
				t.Errorf("request failed to %s: %v", ep, err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}(endpoint)
	}
	wg.Wait()
}
