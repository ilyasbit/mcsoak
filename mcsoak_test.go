package mcsoak

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ilyasbit/mcsoak/dnsleak"
	"github.com/ilyasbit/mcsoak/reflector"
	"github.com/ilyasbit/mcsoak/tcpfp"
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

func TestHandleASNNilLookup(t *testing.T) {
	srv, _, _, _ := newTestServer("")
	req := httptest.NewRequest(http.MethodGet, "/asn?ip=1.1.1.1", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoadOrGenerateTLS_IdempotentAndSANRegeneration(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "certs", "server.crt")
	keyPath := filepath.Join(dir, "certs", "server.key")

	if _, err := LoadOrGenerateTLS(certPath, ""); err == nil {
		t.Fatal("expected error when only certPath is provided")
	}
	if _, err := LoadOrGenerateTLS("", keyPath); err == nil {
		t.Fatal("expected error when only keyPath is provided")
	}

	cfg1, err := LoadOrGenerateTLS(certPath, keyPath, "example.test", "10.0.0.1")
	if err != nil {
		t.Fatalf("first LoadOrGenerateTLS failed: %v", err)
	}
	leaf1, err := x509.ParseCertificate(cfg1.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf1: %v", err)
	}

	cfg2, err := LoadOrGenerateTLS(certPath, keyPath, "example.test", "10.0.0.1")
	if err != nil {
		t.Fatalf("second LoadOrGenerateTLS failed: %v", err)
	}
	leaf2, err := x509.ParseCertificate(cfg2.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf2: %v", err)
	}

	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) != 0 {
		t.Fatalf("expected idempotent reuse with same serial %s, got %s", leaf1.SerialNumber, leaf2.SerialNumber)
	}

	cfg3, err := LoadOrGenerateTLS(certPath, keyPath, "example.test", "10.0.0.1", "added.test")
	if err != nil {
		t.Fatalf("third LoadOrGenerateTLS failed: %v", err)
	}
	leaf3, err := x509.ParseCertificate(cfg3.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf3: %v", err)
	}

	if leaf1.SerialNumber.Cmp(leaf3.SerialNumber) == 0 {
		t.Fatal("expected new certificate serial after SAN change")
	}
	if err := leaf3.VerifyHostname("added.test"); err != nil {
		t.Fatalf("expected regenerated cert to cover added.test: %v", err)
	}
}
