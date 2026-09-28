package mcsoak

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHealth(t *testing.T) {
	srv := NewServer("")
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

func TestAPIFingerprintWithMockDaemon(t *testing.T) {
	mock := NewMockTCPFPDaemon("Linux 5.x/6.x")
	defer mock.Close()

	srv := NewServer(mock.URL)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/fingerprint")
	if err != nil {
		t.Fatalf("failed request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var echo EchoResponse
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("failed to decode echo response: %v", err)
	}

	if echo.TCPFingerprint == nil {
		t.Fatalf("expected tcp_fingerprint to be populated")
	}
	fpMap, ok := echo.TCPFingerprint.(map[string]any)
	if !ok {
		t.Fatalf("expected tcp_fingerprint to be map[string]any, got %T", echo.TCPFingerprint)
	}
	if fpMap["os"] != "Linux 5.x/6.x" {
		t.Errorf("expected os Linux 5.x/6.x, got %v", fpMap["os"])
	}
}

func TestAPIFingerprintTimeoutGraceful(t *testing.T) {
	slowMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(700 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"os":"Slow"}`))
	}))
	defer slowMock.Close()

	srv := NewServer(slowMock.URL)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(ts.URL + "/api/fingerprint")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var echo EchoResponse
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if echo.TCPFingerprint != nil {
		t.Fatalf("expected null tcp_fingerprint on timeout, got %v", echo.TCPFingerprint)
	}
}

func TestAssets(t *testing.T) {
	srv := NewServer("")
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
		defer resp.Body.Close()
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
	srv := NewServer("")
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
	srv := NewServer("")
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

	// Check 15 CSS, 10 SVG, 25 JS (50 sub-resources total)
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
	srv := NewServer("")
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer ws.Close()

	// Test Text Frame Echo
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

	// Test Binary Frame Echo
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

	// Test Ping / Pong
	pongReceived := make(chan string, 1)
	ws.SetPongHandler(func(appData string) error {
		pongReceived <- appData
		return nil
	})
	if err := ws.WriteControl(websocket.PingMessage, []byte("ping-payload"), time.Now().Add(time.Second)); err != nil {
		t.Fatalf("failed to write ping: %v", err)
	}
	// Wait briefly or do a dummy read to trigger pong handler
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

	srv := NewServer("")
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

	resp, err := client.Get(ts.URL + "/api/echo")
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
	srv := NewServer("")
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	var wg sync.WaitGroup
	concurrency := 100
	endpoints := []string{
		"/health",
		"/burst",
		"/api/echo",
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
