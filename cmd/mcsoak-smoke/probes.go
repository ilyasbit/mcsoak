package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

type echoPayload struct {
	Proto string `json:"proto"`
	TLS   *struct {
		Version string `json:"version"`
	} `json:"tls"`
}

type dnsRegisterPayload struct {
	SessionID string `json:"session_id"`
	FQDN      string `json:"fqdn"`
}

type dnsCheckPayload struct {
	Found    bool `json:"found"`
	HitCount int  `json:"hit_count"`
}

type reflectorStatsPayload struct {
	TotalPulses uint64 `json:"total_pulses"`
}

func checkHealthAndAuth(ctx context.Context, client *http.Client, baseURL, token string) error {
	status, _, err := doGet(ctx, client, baseURL+"/health", "")
	if err != nil {
		return fmt.Errorf("GET /health: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /health status = %d, want 200", status)
	}
	if token != "" {
		status, _, err := doGet(ctx, client, baseURL+"/echo", "")
		if err != nil {
			return fmt.Errorf("unauthenticated GET /echo: %w", err)
		}
		if status != http.StatusUnauthorized {
			return fmt.Errorf("unauthenticated GET /echo status = %d, want 401", status)
		}
	}
	return nil
}

func checkHTTPS(ctx context.Context, client *http.Client, baseURL, token string) error {
	status, body, err := doGet(ctx, client, baseURL+"/echo", token)
	if err != nil {
		return fmt.Errorf("GET /echo: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /echo status = %d, want 200", status)
	}
	var echo echoPayload
	if err := json.Unmarshal(body, &echo); err != nil {
		return fmt.Errorf("decode /echo: %w", err)
	}
	if echo.Proto != "HTTP/2.0" {
		return fmt.Errorf("/echo proto = %q, want HTTP/2.0", echo.Proto)
	}
	if echo.TLS == nil || echo.TLS.Version != "TLS 1.3" {
		ver := "<nil>"
		if echo.TLS != nil {
			ver = echo.TLS.Version
		}
		return fmt.Errorf("/echo tls.version = %q, want TLS 1.3", ver)
	}

	if status, _, err := doGet(ctx, client, baseURL+"/fp", token); err != nil {
		return fmt.Errorf("GET /fp: %w", err)
	} else if status != http.StatusOK {
		return fmt.Errorf("GET /fp status = %d, want 200", status)
	}

	if status, _, err := doGet(ctx, client, baseURL+"/asn", token); err != nil {
		return fmt.Errorf("GET /asn: %w", err)
	} else if status != http.StatusOK && status != http.StatusServiceUnavailable {
		return fmt.Errorf("GET /asn status = %d, want 200 or 503", status)
	}

	if status, body, err := doGet(ctx, client, baseURL+"/burst", token); err != nil {
		return fmt.Errorf("GET /burst: %w", err)
	} else if status != http.StatusOK {
		return fmt.Errorf("GET /burst status = %d, want 200", status)
	} else if len(body) < 9000 {
		return fmt.Errorf("GET /burst len = %d, want >= 9000", len(body))
	}

	if status, _, err := doGet(ctx, client, baseURL+"/page", token); err != nil {
		return fmt.Errorf("GET /page: %w", err)
	} else if status != http.StatusOK {
		return fmt.Errorf("GET /page status = %d, want 200", status)
	}
	return nil
}

func checkQUIC(ctx context.Context, cfg SmokeConfig) error {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer tr.Close()

	client := &http.Client{Transport: tr, Timeout: cfg.Timeout}
	url := fmt.Sprintf("https://%s/echo", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.QUICPort)))
	status, body, err := doGet(ctx, client, url, cfg.Token)
	if err != nil {
		return fmt.Errorf("HTTP/3 GET /echo: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("HTTP/3 GET /echo status = %d, want 200", status)
	}
	var echo echoPayload
	if err := json.Unmarshal(body, &echo); err != nil {
		return fmt.Errorf("decode HTTP/3 /echo: %w", err)
	}
	if echo.Proto != "HTTP/3.0" {
		return fmt.Errorf("HTTP/3 /echo proto = %q, want HTTP/3.0", echo.Proto)
	}
	return nil
}

func checkWebSocket(ctx context.Context, cfg SmokeConfig) error {
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: cfg.Timeout,
	}
	headers := http.Header{}
	if cfg.Token != "" {
		headers.Set("Authorization", "Bearer "+cfg.Token)
	}
	wsURL := fmt.Sprintf("wss://%s/ws", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.HTTPSPort)))
	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return fmt.Errorf("ws dial: %w", err)
	}
	defer conn.Close()

	const msg = "mcsoak-smoke-ws"
	if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		return fmt.Errorf("ws write: %w", err)
	}
	_, reply, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("ws read: %w", err)
	}
	if string(reply) != msg {
		return fmt.Errorf("ws echo = %q, want %q", string(reply), msg)
	}
	return nil
}

func exchangeDNS(ctx context.Context, resolver, name string, qtype uint16) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := c.ExchangeContext(ctx, m, resolver)
	if err != nil {
		return err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dns %s %s rcode = %s", dns.TypeToString[qtype], name, dns.RcodeToString[resp.Rcode])
	}
	return nil
}

func checkDNS(ctx context.Context, client *http.Client, baseURL string, cfg SmokeConfig) error {
	status, body, err := doGet(ctx, client, baseURL+"/dns", cfg.Token)
	if err != nil {
		return fmt.Errorf("GET /dns: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /dns status = %d, want 200", status)
	}
	var reg dnsRegisterPayload
	if err := json.Unmarshal(body, &reg); err != nil {
		return fmt.Errorf("decode /dns: %w", err)
	}
	if reg.SessionID == "" {
		return errors.New("/dns returned empty session_id")
	}

	if err := exchangeDNS(ctx, cfg.DNSResolver, cfg.DNSDomain, dns.TypeNS); err != nil {
		return fmt.Errorf("NS query: %w", err)
	}
	if err := exchangeDNS(ctx, cfg.DNSResolver, cfg.DNSDomain, dns.TypeSOA); err != nil {
		return fmt.Errorf("SOA query: %w", err)
	}
	if err := exchangeDNS(ctx, cfg.DNSResolver, reg.SessionID+"."+cfg.DNSDomain, dns.TypeA); err != nil {
		return fmt.Errorf("A query: %w", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		checkURL := fmt.Sprintf("%s/dns/check?id=%s", baseURL, reg.SessionID)
		status, body, err := doGet(ctx, client, checkURL, cfg.Token)
		if err != nil {
			return fmt.Errorf("GET /dns/check: %w", err)
		}
		if status != http.StatusOK {
			return fmt.Errorf("GET /dns/check status = %d, want 200", status)
		}
		var chk dnsCheckPayload
		if err := json.Unmarshal(body, &chk); err != nil {
			return fmt.Errorf("decode /dns/check: %w", err)
		}
		if chk.Found && chk.HitCount >= 1 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("dns leak check timed out: found=%v hit_count=%d", chk.Found, chk.HitCount)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func fetchReflectorPulses(ctx context.Context, client *http.Client, baseURL, token string) (uint64, error) {
	status, body, err := doGet(ctx, client, baseURL+"/reflector/stats", token)
	if err != nil {
		return 0, fmt.Errorf("GET /reflector/stats: %w", err)
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("GET /reflector/stats status = %d, want 200", status)
	}
	var stats reflectorStatsPayload
	if err := json.Unmarshal(body, &stats); err != nil {
		return 0, fmt.Errorf("decode /reflector/stats: %w", err)
	}
	return stats.TotalPulses, nil
}

func checkReflector(ctx context.Context, client *http.Client, baseURL string, cfg SmokeConfig) error {
	before, err := fetchReflectorPulses(ctx, client, baseURL, cfg.Token)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.ReflectorPort))
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return fmt.Errorf("udp dial %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{'M', 'C', 'P', 0x00}); err != nil {
		return fmt.Errorf("udp write pulse: %w", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("udp read pulse reply: %w", err)
	}
	switch {
	case n >= 16:
		var b16 [16]byte
		copy(b16[:], buf[:16])
		if !netip.AddrFrom16(b16).IsValid() {
			return errors.New("invalid IPv6 reflector reply")
		}
	case n >= 4:
		var b4 [4]byte
		copy(b4[:], buf[:4])
		if !netip.AddrFrom4(b4).IsValid() {
			return errors.New("invalid IPv4 reflector reply")
		}
	default:
		return fmt.Errorf("reflector reply too short: %d bytes", n)
	}

	after, err := fetchReflectorPulses(ctx, client, baseURL, cfg.Token)
	if err != nil {
		return err
	}
	if after < before {
		return fmt.Errorf("reflector total_pulses regressed: before=%d after=%d", before, after)
	}
	return nil
}
