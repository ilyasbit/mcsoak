package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// SmokeConfig configures the end-to-end smoke check against a live or test mcsoak instance.
type SmokeConfig struct {
	Host          string
	HTTPSPort     int
	QUICPort      int
	ReflectorPort int
	DNSDomain     string
	DNSResolver   string
	Token         string
	Timeout       time.Duration
	SkipQUIC      bool
	SkipReflector bool
	SkipDNS       bool
}

func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func parseFlags() SmokeConfig {
	var cfg SmokeConfig
	flag.StringVar(&cfg.Host, "host", envString("MCSOAK_SMOKE_HOST", "89.58.24.50"), "Target mcsoak host")
	flag.IntVar(&cfg.HTTPSPort, "https-port", envInt("MCSOAK_SMOKE_HTTPS_PORT", 8443), "HTTPS/HTTP2 port")
	flag.IntVar(&cfg.QUICPort, "quic-port", envInt("MCSOAK_SMOKE_QUIC_PORT", 9443), "HTTP/3 QUIC port")
	flag.IntVar(&cfg.ReflectorPort, "reflector-port", envInt("MCSOAK_SMOKE_REFLECTOR_PORT", 7777), "eBPF reflector UDP port")
	flag.StringVar(&cfg.DNSDomain, "dns-domain", envString("MCSOAK_DNS_DOMAIN", "dns.muterconn.com"), "DNS leak oracle base domain")
	flag.StringVar(&cfg.DNSResolver, "dns-resolver", envString("MCSOAK_DNS_RESOLVER", "1.1.1.1:53"), "DNS resolver address")
	flag.StringVar(&cfg.Token, "token", envString("MCSOAK_TOKEN", ""), "Bearer auth token")
	flag.DurationVar(&cfg.Timeout, "timeout", 15*time.Second, "Overall smoke test timeout")
	flag.BoolVar(&cfg.SkipQUIC, "skip-quic", false, "Skip HTTP/3 QUIC check")
	flag.BoolVar(&cfg.SkipReflector, "skip-reflector", false, "Skip eBPF reflector check")
	flag.BoolVar(&cfg.SkipDNS, "skip-dns", false, "Skip DNS leak oracle check")
	flag.Parse()
	return cfg
}

func newHTTPSClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
}

func doGet(ctx context.Context, client *http.Client, url, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

func runSmoke(ctx context.Context, cfg SmokeConfig) error {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	baseURL := fmt.Sprintf("https://%s", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.HTTPSPort)))
	client := newHTTPSClient(cfg.Timeout)
	defer client.CloseIdleConnections()

	if err := checkHealthAndAuth(ctx, client, baseURL, cfg.Token); err != nil {
		return err
	}
	if err := checkHTTPS(ctx, client, baseURL, cfg.Token); err != nil {
		return err
	}
	if !cfg.SkipQUIC {
		if err := checkQUIC(ctx, cfg); err != nil {
			return err
		}
	}
	if err := checkWebSocket(ctx, cfg); err != nil {
		return err
	}
	if !cfg.SkipDNS {
		if err := checkDNS(ctx, client, baseURL, cfg); err != nil {
			return err
		}
	}
	if !cfg.SkipReflector {
		if err := checkReflector(ctx, client, baseURL, cfg); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	cfg := parseFlags()
	if err := runSmoke(context.Background(), cfg); err != nil {
		fmt.Fprintf(os.Stderr, "mcsoak-smoke failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("mcsoak-smoke: all enabled planes passed")
}
