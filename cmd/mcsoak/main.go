package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ilyasbit/mcsoak"
	"github.com/ilyasbit/mcsoak/dnsleak"
	"github.com/ilyasbit/mcsoak/reflector"
	"github.com/ilyasbit/mcsoak/tcpfp"
	"github.com/quic-go/quic-go/http3"
)

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return defaultVal
	}
	return val == "true" || val == "1" || val == "yes"
}

func parseListenPort(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

func parseCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parsePublicIPv4(raw string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil || ip.To4() == nil {
		return nil
	}
	return ip.To4()
}

func parsePublicIPv6(raw string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil || ip.To4() != nil {
		return nil
	}
	return ip
}

func isRoutablePublicIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsUnspecified()
}

func buildDNSLeakConfig(listenSpec, domain, nsRaw string) (dnsleak.Config, error) {
	cleanDomain := strings.TrimSpace(domain)
	if cleanDomain == "" {
		return dnsleak.Config{}, errors.New("dnsleak requires a non-empty -dns-domain / MCSOAK_DNS_DOMAIN")
	}
	nsNames := parseCSV(nsRaw)
	if len(nsNames) == 0 {
		return dnsleak.Config{}, errors.New("dnsleak requires at least one nameserver in -dns-ns / MCSOAK_DNS_NS")
	}

	cfg := dnsleak.Config{
		BaseDomain: cleanDomain,
		NSNames:    nsNames,
		EchoIPv4:   parsePublicIPv4(getEnv("MCSOAK_PUBLIC_IPV4", "")),
		EchoIPv6:   parsePublicIPv6(getEnv("MCSOAK_PUBLIC_IPV6", "")),
	}

	if strings.TrimSpace(listenSpec) != "" {
		addrs := parseCSV(listenSpec)
		if len(addrs) == 0 {
			return dnsleak.Config{}, errors.New("dnsleak -dns-listen / MCSOAK_DNS_LISTEN yielded no valid addresses")
		}
		cfg.Addrs = addrs
		return cfg, nil
	}

	var autoAddrs []string
	if isRoutablePublicIP(cfg.EchoIPv4) {
		autoAddrs = append(autoAddrs, net.JoinHostPort(cfg.EchoIPv4.String(), "53"))
	}
	if isRoutablePublicIP(cfg.EchoIPv6) {
		autoAddrs = append(autoAddrs, net.JoinHostPort(cfg.EchoIPv6.String(), "53"))
	}
	if len(autoAddrs) == 0 {
		return dnsleak.Config{}, errors.New("dnsleak auto-bind requires at least one valid non-loopback, non-unspecified MCSOAK_PUBLIC_IPV4 or MCSOAK_PUBLIC_IPV6 (or set -dns-listen explicitly)")
	}
	cfg.Addrs = autoAddrs
	return cfg, nil
}

func initDNSStore(enabled bool, domain string) *dnsleak.Store {
	if !enabled {
		return nil
	}
	store := dnsleak.NewStore(0, 0)
	store.SetBaseDomain(domain)
	return store
}

func run() error {
	listenFlag := flag.String("listen", getEnv("MCSOAK_LISTEN", ":8443"), "HTTPS/H2 listen address")
	quicFlag := flag.Bool("quic", getEnvBool("MCSOAK_QUIC", true), "Enable HTTP/3 QUIC listener")
	quicListenFlag := flag.String("quic-listen", getEnv("MCSOAK_QUIC_LISTEN", ":9443"), "HTTP/3 QUIC UDP listen address")
	tokenFlag := flag.String("token", getEnv("MCSOAK_TOKEN", ""), "Static bearer/query auth token")
	certFlag := flag.String("cert", getEnv("MCSOAK_CERT", ""), "Path to TLS certificate file")
	keyFlag := flag.String("key", getEnv("MCSOAK_KEY", ""), "Path to TLS private key file")
	ifaceFlag := flag.String("iface", getEnv("MCSOAK_IFACE", "eth0"), "Network interface for reflector & tcpfp sniffer")
	reflectorFlag := flag.Bool("reflector", getEnvBool("MCSOAK_REFLECTOR", false), "Enable eBPF pulse reflector")
	tcpfpSniffFlag := flag.Bool("tcpfp-sniff", getEnvBool("MCSOAK_TCPFP_SNIFF", false), "Enable in-process AF_PACKET TCP SYN sniffer")
	dnsleakFlag := flag.Bool("dnsleak", getEnvBool("MCSOAK_DNSLEAK", false), "Enable authoritative DNS leak oracle")
	dnsListenFlag := flag.String("dns-listen", getEnv("MCSOAK_DNS_LISTEN", ""), "DNS leak oracle listen addresses (comma-separated; empty auto-binds public IPv4/IPv6 :53)")
	dnsDomainFlag := flag.String("dns-domain", getEnv("MCSOAK_DNS_DOMAIN", "dns.muterconn.com"), "Base domain for DNS leak oracle")
	dnsNSFlag := flag.String("dns-ns", getEnv("MCSOAK_DNS_NS", "ns1.dns.muterconn.com,ns2.dns.muterconn.com"), "Comma-separated authoritative nameservers for DNS leak oracle")
	dnsValidateNSFlag := flag.Bool("dns-validate-ns", getEnvBool("MCSOAK_DNS_VALIDATE_NS", false), "Validate NS delegation via public resolver on startup")
	dnsResolverFlag := flag.String("dns-resolver", getEnv("MCSOAK_DNS_RESOLVER", "1.1.1.1:53"), "Resolver address used for NS delegation validation")
	asnDBFlag := flag.String("asn-db", getEnv("MCSOAK_ASN_DB", ""), "Path to MaxMind .mmdb ASN database")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fpStore := tcpfp.NewStore(0)
	dnsStore := initDNSStore(*dnsleakFlag, *dnsDomainFlag)
	statsTracker := reflector.NewStatsTracker(64)

	if *reflectorFlag {
		refl, err := reflector.StartWithEvents(*ifaceFlag, statsTracker.Record)
		if err != nil {
			return fmt.Errorf("failed to start eBPF reflector on %s: %w", *ifaceFlag, err)
		}
		defer func() {
			if err := refl.Close(); err != nil {
				log.Printf("Warning: Failed to close eBPF reflector: %v", err)
			}
		}()
	}

	serverErrChan := make(chan error, 3)

	if *tcpfpSniffFlag {
		listenPort := parseListenPort(*listenFlag)
		go func() {
			log.Printf("Starting TCP SYN sniffer on iface=%s port=%d", *ifaceFlag, listenPort)
			if err := tcpfp.StartSniffer(ctx, *ifaceFlag, listenPort, fpStore); err != nil && ctx.Err() == nil {
				serverErrChan <- fmt.Errorf("TCP SYN sniffer failed: %w", err)
			}
		}()
	}

	if *dnsleakFlag {
		dnsCfg, err := buildDNSLeakConfig(*dnsListenFlag, *dnsDomainFlag, *dnsNSFlag)
		if err != nil {
			return fmt.Errorf("invalid DNS leak configuration: %w", err)
		}
		dnsSrv := dnsleak.NewServer(dnsStore, dnsCfg)
		if err := dnsSrv.Start(ctx); err != nil {
			return fmt.Errorf("failed to start DNS leak server on %v: %w", dnsCfg.Addrs, err)
		}
		log.Printf("DNS leak oracle listening on %v (domain %s, ns %v)", dnsCfg.Addrs, dnsCfg.BaseDomain, dnsCfg.NSNames)
		defer func() {
			if err := dnsSrv.Close(); err != nil {
				log.Printf("Warning: Failed to close DNS leak server: %v", err)
			}
		}()

		if *dnsValidateNSFlag {
			valCtx, valCancel := context.WithTimeout(ctx, 10*time.Second)
			err := dnsleak.ValidateNSDelegation(valCtx, dnsCfg.BaseDomain, dnsCfg.NSNames, dnsCfg.EchoIPv4, dnsCfg.EchoIPv6, *dnsResolverFlag)
			valCancel()
			if err != nil {
				return fmt.Errorf("DNS NS delegation validation failed: %w", err)
			}
			log.Printf("DNS NS delegation validated for %s via %s", dnsCfg.BaseDomain, *dnsResolverFlag)
		}
	}

	tlsConfig, err := mcsoak.LoadOrGenerateTLS(*certFlag, *keyFlag)
	if err != nil {
		return fmt.Errorf("failed to load or generate TLS config: %w", err)
	}

	var asnLookup *mcsoak.ASNLookup
	if *asnDBFlag != "" {
		asnLookup, err = mcsoak.OpenASNLookup(*asnDBFlag)
		if err != nil {
			return fmt.Errorf("failed to open ASN database %s: %w", *asnDBFlag, err)
		}
		defer func() {
			if err := asnLookup.Close(); err != nil {
				log.Printf("Warning: Failed to close ASN database: %v", err)
			}
		}()
	}

	srv := mcsoak.NewServer(mcsoak.ServerConfig{
		FPStore:        fpStore,
		DNSStore:       dnsStore,
		ReflectorStats: statsTracker,
		ASNLookup:      asnLookup,
		Token:          *tokenFlag,
	})
	handler := srv.Routes()

	httpServer := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", *listenFlag)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", *listenFlag, err)
	}
	tlsListener := tls.NewListener(ln, tlsConfig)

	go func() {
		log.Printf("HTTPS server listening on %s (TLS)", ln.Addr().String())
		if err := httpServer.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- fmt.Errorf("HTTPS server error: %w", err)
		}
	}()

	var h3Server *http3.Server
	if *quicFlag {
		h3Server = &http3.Server{
			Addr:        *quicListenFlag,
			Handler:     handler,
			TLSConfig:   http3.ConfigureTLSConfig(tlsConfig),
			IdleTimeout: 60 * time.Second,
		}
		go func() {
			log.Printf("HTTP/3 QUIC server listening on %s (UDP)", *quicListenFlag)
			if err := h3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErrChan <- fmt.Errorf("HTTP/3 server error: %w", err)
			}
		}()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	var runErr error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal %s, initiating graceful shutdown...", sig)
	case err := <-serverErrChan:
		log.Printf("Server error, initiating graceful shutdown: %v", err)
		runErr = err
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if h3Server != nil {
		if err := h3Server.Close(); err != nil {
			log.Printf("HTTP/3 shutdown error: %v", err)
		}
	}
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Graceful shutdown error: %v", err)
		_ = httpServer.Close()
	}
	log.Println("Server stopped gracefully")
	return runErr
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("%v", err)
	}
}
