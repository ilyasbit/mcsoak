package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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

func main() {
	listenFlag := flag.String("listen", getEnv("SOAK_LISTEN", ":8443"), "HTTPS/H2 listen address")
	quicFlag := flag.Bool("quic", getEnvBool("SOAK_QUIC", true), "Enable HTTP/3 QUIC listener")
	quicListenFlag := flag.String("quic-listen", getEnv("SOAK_QUIC_LISTEN", ":9443"), "HTTP/3 QUIC UDP listen address")
	tokenFlag := flag.String("token", getEnv("SOAK_TOKEN", ""), "Static bearer/query auth token")
	certFlag := flag.String("cert", getEnv("SOAK_CERT", ""), "Path to TLS certificate file")
	keyFlag := flag.String("key", getEnv("SOAK_KEY", ""), "Path to TLS private key file")
	ifaceFlag := flag.String("iface", getEnv("SOAK_IFACE", "eth0"), "Network interface for reflector & tcpfp sniffer")
	reflectorFlag := flag.Bool("reflector", getEnvBool("SOAK_REFLECTOR", false), "Enable eBPF pulse reflector")
	tcpfpSniffFlag := flag.Bool("tcpfp-sniff", getEnvBool("SOAK_TCPFP_SNIFF", false), "Enable in-process AF_PACKET TCP SYN sniffer")
	dnsleakFlag := flag.Bool("dnsleak", getEnvBool("SOAK_DNSLEAK", false), "Enable authoritative DNS leak oracle")
	dnsListenFlag := flag.String("dns-listen", getEnv("SOAK_DNS_LISTEN", ":53"), "DNS leak oracle listen address")
	dnsDomainFlag := flag.String("dns-domain", getEnv("SOAK_DNS_DOMAIN", "sight.muterconn.com"), "Base domain for DNS leak oracle")
	asnDBFlag := flag.String("asn-db", getEnv("SOAK_ASN_DB", ""), "Path to MaxMind .mmdb ASN database")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fpStore := tcpfp.NewStore(0)
	dnsStore := dnsleak.NewStore(0, 0)
	dnsStore.SetBaseDomain(*dnsDomainFlag)
	statsTracker := reflector.NewStatsTracker(64)

	if *reflectorFlag {
		refl, err := reflector.StartWithEvents(*ifaceFlag, statsTracker.Record)
		if err != nil {
			log.Printf("Warning: Failed to start eBPF reflector: %v", err)
		} else {
			defer func() {
				if err := refl.Close(); err != nil {
					log.Printf("Warning: Failed to close eBPF reflector: %v", err)
				}
			}()
		}
	}

	if *tcpfpSniffFlag {
		listenPort := parseListenPort(*listenFlag)
		go func() {
			log.Printf("Starting TCP SYN sniffer on iface=%s port=%d", *ifaceFlag, listenPort)
			if err := tcpfp.StartSniffer(ctx, *ifaceFlag, listenPort, fpStore); err != nil {
				log.Printf("Warning: TCP SYN sniffer stopped: %v", err)
			}
		}()
	}

	var dnsSrv *dnsleak.Server
	if *dnsleakFlag {
		dnsSrv = dnsleak.NewServer(dnsStore, dnsleak.Config{
			Addr:       *dnsListenFlag,
			BaseDomain: *dnsDomainFlag,
		})
		if err := dnsSrv.Start(ctx); err != nil {
			log.Printf("Warning: Failed to start DNS leak server on %s: %v", *dnsListenFlag, err)
		} else {
			log.Printf("DNS leak oracle listening on %s (domain %s)", *dnsListenFlag, *dnsDomainFlag)
			defer func() {
				if err := dnsSrv.Close(); err != nil {
					log.Printf("Warning: Failed to close DNS leak server: %v", err)
				}
			}()
		}
	}

	tlsConfig, err := mcsoak.LoadOrGenerateTLS(*certFlag, *keyFlag)
	if err != nil {
		log.Fatalf("Failed to load or generate TLS config: %v", err)
	}

	var asnLookup *mcsoak.ASNLookup
	if *asnDBFlag != "" {
		var err error
		asnLookup, err = mcsoak.OpenASNLookup(*asnDBFlag)
		if err != nil {
			log.Fatalf("Failed to open ASN database %s: %v", *asnDBFlag, err)
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
		log.Fatalf("Failed to listen on %s: %v", *listenFlag, err)
	}
	tlsListener := tls.NewListener(ln, tlsConfig)

	serverErrChan := make(chan error, 2)
	go func() {
		log.Printf("HTTPS server listening on %s (TLS)", ln.Addr().String())
		if err := httpServer.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	var h3Server *http3.Server
	if *quicFlag {
		h3Server = &http3.Server{
			Addr:      *quicListenFlag,
			Handler:   handler,
			TLSConfig: http3.ConfigureTLSConfig(tlsConfig),
		}
		go func() {
			log.Printf("HTTP/3 QUIC server listening on %s (UDP)", *quicListenFlag)
			if err := h3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErrChan <- err
			}
		}()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Printf("Received signal %s, initiating graceful shutdown...", sig)
	case err := <-serverErrChan:
		log.Fatalf("Server error: %v", err)
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
}
