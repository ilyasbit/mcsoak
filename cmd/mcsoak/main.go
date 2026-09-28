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
	"syscall"
	"time"

	"github.com/ilyasbit/mcsoak"
)

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
}

func main() {
	portFlag := flag.String("port", getEnv("SOAK_PORT", "9443"), "Port to listen on")
	certFlag := flag.String("cert", getEnv("SOAK_CERT", ""), "Path to TLS certificate file")
	keyFlag := flag.String("key", getEnv("SOAK_KEY", ""), "Path to TLS private key file")
	tcpFpFlag := flag.String("tcp-fp", getEnv("TCP_FP_URL", "http://127.0.0.1:7778"), "TCP fingerprint daemon URL")
	flag.Parse()

	tlsConfig, err := mcsoak.LoadOrGenerateTLS(*certFlag, *keyFlag)
	if err != nil {
		log.Fatalf("Failed to load or generate TLS config: %v", err)
	}

	srv := mcsoak.NewServer(*tcpFpFlag)
	httpServer := &http.Server{
		Handler:      srv.Routes(),
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	addr := "[::]:" + *portFlag
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Failed to listen on %s, falling back to :%s: %v", addr, *portFlag, err)
		ln, err = net.Listen("tcp", ":"+*portFlag)
		if err != nil {
			log.Fatalf("Failed to listen on :%s: %v", *portFlag, err)
		}
	}

	tlsListener := tls.NewListener(ln, tlsConfig)

	serverErrChan := make(chan error, 1)
	go func() {
		log.Printf("Server listening on %s (TLS)", ln.Addr().String())
		if err := httpServer.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Printf("Received signal %s, initiating graceful shutdown...", sig)
	case err := <-serverErrChan:
		log.Fatalf("Server error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Graceful shutdown error: %v", err)
		_ = httpServer.Close()
	}
	log.Println("Server stopped gracefully")
}
