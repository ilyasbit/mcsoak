package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/ilyasbit/mcsoak"
	"github.com/ilyasbit/mcsoak/dnsleak"
	"github.com/ilyasbit/mcsoak/reflector"
	"github.com/ilyasbit/mcsoak/tcpfp"
)

func TestRunSmokeEndToEnd(t *testing.T) {
	const token = "smoke-secret-token"
	const dnsDomain = "dns.smoke.local"

	fpStore := tcpfp.NewStore(64)
	fpStore.Record(tcpfp.Fingerprint{
		TargetIP: "127.0.0.1",
		TTL:      64,
	})

	dnsStore := dnsleak.NewStore(64, time.Minute)
	stats := reflector.NewStatsTracker(16)

	srv := mcsoak.NewServer(mcsoak.ServerConfig{
		FPStore:        fpStore,
		DNSStore:       dnsStore,
		ReflectorStats: stats,
		Token:          token,
	})

	cert, err := mcsoak.GenerateSelfSignedCert("127.0.0.1", "localhost")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	})

	httpSrv := &http.Server{Handler: srv.Routes()}
	go func() { _ = httpSrv.Serve(tlsLn) }()
	defer httpSrv.Close()

	dnsSrv := dnsleak.NewServer(dnsStore, dnsleak.Config{
		Addr:       "127.0.0.1:0",
		BaseDomain: dnsDomain,
	})
	if err := dnsSrv.Start(context.Background()); err != nil {
		t.Fatalf("dnsSrv.Start: %v", err)
	}
	defer dnsSrv.Close()

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket: %v", err)
	}
	defer udpConn.Close()

	go func() {
		buf := make([]byte, 64)
		for {
			n, raddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 4 && bytes.Equal(buf[:4], []byte{'M', 'C', 'P', 0x00}) {
				udpAddr := raddr.(*net.UDPAddr)
				ip4 := udpAddr.IP.To4()
				if ip4 != nil {
					var b4 [4]byte
					copy(b4[:], ip4)
					stats.Record(reflector.PulseEvent{
						SrcAddr:   netip.AddrFrom4(b4),
						Proto:     17,
						IPVersion: 4,
					})
					_, _ = udpConn.WriteTo(ip4, raddr)
				}
			}
		}
	}()

	httpsAddr := ln.Addr().(*net.TCPAddr)
	reflAddr := udpConn.LocalAddr().(*net.UDPAddr)

	cfg := SmokeConfig{
		Host:          "127.0.0.1",
		HTTPSPort:     httpsAddr.Port,
		ReflectorPort: reflAddr.Port,
		DNSDomain:     dnsDomain,
		DNSResolver:   dnsSrv.UDPAddr(),
		Token:         token,
		Timeout:       10 * time.Second,
		SkipQUIC:      true,
	}

	if err := runSmoke(context.Background(), cfg); err != nil {
		t.Fatalf("runSmoke failed: %v", err)
	}
	if got := stats.Snapshot(false).TotalPulses; got < 1 {
		t.Fatalf("reflector TotalPulses = %d, want >= 1", got)
	}
}
