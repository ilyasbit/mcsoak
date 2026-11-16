package main

import (
	"net"
	"testing"

	"github.com/ilyasbit/mcsoak/dnsleak"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestHelpersSmoke(t *testing.T) {
	t.Setenv("MCSOAK_TEST_STR", "hello")
	if got := getEnv("MCSOAK_TEST_STR", "default"); got != "hello" {
		t.Fatalf("getEnv = %q, want %q", got, "hello")
	}
	if got := getEnv("MCSOAK_TEST_UNSET", "default"); got != "default" {
		t.Fatalf("getEnv unset = %q, want %q", got, "default")
	}

	t.Setenv("MCSOAK_TEST_BOOL", "true")
	if !getEnvBool("MCSOAK_TEST_BOOL", false) {
		t.Fatalf("getEnvBool(true) = false, want true")
	}
	if getEnvBool("MCSOAK_TEST_BOOL_UNSET", false) {
		t.Fatalf("getEnvBool(unset) = true, want false")
	}

	if got := parseListenPort(":8443"); got != 8443 {
		t.Fatalf("parseListenPort(:8443) = %d, want 8443", got)
	}
	if got := parseListenPort("invalid"); got != 0 {
		t.Fatalf("parseListenPort(invalid) = %d, want 0", got)
	}
}

func TestMCSOAKEnvLoading(t *testing.T) {
	t.Setenv("MCSOAK_LISTEN", ":9444")
	t.Setenv("MCSOAK_QUIC", "false")
	t.Setenv("MCSOAK_QUIC_LISTEN", ":9445")
	t.Setenv("MCSOAK_TOKEN", "secret-token")
	t.Setenv("MCSOAK_CERT", "/tmp/cert.pem")
	t.Setenv("MCSOAK_KEY", "/tmp/key.pem")
	t.Setenv("MCSOAK_IFACE", "ens3")
	t.Setenv("MCSOAK_REFLECTOR", "true")
	t.Setenv("MCSOAK_TCPFP_SNIFF", "1")
	t.Setenv("MCSOAK_DNSLEAK", "yes")
	t.Setenv("MCSOAK_DNS_LISTEN", ":5353")
	t.Setenv("MCSOAK_DNS_DOMAIN", "leak.example.com")
	t.Setenv("MCSOAK_DNS_NS", "ns1.leak.example.com,ns2.leak.example.com")
	t.Setenv("MCSOAK_DNS_VALIDATE_NS", "true")
	t.Setenv("MCSOAK_DNS_RESOLVER", "8.8.8.8:53")
	t.Setenv("MCSOAK_ASN_DB", "/tmp/asn.mmdb")

	if got := getEnv("MCSOAK_LISTEN", ":8443"); got != ":9444" {
		t.Fatalf("MCSOAK_LISTEN = %q, want :9444", got)
	}
	if got := getEnvBool("MCSOAK_QUIC", true); got {
		t.Fatalf("MCSOAK_QUIC = true, want false")
	}
	if got := getEnv("MCSOAK_QUIC_LISTEN", ":9443"); got != ":9445" {
		t.Fatalf("MCSOAK_QUIC_LISTEN = %q, want :9445", got)
	}
	if got := getEnv("MCSOAK_TOKEN", ""); got != "secret-token" {
		t.Fatalf("MCSOAK_TOKEN = %q, want secret-token", got)
	}
	if got := getEnv("MCSOAK_CERT", ""); got != "/tmp/cert.pem" {
		t.Fatalf("MCSOAK_CERT = %q, want /tmp/cert.pem", got)
	}
	if got := getEnv("MCSOAK_KEY", ""); got != "/tmp/key.pem" {
		t.Fatalf("MCSOAK_KEY = %q, want /tmp/key.pem", got)
	}
	if got := getEnv("MCSOAK_IFACE", "eth0"); got != "ens3" {
		t.Fatalf("MCSOAK_IFACE = %q, want ens3", got)
	}
	if !getEnvBool("MCSOAK_REFLECTOR", false) {
		t.Fatalf("MCSOAK_REFLECTOR = false, want true")
	}
	if !getEnvBool("MCSOAK_TCPFP_SNIFF", false) {
		t.Fatalf("MCSOAK_TCPFP_SNIFF = false, want true")
	}
	if !getEnvBool("MCSOAK_DNSLEAK", false) {
		t.Fatalf("MCSOAK_DNSLEAK = false, want true")
	}
	if got := getEnv("MCSOAK_DNS_LISTEN", ""); got != ":5353" {
		t.Fatalf("MCSOAK_DNS_LISTEN = %q, want :5353", got)
	}
	if got := getEnv("MCSOAK_DNS_DOMAIN", "dns.muterconn.com"); got != "leak.example.com" {
		t.Fatalf("MCSOAK_DNS_DOMAIN = %q, want leak.example.com", got)
	}
	if got := getEnv("MCSOAK_DNS_NS", "ns1.dns.muterconn.com,ns2.dns.muterconn.com"); got != "ns1.leak.example.com,ns2.leak.example.com" {
		t.Fatalf("MCSOAK_DNS_NS = %q, want ns1.leak.example.com,ns2.leak.example.com", got)
	}
	if !getEnvBool("MCSOAK_DNS_VALIDATE_NS", false) {
		t.Fatalf("MCSOAK_DNS_VALIDATE_NS = false, want true")
	}
	if got := getEnv("MCSOAK_DNS_RESOLVER", "1.1.1.1:53"); got != "8.8.8.8:53" {
		t.Fatalf("MCSOAK_DNS_RESOLVER = %q, want 8.8.8.8:53", got)
	}
	if got := getEnv("MCSOAK_ASN_DB", ""); got != "/tmp/asn.mmdb" {
		t.Fatalf("MCSOAK_ASN_DB = %q, want /tmp/asn.mmdb", got)
	}
}

func TestBuildDNSLeakConfig(t *testing.T) {
	t.Run("auto_bind_public_ips_sets_port_53_addrs", func(t *testing.T) {
		t.Setenv("MCSOAK_PUBLIC_IPV4", "203.0.113.10")
		t.Setenv("MCSOAK_PUBLIC_IPV6", "2001:db8::10")
		cfg, err := buildDNSLeakConfig("", "dns.muterconn.com", "ns1.dns.muterconn.com, ns2.dns.muterconn.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.Addrs) != 2 || cfg.Addrs[0] != "203.0.113.10:53" || cfg.Addrs[1] != "[2001:db8::10]:53" {
			t.Fatalf("Addrs = %v, want [203.0.113.10:53 [2001:db8::10]:53]", cfg.Addrs)
		}
		if len(cfg.NSNames) != 2 || cfg.NSNames[0] != "ns1.dns.muterconn.com" || cfg.NSNames[1] != "ns2.dns.muterconn.com" {
			t.Fatalf("NSNames = %v, want [ns1.dns.muterconn.com ns2.dns.muterconn.com]", cfg.NSNames)
		}
		if !cfg.EchoIPv4.Equal(net.ParseIP("203.0.113.10")) {
			t.Fatalf("EchoIPv4 = %v, want 203.0.113.10", cfg.EchoIPv4)
		}
		if !cfg.EchoIPv6.Equal(net.ParseIP("2001:db8::10")) {
			t.Fatalf("EchoIPv6 = %v, want 2001:db8::10", cfg.EchoIPv6)
		}
		srv := dnsleak.NewServer(nil, cfg)
		if srv == nil {
			t.Fatal("expected non-nil dnsleak.Server")
		}
	})

	t.Run("auto_bind_rejects_empty_or_loopback_or_unspecified", func(t *testing.T) {
		cases := []struct {
			name string
			v4   string
			v6   string
		}{
			{"both_empty", "", ""},
			{"loopback_only", "127.0.0.1", "::1"},
			{"unspecified_only", "0.0.0.0", "::"},
			{"invalid_only", "not-an-ip", "also-bad"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Setenv("MCSOAK_PUBLIC_IPV4", tc.v4)
				t.Setenv("MCSOAK_PUBLIC_IPV6", tc.v6)
				if _, err := buildDNSLeakConfig("", "dns.muterconn.com", "ns1.dns.muterconn.com"); err == nil {
					t.Fatalf("expected error for %s, got nil", tc.name)
				}
			})
		}
	})

	t.Run("explicit_dns_listen_override", func(t *testing.T) {
		t.Setenv("MCSOAK_PUBLIC_IPV4", "")
		t.Setenv("MCSOAK_PUBLIC_IPV6", "")
		cfg, err := buildDNSLeakConfig("127.0.0.1:5353, [::1]:5353", "dns.muterconn.com", "ns1.dns.muterconn.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.Addrs) != 2 || cfg.Addrs[0] != "127.0.0.1:5353" || cfg.Addrs[1] != "[::1]:5353" {
			t.Fatalf("Addrs = %v, want [127.0.0.1:5353 [::1]:5353]", cfg.Addrs)
		}
		if cfg.EchoIPv4 != nil || cfg.EchoIPv6 != nil {
			t.Fatalf("expected nil EchoIPv4/EchoIPv6 when unset, got v4=%v v6=%v", cfg.EchoIPv4, cfg.EchoIPv6)
		}
	})

	t.Run("rejects_empty_domain_or_ns", func(t *testing.T) {
		t.Setenv("MCSOAK_PUBLIC_IPV4", "203.0.113.10")
		if _, err := buildDNSLeakConfig("", "  ", "ns1.dns.muterconn.com"); err == nil {
			t.Fatal("expected error for empty domain")
		}
		if _, err := buildDNSLeakConfig("", "dns.muterconn.com", " , "); err == nil {
			t.Fatal("expected error for empty NS list")
		}
	})

	t.Run("invalid_or_mismatched_family_ignored_with_explicit_listen", func(t *testing.T) {
		t.Setenv("MCSOAK_PUBLIC_IPV4", "2001:db8::1")
		t.Setenv("MCSOAK_PUBLIC_IPV6", "192.0.2.1")
		cfg, err := buildDNSLeakConfig(":5353", "dns.muterconn.com", "ns1.dns.muterconn.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.EchoIPv4 != nil || cfg.EchoIPv6 != nil {
			t.Fatalf("expected nil for mismatched families, got v4=%v v6=%v", cfg.EchoIPv4, cfg.EchoIPv6)
		}
	})
}

func TestInitDNSStoreGated(t *testing.T) {
	if store := initDNSStore(false, "dns.muterconn.com"); store != nil {
		t.Fatalf("expected nil dnsStore when -dnsleak=false, got %v", store)
	}
	if store := initDNSStore(true, "dns.muterconn.com"); store == nil {
		t.Fatal("expected non-nil dnsStore when -dnsleak=true")
	}
}
