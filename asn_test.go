package mcsoak

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
)

func mmdbEncodeString(s string) []byte {
	n := len(s)
	var out []byte
	if n < 29 {
		out = append(out, byte((2<<5)|n))
	} else {
		out = append(out, byte((2<<5)|29), byte(n-29))
	}
	return append(out, s...)
}

func mmdbEncodeUint32(v uint32) []byte {
	if v == 0 {
		return []byte{6 << 5}
	}
	var buf [4]byte
	buf[0] = byte(v >> 24)
	buf[1] = byte(v >> 16)
	buf[2] = byte(v >> 8)
	buf[3] = byte(v)
	i := 0
	for i < 4 && buf[i] == 0 {
		i++
	}
	size := 4 - i
	out := []byte{byte((6 << 5) | size)}
	return append(out, buf[i:]...)
}

func buildTestASNMMDB(t *testing.T, asn uint32, isp string) string {
	t.Helper()
	var data []byte
	// 1-node tree (6 bytes for 24-bit records); record 17 => data offset 0.
	data = append(data, 0, 0, 17, 0, 0, 17)
	// 16-byte data section separator
	data = append(data, make([]byte, 16)...)
	// Data record at offset 0: map with 2 entries
	data = append(data, byte((7<<5)|2))
	data = append(data, mmdbEncodeString("autonomous_system_number")...)
	data = append(data, mmdbEncodeUint32(asn)...)
	data = append(data, mmdbEncodeString("autonomous_system_organization")...)
	data = append(data, mmdbEncodeString(isp)...)

	// Metadata marker + map (6 entries)
	data = append(data, []byte("\xab\xcd\xefMaxMind.com")...)
	data = append(data, byte((7<<5)|6))
	data = append(data, mmdbEncodeString("node_count")...)
	data = append(data, mmdbEncodeUint32(1)...)
	data = append(data, mmdbEncodeString("record_size")...)
	data = append(data, mmdbEncodeUint32(24)...)
	data = append(data, mmdbEncodeString("ip_version")...)
	data = append(data, mmdbEncodeUint32(4)...)
	data = append(data, mmdbEncodeString("database_type")...)
	data = append(data, mmdbEncodeString("GeoLite2-ASN")...)
	data = append(data, mmdbEncodeString("binary_format_major_version")...)
	data = append(data, mmdbEncodeUint32(2)...)
	data = append(data, mmdbEncodeString("binary_format_minor_version")...)
	data = append(data, mmdbEncodeUint32(0)...)

	path := t.TempDir() + "/test_asn.mmdb"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test mmdb: %v", err)
	}
	return path
}

func TestASNLookupAndHandlers(t *testing.T) {
	var nilLookup *ASNLookup
	if _, ok := nilLookup.Lookup(netip.MustParseAddr("1.1.1.1")); ok {
		t.Fatal("expected nil ASNLookup.Lookup to return false")
	}
	if err := nilLookup.Close(); err != nil {
		t.Fatalf("expected nil ASNLookup.Close to return nil, got %v", err)
	}

	if _, err := OpenASNLookup("/nonexistent/path/missing.mmdb"); err == nil {
		t.Fatal("expected error for missing mmdb path")
	}

	mmdbPath := buildTestASNMMDB(t, 13335, "Cloudflare, Inc.")
	lookup, err := OpenASNLookup(mmdbPath)
	if err != nil {
		t.Fatalf("OpenASNLookup failed: %v", err)
	}
	defer lookup.Close()

	info, ok := lookup.Lookup(netip.MustParseAddr("1.1.1.1"))
	if !ok {
		t.Fatal("expected ASN lookup match for 1.1.1.1")
	}
	if info.ASN != 13335 || info.ISP != "Cloudflare, Inc." {
		t.Fatalf("unexpected ASNInfo: %+v", info)
	}

	srv := NewServer(ServerConfig{
		ASNLookup: lookup,
	})
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	echoResp, err := http.Get(ts.URL + "/echo")
	if err != nil {
		t.Fatalf("GET /echo failed: %v", err)
	}
	defer echoResp.Body.Close()
	if echoResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /echo, got %d", echoResp.StatusCode)
	}
	var echo EchoResponse
	if err := json.NewDecoder(echoResp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode /echo failed: %v", err)
	}
	if echo.ASN != 13335 || echo.ISP != "Cloudflare, Inc." {
		t.Fatalf("expected ASN=13335 ISP='Cloudflare, Inc.' in /echo, got asn=%d isp=%q", echo.ASN, echo.ISP)
	}

	asnResp, err := http.Get(ts.URL + "/asn?ip=1.1.1.1")
	if err != nil {
		t.Fatalf("GET /asn failed: %v", err)
	}
	defer asnResp.Body.Close()
	if asnResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /asn, got %d", asnResp.StatusCode)
	}
	var asnBody struct {
		IP  string `json:"ip"`
		ASN uint32 `json:"asn"`
		ISP string `json:"isp"`
	}
	if err := json.NewDecoder(asnResp.Body).Decode(&asnBody); err != nil {
		t.Fatalf("decode /asn failed: %v", err)
	}
	if asnBody.IP != "1.1.1.1" || asnBody.ASN != 13335 || asnBody.ISP != "Cloudflare, Inc." {
		t.Fatalf("unexpected /asn response: %+v", asnBody)
	}

	badResp, err := http.Get(ts.URL + "/asn?ip=not-an-ip")
	if err != nil {
		t.Fatalf("GET /asn invalid ip failed: %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid ip, got %d", badResp.StatusCode)
	}
}
