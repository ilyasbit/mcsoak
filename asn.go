package mcsoak

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/oschwald/maxminddb-golang"
)

// ASNInfo holds the Autonomous System Number and organization name for an IP.
type ASNInfo struct {
	ASN uint32 `maxminddb:"autonomous_system_number" json:"asn,omitempty"`
	ISP string `maxminddb:"autonomous_system_organization" json:"isp,omitempty"`
}

// ASNLookup provides stateless, concurrent-safe read-only .mmdb ASN/ISP lookups.
type ASNLookup struct {
	reader *maxminddb.Reader
}

// OpenASNLookup opens a MaxMind DB (.mmdb) file for ASN/ISP lookups.
func OpenASNLookup(path string) (*ASNLookup, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mmdb %q: %w", path, err)
	}
	return &ASNLookup{reader: reader}, nil
}

// Lookup returns the ASNInfo for the given IP address.
// Safe to call on a nil *ASNLookup receiver (returns ASNInfo{}, false).
func (a *ASNLookup) Lookup(ip netip.Addr) (ASNInfo, bool) {
	if a == nil || a.reader == nil || !ip.IsValid() {
		return ASNInfo{}, false
	}
	var info ASNInfo
	if err := a.reader.Lookup(net.IP(ip.AsSlice()), &info); err != nil {
		return ASNInfo{}, false
	}
	if info.ASN == 0 && info.ISP == "" {
		return ASNInfo{}, false
	}
	return info, true
}

// Close closes the underlying MaxMind DB reader.
func (a *ASNLookup) Close() error {
	if a == nil || a.reader == nil {
		return nil
	}
	return a.reader.Close()
}
