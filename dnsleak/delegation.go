package dnsleak

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// ValidateNSDelegation verifies via resolverAddr that baseDomain delegates to expectedNS
// and that each nameserver resolves to expectedV4 (if non-nil) and expectedV6 (if non-nil).
func ValidateNSDelegation(ctx context.Context, baseDomain string, expectedNS []string, expectedV4, expectedV6 net.IP, resolverAddr string) error {
	domain := normalizeDomain(baseDomain)
	if domain == "" {
		return errors.New("baseDomain must not be empty")
	}
	if resolverAddr == "" {
		return errors.New("resolverAddr must not be empty")
	}
	normExpected := normalizeDomains(expectedNS)
	if len(normExpected) == 0 {
		return errors.New("expectedNS must not be empty")
	}

	var v4 net.IP
	if expectedV4 != nil {
		v4 = validIPv4(expectedV4)
		if v4 == nil {
			return fmt.Errorf("invalid expectedV4: %v", expectedV4)
		}
	}
	var v6 net.IP
	if expectedV6 != nil {
		v6 = validIPv6(expectedV6)
		if v6 == nil {
			return fmt.Errorf("invalid expectedV6: %v", expectedV6)
		}
	}

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	nsResp, err := exchangeDNS(ctx, client, resolverAddr, domain, dns.TypeNS)
	if err != nil {
		return fmt.Errorf("query NS for %s: %w", domain, err)
	}

	expectedSet := make(map[string]struct{}, len(normExpected))
	for _, ns := range normExpected {
		expectedSet[ns] = struct{}{}
	}
	gotSet := make(map[string]struct{}, len(nsResp.Answer))
	for _, rr := range nsResp.Answer {
		if nsRR, ok := rr.(*dns.NS); ok {
			gotSet[normalizeDomain(nsRR.Ns)] = struct{}{}
		}
	}
	if len(gotSet) != len(expectedSet) {
		return fmt.Errorf("NS mismatch for %s: got %d records, want %d", domain, len(gotSet), len(expectedSet))
	}
	for ns := range expectedSet {
		if _, ok := gotSet[ns]; !ok {
			return fmt.Errorf("missing expected NS %s for %s", ns, domain)
		}
	}

	for _, ns := range normExpected {
		if v4 != nil {
			if err := verifyNSIP(ctx, client, resolverAddr, ns, dns.TypeA, v4); err != nil {
				return err
			}
		}
		if v6 != nil {
			if err := verifyNSIP(ctx, client, resolverAddr, ns, dns.TypeAAAA, v6); err != nil {
				return err
			}
		}
	}
	return nil
}

func exchangeDNS(ctx context.Context, client *dns.Client, resolverAddr, name string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	resp, _, err := client.ExchangeContext(ctx, msg, resolverAddr)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns rcode %s", dns.RcodeToString[resp.Rcode])
	}
	return resp, nil
}

func verifyNSIP(ctx context.Context, client *dns.Client, resolverAddr, ns string, qtype uint16, expected net.IP) error {
	resp, err := exchangeDNS(ctx, client, resolverAddr, ns, qtype)
	if err != nil {
		return fmt.Errorf("query %s for %s: %w", dns.TypeToString[qtype], ns, err)
	}
	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if r.A.Equal(expected) {
				return nil
			}
		case *dns.AAAA:
			if r.AAAA.Equal(expected) {
				return nil
			}
		}
	}
	return fmt.Errorf("NS %s %s record did not match expected %s", ns, dns.TypeToString[qtype], expected)
}
