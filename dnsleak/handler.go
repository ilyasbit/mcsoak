package dnsleak

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	resolverIP := extractRemoteIP(w.RemoteAddr())
	now := time.Now().UTC()

	for _, q := range r.Question {
		qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		if s.store != nil {
			if sessionID, ok := extractSessionID(qname, s.baseDomain); ok {
				qtype := dns.TypeToString[q.Qtype]
				if qtype == "" {
					qtype = "UNKNOWN"
				}
				s.store.Record(sessionID, QueryRecord{
					Subdomain:  qname,
					QType:      qtype,
					ResolverIP: resolverIP,
					Timestamp:  now,
				})
			}
		}

		switch q.Qtype {
		case dns.TypeNS:
			if s.baseDomain != "" && qname == s.baseDomain {
				s.appendNSAndGlue(m, q.Name)
			}
		case dns.TypeSOA:
			if s.baseDomain != "" && qname == s.baseDomain {
				m.Answer = append(m.Answer, s.soaRecord(q.Name))
			}
		case dns.TypeA:
			if v4 := validIPv4(s.cfg.EchoIPv4); v4 != nil {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.cfg.TTL},
					A:   v4,
				})
			}
		case dns.TypeAAAA:
			if v6 := validIPv6(s.cfg.EchoIPv6); v6 != nil {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.cfg.TTL},
					AAAA: v6,
				})
			}
		}
	}

	if len(m.Answer) == 0 && s.baseDomain != "" {
		m.Ns = append(m.Ns, s.soaRecord(dns.Fqdn(s.baseDomain)))
	}

	_ = w.WriteMsg(m)
}

func (s *Server) appendNSAndGlue(m *dns.Msg, qname string) {
	v4 := validIPv4(s.cfg.EchoIPv4)
	v6 := validIPv6(s.cfg.EchoIPv6)
	for _, ns := range s.nsNames {
		nsFQDN := dns.Fqdn(ns)
		m.Answer = append(m.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: s.cfg.TTL},
			Ns:  nsFQDN,
		})
		if ns != s.baseDomain && !strings.HasSuffix(ns, "."+s.baseDomain) {
			continue
		}
		if v4 != nil {
			m.Extra = append(m.Extra, &dns.A{
				Hdr: dns.RR_Header{Name: nsFQDN, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.cfg.TTL},
				A:   v4,
			})
		}
		if v6 != nil {
			m.Extra = append(m.Extra, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: nsFQDN, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.cfg.TTL},
				AAAA: v6,
			})
		}
	}
}

func (s *Server) soaRecord(name string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.cfg.TTL},
		Ns:      dns.Fqdn(s.soaMName),
		Mbox:    dns.Fqdn(s.soaRName),
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  s.cfg.TTL,
	}
}

func resolveAddrs(addr string, addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if trimmed := strings.TrimSpace(a); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) > 0 {
		return out
	}
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		trimmed = ":53"
	}
	return []string{trimmed}
}

func normalizeDomain(d string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
}

func normalizeDomains(ds []string) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		if norm := normalizeDomain(d); norm != "" {
			out = append(out, norm)
		}
	}
	return out
}

func validIPv4(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func validIPv6(ip net.IP) net.IP {
	if ip == nil || ip.To4() != nil {
		return nil
	}
	return ip.To16()
}

func extractSessionID(qname, baseDomain string) (string, bool) {
	if qname == "" {
		return "", false
	}
	if baseDomain != "" {
		suffix := "." + baseDomain
		if !strings.HasSuffix(qname, suffix) {
			return "", false
		}
	}
	label, _, _ := strings.Cut(qname, ".")
	if label == "" {
		return "", false
	}
	return label, true
}

func extractRemoteIP(addr net.Addr) netip.Addr {
	if addr == nil {
		return netip.Addr{}
	}
	var ip net.IP
	switch v := addr.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.TCPAddr:
		ip = v.IP
	default:
		ap, err := netip.ParseAddrPort(addr.String())
		if err == nil {
			return ap.Addr().Unmap()
		}
		return netip.Addr{}
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return parsed.Unmap()
}
