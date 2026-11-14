package dnsleak

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Config configures the UDP/TCP DNS leak oracle server.
type Config struct {
	Addr       string
	BaseDomain string
	EchoIPv4   net.IP
	EchoIPv6   net.IP
	TTL        uint32
}

// Server serves authoritative synthetic DNS responses over UDP and TCP while recording queries in Store.
type Server struct {
	cfg        Config
	baseDomain string
	store      *Store

	mu        sync.Mutex
	udpServer *dns.Server
	tcpServer *dns.Server
	udpAddr   string
	tcpAddr   string
	closed    bool
	wg        sync.WaitGroup
}

// NewServer creates a DNS leak oracle Server backed by store.
func NewServer(store *Store, cfg Config) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":53"
	}
	if cfg.EchoIPv4 == nil {
		cfg.EchoIPv4 = net.ParseIP("127.0.0.1")
	}
	if cfg.EchoIPv6 == nil {
		cfg.EchoIPv6 = net.ParseIP("::1")
	}
	if cfg.TTL == 0 {
		cfg.TTL = 60
	}
	baseDomain := strings.Trim(strings.ToLower(strings.TrimSpace(cfg.BaseDomain)), ".")
	if store != nil && baseDomain != "" {
		store.SetBaseDomain(baseDomain)
	}
	return &Server{
		cfg:        cfg,
		baseDomain: baseDomain,
		store:      store,
	}
}

// Start binds UDP and TCP listeners and begins serving DNS queries until ctx is cancelled or Close is called.
func (s *Server) Start(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", s.cfg.Addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		_ = pc.Close()
		return err
	}

	handler := dns.HandlerFunc(s.handleDNS)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = pc.Close()
		_ = ln.Close()
		return errors.New("dnsleak server already closed")
	}
	s.udpAddr = pc.LocalAddr().String()
	s.tcpAddr = ln.Addr().String()
	s.udpServer = &dns.Server{PacketConn: pc, Handler: handler}
	s.tcpServer = &dns.Server{Listener: ln, Handler: handler}
	s.mu.Unlock()

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		_ = s.udpServer.ActivateAndServe()
	}()
	go func() {
		defer s.wg.Done()
		_ = s.tcpServer.ActivateAndServe()
	}()

	if ctx != nil {
		go func() {
			<-ctx.Done()
			_ = s.Close()
		}()
	}
	return nil
}

// UDPAddr returns the bound UDP address after Start.
func (s *Server) UDPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpAddr
}

// TCPAddr returns the bound TCP address after Start.
func (s *Server) TCPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpAddr
}

// Close gracefully shuts down both UDP and TCP DNS listeners.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	udpSrv := s.udpServer
	tcpSrv := s.tcpServer
	s.mu.Unlock()

	var errs []error
	if udpSrv != nil {
		if err := udpSrv.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	if tcpSrv != nil {
		if err := tcpSrv.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	s.wg.Wait()
	return errors.Join(errs...)
}

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
		case dns.TypeA:
			if v4 := s.cfg.EchoIPv4.To4(); v4 != nil {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    s.cfg.TTL,
					},
					A: v4,
				})
			}
		case dns.TypeAAAA:
			if v6 := s.cfg.EchoIPv6.To16(); v6 != nil {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    s.cfg.TTL,
					},
					AAAA: v6,
				})
			}
		}
	}

	_ = w.WriteMsg(m)
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
