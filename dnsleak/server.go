package dnsleak

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/miekg/dns"
)

// Config configures the UDP/TCP DNS leak oracle server.
type Config struct {
	Addr       string
	Addrs      []string
	BaseDomain string
	NSNames    []string
	SOAMName   string
	SOARName   string
	EchoIPv4   net.IP
	EchoIPv6   net.IP
	TTL        uint32
}

// Server serves authoritative synthetic DNS responses over UDP and TCP while recording queries in Store.
type Server struct {
	cfg        Config
	addrs      []string
	baseDomain string
	nsNames    []string
	soaMName   string
	soaRName   string
	store      *Store

	mu         sync.Mutex
	udpServers []*dns.Server
	tcpServers []*dns.Server
	udpAddrs   []string
	tcpAddrs   []string
	done       chan struct{}
	closed     bool
	wg         sync.WaitGroup
}

// NewServer creates a DNS leak oracle Server backed by store.
func NewServer(store *Store, cfg Config) *Server {
	addrs := resolveAddrs(cfg.Addr, cfg.Addrs)
	if cfg.EchoIPv4 == nil {
		cfg.EchoIPv4 = net.ParseIP("127.0.0.1")
	} else {
		cfg.EchoIPv4 = validIPv4(cfg.EchoIPv4)
	}
	if cfg.EchoIPv6 == nil {
		cfg.EchoIPv6 = net.ParseIP("::1")
	} else {
		cfg.EchoIPv6 = validIPv6(cfg.EchoIPv6)
	}
	if cfg.TTL == 0 {
		cfg.TTL = 60
	}

	baseDomain := normalizeDomain(cfg.BaseDomain)
	if store != nil && baseDomain != "" {
		store.SetBaseDomain(baseDomain)
	}

	nsNames := normalizeDomains(cfg.NSNames)
	if len(nsNames) == 0 && baseDomain != "" {
		nsNames = []string{"ns1." + baseDomain, "ns2." + baseDomain}
	}

	soaMName := normalizeDomain(cfg.SOAMName)
	if soaMName == "" && len(nsNames) > 0 {
		soaMName = nsNames[0]
	}
	soaRName := normalizeDomain(cfg.SOARName)
	if soaRName == "" && baseDomain != "" {
		soaRName = "hostmaster." + baseDomain
	}

	return &Server{
		cfg:        cfg,
		addrs:      addrs,
		baseDomain: baseDomain,
		nsNames:    nsNames,
		soaMName:   soaMName,
		soaRName:   soaRName,
		store:      store,
		done:       make(chan struct{}),
	}
}

// Start binds UDP and TCP listeners and begins serving DNS queries until ctx is cancelled or Close is called.
func (s *Server) Start(ctx context.Context) error {
	pcs := make([]net.PacketConn, 0, len(s.addrs))
	lns := make([]net.Listener, 0, len(s.addrs))
	rollback := func() {
		for _, pc := range pcs {
			_ = pc.Close()
		}
		for _, ln := range lns {
			_ = ln.Close()
		}
	}

	for _, addr := range s.addrs {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			rollback()
			return err
		}
		pcs = append(pcs, pc)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			rollback()
			return err
		}
		lns = append(lns, ln)
	}

	handler := dns.HandlerFunc(s.handleDNS)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		rollback()
		return errors.New("dnsleak server already closed")
	}
	s.udpServers = make([]*dns.Server, 0, len(pcs))
	s.tcpServers = make([]*dns.Server, 0, len(lns))
	s.udpAddrs = make([]string, 0, len(pcs))
	s.tcpAddrs = make([]string, 0, len(lns))
	for i := range pcs {
		s.udpAddrs = append(s.udpAddrs, pcs[i].LocalAddr().String())
		s.tcpAddrs = append(s.tcpAddrs, lns[i].Addr().String())
		s.udpServers = append(s.udpServers, &dns.Server{PacketConn: pcs[i], Handler: handler})
		s.tcpServers = append(s.tcpServers, &dns.Server{Listener: lns[i], Handler: handler})
	}
	udpSrvs := append([]*dns.Server(nil), s.udpServers...)
	tcpSrvs := append([]*dns.Server(nil), s.tcpServers...)
	s.mu.Unlock()

	s.wg.Add(len(udpSrvs) + len(tcpSrvs))
	for _, srv := range udpSrvs {
		go func(ds *dns.Server) {
			defer s.wg.Done()
			_ = ds.ActivateAndServe()
		}(srv)
	}
	for _, srv := range tcpSrvs {
		go func(ds *dns.Server) {
			defer s.wg.Done()
			_ = ds.ActivateAndServe()
		}(srv)
	}

	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = s.Close()
			case <-s.done:
			}
		}()
	}
	return nil
}

// UDPAddr returns the first bound UDP address after Start.
func (s *Server) UDPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.udpAddrs) == 0 {
		return ""
	}
	return s.udpAddrs[0]
}

// TCPAddr returns the first bound TCP address after Start.
func (s *Server) TCPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tcpAddrs) == 0 {
		return ""
	}
	return s.tcpAddrs[0]
}

// UDPAddrs returns all bound UDP addresses after Start.
func (s *Server) UDPAddrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.udpAddrs...)
}

// TCPAddrs returns all bound TCP addresses after Start.
func (s *Server) TCPAddrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tcpAddrs...)
}

// Close gracefully shuts down both UDP and TCP DNS listeners.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.done != nil {
		close(s.done)
	}
	udpSrvs := s.udpServers
	tcpSrvs := s.tcpServers
	s.mu.Unlock()

	var errs []error
	for _, srv := range udpSrvs {
		if srv != nil {
			if err := srv.Shutdown(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, srv := range tcpSrvs {
		if srv != nil {
			if err := srv.Shutdown(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	s.wg.Wait()
	return errors.Join(errs...)
}
