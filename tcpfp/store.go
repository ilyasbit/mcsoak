package tcpfp

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const defaultMaxEntries = 4096

// Store maintains a thread-safe, bounded cache of recent TCP SYN fingerprints keyed by client IP.
type Store struct {
	mu         sync.RWMutex
	entries    map[string]Fingerprint
	order      []string
	maxEntries int
}

// NewStore creates a Fingerprint Store with the given maximum entry capacity.
// If maxEntries <= 0, a default capacity of 4096 is used.
func NewStore(maxEntries int) *Store {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	return &Store{
		entries:    make(map[string]Fingerprint, maxEntries),
		order:      make([]string, 0, maxEntries),
		maxEntries: maxEntries,
	}
}

// Record stores or updates the latest TCP SYN fingerprint for an IP address.
func (s *Store) Record(fp Fingerprint) {
	if fp.TargetIP == "" {
		return
	}
	if fp.ObservedAt.IsZero() {
		fp.ObservedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[fp.TargetIP]; !exists {
		if len(s.order) >= s.maxEntries {
			evicted := s.order[0]
			s.order = s.order[1:]
			delete(s.entries, evicted)
		}
		s.order = append(s.order, fp.TargetIP)
	}
	s.entries[fp.TargetIP] = fp
}

// RecordPacket parses a raw IPv4/IPv6 TCP SYN packet and records it if valid.
func (s *Store) RecordPacket(ipPacket []byte) (*Fingerprint, error) {
	fp, err := ParseIPSYN(ipPacket)
	if err != nil {
		return nil, err
	}
	s.Record(*fp)
	return fp, nil
}

// Lookup retrieves the most recent Fingerprint for the given IP address.
func (s *Store) Lookup(ip string) (Fingerprint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fp, ok := s.entries[ip]
	return fp, ok
}

// Len returns the number of tracked IP fingerprints.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Handler returns an http.Handler serving GET /check?ip=<clientIP>.
func (s *Store) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		ip := extractQueryIP(r)
		fp, ok := s.Lookup(ip)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":     "fingerprint not found",
				"target_ip": ip,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fp)
	})
	return mux
}

func extractQueryIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.URL.Query().Get("ip")); ip != "" {
		return ip
	}
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
