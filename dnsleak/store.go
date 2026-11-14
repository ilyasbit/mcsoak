package dnsleak

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// MaxEntries is the fixed capacity of the circular ring buffer.
	MaxEntries = 32768

	// DefaultTTL is the default retention duration for session entries.
	DefaultTTL = 10 * time.Minute

	maxQueriesPerSession = 64
)

// QueryRecord captures a single observed DNS query for a session.
type QueryRecord struct {
	Subdomain  string     `json:"subdomain"`
	QType      string     `json:"qtype"`
	ResolverIP netip.Addr `json:"resolver_ip"`
	Timestamp  time.Time  `json:"timestamp"`
}

// SessionResult is the lookup and HTTP response payload for a session.
type SessionResult struct {
	SessionID string        `json:"session_id"`
	Found     bool          `json:"found"`
	HitCount  int           `json:"hit_count"`
	CreatedAt time.Time     `json:"created_at,omitempty"`
	ExpiresAt time.Time     `json:"expires_at,omitempty"`
	Queries   []QueryRecord `json:"queries"`
}

type slot struct {
	occupied  bool
	sessionID string
	hitCount  int
	createdAt time.Time
	expiresAt time.Time
	queries   []QueryRecord
}

// Store is a fixed-capacity circular ring buffer with O(1) session index and TTL expiry.
type Store struct {
	mu         sync.RWMutex
	slots      []slot
	index      map[string]int
	head       int
	count      int
	ttl        time.Duration
	baseDomain string
}

// NewStore creates a Store with the given capacity and TTL.
// Values <= 0 default to MaxEntries (32768) and DefaultTTL (10m).
func NewStore(capacity int, ttl time.Duration) *Store {
	if capacity <= 0 {
		capacity = MaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Store{
		slots: make([]slot, capacity),
		index: make(map[string]int, capacity),
		ttl:   ttl,
	}
}

// SetBaseDomain configures the base domain used when generating FQDNs in HandleRegister.
func (s *Store) SetBaseDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseDomain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// Cap returns the fixed ring-buffer capacity.
func (s *Store) Cap() int {
	return len(s.slots)
}

// Len returns the number of currently occupied slots.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// Record stores a DNS query observation for sessionID.
// When the ring buffer is full, the oldest slot is evicted and overwritten in place.
func (s *Store) Record(sessionID string, rec QueryRecord) {
	id := normalizeID(sessionID)
	if id == "" {
		return
	}
	now := rec.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
		rec.Timestamp = now
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if idx, ok := s.index[id]; ok {
		sl := &s.slots[idx]
		if sl.occupied && sl.sessionID == id && !now.After(sl.expiresAt) {
			sl.hitCount++
			sl.expiresAt = now.Add(s.ttl)
			if len(sl.queries) < maxQueriesPerSession {
				sl.queries = append(sl.queries, rec)
			}
			return
		}
		delete(s.index, id)
	}

	idx := s.head
	sl := &s.slots[idx]
	if sl.occupied {
		if existingIdx, ok := s.index[sl.sessionID]; ok && existingIdx == idx {
			delete(s.index, sl.sessionID)
		}
	} else {
		s.count++
	}

	sl.occupied = true
	sl.sessionID = id
	sl.hitCount = 1
	sl.createdAt = now
	sl.expiresAt = now.Add(s.ttl)
	sl.queries = append(sl.queries[:0], rec)

	s.index[id] = idx
	s.head = (s.head + 1) % len(s.slots)
}

// Lookup returns the recorded queries for sessionID if present and not expired at now.
func (s *Store) Lookup(sessionID string, now time.Time) (SessionResult, bool) {
	id := normalizeID(sessionID)
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	idx, ok := s.index[id]
	if !ok {
		return SessionResult{SessionID: id, Found: false, Queries: []QueryRecord{}}, false
	}
	sl := &s.slots[idx]
	if !sl.occupied || sl.sessionID != id || now.After(sl.expiresAt) {
		return SessionResult{SessionID: id, Found: false, Queries: []QueryRecord{}}, false
	}

	queries := make([]QueryRecord, len(sl.queries))
	copy(queries, sl.queries)

	return SessionResult{
		SessionID: id,
		Found:     true,
		HitCount:  sl.hitCount,
		CreatedAt: sl.createdAt,
		ExpiresAt: sl.expiresAt,
		Queries:   queries,
	}, true
}

// PruneExpired removes all entries whose expiry time is before now and returns the count removed.
func (s *Store) PruneExpired(now time.Time) int {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pruned := 0
	for i := range s.slots {
		sl := &s.slots[i]
		if !sl.occupied || !now.After(sl.expiresAt) {
			continue
		}
		if existingIdx, ok := s.index[sl.sessionID]; ok && existingIdx == i {
			delete(s.index, sl.sessionID)
		}
		sl.occupied = false
		sl.sessionID = ""
		sl.hitCount = 0
		sl.createdAt = time.Time{}
		sl.expiresAt = time.Time{}
		sl.queries = sl.queries[:0]
		s.count--
		pruned++
	}
	return pruned
}

type registerResponse struct {
	SessionID string `json:"session_id"`
	FQDN      string `json:"fqdn"`
}

// HandleRegister handles GET /dns, returning a fresh random hex session ID and FQDN.
func (s *Store) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		http.Error(w, "failed to generate session id", http.StatusInternalServerError)
		return
	}
	id := hex.EncodeToString(buf[:])

	s.mu.RLock()
	domain := s.baseDomain
	s.mu.RUnlock()

	fqdn := id
	if domain != "" {
		fqdn = id + "." + domain
	}

	writeJSON(w, http.StatusOK, registerResponse{
		SessionID: id,
		FQDN:      fqdn,
	})
}

// HandleCheck handles GET /dns/check?id=..., returning recorded DNS queries for the session.
func (s *Store) HandleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := normalizeID(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id parameter"})
		return
	}

	res, _ := s.Lookup(id, time.Now().UTC())
	writeJSON(w, http.StatusOK, res)
}

func normalizeID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
