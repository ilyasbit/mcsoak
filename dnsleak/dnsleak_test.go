package dnsleak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStoreRingBufferWraparound(t *testing.T) {
	const capSize = 16
	st := NewStore(capSize, 10*time.Minute)
	now := time.Unix(1_700_000_000, 0).UTC()

	for i := 0; i < capSize*3; i++ {
		id := fmt.Sprintf("sess-%03d", i)
		st.Record(id, QueryRecord{
			Subdomain:  id + ".sight.muterconn.com",
			QType:      "A",
			ResolverIP: netip.MustParseAddr("192.0.2.1"),
			Timestamp:  now.Add(time.Duration(i) * time.Second),
		})
	}

	if got := st.Len(); got != capSize {
		t.Fatalf("expected Len() == %d, got %d", capSize, got)
	}

	for i := 0; i < capSize*2; i++ {
		id := fmt.Sprintf("sess-%03d", i)
		if _, ok := st.Lookup(id, now); ok {
			t.Fatalf("expected evicted session %s to be absent", id)
		}
	}

	for i := capSize * 2; i < capSize*3; i++ {
		id := fmt.Sprintf("sess-%03d", i)
		res, ok := st.Lookup(id, now)
		if !ok || !res.Found || len(res.Queries) != 1 {
			t.Fatalf("expected recent session %s to be present, got ok=%v res=%+v", id, ok, res)
		}
	}
}

func TestStoreDefaultCapacityAndZeroHeapGrowth(t *testing.T) {
	st := NewStore(0, 0)
	if st.Cap() != MaxEntries {
		t.Fatalf("expected default capacity %d, got %d", MaxEntries, st.Cap())
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	ip := netip.MustParseAddr("198.51.100.2")
	for i := 0; i < MaxEntries+1024; i++ {
		st.Record(fmt.Sprintf("s-%d", i), QueryRecord{
			Subdomain:  "sub.example.com",
			QType:      "A",
			ResolverIP: ip,
			Timestamp:  now,
		})
	}
	if st.Len() != MaxEntries {
		t.Fatalf("expected Len() capped at %d, got %d", MaxEntries, st.Len())
	}
}

func TestStoreTTLExpiryAndPrune(t *testing.T) {
	st := NewStore(16, 5*time.Minute)
	t0 := time.Unix(1_700_000_000, 0).UTC()

	st.Record("alpha", QueryRecord{Subdomain: "alpha.test", QType: "A", Timestamp: t0})
	st.Record("beta", QueryRecord{Subdomain: "beta.test", QType: "AAAA", Timestamp: t0.Add(3 * time.Minute)})

	if _, ok := st.Lookup("alpha", t0.Add(4*time.Minute)); !ok {
		t.Fatal("expected alpha to be valid before TTL")
	}
	if _, ok := st.Lookup("alpha", t0.Add(6*time.Minute)); ok {
		t.Fatal("expected alpha to be expired after TTL")
	}

	pruned := st.PruneExpired(t0.Add(6 * time.Minute))
	if pruned != 1 {
		t.Fatalf("expected 1 pruned entry, got %d", pruned)
	}
	if st.Len() != 1 {
		t.Fatalf("expected Len() == 1 after prune, got %d", st.Len())
	}
	if _, ok := st.Lookup("beta", t0.Add(6*time.Minute)); !ok {
		t.Fatal("expected beta to remain valid")
	}
}

func TestServerUDPAndTCPAndHTTPHandlers(t *testing.T) {
	st := NewStore(64, 10*time.Minute)
	srv := NewServer(st, Config{
		Addr:       "127.0.0.1:0",
		BaseDomain: "sight.muterconn.com",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = srv.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/dns", st.HandleRegister)
	mux.HandleFunc("/dns/check", st.HandleCheck)

	badReq := httptest.NewRequest(http.MethodGet, "/dns/check", nil)
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing id, got %d", badRec.Code)
	}

	regReq := httptest.NewRequest(http.MethodGet, "/dns", nil)
	regRec := httptest.NewRecorder()
	mux.ServeHTTP(regRec, regReq)
	if regRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /dns, got %d", regRec.Code)
	}
	var regPayload struct {
		SessionID string `json:"session_id"`
		FQDN      string `json:"fqdn"`
	}
	if err := json.NewDecoder(regRec.Body).Decode(&regPayload); err != nil {
		t.Fatalf("decode /dns failed: %v", err)
	}
	if regPayload.SessionID == "" || regPayload.FQDN != regPayload.SessionID+".sight.muterconn.com" {
		t.Fatalf("unexpected /dns payload: %+v", regPayload)
	}

	udpClient := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	msgA := new(dns.Msg)
	msgA.SetQuestion(dns.Fqdn(regPayload.FQDN), dns.TypeA)
	respA, _, err := udpClient.Exchange(msgA, srv.UDPAddr())
	if err != nil {
		t.Fatalf("UDP DNS exchange failed: %v", err)
	}
	if respA.Rcode != dns.RcodeSuccess || len(respA.Answer) != 1 {
		t.Fatalf("unexpected UDP A response: %+v", respA)
	}

	tcpClient := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(dns.Fqdn(regPayload.FQDN), dns.TypeAAAA)
	respAAAA, _, err := tcpClient.Exchange(msgAAAA, srv.TCPAddr())
	if err != nil {
		t.Fatalf("TCP DNS exchange failed: %v", err)
	}
	if respAAAA.Rcode != dns.RcodeSuccess || len(respAAAA.Answer) != 1 {
		t.Fatalf("unexpected TCP AAAA response: %+v", respAAAA)
	}

	chkReq := httptest.NewRequest(http.MethodGet, "/dns/check?id="+regPayload.SessionID, nil)
	chkRec := httptest.NewRecorder()
	mux.ServeHTTP(chkRec, chkReq)
	if chkRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /dns/check, got %d", chkRec.Code)
	}
	var chkPayload SessionResult
	if err := json.NewDecoder(chkRec.Body).Decode(&chkPayload); err != nil {
		t.Fatalf("decode /dns/check failed: %v", err)
	}
	if !chkPayload.Found || chkPayload.HitCount != 2 || len(chkPayload.Queries) != 2 {
		t.Fatalf("unexpected /dns/check payload: %+v", chkPayload)
	}
	if chkPayload.Queries[0].QType != "A" || chkPayload.Queries[1].QType != "AAAA" {
		t.Fatalf("unexpected query types: %+v", chkPayload.Queries)
	}
	if !chkPayload.Queries[0].ResolverIP.IsLoopback() {
		t.Fatalf("expected loopback resolver IP, got %v", chkPayload.Queries[0].ResolverIP)
	}
}

func TestStoreConcurrentRace(t *testing.T) {
	st := NewStore(128, 10*time.Minute)
	var wg sync.WaitGroup
	now := time.Now().UTC()
	ip := netip.MustParseAddr("127.0.0.1")

	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := fmt.Sprintf("w%d-s%d", worker, i%40)
				st.Record(id, QueryRecord{
					Subdomain:  id + ".sight.muterconn.com",
					QType:      "A",
					ResolverIP: ip,
					Timestamp:  now,
				})
				_, _ = st.Lookup(id, now)
				if i%50 == 0 {
					_ = st.PruneExpired(now)
				}
			}
		}(g)
	}
	wg.Wait()
}
