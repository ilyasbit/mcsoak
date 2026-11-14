package mcsoak

import (
	"bytes"
	"compress/gzip"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ilyasbit/mcsoak/dnsleak"
	"github.com/ilyasbit/mcsoak/reflector"
	"github.com/ilyasbit/mcsoak/tcpfp"
)

type TLSInfo struct {
	Version            string `json:"version,omitempty"`
	CipherSuite        string `json:"cipher_suite,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
	NegotiatedProtocol string `json:"negotiated_protocol,omitempty"`
}

type EchoResponse struct {
	ClientIP       string              `json:"client_ip"`
	Proto          string              `json:"proto"`
	TLS            *TLSInfo            `json:"tls,omitempty"`
	Headers        map[string][]string `json:"headers"`
	TCPFingerprint any                 `json:"tcp_fingerprint,omitempty"`
	ASN            uint32              `json:"asn,omitempty"`
	ISP            string              `json:"isp,omitempty"`
}

type ServerConfig struct {
	FPStore        *tcpfp.Store
	DNSStore       *dnsleak.Store
	ReflectorStats *reflector.StatsTracker
	ASNLookup      *ASNLookup
	Token          string
}

type Server struct {
	fpStore        *tcpfp.Store
	dnsStore       *dnsleak.Store
	reflectorStats *reflector.StatsTracker
	asnLookup      *ASNLookup
	token          string
	upgrader       websocket.Upgrader
	burstData      []byte
}

func NewServer(cfg ServerConfig) *Server {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	burstObj := map[string]any{
		"message": "burst payload",
		"data":    strings.Repeat(hex.EncodeToString([]byte("0123456789abcdef")), 320),
		"size":    10240,
	}
	raw, _ := json.Marshal(burstObj)
	if len(raw) < 10240 {
		padding := make([]byte, 10240-len(raw))
		for i := range padding {
			padding[i] = byte('A' + (i % 26))
		}
		burstObj["padding"] = string(padding)
		raw, _ = json.Marshal(burstObj)
	}
	_, _ = gw.Write(raw)
	_ = gw.Close()

	return &Server{
		fpStore:        cfg.FPStore,
		dnsStore:       cfg.DNSStore,
		reflectorStats: cfg.ReflectorStats,
		asnLookup:      cfg.ASNLookup,
		token:          cfg.Token,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		burstData: buf.Bytes(),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.Handle("/echo", s.authMiddleware(http.HandlerFunc(s.handleEcho)))
	mux.Handle("/asn", s.authMiddleware(http.HandlerFunc(s.handleASN)))
	mux.Handle("/fp", s.authMiddleware(http.HandlerFunc(s.handleFingerprint)))
	mux.Handle("/ws", s.authMiddleware(http.HandlerFunc(s.handleWebSocket)))
	mux.Handle("/page", s.authMiddleware(http.HandlerFunc(s.handlePage)))
	mux.Handle("/assets/", s.authMiddleware(http.HandlerFunc(s.handleAssets)))
	mux.Handle("/burst", s.authMiddleware(http.HandlerFunc(s.handleBurst)))
	mux.Handle("/dns", s.authMiddleware(http.HandlerFunc(s.handleDNSRegister)))
	mux.Handle("/dns/check", s.authMiddleware(http.HandlerFunc(s.handleDNSCheck)))
	mux.Handle("/reflector/stats", s.authMiddleware(http.HandlerFunc(s.handleReflectorStats)))
	return mux
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" {
			next.ServeHTTP(w, r)
			return
		}

		if s.checkToken(r) {
			next.ServeHTTP(w, r)
			return
		}

		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
	})
}

func (s *Server) checkToken(r *http.Request) bool {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		got := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1 {
			return true
		}
	}
	if qToken := r.URL.Query().Get("token"); qToken != "" {
		if subtle.ConstantTimeCompare([]byte(qToken), []byte(s.token)) == 1 {
			return true
		}
	}
	return false
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func extractClientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.URL.Query().Get("ip")); ip != "" {
		return ip
	}
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return clientIP
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	echo := EchoResponse{
		ClientIP: clientIP,
		Proto:    r.Proto,
		Headers:  r.Header,
	}

	if r.TLS != nil {
		echo.TLS = &TLSInfo{
			Version:            tls.VersionName(r.TLS.Version),
			CipherSuite:        tls.CipherSuiteName(r.TLS.CipherSuite),
			ServerName:         r.TLS.ServerName,
			NegotiatedProtocol: r.TLS.NegotiatedProtocol,
		}
	}

	if s.fpStore != nil {
		if fp, ok := s.fpStore.Lookup(clientIP); ok {
			echo.TCPFingerprint = fp
		}
	}

	if s.asnLookup != nil {
		if addr, err := netip.ParseAddr(clientIP); err == nil {
			if info, ok := s.asnLookup.Lookup(addr); ok {
				echo.ASN = info.ASN
				echo.ISP = info.ISP
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(echo)
}

func (s *Server) handleASN(w http.ResponseWriter, r *http.Request) {
	ipStr := extractClientIP(r)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid ip address")
		return
	}

	resp := struct {
		IP  string `json:"ip"`
		ASN uint32 `json:"asn"`
		ISP string `json:"isp"`
	}{
		IP: addr.String(),
	}
	if info, ok := s.asnLookup.Lookup(addr); ok {
		resp.ASN = info.ASN
		resp.ISP = info.ISP
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if s.fpStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "tcpfp store not configured")
		return
	}

	ip := extractClientIP(r)
	fp, ok := s.fpStore.Lookup(ip)
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
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(fp)
}

func (s *Server) handleDNSRegister(w http.ResponseWriter, r *http.Request) {
	if s.dnsStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "dnsleak store not configured")
		return
	}
	s.dnsStore.HandleRegister(w, r)
}

func (s *Server) handleDNSCheck(w http.ResponseWriter, r *http.Request) {
	if s.dnsStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "dnsleak store not configured")
		return
	}
	s.dnsStore.HandleCheck(w, r)
}

func (s *Server) handleReflectorStats(w http.ResponseWriter, r *http.Request) {
	if s.reflectorStats == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "reflector stats not configured")
		return
	}
	ipsParam := r.URL.Query().Get("ips")
	includeIPs := ipsParam == "true" || ipsParam == "1"

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.reflectorStats.Snapshot(includeIPs))
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetPingHandler(func(appData string) error {
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
	})

	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
			if err := conn.WriteMessage(messageType, p); err != nil {
				break
			}
		}
	}
}

