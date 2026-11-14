package mcsoak

import (
	"bytes"
	"compress/gzip"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ilyasbit/mcsoak/dnsleak"
	"github.com/ilyasbit/mcsoak/reflector"
	"github.com/ilyasbit/mcsoak/tcpfp"
)

var assetRegex = regexp.MustCompile(`^/assets/(chunk|style|img)_(\d+)\.(js|css|svg)$`)

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
}

type ServerConfig struct {
	FPStore        *tcpfp.Store
	DNSStore       *dnsleak.Store
	ReflectorStats *reflector.StatsTracker
	Token          string
}

type Server struct {
	fpStore        *tcpfp.Store
	dnsStore       *dnsleak.Store
	reflectorStats *reflector.StatsTracker
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(echo)
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

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>MCSOak Page</title>\n")

	// 15 CSS sub-resources
	for i := 1; i <= 15; i++ {
		b.WriteString(fmt.Sprintf("<link rel=\"stylesheet\" href=\"/assets/style_%d.css\">\n", i))
	}

	b.WriteString("</head>\n<body>\n<h1>MCSOak Test Page</h1>\n<div id=\"svg-container\">\n")

	// 10 SVG sub-resources
	for i := 1; i <= 10; i++ {
		b.WriteString(fmt.Sprintf("<img src=\"/assets/img_%d.svg\" alt=\"img_%d\">\n", i, i))
	}
	b.WriteString("</div>\n<script>\n")
	b.WriteString(`
const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(proto + '//' + location.host + '/ws');
ws.onopen = () => console.log('ws open');
ws.onmessage = (e) => console.log('ws msg:', e.data);
`)
	b.WriteString("</script>\n")

	// 25 JS sub-resources
	for i := 1; i <= 25; i++ {
		b.WriteString(fmt.Sprintf("<script src=\"/assets/chunk_%d.js\"></script>\n", i))
	}

	b.WriteString("</body>\n</html>\n")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	matches := assetRegex.FindStringSubmatch(r.URL.Path)
	if len(matches) != 4 {
		http.NotFound(w, r)
		return
	}

	kind := matches[1]
	idxStr := matches[2]
	ext := matches[3]
	idx, _ := strconv.Atoi(idxStr)

	switch ext {
	case "js":
		w.Header().Set("Content-Type", "application/javascript")
	case "css":
		w.Header().Set("Content-Type", "text/css")
	case "svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	payload := make([]byte, 2048)
	rnd := rand.New(rand.NewSource(int64(idx*1000 + len(kind))))
	_, _ = rnd.Read(payload)

	var content []byte
	switch ext {
	case "js":
		prefix := fmt.Sprintf("/* chunk %d */\nwindow.asset_%s_%d = \"", idx, kind, idx)
		suffix := "\";\n"
		bodyLen := 2048 - len(prefix) - len(suffix)
		if bodyLen > 0 {
			hexPart := hex.EncodeToString(payload)[:bodyLen]
			content = []byte(prefix + hexPart + suffix)
		} else {
			content = payload
		}
	case "css":
		prefix := fmt.Sprintf("/* style %d */\n.asset_%s_%d { content: \"", idx, kind, idx)
		suffix := "\"; }\n"
		bodyLen := 2048 - len(prefix) - len(suffix)
		if bodyLen > 0 {
			hexPart := hex.EncodeToString(payload)[:bodyLen]
			content = []byte(prefix + hexPart + suffix)
		} else {
			content = payload
		}
	case "svg":
		prefix := fmt.Sprintf("<svg xmlns=\"http://www.w3.org/2000/svg\" data-idx=\"%d\"><desc>", idx)
		suffix := "</desc></svg>"
		bodyLen := 2048 - len(prefix) - len(suffix)
		if bodyLen > 0 {
			hexPart := hex.EncodeToString(payload)[:bodyLen]
			content = []byte(prefix + hexPart + suffix)
		} else {
			content = payload
		}
	default:
		content = payload
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) handleBurst(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Length", strconv.Itoa(len(s.burstData)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.burstData)
}
