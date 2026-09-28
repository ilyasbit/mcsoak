package mcsoak

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
)

type mockTCPFPResponse struct {
	OS         string `json:"os"`
	TCPOptions string `json:"tcp_options"`
	TargetIP   string `json:"target_ip"`
}

// NewMockTCPFPDaemon creates an in-process httptest.Server serving /check.
func NewMockTCPFPDaemon(defaultOS string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.Header.Get("X-Real-IP")
		if clientIP == "" {
			clientIP = r.Header.Get("X-Forwarded-For")
			if clientIP != "" {
				if idx := strings.Index(clientIP, ","); idx != -1 {
					clientIP = strings.TrimSpace(clientIP[:idx])
				}
			}
		}
		if clientIP == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil {
				clientIP = host
			} else {
				clientIP = r.RemoteAddr
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockTCPFPResponse{
			OS:         defaultOS,
			TCPOptions: "MSS,SACK,TS,WSCALE",
			TargetIP:   clientIP,
		})
	})

	return httptest.NewServer(mux)
}
