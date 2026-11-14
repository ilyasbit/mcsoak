package mcsoak

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var assetRegex = regexp.MustCompile(`^/assets/(chunk|style|img)_(\d+)\.(js|css|svg)$`)

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
