package tcpfp

import "time"

// OSProfile represents a classified operating system family from TCP SYN characteristics.
type OSProfile string

const (
	OSUnknown OSProfile = "unknown"
	OSLinux   OSProfile = "linux"
	OSWindows OSProfile = "windows"
	OSMacOS   OSProfile = "macos"
	OSiOS     OSProfile = "ios"
	OSAndroid OSProfile = "android"
	OSFreeBSD OSProfile = "freebsd"
)

// Fingerprint holds passive TCP SYN fingerprint telemetry for a client IP.
type Fingerprint struct {
	TargetIP      string    `json:"target_ip"`
	OS            OSProfile `json:"os"`
	TCPOptions    string    `json:"tcp_options"`
	Signature     string    `json:"signature"`
	IPVersion     uint8     `json:"ip_version"`
	TTL           uint8     `json:"ttl"`
	InitialTTL    uint8     `json:"initial_ttl"`
	WindowSize    uint16    `json:"window_size"`
	MSS           uint16    `json:"mss,omitempty"`
	WindowScale   uint8     `json:"window_scale,omitempty"`
	SACKPermitted bool      `json:"sack_permitted"`
	Timestamp     bool      `json:"timestamp"`
	SrcPort       uint16    `json:"src_port"`
	DstPort       uint16    `json:"dst_port"`
	ObservedAt    time.Time `json:"observed_at"`
}
