package tcpfp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	ethHeaderLen = 14
	ethTypeIPv4  = 0x0800
	ethTypeIPv6  = 0x86DD
	ipProtoTCP   = 6
	tcpFlagSYN   = 0x02
	tcpFlagACK   = 0x10

	optEOL       = 0
	optNOP       = 1
	optMSS       = 2
	optWScale    = 3
	optSACKPerm  = 4
	optTimestamp = 8
)

var (
	ErrTooShort   = errors.New("packet too short")
	ErrNotIP      = errors.New("unsupported network protocol")
	ErrNotTCP     = errors.New("packet is not TCP")
	ErrNotSYN     = errors.New("TCP packet is not a pure SYN")
	ErrBadOptions = errors.New("malformed TCP options")
)

// ParseEthernetSYN parses an Ethernet frame containing an IPv4 or IPv6 TCP SYN packet.
func ParseEthernetSYN(frame []byte) (*Fingerprint, error) {
	if len(frame) < ethHeaderLen {
		return nil, ErrTooShort
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	switch etherType {
	case ethTypeIPv4, ethTypeIPv6:
		return ParseIPSYN(frame[ethHeaderLen:])
	default:
		return nil, ErrNotIP
	}
}

// ParseIPSYN parses a raw IPv4 or IPv6 packet containing a TCP SYN segment.
func ParseIPSYN(pkt []byte) (*Fingerprint, error) {
	if len(pkt) < 1 {
		return nil, ErrTooShort
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		return parseIPv4SYN(pkt)
	case 6:
		return parseIPv6SYN(pkt)
	default:
		return nil, ErrNotIP
	}
}

func parseIPv4SYN(pkt []byte) (*Fingerprint, error) {
	if len(pkt) < 20 {
		return nil, ErrTooShort
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, ErrTooShort
	}
	if pkt[9] != ipProtoTCP {
		return nil, ErrNotTCP
	}
	srcIP := net.IP(pkt[12:16]).String()
	ttl := pkt[8]
	return parseTCPSYN(4, srcIP, ttl, pkt[ihl:])
}

func parseIPv6SYN(pkt []byte) (*Fingerprint, error) {
	if len(pkt) < 40 {
		return nil, ErrTooShort
	}
	if pkt[6] != ipProtoTCP {
		return nil, ErrNotTCP
	}
	srcIP := net.IP(pkt[8:24]).String()
	hopLimit := pkt[7]
	return parseTCPSYN(6, srcIP, hopLimit, pkt[40:])
}

func parseTCPSYN(ipVer uint8, srcIP string, ttl uint8, seg []byte) (*Fingerprint, error) {
	if len(seg) < 20 {
		return nil, ErrTooShort
	}
	dataOffset := int(seg[12]>>4) * 4
	if dataOffset < 20 || len(seg) < dataOffset {
		return nil, ErrTooShort
	}
	flags := seg[13]
	if flags&tcpFlagSYN == 0 || flags&tcpFlagACK != 0 {
		return nil, ErrNotSYN
	}

	fp := &Fingerprint{
		TargetIP:   srcIP,
		IPVersion:  ipVer,
		TTL:        ttl,
		InitialTTL: inferInitialTTL(ttl),
		WindowSize: binary.BigEndian.Uint16(seg[14:16]),
		SrcPort:    binary.BigEndian.Uint16(seg[0:2]),
		DstPort:    binary.BigEndian.Uint16(seg[2:4]),
		ObservedAt: time.Now().UTC(),
	}

	opts, rawCodes, err := parseTCPOptions(seg[20:dataOffset], fp)
	if err != nil {
		return nil, err
	}
	fp.TCPOptions = strings.Join(opts, ",")
	fp.Signature = fmt.Sprintf("%d_%d_%s_%d", fp.WindowSize, fp.MSS, strings.Join(rawCodes, "-"), fp.WindowScale)
	fp.OS = ClassifyOS(fp)
	return fp, nil
}

func parseTCPOptions(raw []byte, fp *Fingerprint) ([]string, []string, error) {
	var labels []string
	var codes []string
	i := 0
	for i < len(raw) {
		kind := raw[i]
		switch kind {
		case optEOL:
			codes = append(codes, "0")
			return labels, codes, nil
		case optNOP:
			codes = append(codes, "1")
			i++
			continue
		}
		if i+1 >= len(raw) {
			return nil, nil, ErrBadOptions
		}
		optLen := int(raw[i+1])
		if optLen < 2 || i+optLen > len(raw) {
			return nil, nil, ErrBadOptions
		}
		codes = append(codes, fmt.Sprintf("%d", kind))
		switch kind {
		case optMSS:
			if optLen == 4 {
				fp.MSS = binary.BigEndian.Uint16(raw[i+2 : i+4])
				labels = append(labels, "MSS")
			}
		case optWScale:
			if optLen == 3 {
				fp.WindowScale = raw[i+2]
				labels = append(labels, "WSCALE")
			}
		case optSACKPerm:
			if optLen == 2 {
				fp.SACKPermitted = true
				labels = append(labels, "SACK")
			}
		case optTimestamp:
			if optLen == 10 {
				fp.Timestamp = true
				labels = append(labels, "TS")
			}
		default:
			labels = append(labels, fmt.Sprintf("OPT%d", kind))
		}
		i += optLen
	}
	return labels, codes, nil
}

func inferInitialTTL(ttl uint8) uint8 {
	switch {
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	default:
		return 255
	}
}

// ClassifyOS infers the client OS family from SYN TTL, window size, and TCP options.
func ClassifyOS(fp *Fingerprint) OSProfile {
	if fp == nil {
		return OSUnknown
	}
	initTTL := fp.InitialTTL
	if initTTL == 0 {
		initTTL = inferInitialTTL(fp.TTL)
	}

	if initTTL == 128 {
		return OSWindows
	}
	if initTTL == 64 {
		if fp.WindowSize == 65535 && fp.Timestamp && fp.WindowScale == 6 {
			return OSMacOS
		}
		if fp.WindowSize == 65535 && fp.Timestamp && fp.WindowScale == 5 {
			return OSiOS
		}
		if fp.WindowSize == 65535 && !fp.Timestamp {
			return OSFreeBSD
		}
		if fp.Timestamp && fp.SACKPermitted {
			if fp.WindowScale == 8 && fp.WindowSize == 65535 {
				return OSAndroid
			}
			return OSLinux
		}
	}
	return OSUnknown
}
