//go:build linux

package reflector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf sight.bpf.c -- -I/usr/include/bpf

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type reflectorHandle struct {
	ifaceName string
	nlLink    netlink.Link
	objs      bpfObjects
	xdpLink   link.Link
	tcFilter  *netlink.BpfFilter
	ringRd    *ringbuf.Reader
	wg        sync.WaitGroup
}

func (h *reflectorHandle) Close() error {
	log.Printf("Detaching eBPF programs from %s...", h.ifaceName)
	var firstErr error
	if h.ringRd != nil {
		if err := h.ringRd.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			firstErr = err
		}
		h.wg.Wait()
	}
	if h.tcFilter != nil {
		if err := netlink.FilterDel(h.tcFilter); err != nil {
			log.Printf("Warning: Failed to clean up TC Egress filter: %v", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if h.xdpLink != nil {
		if err := h.xdpLink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if h.nlLink != nil {
		log.Printf("Netlink: Detaching XDP program from interface %s...", h.ifaceName)
		_ = netlink.LinkSetXdpFd(h.nlLink, -1)
	}
	if err := h.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Start loads and attaches the XDP pulse reflector and TC clsact egress RST drop filter
// to the specified network interface.
func Start(ifaceName string) (io.Closer, error) {
	return StartWithEvents(ifaceName, nil)
}

// StartWithEvents loads and attaches the XDP pulse reflector and TC clsact egress RST drop filter,
// and if handler is non-nil, streams decoded PulseEvent records from the BPF ring buffer.
func StartWithEvents(ifaceName string, handler EventHandler) (io.Closer, error) {
	if ifaceName == "" {
		ifaceName = "eth0"
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to locate interface %s: %w", ifaceName, err)
	}

	nlLink, err := netlink.LinkByIndex(iface.Index)
	if err == nil && nlLink != nil {
		log.Printf("Netlink: Clearing any stale XDP program from %s on startup...", ifaceName)
		_ = netlink.LinkSetXdpFd(nlLink, -1)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPulseReflector,
		Interface: iface.Index,
	})
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("failed to attach XDP to %s: %w", ifaceName, err)
	}
	log.Printf("eBPF XDP Program successfully attached to %s", ifaceName)

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !os.IsExist(err) {
		log.Printf("Warning: Failed to add clsact qdisc on %s: %v", ifaceName, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.TcEgressDropRst.FD(),
		Name:         "tc_egress_drop_rst",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		_ = xdpLink.Close()
		if nlLink != nil {
			_ = netlink.LinkSetXdpFd(nlLink, -1)
		}
		_ = objs.Close()
		return nil, fmt.Errorf("failed to attach TC Egress filter to %s: %w", ifaceName, err)
	}
	log.Printf("eBPF TC Egress Filter successfully attached to %s", ifaceName)

	return &reflectorHandle{
		ifaceName: ifaceName,
		nlLink:    nlLink,
		objs:      objs,
		xdpLink:   xdpLink,
		tcFilter:  filter,
	}, nil
}
