package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf ../../bpf/probe.c

// type alias for event struct
type Event = bpfEvent

// eBPF resources
type Probe struct {
	objs      bpfObjects
	link      link.Link
	reader    *ringbuf.Reader
	closeOnce sync.Once
}

// loads and compiles eBPF objects into kernel, attact it to network interface
// and creates ring buffer
func Load(iface string) (*Probe, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", iface, err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpTlsParser,
		Interface: ifi.Index,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach xdp to %q: %w", iface, err)
	}

	reader, err := ringbuf.NewReader(objs.Ringbuf)
	if err != nil {
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}

	return &Probe{
		objs:   objs,
		link:   xdpLink,
		reader: reader,
	}, nil
}

// reads a tls packet (event struct) from ring buffer
func (p *Probe) Read() (Event, error) {
	record, err := p.reader.Read()
	if err != nil {
		return Event{}, err
	}

	var e Event
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &e); err != nil {
		return Event{}, fmt.Errorf("parse event: %w", err)
	}

	return e, nil
}

// removes XDP program, cleans up ring buffer and free all other eBPF resources.
func (p *Probe) Close() error {
	var errs []error

	p.closeOnce.Do(func() {
		if p.reader != nil {
			if err := p.reader.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
				errs = append(errs, fmt.Errorf("close ringbuf reader: %w", err))
			}
			p.reader = nil
		}
		if p.link != nil {
			if err := p.link.Close(); err != nil {
				errs = append(errs, fmt.Errorf("detach xdp link: %w", err))
			}
			p.link = nil
		}
		if err := p.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close bpf objects: %w", err))
		}
	})

	return errors.Join(errs...)
}
