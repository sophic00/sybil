package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/sophic00/sybil/ebpf"
	"github.com/sophic00/sybil/internal/tlshello"
)

var (
	ifaceName      = flag.String("iface", "lo", "Interface to attach XDP program to")
	matchPort      = flag.Uint("port", 0, "Only inspect TCP traffic where either source or destination port matches")
	helloOutPath   = flag.String("hello-out", "", "Write the first detected TLS hello record bytes to this file")
	exitAfterHello = flag.Bool("exit-after-hello", false, "Exit after the first matching TLS hello is detected")
)

type tlsStreamFactory struct {
	onHello func(net, transport gopacket.Flow, hello *tlshello.Hello)
}

func (f *tlsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	return &tlsStream{net: net, transport: transport, onHello: f.onHello}
}

type tlsStream struct {
	net, transport gopacket.Flow
	extractor      tlshello.Extractor
	done           bool
	onHello        func(net, transport gopacket.Flow, hello *tlshello.Hello)
}

func (s *tlsStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if s.done {
		return
	}

	for _, reassembly := range reassemblies {
		data := reassembly.Bytes
		if len(data) == 0 {
			continue
		}

		hello, err := s.extractor.Feed(data)
		if err != nil {
			s.done = true
			return
		}
		if hello == nil {
			continue
		}

		fmt.Printf("\n--- Detected TLS %s (%s:%s -> %s:%s) ---\n",
			hello.Type, s.net.Src(), s.transport.Src(), s.net.Dst(), s.transport.Dst())
		fmt.Printf("record_bytes=%d handshake_bytes=%d stream_offset=%d\n",
			len(hello.RecordBytes), len(hello.HandshakeBytes), hello.StreamOffset)
		fmt.Println(hex.Dump(hello.RecordBytes))
		if s.onHello != nil {
			s.onHello(s.net, s.transport, hello)
		}
		s.done = true
		return
	}
}

func (s *tlsStream) ReassemblyComplete() {}

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var helloOnce sync.Once
	onHello := func(_ gopacket.Flow, _ gopacket.Flow, hello *tlshello.Hello) {
		helloOnce.Do(func() {
			if *helloOutPath != "" {
				if err := os.WriteFile(*helloOutPath, hello.RecordBytes, 0o644); err != nil {
					log.Printf("write hello output: %v", err)
				}
			}
			if *exitAfterHello {
				cancel()
			}
		})
	}

	// 1. Increase RLIMIT_MEMLOCK
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	// 2. Load eBPF objects
	var objs ebpf.XdpTcpObjects
	if err := ebpf.LoadXdpTcpObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// 3. Attach XDP program to the interface
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("lookup interface %q: %v", *ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpTcpParser,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("attaching XDP: %v", err)
	}
	defer l.Close()

	// 4. Setup perf reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*128)
	if err != nil {
		log.Fatalf("perf reader: %v", err)
	}
	defer rd.Close()

	streamFactory := &tlsStreamFactory{onHello: onHello}
	pool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(pool)

	fmt.Printf("Capturing TCP on %s... (Ctrl+C to stop)\n", *ifaceName)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()

	go func() {
		<-sig
		cancel()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Periodically flush old streams to trigger reassembly
			assembler.FlushOlderThan(time.Now().Add(-time.Second * 3))
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				continue
			}

			if record.LostSamples > 0 {
				log.Printf("lost %d samples", record.LostSamples)
				continue
			}
			if len(record.RawSample) < 4 {
				continue
			}

			// Skip the 4-byte dummy metadata to get the raw Ethernet frame
			packetData := record.RawSample[4:]
			packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)

			var netFlow gopacket.Flow
			var tcp *layers.TCP

			if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
				netFlow = ip4.(*layers.IPv4).NetworkFlow()
			} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
				netFlow = ip6.(*layers.IPv6).NetworkFlow()
			}

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp = tcpLayer.(*layers.TCP)
			}

			if tcp != nil && *matchPort != 0 {
				if uint(tcp.SrcPort) != *matchPort && uint(tcp.DstPort) != *matchPort {
					continue
				}
			}

			if netFlow != (gopacket.Flow{}) && tcp != nil {
				assembler.AssembleWithTimestamp(netFlow, tcp, packet.Metadata().Timestamp)
			}
		}
	}
}
