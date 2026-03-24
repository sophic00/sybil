package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
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
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	redis "github.com/redis/go-redis/v9"
	"github.com/sophic00/sybil/ebpf"
	"github.com/sophic00/sybil/internal/fingerprint"
	"github.com/sophic00/sybil/internal/parser"
	"github.com/sophic00/sybil/internal/risk"
	"github.com/sophic00/sybil/internal/tlshello"
)

var (
	captureBackend      = flag.String("backend", "pcap", "Capture backend: pcap or ebpf")
	ifaceName           = flag.String("iface", "lo", "Interface to attach XDP program to")
	matchPort           = flag.Uint("port", 0, "Only inspect TCP traffic where either source or destination port matches")
	helloOutPath        = flag.String("hello-out", "", "Write the first detected TLS hello record bytes to this file")
	exitAfterHello      = flag.Bool("exit-after-hello", false, "Exit after the first matching TLS hello is detected")
	redisAddr           = flag.String("redis-addr", "", "Redis address for live JA4 risk scoring")
	redisPassword       = flag.String("redis-password", "", "Redis password for live JA4 risk scoring")
	redisDB             = flag.Int("redis-db", 0, "Redis database for live JA4 risk scoring")
	riskKeyPrefix       = flag.String("risk-key-prefix", "sybil:risk", "Redis key prefix for live JA4 risk scoring")
	ja4LookupURL        = flag.String("ja4-lookup-url", "", "Optional JA4 lookup URL or template. Use %s to inject the URL-escaped JA4 fingerprint")
	ja4LookupTimeout    = flag.Duration("ja4-lookup-timeout", 2*time.Second, "Timeout for external JA4 enrichment lookups")
	riskUseHostFallback = flag.Bool("risk-use-host-fallback", true, "Use SNI host as a weaker diversity signal when the real endpoint path is unavailable")
)

type tlsStreamFactory struct {
	onHello       func(net, transport gopacket.Flow, hello *tlshello.Hello)
	onClientHello func(net, transport gopacket.Flow, hello *tlshello.Hello, fields *parser.ClientHelloFields, ja4 *fingerprint.JA4)
}

func (f *tlsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	return &tlsStream{
		net:           net,
		transport:     transport,
		onHello:       f.onHello,
		onClientHello: f.onClientHello,
	}
}

type tlsStream struct {
	net, transport gopacket.Flow
	extractor      tlshello.Extractor
	done           bool
	onHello        func(net, transport gopacket.Flow, hello *tlshello.Hello)
	onClientHello  func(net, transport gopacket.Flow, hello *tlshello.Hello, fields *parser.ClientHelloFields, ja4 *fingerprint.JA4)
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

		if hello.Type == tlshello.ClientHello {
			fields, err := parser.ParseClientHello(hello.RecordBytes)
			if err != nil {
				fmt.Printf("ClientHello parse error: %v\n", err)
			} else {
				fmt.Println("Parsed ClientHello Fields:")
				fmt.Printf("  protocol            : %s\n", fields.Protocol)
				fmt.Printf("  tls_version         : %s\n", parser.TLSVersionString(fields.TLSVersion))
				fmt.Printf("  record_version      : %s\n", parser.TLSVersionString(fields.RecordVersion))
				fmt.Printf("  hello_version       : %s\n", parser.TLSVersionString(fields.HelloVersion))
				fmt.Printf("  sni_type            : %s\n", fields.SNIType)
				fmt.Printf("  sni_hostname        : %s\n", fields.SNIHost)
				fmt.Printf("  cipher_count        : %d\n", fields.CipherCount)
				fmt.Printf("  extension_count     : %d\n", fields.ExtensionCount)
				fmt.Printf("  alpn_first          : %s\n", fields.FirstALPN)

				ja4, err := fingerprint.BuildJA4(fields)
				if err != nil {
					fmt.Printf("JA4 build error: %v\n", err)
				} else {
					fmt.Printf("  ja4_a               : %s\n", ja4.A)
					fmt.Printf("  ja4_b               : %s\n", ja4.B)
					fmt.Printf("  ja4_c               : %s\n", ja4.C)
					fmt.Printf("JA4: %s\n", ja4.Fingerprint)

					if s.onClientHello != nil {
						s.onClientHello(s.net, s.transport, hello, fields, &ja4)
					}
				}
			}
		}

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
	if *captureBackend != "pcap" && *captureBackend != "ebpf" {
		log.Fatalf("invalid -backend %q (expected pcap or ebpf)", *captureBackend)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var threatScorer *risk.Scorer
	if *redisAddr != "" {
		rdb := redis.NewClient(&redis.Options{
			Addr:     *redisAddr,
			Password: *redisPassword,
			DB:       *redisDB,
		})
		defer rdb.Close()

		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Fatalf("redis ping failed: %v", err)
		}

		cfg := risk.DefaultConfig()
		cfg.UseHostFallback = *riskUseHostFallback

		store := risk.NewRedisStore(rdb, *riskKeyPrefix)
		var lookup risk.LookupClient
		if *ja4LookupURL != "" {
			lookup = risk.NewHTTPLookupClient(*ja4LookupURL, &http.Client{Timeout: *ja4LookupTimeout})
		}
		threatScorer = risk.NewScorer(store, lookup, cfg)
	}

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

	onClientHello := func(netFlow, _ gopacket.Flow, _ *tlshello.Hello, fields *parser.ClientHelloFields, ja4 *fingerprint.JA4) {
		if threatScorer == nil || fields == nil || ja4 == nil {
			return
		}

		assessment, err := threatScorer.Assess(ctx, risk.Observation{
			JA4:       ja4.Fingerprint,
			SourceIP:  netFlow.Src().String(),
			Hostname:  fields.SNIHost,
			Timestamp: time.Now(),
		})
		if err != nil {
			log.Printf("risk assessment failed for %s: %v", ja4.Fingerprint, err)
			return
		}

		fmt.Printf("Threat Score: %d/100 action=%s", assessment.Score, assessment.Action)
		if assessment.Delay > 0 {
			fmt.Printf(" delay=%s", assessment.Delay)
		}
		fmt.Println()
		for _, component := range assessment.Components {
			fmt.Printf("  %-20s %2d/%-2d %s\n", component.Name+":", component.Score, component.Weight, component.Detail)
		}
		if assessment.LookupError != "" {
			fmt.Printf("  lookup_error         %s\n", assessment.LookupError)
		}
	}

	streamFactory := &tlsStreamFactory{
		onHello:       onHello,
		onClientHello: onClientHello,
	}
	pool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(pool)

	fmt.Printf("Capturing TCP on %s using %s backend... (Ctrl+C to stop)\n", *ifaceName, *captureBackend)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()

	go func() {
		<-sig
		cancel()
	}()

	var (
		rd     *perf.Reader
		source *gopacket.PacketSource
	)

	switch *captureBackend {
	case "ebpf":
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatalf("failed to remove memlock: %v", err)
		}

		var objs ebpf.XdpTcpObjects
		if err := ebpf.LoadXdpTcpObjects(&objs, nil); err != nil {
			log.Fatalf("loading objects: %v", err)
		}
		defer objs.Close()

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

		rd, err = perf.NewReader(objs.Events, os.Getpagesize()*128)
		if err != nil {
			log.Fatalf("perf reader: %v", err)
		}
		defer rd.Close()

	case "pcap":
		handle, err := pcap.OpenLive(*ifaceName, 65535, true, pcap.BlockForever)
		if err != nil {
			log.Fatalf("open pcap on %s: %v", *ifaceName, err)
		}
		defer handle.Close()

		filter := "tcp"
		if *matchPort != 0 {
			filter = fmt.Sprintf("tcp and port %d", *matchPort)
		}
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatalf("set pcap filter %q: %v", filter, err)
		}

		source = gopacket.NewPacketSource(handle, handle.LinkType())
		source.NoCopy = true
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Periodically flush old streams to trigger reassembly
			assembler.FlushOlderThan(time.Now().Add(-time.Second * 3))
		default:
			var packet gopacket.Packet
			switch *captureBackend {
			case "ebpf":
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

				packetData := record.RawSample[4:]
				packet = gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)

			case "pcap":
				select {
				case <-ctx.Done():
					return
				case pkt, ok := <-source.Packets():
					if !ok {
						return
					}
					packet = pkt
				}
			}

			if packet == nil {
				continue
			}

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
