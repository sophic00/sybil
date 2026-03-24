package cli

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
	"github.com/sophic00/sybil/ebpf"
	"github.com/sophic00/sybil/internal/config"
	"github.com/sophic00/sybil/internal/fingerprint"
	"github.com/sophic00/sybil/internal/parser"
	internalredis "github.com/sophic00/sybil/internal/redis"
	"github.com/sophic00/sybil/internal/risk"
	"github.com/sophic00/sybil/internal/tlshello"
)

const (
	streamFlushInterval = time.Second
	streamMaxAge        = 3 * streamFlushInterval
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

func Run() error {
	cfg, err := parseConfig()
	if err != nil {
		return err
	}
	if cfg.Backend != "pcap" && cfg.Backend != "ebpf" {
		return fmt.Errorf("invalid -backend %q (expected pcap or ebpf)", cfg.Backend)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var threatScorer *risk.Scorer
	if cfg.RedisAddr != "" {
		if _, err := internalredis.InitRedis(ctx, internalredis.Config{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		}); err != nil {
			return err
		}
		defer func() {
			if err := internalredis.Close(); err != nil {
				log.Printf("redis close failed: %v", err)
			}
		}()

		riskCfg := risk.DefaultConfig()
		riskCfg.UseHostFallback = cfg.RiskUseHostFallback

		store := risk.NewRedisStore(internalredis.Client(), cfg.RiskKeyPrefix)
		var lookup risk.LookupClient
		if cfg.JA4LookupURL != "" {
			lookup = risk.NewHTTPLookupClient(cfg.JA4LookupURL, &http.Client{Timeout: cfg.JA4LookupTimeout})
		}
		threatScorer = risk.NewScorer(store, lookup, riskCfg)
	}

	var helloOnce sync.Once
	onHello := func(_ gopacket.Flow, _ gopacket.Flow, hello *tlshello.Hello) {
		helloOnce.Do(func() {
			if cfg.HelloOut != "" {
				if err := os.WriteFile(cfg.HelloOut, hello.RecordBytes, 0o644); err != nil {
					log.Printf("write hello output: %v", err)
				}
			}
			if cfg.ExitAfterHello {
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

	fmt.Printf("Capturing TCP on %s using %s backend... (Ctrl+C to stop)\n", cfg.Iface, cfg.Backend)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(streamFlushInterval)
	defer ticker.Stop()

	go func() {
		<-sig
		cancel()
	}()

	var (
		rd     *perf.Reader
		source *gopacket.PacketSource
	)

	switch cfg.Backend {
	case "ebpf":
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("failed to remove memlock: %w", err)
		}

		var objs ebpf.XdpTcpObjects
		if err := ebpf.LoadXdpTcpObjects(&objs, nil); err != nil {
			return fmt.Errorf("loading objects: %w", err)
		}
		defer objs.Close()

		iface, err := net.InterfaceByName(cfg.Iface)
		if err != nil {
			return fmt.Errorf("lookup interface %q: %w", cfg.Iface, err)
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpTcpParser,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP: %w", err)
		}
		defer l.Close()

		rd, err = perf.NewReader(objs.Events, os.Getpagesize()*128)
		if err != nil {
			return fmt.Errorf("perf reader: %w", err)
		}
		defer rd.Close()

	case "pcap":
		handle, err := pcap.OpenLive(cfg.Iface, 65535, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("open pcap on %s: %w", cfg.Iface, err)
		}
		defer handle.Close()

		filter := "tcp"
		if cfg.Port != 0 {
			filter = fmt.Sprintf("tcp and port %d", cfg.Port)
		}
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("set pcap filter %q: %w", filter, err)
		}

		source = gopacket.NewPacketSource(handle, handle.LinkType())
		source.NoCopy = true
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			assembler.FlushOlderThan(time.Now().Add(-streamMaxAge))
		default:
			var packet gopacket.Packet
			switch cfg.Backend {
			case "ebpf":
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						return nil
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
					return nil
				case pkt, ok := <-source.Packets():
					if !ok {
						return nil
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

			if tcp != nil && cfg.Port != 0 {
				if uint(tcp.SrcPort) != cfg.Port && uint(tcp.DstPort) != cfg.Port {
					continue
				}
			}

			if netFlow != (gopacket.Flow{}) && tcp != nil {
				assembler.AssembleWithTimestamp(netFlow, tcp, packet.Metadata().Timestamp)
			}
		}
	}
}

func parseConfig() (config.Config, error) {
	defaults := config.Default()
	values := defaults
	var configPath string

	flag.StringVar(&configPath, "config", "", "Path to TOML config file")
	flag.StringVar(&values.Backend, "backend", defaults.Backend, "Capture backend: pcap or ebpf")
	flag.StringVar(&values.Iface, "iface", defaults.Iface, "Interface to attach XDP program to")
	flag.UintVar(&values.Port, "port", defaults.Port, "Only inspect TCP traffic where either source or destination port matches")
	flag.StringVar(&values.HelloOut, "hello-out", defaults.HelloOut, "Write the first detected TLS hello record bytes to this file")
	flag.BoolVar(&values.ExitAfterHello, "exit-after-hello", defaults.ExitAfterHello, "Exit after the first matching TLS hello is detected")
	flag.StringVar(&values.RedisAddr, "redis-addr", defaults.RedisAddr, "Redis address for live JA4 risk scoring")
	flag.StringVar(&values.RedisPassword, "redis-password", defaults.RedisPassword, "Redis password for live JA4 risk scoring")
	flag.IntVar(&values.RedisDB, "redis-db", defaults.RedisDB, "Redis database for live JA4 risk scoring")
	flag.StringVar(&values.RiskKeyPrefix, "risk-key-prefix", defaults.RiskKeyPrefix, "Redis key prefix for live JA4 risk scoring")
	flag.StringVar(&values.JA4LookupURL, "ja4-lookup-url", defaults.JA4LookupURL, "Optional JA4 lookup URL or template. Use %s to inject the URL-escaped JA4 fingerprint")
	flag.DurationVar(&values.JA4LookupTimeout, "ja4-lookup-timeout", defaults.JA4LookupTimeout, "Timeout for external JA4 enrichment lookups")
	flag.BoolVar(&values.RiskUseHostFallback, "risk-use-host-fallback", defaults.RiskUseHostFallback, "Use SNI host as a weaker diversity signal when the real endpoint path is unavailable")
	flag.Parse()

	cfg := defaults
	if configPath != "" {
		loaded, err := config.Load(configPath)
		if err != nil {
			return config.Config{}, err
		}
		cfg = loaded
	}

	config.ApplyFlagOverrides(flag.CommandLine, &cfg, values)
	return cfg, nil
}
