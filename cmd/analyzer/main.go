package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/sophic00/sybil/internal/ebpf"
)

func main() {
	iface := flag.String("iface", "", "network interface to attach XDP probe to")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "usage: analyzer -iface <interface>")
		os.Exit(1)
	}

	log.Printf("loading eBPF probe on interface %q...", *iface)

	probe, err := ebpf.Load(*iface)
	if err != nil {
		log.Fatalf("failed to load and attach probe: %v", err)
	}
	defer func() {
		log.Println("cleaning up eBPF resources...")
		if err := probe.Close(); err != nil {
			log.Printf("error during cleanup: %v", err)
		}
		log.Println("shutdown complete")
	}()

	log.Printf("XDP probe attached, listening for TLS Client Hello packets...")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		probe.Close()
	}()

	for {
		event, err := probe.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("failed to read event: %v", err)
			continue
		}
		srcIP := intToIP(event.SrcIp)
		dstIP := intToIP(event.DstIp)
		log.Printf("TLS Client Hello: %s:%d -> %s:%d (%d bytes)",
			srcIP, event.SrcPort, dstIP, event.DstPort, event.TlsLen)
	}
}

func intToIP(n uint32) net.IP {
	return net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
}
