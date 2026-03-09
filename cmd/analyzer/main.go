package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sophic00/sybil/internal/capture"
	"github.com/sophic00/sybil/internal/parser"
)

func main() {
	iface := flag.String("iface", "", "network interface to capture on")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "usage: analyzer -iface <interface>")
		os.Exit(1)
	}

	log.Printf("starting capture on interface %q...", *iface)

	sniffer, err := capture.New(*iface)
	if err != nil {
		log.Fatalf("failed to start capture: %v", err)
	}
	defer sniffer.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go sniffer.Run()

	log.Println("listening for TLS Client Hello packets...")

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down...")
			sniffer.Close()
			return
		case hello, ok := <-sniffer.Hellos():
			if !ok {
				return
			}
			log.Printf("TLS Client Hello: %s:%d -> %s:%d (%d bytes)",
				hello.SrcIP, hello.SrcPort, hello.DstIP, hello.DstPort, len(hello.Raw))

			parsed, err := parser.ParseTLS(hello.Raw)
			if err != nil {
				log.Printf("  failed to parse TLS: %v", err)
			} else {
				log.Printf("  Version: 0x%04x | SNI: %s | ALPN: %s",
					parsed.TLSVersion, parsed.SNI, parsed.ALPN)
				log.Printf("  CipherSuites(%d): %04x", len(parsed.CipherSuites), parsed.CipherSuites)
				log.Printf("  Extensions(%d): %v", len(parsed.Extensions), parsed.Extensions)
				log.Printf("  SupportedGroups: %04x", parsed.SupportedGroups)
				log.Printf("  SignatureAlgorithms: %04x", parsed.SignatureAlgorithms)
			}
		}
	}
}
