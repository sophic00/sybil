package capture

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/gopacket/gopacket/tcpassembly/tcpreader"
)

const maxTLSRecordSize = 16384

// TLSHello holds a fully reassembled TLS Client Hello with connection metadata.
// The Raw field preserves the original byte ordering required for JA4+ fingerprinting.
type TLSHello struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Raw     []byte // complete TLS record (5-byte header + payload)
}

type Sniffer struct {
	handle    *pcap.Handle
	hellos    chan TLSHello
	done      chan struct{}
	closeOnce sync.Once
}

func New(iface string) (*Sniffer, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open pcap on %q: %w", iface, err)
	}

	if err := handle.SetBPFFilter("tcp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set BPF filter: %w", err)
	}

	return &Sniffer{
		handle: handle,
		hellos: make(chan TLSHello, 256),
		done:   make(chan struct{}),
	}, nil
}

func (s *Sniffer) Hellos() <-chan TLSHello {
	return s.hellos
}

// Run starts the packet capture loop. It blocks until Close is called or the
// capture handle is shut down. Callers should typically run this in its own
// goroutine and read from Hellos().
func (s *Sniffer) Run() {
	defer close(s.hellos)

	factory := &tlsStreamFactory{hellos: s.hellos}
	pool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(pool)

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packets := packetSource.Packets()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			assembler.FlushAll()
			return
		case packet, ok := <-packets:
			if !ok {
				assembler.FlushAll()
				return
			}
			netLayer := packet.NetworkLayer()
			if netLayer == nil {
				continue
			}
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			tcp := tcpLayer.(*layers.TCP)
			assembler.AssembleWithTimestamp(
				netLayer.NetworkFlow(),
				tcp,
				packet.Metadata().Timestamp,
			)
		case <-ticker.C:
			assembler.FlushOlderThan(time.Now().Add(-2 * time.Minute))
		}
	}
}

func (s *Sniffer) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.handle.Close()
	})
}

// tlsStreamFactory creates a new stream handler for each TCP connection and
// checks whether the first bytes look like a TLS Client Hello.
type tlsStreamFactory struct {
	hellos chan<- TLSHello
}

func (f *tlsStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go handleStream(netFlow, tcpFlow, &r, f.hellos)
	return &r
}

// handleStream reads from a reassembled TCP stream, detects TLS Client Hello
// records, and emits them on the hellos channel. It always drains the reader
// before returning so the assembler can reclaim resources.
func handleStream(netFlow, tcpFlow gopacket.Flow, r io.Reader, hellos chan<- TLSHello) {
	drain := func() { io.Copy(io.Discard, r) }

	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		drain()
		return
	}

	// TLS record: content type 0x16 (handshake), major version 0x03
	if header[0] != 0x16 || header[1] != 0x03 {
		drain()
		return
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen <= 0 || recordLen > maxTLSRecordSize {
		log.Printf("TLS record too large or zero (%d bytes), skipping", recordLen)
		drain()
		return
	}

	record := make([]byte, 5+recordLen)
	copy(record, header)
	if _, err := io.ReadFull(r, record[5:]); err != nil {
		drain()
		return
	}

	// Handshake type 0x01 = Client Hello
	if record[5] != 0x01 {
		drain()
		return
	}

	srcIP := net.IP(append([]byte(nil), netFlow.Src().Raw()...))
	dstIP := net.IP(append([]byte(nil), netFlow.Dst().Raw()...))
	srcPort := binary.BigEndian.Uint16(tcpFlow.Src().Raw())
	dstPort := binary.BigEndian.Uint16(tcpFlow.Dst().Raw())

	hellos <- TLSHello{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Raw:     record,
	}

	drain()
}
