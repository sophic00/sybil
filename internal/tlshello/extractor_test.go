package tlshello

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
)

func TestExtractorMatchesTLSStreamAndTShark(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark is required for this accuracy test")
	}

	testCases := []struct {
		name     string
		min      uint16
		max      uint16
		segments []int
	}{
		{
			name:     "tls12_fragmented",
			min:      tls.VersionTLS12,
			max:      tls.VersionTLS12,
			segments: []int{1, 2, 3, 5, 8, 13, 21, 34, 55},
		},
		{
			name:     "tls13_fragmented",
			min:      tls.VersionTLS13,
			max:      tls.VersionTLS13,
			segments: []int{2, 1, 7, 11, 19, 23, 29, 31, 37},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want := captureClientHello(t, &tls.Config{
				ServerName:         "example.com",
				NextProtos:         []string{"h2", "http/1.1"},
				MinVersion:         tc.min,
				MaxVersion:         tc.max,
				InsecureSkipVerify: true,
			})

			frames := buildTCPFlow(t, want, tc.segments)
			got := extractFromFrames(t, frames)
			if got.Type != ClientHello {
				t.Fatalf("extractor recovered %s, want %s", got.Type, ClientHello)
			}
			if !bytes.Equal(got.RecordBytes, want) {
				t.Fatalf("extractor bytes differ from source ClientHello\nwant=%x\ngot=%x", want, got.RecordBytes)
			}

			pcapPath := writePCAP(t, frames)
			ref := tsharkClientHello(t, pcapPath)
			if !bytes.Equal(ref, want) {
				t.Fatalf("tshark bytes differ from source ClientHello\nwant=%x\nref=%x", want, ref)
			}
			if !bytes.Equal(got.RecordBytes, ref) {
				t.Fatalf("extractor bytes differ from tshark\nref=%x\ngot=%x", ref, got.RecordBytes)
			}
		})
	}
}

func captureClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()

	errCh := make(chan error, 1)
	go func() {
		defer clientConn.Close()
		client := tls.Client(clientConn, cfg)
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		errCh <- client.Handshake()
	}()

	var stream bytes.Buffer
	buf := make([]byte, 2048)
	if err := serverConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	for {
		n, err := serverConn.Read(buf)
		if n > 0 {
			stream.Write(buf[:n])
			_ = serverConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		}

		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			break
		}
		if errors.Is(err, io.EOF) {
			break
		}
		t.Fatalf("read client hello: %v", err)
	}

	serverConn.Close()
	<-errCh

	if stream.Len() == 0 {
		t.Fatal("captured empty TLS stream")
	}
	if stream.Bytes()[0] != 0x16 {
		t.Fatalf("captured stream does not begin with a TLS handshake record: %x", stream.Bytes())
	}

	return append([]byte(nil), stream.Bytes()...)
}

func buildTCPFlow(t *testing.T, payload []byte, segmentSizes []int) [][]byte {
	t.Helper()

	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	serverMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	clientIP := net.IPv4(192, 0, 2, 1)
	serverIP := net.IPv4(192, 0, 2, 2)
	clientPort := layers.TCPPort(42424)
	serverPort := layers.TCPPort(443)

	clientSeq := uint32(1000)
	serverSeq := uint32(9000)

	var frames [][]byte
	frames = append(frames, serializeTCPPacket(t, clientMAC, serverMAC, clientIP, serverIP, clientPort, serverPort, clientSeq, 0, true, false, false, nil))
	frames = append(frames, serializeTCPPacket(t, serverMAC, clientMAC, serverIP, clientIP, serverPort, clientPort, serverSeq, clientSeq+1, true, true, false, nil))
	frames = append(frames, serializeTCPPacket(t, clientMAC, serverMAC, clientIP, serverIP, clientPort, serverPort, clientSeq+1, serverSeq+1, false, true, false, nil))
	clientSeq++
	serverSeq++

	for _, segment := range splitPayload(payload, segmentSizes) {
		frames = append(frames, serializeTCPPacket(t, clientMAC, serverMAC, clientIP, serverIP, clientPort, serverPort, clientSeq, serverSeq, false, true, true, segment))
		clientSeq += uint32(len(segment))
		frames = append(frames, serializeTCPPacket(t, serverMAC, clientMAC, serverIP, clientIP, serverPort, clientPort, serverSeq, clientSeq, false, true, false, nil))
	}

	return frames
}

func splitPayload(payload []byte, sizes []int) [][]byte {
	var segments [][]byte
	offset := 0

	for _, size := range sizes {
		if offset >= len(payload) {
			break
		}
		if size > len(payload)-offset {
			size = len(payload) - offset
		}
		segments = append(segments, append([]byte(nil), payload[offset:offset+size]...))
		offset += size
	}

	if offset < len(payload) {
		segments = append(segments, append([]byte(nil), payload[offset:]...))
	}

	return segments
}

func serializeTCPPacket(
	t *testing.T,
	srcMAC, dstMAC net.HardwareAddr,
	srcIP, dstIP net.IP,
	srcPort, dstPort layers.TCPPort,
	seq, ack uint32,
	syn, ackFlag, psh bool,
	payload []byte,
) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		Ack:     ack,
		SYN:     syn,
		ACK:     ackFlag,
		PSH:     psh,
		Window:  64240,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip,
		tcp,
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	return append([]byte(nil), buf.Bytes()...)
}

type helloCollectorFactory struct {
	results chan *Hello
}

func (f *helloCollectorFactory) New(netFlow, transport gopacket.Flow) tcpassembly.Stream {
	return &helloCollectorStream{results: f.results}
}

type helloCollectorStream struct {
	extractor Extractor
	results   chan *Hello
	done      bool
}

func (s *helloCollectorStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if s.done {
		return
	}

	for _, reassembly := range reassemblies {
		hello, err := s.extractor.Feed(reassembly.Bytes)
		if err != nil {
			s.done = true
			return
		}
		if hello == nil {
			continue
		}

		s.results <- hello
		s.done = true
		return
	}
}

func (s *helloCollectorStream) ReassemblyComplete() {}

func extractFromFrames(t *testing.T, frames [][]byte) *Hello {
	t.Helper()

	results := make(chan *Hello, 1)
	pool := tcpassembly.NewStreamPool(&helloCollectorFactory{results: results})
	assembler := tcpassembly.NewAssembler(pool)
	base := time.Unix(1_700_000_000, 0)

	for i, frame := range frames {
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		ip := ipLayer.(*layers.IPv4)
		tcp := tcpLayer.(*layers.TCP)
		assembler.AssembleWithTimestamp(ip.NetworkFlow(), tcp, base.Add(time.Duration(i)*time.Millisecond))
	}

	assembler.FlushAll()

	select {
	case hello := <-results:
		return hello
	default:
		t.Fatal("extractor did not recover a TLS hello from the packet stream")
		return nil
	}
}

func writePCAP(t *testing.T, frames [][]byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "clienthello.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	base := time.Unix(1_700_000_000, 0)
	for i, frame := range frames {
		info := gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(i) * time.Millisecond),
			CaptureLength: len(frame),
			Length:        len(frame),
		}
		if err := writer.WritePacket(info, frame); err != nil {
			t.Fatalf("write pcap packet: %v", err)
		}
	}

	return path
}

func tsharkClientHello(t *testing.T, pcapPath string) []byte {
	t.Helper()

	var stderr bytes.Buffer
	cmd := exec.Command(
		"tshark",
		"-2",
		"-r", pcapPath,
		"-d", "tcp.port==443,tls",
		"-o", "tcp.desegment_tcp_streams:TRUE",
		"-o", "tls.desegment_ssl_records:TRUE",
		"-Y", "tls.handshake.type == 1",
		"-T", "fields",
		"-e", "tcp.reassembled.data",
		"-e", "tcp.payload",
	)
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("tshark failed: %v\nstderr=%s", err, stderr.String())
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		for _, field := range strings.Split(line, "\t") {
			if strings.TrimSpace(field) == "" {
				continue
			}

			decoded, err := decodeHexField(field)
			if err == nil && len(decoded) > 0 {
				return decoded
			}
		}
	}

	t.Fatalf("tshark did not emit a client hello payload\nstdout=%s\nstderr=%s", out, stderr.String())
	return nil
}

func decodeHexField(field string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r
		default:
			return -1
		}
	}, field)

	if clean == "" {
		return nil, nil
	}

	return hex.DecodeString(clean)
}
