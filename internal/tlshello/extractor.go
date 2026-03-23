package tlshello

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	recordHeaderLen    = 5
	handshakeHeaderLen = 4
	maxBufferedBytes   = 256 << 10
)

type MessageType byte

const (
	ClientHello MessageType = 0x01
	ServerHello MessageType = 0x02
)

func (m MessageType) String() string {
	switch m {
	case ClientHello:
		return "CLIENT HELLO"
	case ServerHello:
		return "SERVER HELLO"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(m))
	}
}

type Hello struct {
	Type           MessageType
	RecordBytes    []byte
	HandshakeBytes []byte
	StreamOffset   int
}

type Extractor struct {
	buf       []byte
	scanStart int
	done      bool
}

var (
	errNotHelloRecord = errors.New("tls record does not contain a hello handshake")
	ErrBufferLimit    = errors.New("buffered stream exceeds tls hello extractor limit")
)

func (e *Extractor) Feed(data []byte) (*Hello, error) {
	if e.done {
		return nil, nil
	}

	if len(data) > 0 {
		e.buf = append(e.buf, data...)
		if len(e.buf) > maxBufferedBytes {
			return nil, ErrBufferLimit
		}
	}

	for {
		offset, ok := findHandshakeRecord(e.buf, e.scanStart)
		if !ok {
			if len(e.buf) >= recordHeaderLen-1 {
				e.scanStart = len(e.buf) - (recordHeaderLen - 1)
			}
			return nil, nil
		}

		hello, needMore, err := parseHello(e.buf[offset:])
		if needMore {
			return nil, nil
		}
		if errors.Is(err, errNotHelloRecord) {
			e.scanStart = offset + 1
			continue
		}
		if err != nil {
			return nil, err
		}

		hello.StreamOffset = offset
		e.done = true
		return hello, nil
	}
}

func findHandshakeRecord(buf []byte, start int) (int, bool) {
	for i := start; i+recordHeaderLen <= len(buf); i++ {
		if looksLikeHandshakeRecord(buf[i:]) {
			return i, true
		}
	}
	return 0, false
}

func parseHello(stream []byte) (*Hello, bool, error) {
	var (
		rawEnd      int
		handshake   []byte
		needPayload = -1
		helloType   MessageType
	)

	for {
		if len(stream[rawEnd:]) < recordHeaderLen {
			return nil, true, nil
		}

		record := stream[rawEnd:]
		if !looksLikeHandshakeRecord(record) {
			if needPayload == -1 {
				return nil, false, errNotHelloRecord
			}
			return nil, false, fmt.Errorf("hello spans a non-handshake TLS record at raw offset %d", rawEnd)
		}

		recordLen := int(binary.BigEndian.Uint16(record[3:5]))
		if len(record) < recordHeaderLen+recordLen {
			return nil, true, nil
		}

		payload := record[recordHeaderLen : recordHeaderLen+recordLen]
		if needPayload == -1 {
			if len(payload) < handshakeHeaderLen {
				return nil, false, errNotHelloRecord
			}

			helloType = MessageType(payload[0])
			if helloType != ClientHello && helloType != ServerHello {
				return nil, false, errNotHelloRecord
			}

			needPayload = handshakeHeaderLen +
				int(payload[1])<<16 +
				int(payload[2])<<8 +
				int(payload[3])
		}

		take := recordLen
		remaining := needPayload - len(handshake)
		if take > remaining {
			take = remaining
		}
		handshake = append(handshake, payload[:take]...)
		rawEnd += recordHeaderLen + recordLen

		if len(handshake) >= needPayload {
			return &Hello{
				Type:           helloType,
				RecordBytes:    append([]byte(nil), stream[:rawEnd]...),
				HandshakeBytes: append([]byte(nil), handshake[:needPayload]...),
			}, false, nil
		}
	}
}

func looksLikeHandshakeRecord(buf []byte) bool {
	if len(buf) < recordHeaderLen {
		return false
	}
	if buf[0] != 0x16 {
		return false
	}
	if buf[1] != 0x03 {
		return false
	}
	if buf[2] > 0x04 {
		return false
	}
	return binary.BigEndian.Uint16(buf[3:5]) > 0
}
