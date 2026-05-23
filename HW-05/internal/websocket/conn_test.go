package websocket

import (
	"bufio"
	"encoding/binary"
	"net"
	"testing"
)

func TestReadBinarySupportsContinuationFrames(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ws := &Conn{
		Conn:   server,
		reader: bufio.NewReader(server),
		writer: bufio.NewWriter(server),
	}

	go func() {
		writeMaskedFrame(t, client, false, OpcodeBinary, []byte("hello "))
		writeMaskedFrame(t, client, true, OpcodeContinuation, []byte("world"))
	}()

	payload, err := ws.ReadBinary()
	if err != nil {
		t.Fatalf("ReadBinary failed: %v", err)
	}
	if string(payload) != "hello world" {
		t.Fatalf("unexpected payload %q", payload)
	}
}

func writeMaskedFrame(t *testing.T, conn net.Conn, fin bool, opcode byte, payload []byte) {
	t.Helper()

	first := opcode
	if fin {
		first |= 0x80
	}
	header := []byte{first}
	length := len(payload)
	switch {
	case length < 126:
		header = append(header, 0x80|byte(length))
	case length <= 0xffff:
		header = append(header, 0x80|126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(length))
		header = append(header, ext...)
	default:
		header = append(header, 0x80|127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(length))
		header = append(header, ext...)
	}

	mask := []byte{1, 2, 3, 4}
	masked := append([]byte(nil), payload...)
	for i := range masked {
		masked[i] ^= mask[i%len(mask)]
	}

	if _, err := conn.Write(append(append(header, mask...), masked...)); err != nil {
		t.Errorf("write frame failed: %v", err)
	}
}
