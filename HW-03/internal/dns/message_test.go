package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestQueryMarshalParseRoundTrip(t *testing.T) {
	msg := NewQuery("github.com", TypeA, true)
	wire, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	parsed, err := ParseMessage(wire)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}

	if parsed.Header.ID != msg.Header.ID {
		t.Fatalf("ID mismatch: got %x want %x", parsed.Header.ID, msg.Header.ID)
	}
	if !parsed.Header.RecursionDesired() {
		t.Fatalf("expected RD flag to be set")
	}
	if len(parsed.Questions) != 1 {
		t.Fatalf("expected 1 question, got %d", len(parsed.Questions))
	}
	if parsed.Questions[0].Name != "github.com" || parsed.Questions[0].Type != TypeA {
		t.Fatalf("unexpected question: %+v", parsed.Questions[0])
	}
}

func TestParseCompressedMXResponse(t *testing.T) {
	questionName := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	answerMX := []byte{
		0xc0, 0x0c,
		0x00, 0x0f,
		0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c,
		0x00, 0x09,
		0x00, 0x0a,
		0x04, 'm', 'a', 'i', 'l', 0xc0, 0x0c,
	}
	answerA := []byte{
		0x04, 'm', 'a', 'i', 'l', 0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c,
		0x00, 0x04,
		192, 0, 2, 25,
	}

	wire := make([]byte, 12)
	binary.BigEndian.PutUint16(wire[0:2], 0x1234)
	binary.BigEndian.PutUint16(wire[2:4], 0x8180)
	binary.BigEndian.PutUint16(wire[4:6], 1)
	binary.BigEndian.PutUint16(wire[6:8], 2)
	wire = append(wire, questionName...)
	wire = append(wire, 0x00, 0x0f, 0x00, 0x01)
	wire = append(wire, answerMX...)
	wire = append(wire, answerA...)

	msg, err := ParseMessage(wire)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}

	if len(msg.Answers) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(msg.Answers))
	}

	mx := msg.Answers[0]
	if mx.Name != "example.com" || mx.Type != TypeMX || mx.Data != "mail.example.com" || mx.MXPreference != 10 {
		t.Fatalf("unexpected MX record: %+v", mx)
	}

	a := msg.Answers[1]
	if a.Name != "mail.example.com" || a.Type != TypeA {
		t.Fatalf("unexpected A record header: %+v", a)
	}
	if !a.IP.Equal(net.IPv4(192, 0, 2, 25)) {
		t.Fatalf("unexpected A record ip: %v", a.IP)
	}
}

func TestParseMessageRejectsTruncatedPacket(t *testing.T) {
	_, err := ParseMessage([]byte{0, 1, 2})
	if err == nil {
		t.Fatalf("expected error for truncated DNS packet")
	}
}
