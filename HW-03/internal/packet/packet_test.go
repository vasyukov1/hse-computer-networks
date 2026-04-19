package packet

import (
	"net"
	"testing"
)

func TestIPv4AndUDPRoundTrip(t *testing.T) {
	srcIP := net.IPv4(10, 0, 0, 2)
	dstIP := net.IPv4(8, 8, 8, 8)

	udpWire, err := (UDPDatagram{
		SourcePort:      53000,
		DestinationPort: 53,
		Payload:         []byte{1, 2, 3, 4, 5},
	}).MarshalBinary(srcIP, dstIP)
	if err != nil {
		t.Fatalf("UDP MarshalBinary() error = %v", err)
	}
	if got := UDPChecksum(srcIP, dstIP, udpWire); got != 0 {
		t.Fatalf("expected valid UDP checksum, got 0x%04x", got)
	}

	ipWire, err := (IPv4Packet{
		Identification: 0x4567,
		TTL:            64,
		Protocol:       ProtocolUDP,
		Source:         srcIP,
		Destination:    dstIP,
		Payload:        udpWire,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("IPv4 MarshalBinary() error = %v", err)
	}
	if got := Checksum(ipWire[:20]); got != 0 {
		t.Fatalf("expected valid IPv4 checksum, got 0x%04x", got)
	}

	ipPacket, err := ParseIPv4Packet(ipWire)
	if err != nil {
		t.Fatalf("ParseIPv4Packet() error = %v", err)
	}
	if !ipPacket.Source.Equal(srcIP) || !ipPacket.Destination.Equal(dstIP) {
		t.Fatalf("unexpected IPv4 addresses: %+v", ipPacket)
	}

	udpPacket, err := ParseUDPDatagram(ipPacket.Payload)
	if err != nil {
		t.Fatalf("ParseUDPDatagram() error = %v", err)
	}
	if udpPacket.SourcePort != 53000 || udpPacket.DestinationPort != 53 {
		t.Fatalf("unexpected UDP ports: %+v", udpPacket)
	}
	if string(udpPacket.Payload) != string([]byte{1, 2, 3, 4, 5}) {
		t.Fatalf("unexpected UDP payload: %v", udpPacket.Payload)
	}
}

func TestParseTCPHeaderRejectsShortPacket(t *testing.T) {
	if _, err := ParseTCPHeader([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for short TCP packet")
	}
}
