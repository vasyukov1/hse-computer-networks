package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	EtherTypeIPv4 = 0x0800
	ProtocolICMP  = 1
	ProtocolTCP   = 6
	ProtocolUDP   = 17
)

type EthernetFrame struct {
	Destination net.HardwareAddr
	Source      net.HardwareAddr
	EtherType   uint16
	Payload     []byte
}

type IPv4Packet struct {
	VersionIHL     uint8
	TOS            uint8
	TotalLength    uint16
	Identification uint16
	FlagsFragment  uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	Source         net.IP
	Destination    net.IP
	Options        []byte
	Payload        []byte
}

type UDPDatagram struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
	Payload         []byte
}

type TCPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	DataOffset      uint8
	Flags           uint16
	Payload         []byte
}

func (f EthernetFrame) MarshalBinary() ([]byte, error) {
	if len(f.Destination) != 6 || len(f.Source) != 6 {
		return nil, errors.New("Ethernet frame требует MAC длиной 6 байт")
	}
	out := make([]byte, 14+len(f.Payload))
	copy(out[0:6], f.Destination)
	copy(out[6:12], f.Source)
	binary.BigEndian.PutUint16(out[12:14], f.EtherType)
	copy(out[14:], f.Payload)
	return out, nil
}

func ParseEthernetFrame(data []byte) (EthernetFrame, error) {
	if len(data) < 14 {
		return EthernetFrame{}, fmt.Errorf("слишком короткий Ethernet кадр: %d", len(data))
	}
	return EthernetFrame{
		Destination: append(net.HardwareAddr(nil), data[0:6]...),
		Source:      append(net.HardwareAddr(nil), data[6:12]...),
		EtherType:   binary.BigEndian.Uint16(data[12:14]),
		Payload:     append([]byte(nil), data[14:]...),
	}, nil
}

func (p IPv4Packet) MarshalBinary() ([]byte, error) {
	src := p.Source.To4()
	dst := p.Destination.To4()
	if src == nil || dst == nil {
		return nil, errors.New("IPv4 packet требует IPv4 source/destination")
	}

	ihl := 5 + len(p.Options)/4
	headerLen := ihl * 4
	out := make([]byte, headerLen+len(p.Payload))
	out[0] = uint8((4 << 4) | ihl)
	out[1] = p.TOS
	totalLength := uint16(len(out))
	binary.BigEndian.PutUint16(out[2:4], totalLength)
	binary.BigEndian.PutUint16(out[4:6], p.Identification)
	binary.BigEndian.PutUint16(out[6:8], p.FlagsFragment)
	if p.TTL == 0 {
		p.TTL = 64
	}
	out[8] = p.TTL
	out[9] = p.Protocol
	copy(out[12:16], src)
	copy(out[16:20], dst)
	if len(p.Options) > 0 {
		copy(out[20:headerLen], p.Options)
	}
	copy(out[headerLen:], p.Payload)

	checksum := Checksum(out[:headerLen])
	binary.BigEndian.PutUint16(out[10:12], checksum)
	return out, nil
}

func ParseIPv4Packet(data []byte) (IPv4Packet, error) {
	if len(data) < 20 {
		return IPv4Packet{}, fmt.Errorf("слишком короткий IPv4 пакет: %d", len(data))
	}
	version := data[0] >> 4
	ihl := int(data[0]&0x0f) * 4
	if version != 4 || ihl < 20 || len(data) < ihl {
		return IPv4Packet{}, errors.New("некорректный IPv4 заголовок")
	}
	totalLength := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLength < ihl || totalLength > len(data) {
		totalLength = len(data)
	}

	return IPv4Packet{
		VersionIHL:     data[0],
		TOS:            data[1],
		TotalLength:    uint16(totalLength),
		Identification: binary.BigEndian.Uint16(data[4:6]),
		FlagsFragment:  binary.BigEndian.Uint16(data[6:8]),
		TTL:            data[8],
		Protocol:       data[9],
		HeaderChecksum: binary.BigEndian.Uint16(data[10:12]),
		Source:         append(net.IP(nil), data[12:16]...),
		Destination:    append(net.IP(nil), data[16:20]...),
		Options:        append([]byte(nil), data[20:ihl]...),
		Payload:        append([]byte(nil), data[ihl:totalLength]...),
	}, nil
}

func (u UDPDatagram) MarshalBinary(srcIP, dstIP net.IP) ([]byte, error) {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return nil, errors.New("UDP checksum требует IPv4 адреса")
	}
	out := make([]byte, 8+len(u.Payload))
	binary.BigEndian.PutUint16(out[0:2], u.SourcePort)
	binary.BigEndian.PutUint16(out[2:4], u.DestinationPort)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)))
	copy(out[8:], u.Payload)
	checksum := UDPChecksum(src, dst, out)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(out[6:8], checksum)
	return out, nil
}

func ParseUDPDatagram(data []byte) (UDPDatagram, error) {
	if len(data) < 8 {
		return UDPDatagram{}, fmt.Errorf("слишком короткий UDP сегмент: %d", len(data))
	}
	length := int(binary.BigEndian.Uint16(data[4:6]))
	if length < 8 || length > len(data) {
		length = len(data)
	}
	return UDPDatagram{
		SourcePort:      binary.BigEndian.Uint16(data[0:2]),
		DestinationPort: binary.BigEndian.Uint16(data[2:4]),
		Length:          uint16(length),
		Checksum:        binary.BigEndian.Uint16(data[6:8]),
		Payload:         append([]byte(nil), data[8:length]...),
	}, nil
}

func ParseTCPHeader(data []byte) (TCPHeader, error) {
	if len(data) < 20 {
		return TCPHeader{}, fmt.Errorf("слишком короткий TCP сегмент: %d", len(data))
	}
	offset := int((data[12] >> 4) * 4)
	if offset < 20 || offset > len(data) {
		return TCPHeader{}, errors.New("некорректный TCP data offset")
	}
	flags := binary.BigEndian.Uint16(data[12:14]) & 0x01ff
	return TCPHeader{
		SourcePort:      binary.BigEndian.Uint16(data[0:2]),
		DestinationPort: binary.BigEndian.Uint16(data[2:4]),
		DataOffset:      uint8(offset),
		Flags:           flags,
		Payload:         append([]byte(nil), data[offset:]...),
	}, nil
}

func UDPChecksum(srcIP, dstIP net.IP, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = ProtocolUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	return Checksum(pseudo)
}

func Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
