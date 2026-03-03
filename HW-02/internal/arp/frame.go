package arp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	EthernetHeaderLen = 14
	EthAddrLen        = 6
	IPv4AddrLen       = 4

	HardwareTypeEthernet = 1
	ProtocolTypeIPv4     = 0x0800

	EtherTypeARP = 0x0806

	OperationRequest = 1
	OperationReply   = 2
)

var (
	BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ZeroMAC      = net.HardwareAddr{0, 0, 0, 0, 0, 0}
)

// EthernetFrame представляет заголовок Ethernet и полезную нагрузку
type EthernetFrame struct {
	Destination net.HardwareAddr
	Source      net.HardwareAddr
	EtherType   uint16
	Payload     []byte
}

// MarshalBinary сериализует Ethernet-кадр в байты
func (f EthernetFrame) MarshalBinary() ([]byte, error) {
	if len(f.Destination) != EthAddrLen {
		return nil, fmt.Errorf("некорректная длина Destination MAC: %d", len(f.Destination))
	}
	if len(f.Source) != EthAddrLen {
		return nil, fmt.Errorf("некорректная длина Source MAC: %d", len(f.Source))
	}

	out := make([]byte, EthernetHeaderLen+len(f.Payload))
	copy(out[0:6], f.Destination)
	copy(out[6:12], f.Source)
	binary.BigEndian.PutUint16(out[12:14], f.EtherType)
	copy(out[14:], f.Payload)
	return out, nil
}

// ParseEthernetFrame разбирает Ethernet-кадр из сырых байт
func ParseEthernetFrame(data []byte) (EthernetFrame, error) {
	if len(data) < EthernetHeaderLen {
		return EthernetFrame{}, fmt.Errorf("слишком короткий Ethernet-кадр: %d байт", len(data))
	}

	frame := EthernetFrame{
		Destination: append(net.HardwareAddr(nil), data[0:6]...),
		Source:      append(net.HardwareAddr(nil), data[6:12]...),
		EtherType:   binary.BigEndian.Uint16(data[12:14]),
		Payload:     append([]byte(nil), data[14:]...),
	}
	return frame, nil
}

// ARPPacket представляет ARP заголовок и ARP payload
type ARPPacket struct {
	HardwareType uint16
	ProtocolType uint16
	HardwareSize uint8
	ProtocolSize uint8
	Operation    uint16

	SenderHWAddr []byte
	SenderIP     net.IP
	TargetHWAddr []byte
	TargetIP     net.IP
}

// MarshalBinary сериализует ARP-пакет
func (a ARPPacket) MarshalBinary() ([]byte, error) {
	if a.HardwareSize == 0 || a.ProtocolSize == 0 {
		return nil, errors.New("в ARP не заданы размеры аппаратного/протокольного адреса")
	}
	if len(a.SenderHWAddr) != int(a.HardwareSize) {
		return nil, fmt.Errorf("длина SenderHWAddr (%d) не совпадает с HardwareSize (%d)", len(a.SenderHWAddr), a.HardwareSize)
	}
	if len(a.TargetHWAddr) != int(a.HardwareSize) {
		return nil, fmt.Errorf("длина TargetHWAddr (%d) не совпадает с HardwareSize (%d)", len(a.TargetHWAddr), a.HardwareSize)
	}

	senderIP := normalizeIP(a.SenderIP, int(a.ProtocolSize))
	targetIP := normalizeIP(a.TargetIP, int(a.ProtocolSize))
	if len(senderIP) != int(a.ProtocolSize) || len(targetIP) != int(a.ProtocolSize) {
		return nil, fmt.Errorf("длина IP-адреса должна быть %d", a.ProtocolSize)
	}

	payloadLen := 8 + 2*int(a.HardwareSize) + 2*int(a.ProtocolSize)
	out := make([]byte, payloadLen)

	binary.BigEndian.PutUint16(out[0:2], a.HardwareType)
	binary.BigEndian.PutUint16(out[2:4], a.ProtocolType)
	out[4] = a.HardwareSize
	out[5] = a.ProtocolSize
	binary.BigEndian.PutUint16(out[6:8], a.Operation)

	off := 8
	copy(out[off:off+int(a.HardwareSize)], a.SenderHWAddr)
	off += int(a.HardwareSize)
	copy(out[off:off+int(a.ProtocolSize)], senderIP)
	off += int(a.ProtocolSize)
	copy(out[off:off+int(a.HardwareSize)], a.TargetHWAddr)
	off += int(a.HardwareSize)
	copy(out[off:off+int(a.ProtocolSize)], targetIP)

	return out, nil
}

// ParseARPPacket разбирает ARP-пакет из payload Ethernet-кадра
func ParseARPPacket(data []byte) (ARPPacket, error) {
	if len(data) < 8 {
		return ARPPacket{}, fmt.Errorf("слишком короткий ARP payload: %d", len(data))
	}

	pkt := ARPPacket{
		HardwareType: binary.BigEndian.Uint16(data[0:2]),
		ProtocolType: binary.BigEndian.Uint16(data[2:4]),
		HardwareSize: data[4],
		ProtocolSize: data[5],
		Operation:    binary.BigEndian.Uint16(data[6:8]),
	}

	need := 8 + 2*int(pkt.HardwareSize) + 2*int(pkt.ProtocolSize)
	if len(data) < need {
		return ARPPacket{}, fmt.Errorf("недостаточно данных для ARP: нужно %d, есть %d", need, len(data))
	}

	off := 8
	pkt.SenderHWAddr = append([]byte(nil), data[off:off+int(pkt.HardwareSize)]...)
	off += int(pkt.HardwareSize)
	pkt.SenderIP = append(net.IP(nil), data[off:off+int(pkt.ProtocolSize)]...)
	off += int(pkt.ProtocolSize)
	pkt.TargetHWAddr = append([]byte(nil), data[off:off+int(pkt.HardwareSize)]...)
	off += int(pkt.HardwareSize)
	pkt.TargetIP = append(net.IP(nil), data[off:off+int(pkt.ProtocolSize)]...)

	return pkt, nil
}

func (a ARPPacket) OperationString() string {
	switch a.Operation {
	case OperationRequest:
		return "request"
	case OperationReply:
		return "reply"
	default:
		return fmt.Sprintf("unknown(%d)", a.Operation)
	}
}

func IsBroadcastMAC(mac net.HardwareAddr) bool {
	return len(mac) == EthAddrLen && bytes.Equal(mac, BroadcastMAC)
}

func IsZeroMAC(mac []byte) bool {
	if len(mac) != EthAddrLen {
		return false
	}
	return bytes.Equal(mac, ZeroMAC)
}

// Gratuitous ARP request: sender IP == target IP и операция request
func IsGratuitousARPRequest(pkt ARPPacket) bool {
	if pkt.Operation != OperationRequest {
		return false
	}
	return pkt.SenderIP.To4() != nil && pkt.TargetIP.To4() != nil && pkt.SenderIP.Equal(pkt.TargetIP)
}

func normalizeIP(ip net.IP, size int) []byte {
	if size == IPv4AddrLen {
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	}
	return ip
}
