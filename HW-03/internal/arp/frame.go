package arp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/pcap"

	"hw03dns/internal/sysinfo"
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

type EthernetFrame struct {
	Destination net.HardwareAddr
	Source      net.HardwareAddr
	EtherType   uint16
	Payload     []byte
}

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

func ParseEthernetFrame(data []byte) (EthernetFrame, error) {
	if len(data) < EthernetHeaderLen {
		return EthernetFrame{}, fmt.Errorf("слишком короткий Ethernet кадр: %d байт", len(data))
	}

	return EthernetFrame{
		Destination: append(net.HardwareAddr(nil), data[0:6]...),
		Source:      append(net.HardwareAddr(nil), data[6:12]...),
		EtherType:   binary.BigEndian.Uint16(data[12:14]),
		Payload:     append([]byte(nil), data[14:]...),
	}, nil
}

func (a ARPPacket) MarshalBinary() ([]byte, error) {
	if a.HardwareSize == 0 || a.ProtocolSize == 0 {
		return nil, errors.New("ARP packet не содержит размеров адресов")
	}
	if len(a.SenderHWAddr) != int(a.HardwareSize) || len(a.TargetHWAddr) != int(a.HardwareSize) {
		return nil, errors.New("длина MAC-адресов не совпадает с HardwareSize")
	}

	senderIP := a.SenderIP.To4()
	targetIP := a.TargetIP.To4()
	if len(senderIP) != int(a.ProtocolSize) || len(targetIP) != int(a.ProtocolSize) {
		return nil, errors.New("длина IPv4 адресов не совпадает с ProtocolSize")
	}

	out := make([]byte, 8+2*int(a.HardwareSize)+2*int(a.ProtocolSize))
	binary.BigEndian.PutUint16(out[0:2], a.HardwareType)
	binary.BigEndian.PutUint16(out[2:4], a.ProtocolType)
	out[4] = a.HardwareSize
	out[5] = a.ProtocolSize
	binary.BigEndian.PutUint16(out[6:8], a.Operation)

	offset := 8
	copy(out[offset:offset+int(a.HardwareSize)], a.SenderHWAddr)
	offset += int(a.HardwareSize)
	copy(out[offset:offset+int(a.ProtocolSize)], senderIP)
	offset += int(a.ProtocolSize)
	copy(out[offset:offset+int(a.HardwareSize)], a.TargetHWAddr)
	offset += int(a.HardwareSize)
	copy(out[offset:offset+int(a.ProtocolSize)], targetIP)

	return out, nil
}

func ParseARPPacket(data []byte) (ARPPacket, error) {
	if len(data) < 8 {
		return ARPPacket{}, fmt.Errorf("слишком короткий ARP payload: %d", len(data))
	}

	packet := ARPPacket{
		HardwareType: binary.BigEndian.Uint16(data[0:2]),
		ProtocolType: binary.BigEndian.Uint16(data[2:4]),
		HardwareSize: data[4],
		ProtocolSize: data[5],
		Operation:    binary.BigEndian.Uint16(data[6:8]),
	}

	need := 8 + 2*int(packet.HardwareSize) + 2*int(packet.ProtocolSize)
	if len(data) < need {
		return ARPPacket{}, fmt.Errorf("недостаточно данных для ARP: %d < %d", len(data), need)
	}

	offset := 8
	packet.SenderHWAddr = append([]byte(nil), data[offset:offset+int(packet.HardwareSize)]...)
	offset += int(packet.HardwareSize)
	packet.SenderIP = append(net.IP(nil), data[offset:offset+int(packet.ProtocolSize)]...)
	offset += int(packet.ProtocolSize)
	packet.TargetHWAddr = append([]byte(nil), data[offset:offset+int(packet.HardwareSize)]...)
	offset += int(packet.HardwareSize)
	packet.TargetIP = append(net.IP(nil), data[offset:offset+int(packet.ProtocolSize)]...)

	return packet, nil
}

func ResolveIPv4(ctx context.Context, iface sysinfo.InterfaceInfo, targetIP net.IP, snapLen, readTimeoutMS int32, wait time.Duration, tries int) (net.HardwareAddr, error) {
	handle, err := pcap.OpenLive(iface.Name, snapLen, true, readTimeoutMS)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть pcap на %s: %w", iface.Name, err)
	}
	defer handle.Close()

	if err := handle.SetFilter("arp"); err != nil {
		return nil, fmt.Errorf("не удалось установить BPF фильтр arp: %w", err)
	}

	frame, err := buildARPRequestFrame(iface, targetIP)
	if err != nil {
		return nil, err
	}

	if tries <= 0 {
		tries = 1
	}
	if wait <= 0 {
		wait = 2 * time.Second
	}

	for attempt := 0; attempt < tries; attempt++ {
		if err := handle.Inject(frame); err != nil {
			return nil, fmt.Errorf("не удалось отправить ARP request: %w", err)
		}

		deadlineCtx, cancel := context.WithTimeout(ctx, wait)
		mac, err := waitARPReply(deadlineCtx, handle, iface, targetIP)
		cancel()
		if err == nil {
			return mac, nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		return nil, err
	}

	return nil, fmt.Errorf("узел %s не ответил на ARP после %d попыток", targetIP, tries)
}

func buildARPRequestFrame(iface sysinfo.InterfaceInfo, targetIP net.IP) ([]byte, error) {
	arpRequest := ARPPacket{
		HardwareType: HardwareTypeEthernet,
		ProtocolType: ProtocolTypeIPv4,
		HardwareSize: EthAddrLen,
		ProtocolSize: IPv4AddrLen,
		Operation:    OperationRequest,
		SenderHWAddr: append([]byte(nil), iface.MAC...),
		SenderIP:     iface.IPv4.To4(),
		TargetHWAddr: append([]byte(nil), ZeroMAC...),
		TargetIP:     targetIP.To4(),
	}

	arpPayload, err := arpRequest.MarshalBinary()
	if err != nil {
		return nil, err
	}

	eth := EthernetFrame{
		Destination: append(net.HardwareAddr(nil), BroadcastMAC...),
		Source:      append(net.HardwareAddr(nil), iface.MAC...),
		EtherType:   EtherTypeARP,
		Payload:     arpPayload,
	}
	return eth.MarshalBinary()
}

func waitARPReply(ctx context.Context, handle *pcap.Pcap, iface sysinfo.InterfaceInfo, targetIP net.IP) (net.HardwareAddr, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkt, result := handle.NextEx()
		switch result {
		case 0:
			continue
		case -1:
			return nil, handle.Geterror()
		case -2:
			return nil, errors.New("неожиданный EOF от pcap")
		case 1:
			if pkt == nil {
				continue
			}
		default:
			continue
		}

		frame, err := ParseEthernetFrame(pkt.Data)
		if err != nil || frame.EtherType != EtherTypeARP {
			continue
		}
		arpPacket, err := ParseARPPacket(frame.Payload)
		if err != nil || arpPacket.Operation != OperationReply {
			continue
		}
		if !arpPacket.SenderIP.Equal(targetIP.To4()) {
			continue
		}
		if !arpPacket.TargetIP.Equal(iface.IPv4.To4()) {
			continue
		}
		return net.HardwareAddr(append([]byte(nil), arpPacket.SenderHWAddr...)), nil
	}
}

func IsBroadcastMAC(mac net.HardwareAddr) bool {
	return len(mac) == EthAddrLen && bytes.Equal(mac, BroadcastMAC)
}
