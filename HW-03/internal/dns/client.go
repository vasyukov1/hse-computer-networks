package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/pcap"

	"hw03dns/internal/arp"
	"hw03dns/internal/packet"
	"hw03dns/internal/sysinfo"
)

type ClientConfig struct {
	SnapLen       int32
	ReadTimeoutMS int32
	ARPWait       time.Duration
	ARPRetryCount int
	DNSWait       time.Duration
}

type ExchangeResult struct {
	ServerIP      net.IP
	NextHopIP     net.IP
	NextHopMAC    net.HardwareAddr
	SourcePort    uint16
	Query         Message
	Response      Message
	ResponseFrame packet.EthernetFrame
	ResponseIP    packet.IPv4Packet
	ResponseUDP   packet.UDPDatagram
}

func ExchangeRawUDP(ctx context.Context, summary sysinfo.NetworkSummary, cfg ClientConfig, serverIP net.IP, msg Message) (ExchangeResult, error) {
	serverIP = serverIP.To4()
	if serverIP == nil {
		return ExchangeResult{}, errors.New("ExchangeRawUDP требует IPv4 адрес DNS сервера")
	}

	nextHopIP := sysinfo.NextHopIPv4(summary, serverIP)
	nextHopMAC, err := arp.ResolveIPv4(ctx, summary.Interface, nextHopIP, cfg.SnapLen, cfg.ReadTimeoutMS, cfg.ARPWait, cfg.ARPRetryCount)
	if err != nil {
		return ExchangeResult{}, err
	}

	handle, err := pcap.OpenLive(summary.Interface.Name, cfg.SnapLen, true, cfg.ReadTimeoutMS)
	if err != nil {
		return ExchangeResult{}, fmt.Errorf("не удалось открыть pcap на %s: %w", summary.Interface.Name, err)
	}
	defer handle.Close()

	sourcePort := randomEphemeralPort()
	filter := fmt.Sprintf("udp and src host %s and dst host %s and src port 53 and dst port %d",
		serverIP.String(),
		summary.Interface.IPv4.String(),
		sourcePort,
	)
	if err := handle.SetFilter(filter); err != nil {
		return ExchangeResult{}, fmt.Errorf("не удалось установить BPF фильтр %q: %w", filter, err)
	}

	queryBytes, err := msg.MarshalBinary()
	if err != nil {
		return ExchangeResult{}, err
	}
	frameBytes, err := buildDNSFrame(summary, nextHopMAC, serverIP, sourcePort, queryBytes)
	if err != nil {
		return ExchangeResult{}, err
	}

	if err := handle.Inject(frameBytes); err != nil {
		return ExchangeResult{}, fmt.Errorf("не удалось отправить Ethernet frame: %w", err)
	}

	wait := cfg.DNSWait
	if wait <= 0 {
		wait = 5 * time.Second
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	for {
		if deadlineCtx.Err() != nil {
			return ExchangeResult{}, deadlineCtx.Err()
		}
		pkt, result := handle.NextEx()
		switch result {
		case 0:
			continue
		case -1:
			return ExchangeResult{}, handle.Geterror()
		case -2:
			return ExchangeResult{}, errors.New("неожиданный EOF от pcap")
		case 1:
			if pkt == nil {
				continue
			}
		default:
			continue
		}

		eth, ip, udp, response, err := parseDNSPacket(pkt.Data)
		if err != nil {
			continue
		}
		if !response.Header.IsResponse() || response.Header.ID != msg.Header.ID {
			continue
		}
		if !ip.Source.Equal(serverIP) || !ip.Destination.Equal(summary.Interface.IPv4.To4()) {
			continue
		}
		if udp.DestinationPort != sourcePort {
			continue
		}

		return ExchangeResult{
			ServerIP:      serverIP,
			NextHopIP:     nextHopIP,
			NextHopMAC:    nextHopMAC,
			SourcePort:    sourcePort,
			Query:         msg,
			Response:      response,
			ResponseFrame: eth,
			ResponseIP:    ip,
			ResponseUDP:   udp,
		}, nil
	}
}

func buildDNSFrame(summary sysinfo.NetworkSummary, dstMAC net.HardwareAddr, serverIP net.IP, sourcePort uint16, dnsPayload []byte) ([]byte, error) {
	udpPayload, err := (packet.UDPDatagram{
		SourcePort:      sourcePort,
		DestinationPort: 53,
		Payload:         dnsPayload,
	}).MarshalBinary(summary.Interface.IPv4, serverIP)
	if err != nil {
		return nil, err
	}

	ipPayload, err := (packet.IPv4Packet{
		Identification: uint16(rand.Intn(65535)),
		FlagsFragment:  0,
		TTL:            64,
		Protocol:       packet.ProtocolUDP,
		Source:         summary.Interface.IPv4,
		Destination:    serverIP,
		Payload:        udpPayload,
	}).MarshalBinary()
	if err != nil {
		return nil, err
	}

	return (packet.EthernetFrame{
		Destination: dstMAC,
		Source:      summary.Interface.MAC,
		EtherType:   packet.EtherTypeIPv4,
		Payload:     ipPayload,
	}).MarshalBinary()
}

func parseDNSPacket(frame []byte) (packet.EthernetFrame, packet.IPv4Packet, packet.UDPDatagram, Message, error) {
	eth, err := packet.ParseEthernetFrame(frame)
	if err != nil {
		return packet.EthernetFrame{}, packet.IPv4Packet{}, packet.UDPDatagram{}, Message{}, err
	}
	if eth.EtherType != packet.EtherTypeIPv4 {
		return packet.EthernetFrame{}, packet.IPv4Packet{}, packet.UDPDatagram{}, Message{}, errors.New("не IPv4")
	}
	ip, err := packet.ParseIPv4Packet(eth.Payload)
	if err != nil {
		return packet.EthernetFrame{}, packet.IPv4Packet{}, packet.UDPDatagram{}, Message{}, err
	}
	if ip.Protocol != packet.ProtocolUDP {
		return packet.EthernetFrame{}, packet.IPv4Packet{}, packet.UDPDatagram{}, Message{}, errors.New("не UDP")
	}
	udp, err := packet.ParseUDPDatagram(ip.Payload)
	if err != nil {
		return packet.EthernetFrame{}, packet.IPv4Packet{}, packet.UDPDatagram{}, Message{}, err
	}
	msg, err := ParseMessage(udp.Payload)
	if err != nil {
		return packet.EthernetFrame{}, packet.IPv4Packet{}, packet.UDPDatagram{}, Message{}, err
	}
	return eth, ip, udp, msg, nil
}

func CollectMXRecords(msg Message) []ResourceRecord {
	var out []ResourceRecord
	for _, rr := range msg.Answers {
		if rr.Type == TypeMX {
			out = append(out, rr)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MXPreference == out[j].MXPreference {
			return out[i].Data < out[j].Data
		}
		return out[i].MXPreference < out[j].MXPreference
	})
	return out
}

func CollectARecords(msg Message) []net.IP {
	seen := make(map[string]struct{})
	var result []net.IP
	for _, rr := range append(append([]ResourceRecord{}, msg.Answers...), msg.Additionals...) {
		if rr.Type != TypeA || rr.IP.To4() == nil {
			continue
		}
		key := rr.IP.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, rr.IP.To4())
	}
	return result
}

func SummarizeMessage(msg Message) string {
	var parts []string
	if len(msg.Questions) > 0 {
		var questions []string
		for _, q := range msg.Questions {
			questions = append(questions, fmt.Sprintf("%s %s", q.Name, TypeString(q.Type)))
		}
		parts = append(parts, "Q="+strings.Join(questions, "; "))
	}
	if len(msg.Answers) > 0 {
		parts = append(parts, "AN="+summarizeRRs(msg.Answers))
	}
	if len(msg.Authorities) > 0 {
		parts = append(parts, "NS="+summarizeRRs(msg.Authorities))
	}
	if len(msg.Additionals) > 0 {
		parts = append(parts, "AR="+summarizeRRs(msg.Additionals))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " | ")
}

func summarizeRRs(records []ResourceRecord) string {
	const maxItems = 4
	var parts []string
	for i, rr := range records {
		if i == maxItems {
			parts = append(parts, fmt.Sprintf("... +%d", len(records)-maxItems))
			break
		}
		value := rr.Data
		if rr.Type == TypeMX {
			value = fmt.Sprintf("%d %s", rr.MXPreference, rr.Data)
		}
		parts = append(parts, fmt.Sprintf("%s %s", rr.Name, value))
	}
	return strings.Join(parts, "; ")
}

func randomEphemeralPort() uint16 {
	return uint16(40000 + rand.Intn(20000))
}
