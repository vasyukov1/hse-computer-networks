package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/pcap"

	"hw03dns/internal/dns"
	"hw03dns/internal/packet"
)

type SniffCommand struct {
	env Env
}

func NewSniffCommand(env Env) *SniffCommand {
	return &SniffCommand{env: env}
}

func (c *SniffCommand) Name() string {
	return "sniff"
}

func (c *SniffCommand) Description() string {
	return "захват DNS пакетов в promiscuous режиме"
}

func (c *SniffCommand) Usage() string {
	return "sniff [seconds]"
}

func (c *SniffCommand) Run(ctx context.Context, args []string) error {
	duration := 30 * time.Second
	if len(args) >= 1 {
		d, err := parsePositiveSeconds(args[0])
		if err != nil {
			return err
		}
		duration = d
	}

	handle, err := pcap.OpenLive(c.env.Summary.Interface.Name, c.env.SnapLen, true, c.env.ReadTimeoutMS)
	if err != nil {
		return fmt.Errorf("не удалось открыть pcap на %s: %w", c.env.Summary.Interface.Name, err)
	}
	defer handle.Close()

	filter := "udp port 53 or tcp port 53"
	if err := handle.SetFilter(filter); err != nil {
		return fmt.Errorf("не удалось установить BPF фильтр %q: %w", filter, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	fmt.Printf("Sniffer запущен на %s на %s\n", c.env.Summary.Interface.Name, duration)
	fmt.Println("Формат: [timestamp] MAC/IP/port -> MAC/IP/port | transport | DNS id flags rcode | секции")

	for {
		if runCtx.Err() != nil {
			fmt.Println("Sniffer завершен по таймеру")
			return nil
		}

		pkt, result := handle.NextEx()
		switch result {
		case 0:
			continue
		case -1:
			return handle.Geterror()
		case -2:
			return errors.New("неожиданный EOF от pcap")
		case 1:
			if pkt == nil {
				continue
			}
		default:
			continue
		}

		line, ok := formatDNSPacket(pkt.Time, pkt.Data)
		if ok {
			fmt.Println(line)
		}
	}
}

func formatDNSPacket(ts time.Time, frame []byte) (string, bool) {
	eth, err := packet.ParseEthernetFrame(frame)
	if err != nil || eth.EtherType != packet.EtherTypeIPv4 {
		return "", false
	}
	ip, err := packet.ParseIPv4Packet(eth.Payload)
	if err != nil {
		return "", false
	}

	var (
		srcPort, dstPort uint16
		transport        string
		payload          []byte
	)
	switch ip.Protocol {
	case packet.ProtocolUDP:
		udp, err := packet.ParseUDPDatagram(ip.Payload)
		if err != nil {
			return "", false
		}
		srcPort, dstPort = udp.SourcePort, udp.DestinationPort
		payload = udp.Payload
		transport = "udp"
	case packet.ProtocolTCP:
		tcpHdr, err := packet.ParseTCPHeader(ip.Payload)
		if err != nil || len(tcpHdr.Payload) < 2 {
			return "", false
		}
		srcPort, dstPort = tcpHdr.SourcePort, tcpHdr.DestinationPort
		length := int(tcpHdr.Payload[0])<<8 | int(tcpHdr.Payload[1])
		if length <= 0 || 2+length > len(tcpHdr.Payload) {
			payload = tcpHdr.Payload[2:]
		} else {
			payload = tcpHdr.Payload[2 : 2+length]
		}
		transport = "tcp"
	default:
		return "", false
	}

	msg, err := dns.ParseMessage(payload)
	if err != nil {
		return "", false
	}

	return fmt.Sprintf("[%s] %s/%s:%d -> %s/%s:%d | %s | DNS id=0x%04x %s %s | %s",
		ts.Format(time.RFC3339Nano),
		eth.Source,
		ip.Source,
		srcPort,
		eth.Destination,
		ip.Destination,
		dstPort,
		transport,
		msg.Header.ID,
		msg.Header.FlagSummary(),
		dns.RCodeString(msg.Header.RCode()),
		dns.SummarizeMessage(msg),
	), true
}
