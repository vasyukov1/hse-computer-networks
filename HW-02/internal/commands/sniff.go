package commands

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/pcap"

	"hw02arp/internal/arp"
)

// SniffCommand перехватывает ARP трафик и печатает поля кадров
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
	return "захват ARP-пакетов в promiscuous режиме"
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

	runCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	h, err := pcap.OpenLive(c.env.InterfaceName, c.env.SnapLen, true, c.env.ReadTimeoutMS)
	if err != nil {
		return fmt.Errorf("не удалось открыть pcap на %s: %w", c.env.InterfaceName, err)
	}
	defer h.Close()

	if err := h.SetFilter("arp"); err != nil {
		return fmt.Errorf("не удалось установить BPF фильтр arp: %w", err)
	}

	fmt.Printf("Sniffer запущен на %s на %s\n", c.env.InterfaceName, duration)
	fmt.Println("Формат вывода: [timestamp] src-mac -> dst-mac | ARP op | sender-ip(sender-mac) -> target-ip(target-mac)")

	for {
		if runCtx.Err() != nil {
			fmt.Println("Sniffer завершен по таймеру")
			return nil
		}

		pkt, result := h.NextEx()
		switch result {
		case 0:
			continue
		case -1:
			return h.Geterror()
		case -2:
			return errors.New("неожиданный EOF от pcap")
		case 1:
			if pkt == nil {
				continue
			}
		default:
			continue
		}

		frame, err := arp.ParseEthernetFrame(pkt.Data)
		if err != nil || frame.EtherType != arp.EtherTypeARP {
			continue
		}

		arpPkt, err := arp.ParseARPPacket(frame.Payload)
		if err != nil {
			continue
		}

		fmt.Printf("[%s] %s -> %s | ARP %s | %s(%s) -> %s(%s)\n",
			pkt.Time.Format(time.RFC3339Nano),
			normalizeMAC(frame.Source),
			normalizeMAC(frame.Destination),
			arpPkt.OperationString(),
			arpPkt.SenderIP,
			normalizeMAC(arpPkt.SenderHWAddr),
			arpPkt.TargetIP,
			normalizeMAC(arpPkt.TargetHWAddr),
		)
	}
}

func normalizeMAC(mac []byte) string {
	hw := net.HardwareAddr(mac)
	if len(hw) == 0 {
		return "<empty>"
	}
	return hw.String()
}
