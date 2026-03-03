package commands

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/pcap"

	"hw02arp/internal/arp"
	"hw02arp/internal/sysinfo"
)

// DiscoverCommand отправляет ARP request и ожидает ARP reply от роутера
type DiscoverCommand struct {
	env Env
}

func NewDiscoverCommand(env Env) *DiscoverCommand {
	return &DiscoverCommand{env: env}
}

func (c *DiscoverCommand) Name() string {
	return "discover"
}

func (c *DiscoverCommand) Description() string {
	return "узнать MAC-адрес роутера через ARP"
}

func (c *DiscoverCommand) Usage() string {
	return "discover [router-ip] [timeout-sec]"
}

func (c *DiscoverCommand) Run(ctx context.Context, args []string) error {
	ifaceInfo, err := sysinfo.InterfaceInfoByName(c.env.InterfaceName)
	if err != nil {
		return err
	}

	routerIP, err := c.resolveRouterIP(ctx, args)
	if err != nil {
		return err
	}

	wait := c.env.DiscoveryWait
	if len(args) >= 2 {
		customWait, err := parsePositiveSeconds(args[1])
		if err != nil {
			return err
		}
		wait = customWait
	}

	env := c.env
	env.DiscoveryWait = wait

	routerMAC, err := resolveRouterMAC(ctx, env, ifaceInfo, routerIP)
	if err != nil {
		return err
	}

	fmt.Printf("Интерфейс: %s\n", ifaceInfo.Name)
	fmt.Printf("Локальный IP: %s\n", ifaceInfo.IPv4)
	fmt.Printf("Локальный MAC: %s\n", ifaceInfo.MAC)
	fmt.Printf("Router IP: %s\n", routerIP)
	fmt.Printf("Router MAC: %s\n", routerMAC)
	return nil
}

func (c *DiscoverCommand) resolveRouterIP(ctx context.Context, args []string) (net.IP, error) {
	if len(args) >= 1 {
		ip := net.ParseIP(args[0]).To4()
		if ip == nil {
			return nil, fmt.Errorf("некорректный IPv4 роутера: %q", args[0])
		}
		return ip, nil
	}
	return sysinfo.DetectDefaultGatewayIPv4ForInterface(ctx, c.env.InterfaceName)
}

// resolveRouterMAC отправляет ARP request и ожидает корректный ARP reply
func resolveRouterMAC(ctx context.Context, env Env, iface sysinfo.InterfaceInfo, routerIP net.IP) (net.HardwareAddr, error) {
	h, err := pcap.OpenLive(env.InterfaceName, env.SnapLen, true, env.ReadTimeoutMS)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть pcap на %s: %w", env.InterfaceName, err)
	}
	defer h.Close()

	if err := h.SetFilter("arp"); err != nil {
		return nil, fmt.Errorf("не удалось установить BPF фильтр arp: %w", err)
	}

	requestFrame, err := buildARPRequestFrame(iface, routerIP)
	if err != nil {
		return nil, err
	}

	tries := env.DiscoveryTries
	if tries <= 0 {
		tries = 1
	}
	perAttemptWait := env.DiscoveryWait
	if perAttemptWait <= 0 {
		perAttemptWait = 2 * time.Second
	}

	for attempt := 1; attempt <= tries; attempt++ {
		if err := h.Inject(requestFrame); err != nil {
			return nil, fmt.Errorf("ошибка отправки ARP запроса: %w", err)
		}

		deadlineCtx, cancel := context.WithTimeout(ctx, perAttemptWait)
		mac, waitErr := waitRouterARPReply(deadlineCtx, h, iface, routerIP)
		cancel()
		if waitErr == nil {
			return mac, nil
		}

		if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		return nil, waitErr
	}

	return nil, fmt.Errorf("роутер %s не ответил на ARP после %d попыток", routerIP, tries)
}

func waitRouterARPReply(ctx context.Context, h *pcap.Pcap, iface sysinfo.InterfaceInfo, routerIP net.IP) (net.HardwareAddr, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkt, result := h.NextEx()
		switch result {
		case 0:
			continue
		case -1:
			return nil, h.Geterror()
		case -2:
			return nil, errors.New("неожиданный EOF от pcap")
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
		if arpPkt.Operation != arp.OperationReply {
			continue
		}
		if !arpPkt.SenderIP.Equal(routerIP) {
			continue
		}
		if !arpPkt.TargetIP.Equal(iface.IPv4.To4()) {
			continue
		}

		return net.HardwareAddr(append([]byte(nil), arpPkt.SenderHWAddr...)), nil
	}
}

func buildARPRequestFrame(iface sysinfo.InterfaceInfo, routerIP net.IP) ([]byte, error) {
	arpRequest := arp.ARPPacket{
		HardwareType: arp.HardwareTypeEthernet,
		ProtocolType: arp.ProtocolTypeIPv4,
		HardwareSize: arp.EthAddrLen,
		ProtocolSize: arp.IPv4AddrLen,
		Operation:    arp.OperationRequest,
		SenderHWAddr: append([]byte(nil), iface.MAC...),
		SenderIP:     iface.IPv4.To4(),
		TargetHWAddr: append([]byte(nil), arp.ZeroMAC...),
		TargetIP:     routerIP.To4(),
	}

	arpPayload, err := arpRequest.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("не удалось сериализовать ARP request: %w", err)
	}

	eth := arp.EthernetFrame{
		Destination: append(net.HardwareAddr(nil), arp.BroadcastMAC...),
		Source:      append(net.HardwareAddr(nil), iface.MAC...),
		EtherType:   arp.EtherTypeARP,
		Payload:     arpPayload,
	}

	frame, err := eth.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("не удалось сериализовать Ethernet frame: %w", err)
	}
	return frame, nil
}
