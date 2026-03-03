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

// StatsCommand собирает статистику по трафику за заданный интервал
type StatsCommand struct {
	env Env
}

func NewStatsCommand(env Env) *StatsCommand {
	return &StatsCommand{env: env}
}

func (c *StatsCommand) Name() string {
	return "stats"
}

func (c *StatsCommand) Description() string {
	return "сбор 8 метрик по Ethernet/ARP за заданное время"
}

func (c *StatsCommand) Usage() string {
	return "stats <seconds> [router-ip]"
}

func (c *StatsCommand) Run(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("использование: %s", c.Usage())
	}

	duration, err := parsePositiveSeconds(args[0])
	if err != nil {
		return err
	}

	ifaceInfo, err := sysinfo.InterfaceInfoByName(c.env.InterfaceName)
	if err != nil {
		return err
	}

	routerIP, err := c.resolveRouterIP(ctx, args)
	if err != nil {
		return err
	}

	resolveTimeout := c.env.DiscoveryWait
	if c.env.DiscoveryTries > 1 {
		resolveTimeout = resolveTimeout * time.Duration(c.env.DiscoveryTries)
	}
	resolveCtx, cancelResolve := context.WithTimeout(ctx, resolveTimeout)
	routerMAC, err := resolveRouterMAC(resolveCtx, c.env, ifaceInfo, routerIP)
	cancelResolve()
	if err != nil {
		fmt.Printf("Предупреждение: не удалось определить MAC роутера (%v). Метрика №8 будет 0.\n", err)
		routerMAC = nil
	}

	h, err := pcap.OpenLive(c.env.InterfaceName, c.env.SnapLen, true, c.env.ReadTimeoutMS)
	if err != nil {
		return fmt.Errorf("не удалось открыть pcap на %s: %w", c.env.InterfaceName, err)
	}
	defer h.Close()

	runCtx, cancelRun := context.WithTimeout(ctx, duration)
	defer cancelRun()

	fmt.Printf("Сбор статистики на %s в течение %s\n", c.env.InterfaceName, duration)
	if routerMAC != nil {
		fmt.Printf("Устройство <-> роутер: %s (%s) <-> %s (%s)\n", ifaceInfo.IPv4, ifaceInfo.MAC, routerIP, routerMAC)
	}

	collector := newStatsCollector(ifaceInfo.MAC, routerMAC)
	injectProbeARP(h, ifaceInfo, routerIP)

	for {
		if runCtx.Err() != nil {
			break
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

		collector.consume(pkt)
	}

	collector.print(duration)
	return nil
}

func injectProbeARP(h *pcap.Pcap, ifaceInfo sysinfo.InterfaceInfo, routerIP net.IP) {
	frame, err := buildARPRequestFrame(ifaceInfo, routerIP)
	if err != nil {
		fmt.Printf("Предупреждение: не удалось сформировать probe ARP request: %v\n", err)
		return
	}
	if err := h.Inject(frame); err != nil {
		fmt.Printf("Предупреждение: не удалось отправить probe ARP request: %v\n", err)
		return
	}
	fmt.Printf("Отправлен probe ARP request к роутеру %s для активации ARP-обмена.\n", routerIP)
}

func (c *StatsCommand) resolveRouterIP(ctx context.Context, args []string) (net.IP, error) {
	if len(args) >= 2 {
		ip := net.ParseIP(args[1]).To4()
		if ip == nil {
			return nil, fmt.Errorf("некорректный IPv4 роутера: %q", args[1])
		}
		return ip, nil
	}
	return sysinfo.DetectDefaultGatewayIPv4ForInterface(ctx, c.env.InterfaceName)
}

type requestKey struct {
	srcIP string
	dstIP string
}

type statsCollector struct {
	totalFrames              uint64
	arpFrames                uint64
	uniqueMACs               map[string]struct{}
	broadcastEtherFrames     uint64
	broadcastARPFrames       uint64
	gratuitousARPRequests    uint64
	targetedReqRespPairs     uint64
	bytesBetweenHostAndRoute uint64

	hostMAC   net.HardwareAddr
	routerMAC net.HardwareAddr

	pendingRequests map[requestKey]int
}

func newStatsCollector(hostMAC, routerMAC net.HardwareAddr) *statsCollector {
	return &statsCollector{
		uniqueMACs:      make(map[string]struct{}),
		hostMAC:         append(net.HardwareAddr(nil), hostMAC...),
		routerMAC:       append(net.HardwareAddr(nil), routerMAC...),
		pendingRequests: make(map[requestKey]int),
	}
}

func (s *statsCollector) consume(pkt *pcap.Packet) {
	s.totalFrames++

	frame, err := arp.ParseEthernetFrame(pkt.Data)
	if err != nil {
		return
	}

	s.addMAC(frame.Source)
	s.addMAC(frame.Destination)

	if arp.IsBroadcastMAC(frame.Destination) {
		s.broadcastEtherFrames++
	}

	if s.shouldCountBytesBetweenHostAndRouter(frame) {
		s.bytesBetweenHostAndRoute += uint64(pkt.Len)
	}

	if frame.EtherType != arp.EtherTypeARP {
		return
	}

	s.arpFrames++
	if arp.IsBroadcastMAC(frame.Destination) {
		s.broadcastARPFrames++
	}

	arpPkt, err := arp.ParseARPPacket(frame.Payload)
	if err != nil {
		return
	}

	if arp.IsGratuitousARPRequest(arpPkt) {
		s.gratuitousARPRequests++
	}

	s.matchRequestResponse(arpPkt)
}

func (s *statsCollector) shouldCountBytesBetweenHostAndRouter(frame arp.EthernetFrame) bool {
	if len(s.routerMAC) != arp.EthAddrLen {
		return false
	}
	hostToRouter := frame.Source.String() == s.hostMAC.String() && frame.Destination.String() == s.routerMAC.String()
	routerToHost := frame.Source.String() == s.routerMAC.String() && frame.Destination.String() == s.hostMAC.String()
	return hostToRouter || routerToHost
}

func (s *statsCollector) addMAC(mac net.HardwareAddr) {
	if len(mac) != arp.EthAddrLen {
		return
	}
	s.uniqueMACs[mac.String()] = struct{}{}
}

func (s *statsCollector) matchRequestResponse(pkt arp.ARPPacket) {
	sender := pkt.SenderIP.To4()
	target := pkt.TargetIP.To4()
	if sender == nil || target == nil {
		return
	}

	senderS := sender.String()
	targetS := target.String()

	switch pkt.Operation {
	case arp.OperationRequest:
		if senderS == targetS {
			return
		}
		k := requestKey{srcIP: senderS, dstIP: targetS}
		s.pendingRequests[k]++
	case arp.OperationReply:
		k := requestKey{srcIP: targetS, dstIP: senderS}
		if s.pendingRequests[k] > 0 {
			s.pendingRequests[k]--
			s.targetedReqRespPairs++
			if s.pendingRequests[k] == 0 {
				delete(s.pendingRequests, k)
			}
		}
	}
}

func (s *statsCollector) print(duration time.Duration) {
	fmt.Println("\nРезультаты сбора статистики:")
	fmt.Printf("1. Всего Ethernet фреймов: %d\n", s.totalFrames)
	fmt.Printf("2. Всего ARP пакетов: %d\n", s.arpFrames)
	fmt.Printf("3. Уникальных MAC адресов: %d\n", len(s.uniqueMACs))
	fmt.Printf("4. Широковещательных Ethernet сообщений: %d\n", s.broadcastEtherFrames)
	fmt.Printf("5. Широковещательных ARP сообщений: %d\n", s.broadcastARPFrames)
	fmt.Printf("6. Gratuitous ARP Requests: %d\n", s.gratuitousARPRequests)
	fmt.Printf("7. Пары ARP targeted request + response: %d\n", s.targetedReqRespPairs)
	fmt.Printf("8. Объем данных между устройством и роутером (байт): %d\n", s.bytesBetweenHostAndRoute)
	fmt.Printf("Период наблюдения: %s\n", duration)
}
