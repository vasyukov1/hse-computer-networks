package commands

import (
	"context"
	"fmt"
	"net"
	"strings"

	"hw03dns/internal/dns"
)

type CompareCommand struct {
	env Env
}

func NewCompareCommand(env Env) *CompareCommand {
	return &CompareCommand{env: env}
}

func (c *CompareCommand) Name() string {
	return "compare"
}

func (c *CompareCommand) Description() string {
	return "сравнить ответы root DNS и DNS провайдера для github.com, hse.ru, draw.io"
}

func (c *CompareCommand) Usage() string {
	return "compare [root-ip] [provider-ip]"
}

func (c *CompareCommand) Run(ctx context.Context, args []string) error {
	rootIP := c.env.Summary.RootDNS
	providerIP := c.env.Summary.ProviderDNS
	if len(args) >= 1 {
		ip := net.ParseIP(args[0]).To4()
		if ip == nil {
			return fmt.Errorf("некорректный root DNS IPv4: %q", args[0])
		}
		rootIP = ip
	}
	if len(args) >= 2 {
		ip := net.ParseIP(args[1]).To4()
		if ip == nil {
			return fmt.Errorf("некорректный provider DNS IPv4: %q", args[1])
		}
		providerIP = ip
	}

	if c.env.Summary.VPNDefaultRoute {
		fmt.Printf("Предупреждение: default route указывает на %s, но raw DNS будет отправляться через физический интерфейс %s.\n",
			c.env.Summary.DefaultRouteInterface,
			c.env.Summary.Interface.Name,
		)
	}

	clientCfg := dns.ClientConfig{
		SnapLen:       c.env.SnapLen,
		ReadTimeoutMS: c.env.ReadTimeoutMS,
		ARPWait:       c.env.ARPWait,
		ARPRetryCount: c.env.ARPRetryCount,
		DNSWait:       c.env.DNSWait,
	}

	domains := []string{"github.com", "hse.ru", "draw.io"}
	for _, domain := range domains {
		if err := c.runScenario(ctx, clientCfg, "root", rootIP, domain, false); err != nil {
			return err
		}
		if err := c.runScenario(ctx, clientCfg, "provider", providerIP, domain, true); err != nil {
			return err
		}
	}
	return nil
}

func (c *CompareCommand) runScenario(ctx context.Context, cfg dns.ClientConfig, label string, serverIP net.IP, domain string, recursive bool) error {
	result, err := dns.ExchangeRawUDP(ctx, c.env.Summary, cfg, serverIP, dns.NewQuery(domain, dns.TypeA, recursive))
	if err != nil {
		return fmt.Errorf("%s DNS %s: %w", label, domain, err)
	}

	fmt.Printf("\n[%s] %s via %s\n", label, domain, serverIP)
	fmt.Printf("ID=0x%04x flags=%s rcode=%s next-hop=%s (%s)\n",
		result.Response.Header.ID,
		result.Response.Header.FlagSummary(),
		dns.RCodeString(result.Response.Header.RCode()),
		result.NextHopIP,
		result.NextHopMAC,
	)
	fmt.Printf("Answer (%d): %s\n", len(result.Response.Answers), formatRRSection(result.Response.Answers))
	fmt.Printf("Authority (%d): %s\n", len(result.Response.Authorities), formatRRSection(result.Response.Authorities))
	fmt.Printf("Additional (%d): %s\n", len(result.Response.Additionals), formatRRSection(result.Response.Additionals))
	return nil
}

func formatRRSection(records []dns.ResourceRecord) string {
	if len(records) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(records))
	for i, rr := range records {
		if i == 4 {
			parts = append(parts, fmt.Sprintf("... +%d", len(records)-4))
			break
		}
		value := rr.Data
		if rr.Type == dns.TypeMX {
			value = fmt.Sprintf("%d %s", rr.MXPreference, rr.Data)
		}
		parts = append(parts, fmt.Sprintf("%s %s %s", rr.Name, dns.TypeString(rr.Type), value))
	}
	return strings.Join(parts, "; ")
}
