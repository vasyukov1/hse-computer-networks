package commands

import (
	"context"
	"fmt"
	"net"
	"sort"

	"hw03dns/internal/dns"
)

type MXCommand struct {
	env Env
}

func NewMXCommand(env Env) *MXCommand {
	return &MXCommand{env: env}
}

func (c *MXCommand) Name() string {
	return "mx"
}

func (c *MXCommand) Description() string {
	return "найти MX хосты домена и их IPv4 адреса"
}

func (c *MXCommand) Usage() string {
	return "mx <domain> [dns-server-ip]"
}

func (c *MXCommand) Run(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("использование: %s", c.Usage())
	}

	domain := args[0]
	serverIP := c.env.Summary.ProviderDNS
	if len(args) >= 2 {
		ip := net.ParseIP(args[1]).To4()
		if ip == nil {
			return fmt.Errorf("некорректный IPv4 адрес DNS сервера: %q", args[1])
		}
		serverIP = ip
	}

	clientCfg := dns.ClientConfig{
		SnapLen:       c.env.SnapLen,
		ReadTimeoutMS: c.env.ReadTimeoutMS,
		ARPWait:       c.env.ARPWait,
		ARPRetryCount: c.env.ARPRetryCount,
		DNSWait:       c.env.DNSWait,
	}

	mxResult, err := dns.ExchangeRawUDP(ctx, c.env.Summary, clientCfg, serverIP, dns.NewQuery(domain, dns.TypeMX, true))
	if err != nil {
		return err
	}

	mxRecords := dns.CollectMXRecords(mxResult.Response)
	if len(mxRecords) == 0 {
		fmt.Printf("%s -> MX not found\n", domain)
		return nil
	}

	type line struct {
		host string
		ip   string
		pref uint16
	}
	var lines []line
	for _, mx := range mxRecords {
		aResult, err := dns.ExchangeRawUDP(ctx, c.env.Summary, clientCfg, serverIP, dns.NewQuery(mx.Data, dns.TypeA, true))
		if err != nil {
			fmt.Printf("%s -> %s -> lookup failed (%v)\n", domain, mx.Data, err)
			continue
		}
		ips := dns.CollectARecords(aResult.Response)
		if len(ips) == 0 {
			fmt.Printf("%s -> %s -> A not found\n", domain, mx.Data)
			continue
		}
		for _, ip := range ips {
			lines = append(lines, line{host: mx.Data, ip: ip.String(), pref: mx.MXPreference})
		}
	}

	sort.Slice(lines, func(i, j int) bool {
		if lines[i].pref == lines[j].pref {
			if lines[i].host == lines[j].host {
				return lines[i].ip < lines[j].ip
			}
			return lines[i].host < lines[j].host
		}
		return lines[i].pref < lines[j].pref
	})

	for _, item := range lines {
		fmt.Printf("%s -> %s -> %s\n", domain, item.host, item.ip)
	}
	return nil
}
