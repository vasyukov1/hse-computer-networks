package sysinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type InterfaceInfo struct {
	Name       string
	MAC        net.HardwareAddr
	IPv4       net.IP
	Mask       net.IPMask
	PrefixBits int
	Index      int
}

type NetworkSummary struct {
	Interface             InterfaceInfo
	Gateway               net.IP
	ProviderDNS           net.IP
	RootDNS               net.IP
	DefaultRouteInterface string
	VPNDefaultRoute       bool
}

type OverrideStrings struct {
	Interface       string
	ClientIPv4      string
	ClientMAC       string
	GatewayIPv4     string
	ProviderDNSIPv4 string
	RootDNSIPv4     string
}

type Overrides struct {
	Interface       string
	ClientIPv4      net.IP
	ClientMAC       net.HardwareAddr
	GatewayIPv4     net.IP
	ProviderDNSIPv4 net.IP
	RootDNSIPv4     net.IP
}

type dnsResolver struct {
	InterfaceName string
	Nameservers   []net.IP
}

func NewOverridesFromStrings(values OverrideStrings) (Overrides, error) {
	var result Overrides
	result.Interface = strings.TrimSpace(values.Interface)

	var err error
	if result.ClientIPv4, err = parseOptionalIPv4(values.ClientIPv4); err != nil {
		return Overrides{}, fmt.Errorf("client_ipv4: %w", err)
	}
	if result.ClientMAC, err = parseOptionalMAC(values.ClientMAC); err != nil {
		return Overrides{}, fmt.Errorf("client_mac: %w", err)
	}
	if result.GatewayIPv4, err = parseOptionalIPv4(values.GatewayIPv4); err != nil {
		return Overrides{}, fmt.Errorf("gateway_ipv4: %w", err)
	}
	if result.ProviderDNSIPv4, err = parseOptionalIPv4(values.ProviderDNSIPv4); err != nil {
		return Overrides{}, fmt.Errorf("provider_dns_ipv4: %w", err)
	}
	if result.RootDNSIPv4, err = parseOptionalIPv4(values.RootDNSIPv4); err != nil {
		return Overrides{}, fmt.Errorf("root_dns_ipv4: %w", err)
	}
	return result, nil
}

func DetectNetworkSummary(ctx context.Context, overrides Overrides) (NetworkSummary, error) {
	defaultIface, err := detectDefaultRouteInterface(ctx)
	if err != nil {
		defaultIface = ""
	}

	iface, err := detectBestInterface(overrides.Interface, defaultIface)
	if err != nil {
		return NetworkSummary{}, err
	}

	if overrides.ClientIPv4 != nil {
		iface.IPv4 = append(net.IP(nil), overrides.ClientIPv4...)
	}
	if overrides.ClientMAC != nil {
		iface.MAC = append(net.HardwareAddr(nil), overrides.ClientMAC...)
	}

	gateway := overrides.GatewayIPv4
	if gateway == nil {
		gateway, err = DetectDefaultGatewayIPv4ForInterface(ctx, iface.Name)
		if err != nil {
			return NetworkSummary{}, err
		}
	}

	providerDNS := overrides.ProviderDNSIPv4
	if providerDNS == nil {
		providerDNS, err = DetectProviderDNSIPv4ForInterface(ctx, iface.Name)
		if err != nil {
			return NetworkSummary{}, err
		}
	}

	rootDNS := overrides.RootDNSIPv4
	if rootDNS == nil {
		rootDNS = net.ParseIP("198.41.0.4").To4()
	}

	return NetworkSummary{
		Interface:             iface,
		Gateway:               gateway,
		ProviderDNS:           providerDNS,
		RootDNS:               rootDNS,
		DefaultRouteInterface: defaultIface,
		VPNDefaultRoute:       isTunnelInterface(defaultIface),
	}, nil
}

func detectBestInterface(explicitName, defaultIface string) (InterfaceInfo, error) {
	if explicitName != "" {
		return InterfaceInfoByName(explicitName)
	}

	if defaultIface != "" && !isTunnelInterface(defaultIface) && isPhysicalInterfaceName(defaultIface) {
		if info, err := InterfaceInfoByName(defaultIface); err == nil {
			return info, nil
		}
	}

	if infos, err := interfacesFromDNSScoped(); err == nil {
		for _, info := range infos {
			if isPhysicalInterfaceName(info.Name) {
				return info, nil
			}
		}
	}

	all, err := allEligibleInterfaces()
	if err != nil {
		return InterfaceInfo{}, err
	}
	if len(all) == 0 {
		return InterfaceInfo{}, errors.New("не найден активный L2 интерфейс с IPv4 и MAC")
	}
	return all[0], nil
}

func AutoDetectInterfaceName() (string, error) {
	info, err := detectBestInterface("", "")
	if err != nil {
		return "", err
	}
	return info.Name, nil
}

func InterfaceInfoByName(name string) (InterfaceInfo, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return InterfaceInfo{}, err
	}
	if len(iface.HardwareAddr) == 0 {
		return InterfaceInfo{}, fmt.Errorf("интерфейс %q не имеет MAC-адреса", name)
	}
	ipv4, mask, prefix, err := IPv4OfInterface(name)
	if err != nil {
		return InterfaceInfo{}, err
	}
	return InterfaceInfo{
		Name:       iface.Name,
		MAC:        append(net.HardwareAddr(nil), iface.HardwareAddr...),
		IPv4:       ipv4,
		Mask:       mask,
		PrefixBits: prefix,
		Index:      iface.Index,
	}, nil
}

func IPv4OfInterface(name string) (net.IP, net.IPMask, int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, 0, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, 0, err
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipNet.IP.To4()
		if v4 == nil {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		return append(net.IP(nil), v4...), append(net.IPMask(nil), ipNet.Mask...), ones, nil
	}
	return nil, nil, 0, fmt.Errorf("у интерфейса %q не найден IPv4", name)
}

func DetectDefaultGatewayIPv4(ctx context.Context) (net.IP, error) {
	return DetectDefaultGatewayIPv4ForInterface(ctx, "")
}

func DetectDefaultGatewayIPv4ForInterface(ctx context.Context, ifaceName string) (net.IP, error) {
	switch runtime.GOOS {
	case "darwin":
		if strings.TrimSpace(ifaceName) != "" {
			out, err := commandOutput(ctx, "route", "-n", "get", "-ifscope", ifaceName, "default")
			if err == nil {
				if ip := parseGatewayFromDarwin(out); ip != nil {
					return ip, nil
				}
			}
		}

		out, err := commandOutput(ctx, "route", "-n", "get", "default")
		if err == nil {
			if ip := parseGatewayFromDarwin(out); ip != nil {
				if ifaceName == "" {
					return ip, nil
				}
			}
		}

		out, err = commandOutput(ctx, "netstat", "-rn", "-f", "inet")
		if err == nil {
			if ip := parseGatewayFromDarwinNetstat(out, ifaceName); ip != nil {
				return ip, nil
			}
		}
	case "linux":
		out, err := commandOutput(ctx, "ip", "route", "show", "default")
		if err == nil {
			if ip := parseGatewayFromLinux(out, ifaceName); ip != nil {
				return ip, nil
			}
		}
		out, err = commandOutput(ctx, "route", "-n")
		if err == nil {
			if ip := parseGatewayFromRouteN(out); ip != nil {
				return ip, nil
			}
		}
	default:
		return nil, fmt.Errorf("автопоиск gateway не реализован для %s", runtime.GOOS)
	}
	return nil, errors.New("не удалось определить default gateway")
}

func DetectProviderDNSIPv4ForInterface(ctx context.Context, ifaceName string) (net.IP, error) {
	switch runtime.GOOS {
	case "darwin":
		resolvers, err := parseDarwinResolvers(ctx)
		if err != nil {
			return nil, err
		}

		for _, resolver := range resolvers {
			if resolver.InterfaceName == ifaceName && len(resolver.Nameservers) > 0 {
				return resolver.Nameservers[0], nil
			}
		}
		for _, resolver := range resolvers {
			if resolver.InterfaceName == "" && len(resolver.Nameservers) > 0 {
				return resolver.Nameservers[0], nil
			}
		}
	case "linux":
		out, err := commandOutput(ctx, "resolvectl", "dns", ifaceName)
		if err == nil {
			re := regexp.MustCompile(`\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)
			m := re.FindStringSubmatch(out)
			if len(m) >= 2 {
				return net.ParseIP(m[1]).To4(), nil
			}
		}
		out, err = commandOutput(ctx, "cat", "/etc/resolv.conf")
		if err == nil {
			re := regexp.MustCompile(`(?m)^\s*nameserver\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*$`)
			m := re.FindStringSubmatch(out)
			if len(m) >= 2 {
				return net.ParseIP(m[1]).To4(), nil
			}
		}
	}
	return nil, fmt.Errorf("не удалось определить DNS сервер провайдера для интерфейса %s", ifaceName)
}

func NextHopIPv4(summary NetworkSummary, dst net.IP) net.IP {
	if sameSubnet(summary.Interface.IPv4, dst, summary.Interface.Mask) {
		return dst.To4()
	}
	return summary.Gateway.To4()
}

func sameSubnet(a, b net.IP, mask net.IPMask) bool {
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil || len(mask) < 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		if a4[i]&mask[i] != b4[i]&mask[i] {
			return false
		}
	}
	return true
}

func commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errOut.String())
		if msg != "" {
			return "", fmt.Errorf("%s %v: %w (%s)", name, args, err, msg)
		}
		return "", fmt.Errorf("%s %v: %w", name, args, err)
	}
	return out.String(), nil
}

func detectDefaultRouteInterface(ctx context.Context) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := commandOutput(ctx, "route", "-n", "get", "default")
		if err != nil {
			return "", err
		}
		re := regexp.MustCompile(`(?m)^\s*interface:\s*(\S+)\s*$`)
		m := re.FindStringSubmatch(out)
		if len(m) < 2 {
			return "", errors.New("не найден interface в route -n get default")
		}
		return m[1], nil
	case "linux":
		out, err := commandOutput(ctx, "ip", "route", "show", "default")
		if err != nil {
			return "", err
		}
		re := regexp.MustCompile(`\bdev\s+(\S+)`)
		m := re.FindStringSubmatch(out)
		if len(m) < 2 {
			return "", errors.New("не найден default interface")
		}
		return m[1], nil
	default:
		return "", fmt.Errorf("определение default interface не реализовано для %s", runtime.GOOS)
	}
}

func parseGatewayFromDarwin(out string) net.IP {
	re := regexp.MustCompile(`(?m)^\s*gateway:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*$`)
	m := re.FindStringSubmatch(out)
	if len(m) < 2 {
		return nil
	}
	return net.ParseIP(m[1]).To4()
}

func parseGatewayFromLinux(out string, ifaceName string) net.IP {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "default") {
			continue
		}
		if ifaceName != "" && !strings.Contains(line, " dev "+ifaceName+" ") && !strings.HasSuffix(line, " dev "+ifaceName) {
			continue
		}
		re := regexp.MustCompile(`\bvia\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)
		m := re.FindStringSubmatch(line)
		if len(m) >= 2 {
			return net.ParseIP(m[1]).To4()
		}
	}
	return nil
}

func parseGatewayFromRouteN(out string) net.IP {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "0.0.0.0" || strings.EqualFold(fields[0], "default") {
			if ip := net.ParseIP(fields[1]).To4(); ip != nil {
				return ip
			}
		}
	}
	return nil
}

func parseGatewayFromDarwinNetstat(out string, ifaceName string) net.IP {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" {
			continue
		}
		if ifaceName != "" && fields[3] != ifaceName {
			continue
		}
		if ip := net.ParseIP(fields[1]).To4(); ip != nil {
			return ip
		}
	}
	return nil
}

func parseDarwinResolvers(ctx context.Context) ([]dnsResolver, error) {
	out, err := commandOutput(ctx, "scutil", "--dns")
	if err != nil {
		return nil, err
	}

	var resolvers []dnsResolver
	var current dnsResolver
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "resolver #") {
			if len(current.Nameservers) > 0 || current.InterfaceName != "" {
				resolvers = append(resolvers, current)
			}
			current = dnsResolver{}
			continue
		}
		if strings.HasPrefix(trimmed, "nameserver[") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) != 2 {
				continue
			}
			ip := net.ParseIP(strings.TrimSpace(parts[1])).To4()
			if ip != nil {
				current.Nameservers = append(current.Nameservers, ip)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "if_index") {
			re := regexp.MustCompile(`if_index\s*:\s*\d+\s+\(([^)]+)\)`)
			m := re.FindStringSubmatch(trimmed)
			if len(m) >= 2 {
				current.InterfaceName = m[1]
			}
		}
	}
	if len(current.Nameservers) > 0 || current.InterfaceName != "" {
		resolvers = append(resolvers, current)
	}
	return resolvers, nil
}

func interfacesFromDNSScoped() ([]InterfaceInfo, error) {
	ctx := context.Background()
	resolvers, err := parseDarwinResolvers(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var result []InterfaceInfo
	for _, resolver := range resolvers {
		if resolver.InterfaceName == "" {
			continue
		}
		if _, ok := seen[resolver.InterfaceName]; ok {
			continue
		}
		info, err := InterfaceInfoByName(resolver.InterfaceName)
		if err != nil {
			continue
		}
		if isTunnelInterface(info.Name) || !isPhysicalInterfaceName(info.Name) {
			continue
		}
		seen[resolver.InterfaceName] = struct{}{}
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func allEligibleInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []InterfaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 || !isPhysicalInterfaceName(iface.Name) || isTunnelInterface(iface.Name) {
			continue
		}
		info, err := InterfaceInfoByName(iface.Name)
		if err != nil {
			continue
		}
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool {
		return scoreInterface(result[i].Name) < scoreInterface(result[j].Name)
	})
	return result, nil
}

func scoreInterface(name string) string {
	switch {
	case strings.HasPrefix(name, "en0"):
		return "0-" + name
	case strings.HasPrefix(name, "en"):
		return "1-" + name
	case strings.HasPrefix(name, "eth"):
		return "2-" + name
	default:
		return "9-" + name
	}
}

func isTunnelInterface(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{"utun", "tun", "tap", "ppp", "wg"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func isPhysicalInterfaceName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{"en", "eth"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func parseOptionalIPv4(raw string) (net.IP, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	ip := net.ParseIP(raw).To4()
	if ip == nil {
		return nil, fmt.Errorf("ожидается IPv4, получено %q", raw)
	}
	return ip, nil
}

func parseOptionalMAC(raw string) (net.HardwareAddr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	mac, err := net.ParseMAC(raw)
	if err != nil {
		return nil, err
	}
	return mac, nil
}

func (s NetworkSummary) MarshalJSON() ([]byte, error) {
	type alias struct {
		Interface             string `json:"interface"`
		ClientIPv4            string `json:"client_ipv4"`
		ClientMAC             string `json:"client_mac"`
		Gateway               string `json:"gateway_ipv4"`
		ProviderDNS           string `json:"provider_dns_ipv4"`
		RootDNS               string `json:"root_dns_ipv4"`
		DefaultRouteInterface string `json:"default_route_interface"`
		VPNDefaultRoute       bool   `json:"vpn_default_route"`
	}
	return json.Marshal(alias{
		Interface:             s.Interface.Name,
		ClientIPv4:            s.Interface.IPv4.String(),
		ClientMAC:             s.Interface.MAC.String(),
		Gateway:               s.Gateway.String(),
		ProviderDNS:           s.ProviderDNS.String(),
		RootDNS:               s.RootDNS.String(),
		DefaultRouteInterface: s.DefaultRouteInterface,
		VPNDefaultRoute:       s.VPNDefaultRoute,
	})
}

func ParseIPv4WithPort(raw string) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, 0, fmt.Errorf("некорректный IPv4: %s", host)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, err
	}
	return ip, uint16(port64), nil
}
