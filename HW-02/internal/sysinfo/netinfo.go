package sysinfo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// InterfaceInfo содержит информацию для ARP-команд
type InterfaceInfo struct {
	Name string
	MAC  net.HardwareAddr
	IPv4 net.IP
}

// AutoDetectInterfaceName выбирает первый активный не-loopback интерфейс с IPv4
func AutoDetectInterfaceName() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		if _, err := IPv4OfInterface(iface.Name); err == nil {
			return iface.Name, nil
		}
	}
	return "", errors.New("подходящий интерфейс с IPv4 не найден")
}

func InterfaceInfoByName(name string) (InterfaceInfo, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return InterfaceInfo{}, err
	}
	if len(iface.HardwareAddr) == 0 {
		return InterfaceInfo{}, fmt.Errorf("интерфейс %q не имеет MAC-адреса", name)
	}
	ipv4, err := IPv4OfInterface(name)
	if err != nil {
		return InterfaceInfo{}, err
	}
	return InterfaceInfo{Name: iface.Name, MAC: iface.HardwareAddr, IPv4: ipv4}, nil
}

// IPv4OfInterface возвращает первый IPv4 адрес интерфейса
func IPv4OfInterface(name string) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("у интерфейса %q не найден IPv4", name)
}

// DetectDefaultGatewayIPv4 определяет IPv4 адрес default gateway
func DetectDefaultGatewayIPv4(ctx context.Context) (net.IP, error) {
	return DetectDefaultGatewayIPv4ForInterface(ctx, "")
}

// DetectDefaultGatewayIPv4ForInterface определяет gateway с учётом интерфейса
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
		if err != nil {
			return nil, err
		}
		if ip := parseGatewayFromDarwin(out); ip != nil {
			return ip, nil
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
		return nil, fmt.Errorf("автопоиск default gateway не реализован для %s", runtime.GOOS)
	}
	return nil, errors.New("не удалось определить default gateway")
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
		if len(m) < 2 {
			continue
		}
		if ip := net.ParseIP(m[1]).To4(); ip != nil {
			return ip
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
		if len(fields) < 4 {
			continue
		}
		if fields[0] != "default" {
			continue
		}
		gw := net.ParseIP(fields[1]).To4()
		if gw == nil {
			continue
		}

		netif := fields[3]
		if ifaceName != "" && netif != ifaceName {
			continue
		}
		return gw
	}
	return nil
}
