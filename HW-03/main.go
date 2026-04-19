package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hw03dns/internal/commands"
	"hw03dns/internal/sysinfo"
)

type appConfig struct {
	Interface       string `json:"interface"`
	ClientIPv4      string `json:"client_ipv4"`
	ClientMAC       string `json:"client_mac"`
	GatewayIPv4     string `json:"gateway_ipv4"`
	ProviderDNSIPv4 string `json:"provider_dns_ipv4"`
	RootDNSIPv4     string `json:"root_dns_ipv4"`
}

func main() {
	ifaceFlag := flag.String("iface", "", "имя сетевого интерфейса (например: en0, eth0)")
	configFlag := flag.String("config", "config.json", "путь к JSON конфигу")
	flag.Parse()

	cfg, cfgPath, err := loadConfig(*configFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Не удалось загрузить конфиг: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	overrides, err := sysinfo.NewOverridesFromStrings(sysinfo.OverrideStrings{
		Interface:       firstNonEmpty(strings.TrimSpace(*ifaceFlag), cfg.Interface),
		ClientIPv4:      cfg.ClientIPv4,
		ClientMAC:       cfg.ClientMAC,
		GatewayIPv4:     cfg.GatewayIPv4,
		ProviderDNSIPv4: cfg.ProviderDNSIPv4,
		RootDNSIPv4:     cfg.RootDNSIPv4,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Некорректный конфиг: %v\n", err)
		os.Exit(1)
	}

	network, err := sysinfo.DetectNetworkSummary(ctx, overrides)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Не удалось определить сетевую конфигурацию: %v\n", err)
		os.Exit(1)
	}

	env := commands.Env{
		Summary:        network,
		SnapLen:        65535,
		ReadTimeoutMS:  500,
		ARPRetryCount:  3,
		ARPWait:        2 * time.Second,
		DNSWait:        5 * time.Second,
		ConfigPath:     cfgPath,
		DefaultRootDNS: network.RootDNS,
	}

	runners := map[string]commands.Runner{
		"sniff":   commands.NewSniffCommand(env),
		"mx":      commands.NewMXCommand(env),
		"compare": commands.NewCompareCommand(env),
	}

	printSummary(env, runners)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("dns> ")
		if !scanner.Scan() {
			fmt.Println("\nВыход")
			return
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		name := strings.ToLower(parts[0])
		args := parts[1:]

		switch name {
		case "help", "h", "?":
			printHelp(runners)
			continue
		case "exit", "quit":
			fmt.Println("Выход")
			return
		}

		runner, ok := runners[name]
		if !ok {
			fmt.Printf("Неизвестная команда: %s\n", name)
			printHelp(runners)
			continue
		}

		if err := runner.Run(context.Background(), args); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				fmt.Fprintln(os.Stderr, "Операция не завершилась вовремя")
				continue
			}
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
		}
	}
}

func loadConfig(path string) (appConfig, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return appConfig{}, "", err
	}

	raw, err := os.ReadFile(abs)
	if err != nil {
		return appConfig{}, abs, err
	}

	var cfg appConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return appConfig{}, abs, err
	}
	return cfg, abs, nil
}

func printSummary(env commands.Env, runners map[string]commands.Runner) {
	fmt.Printf("Конфиг: %s\n", env.ConfigPath)
	fmt.Printf("Интерфейс: %s\n", env.Summary.Interface.Name)
	fmt.Printf("Локальный IPv4: %s/%d\n", env.Summary.Interface.IPv4, env.Summary.Interface.PrefixBits)
	fmt.Printf("Локальный MAC: %s\n", env.Summary.Interface.MAC)
	fmt.Printf("Gateway: %s\n", env.Summary.Gateway)
	fmt.Printf("Provider DNS: %s\n", env.Summary.ProviderDNS)
	fmt.Printf("Root DNS: %s\n", env.Summary.RootDNS)
	if env.Summary.VPNDefaultRoute {
		fmt.Printf("VPN default route: да (%s). Raw Ethernet будет отправляться через %s.\n", env.Summary.DefaultRouteInterface, env.Summary.Interface.Name)
	} else {
		fmt.Printf("VPN default route: нет (default interface: %s)\n", env.Summary.DefaultRouteInterface)
	}
	printHelp(runners)
}

func printHelp(runners map[string]commands.Runner) {
	fmt.Println("Доступные команды:")
	fmt.Println("  help                          - показать список команд")
	for _, name := range []string{"sniff", "mx", "compare"} {
		r := runners[name]
		fmt.Printf("  %-29s - %s\n", r.Usage(), r.Description())
	}
	fmt.Println("  exit | quit                   - завершить программу")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
