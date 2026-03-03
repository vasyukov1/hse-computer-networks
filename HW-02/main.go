package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"hw02arp/internal/commands"
	"hw02arp/internal/sysinfo"
)

func main() {
	ifaceFlag := flag.String("iface", "", "имя сетевого интерфейса (например: en0, eth0)")
	flag.Parse()

	ifaceName := strings.TrimSpace(*ifaceFlag)
	if ifaceName == "" {
		autoName, err := sysinfo.AutoDetectInterfaceName()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Не удалось автоматически определить интерфейс: %v\n", err)
			fmt.Fprintln(os.Stderr, "Укажите интерфейс вручную через флаг -iface")
			os.Exit(1)
		}
		ifaceName = autoName
	}

	env := commands.Env{
		InterfaceName:  ifaceName,
		SnapLen:        65535,
		ReadTimeoutMS:  500,
		DiscoveryWait:  5 * time.Second,
		DiscoveryTries: 3,
	}

	runners := map[string]commands.Runner{
		"sniff":    commands.NewSniffCommand(env),
		"discover": commands.NewDiscoverCommand(env),
		"stats":    commands.NewStatsCommand(env),
	}

	fmt.Printf("Интерфейс: %s\n", ifaceName)
	printHelp(runners)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("arp> ")
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

		ctx := context.Background()
		if err := runner.Run(ctx, args); err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
		}
	}
}

func printHelp(runners map[string]commands.Runner) {
	fmt.Println("Доступные команды:")
	fmt.Println("  help                      - показать список команд")
	for _, name := range []string{"sniff", "discover", "stats"} {
		r := runners[name]
		fmt.Printf("  %-25s - %s\n", r.Usage(), r.Description())
	}
	fmt.Println("  exit | quit               - завершить программу")
}
