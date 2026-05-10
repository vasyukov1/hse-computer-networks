package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"hw04mydrive/internal/client"
	"hw04mydrive/internal/config"
)

// main запуск клиента и обработка команд.
func main() {
	configPath := flag.String("config", "./config/client_config.json", "путь к JSON-конфигу клиента")
	flag.Parse()

	cfg, path, err := config.LoadClient(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Не удалось загрузить конфиг клиента: %v\n", err)
		os.Exit(1)
	}

	if strings.TrimSpace(cfg.ClientID) == "" {
		cfg.ClientID, err = config.GenerateClientID()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Не удалось сгенерировать постоянный идентификатор клиента: %v\n", err)
			os.Exit(1)
		}
		if err := config.SaveClient(path, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Не удалось сохранить постоянный идентификатор клиента в конфиг: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Сгенерирован постоянный идентификатор клиента: %s\n", cfg.ClientID)
	}

	app, err := client.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Не удалось создать клиент: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("MyDrive клиент\n")
	fmt.Printf("Идентификатор клиента: %s\n", cfg.ClientID)
	fmt.Printf("Директория синхронизации: %s\n", cfg.SyncDir)
	fmt.Printf("Сервер: %s\n", cfg.Address())
	fmt.Printf("Максимум соединений: %d\n", cfg.MaxConnections)
	fmt.Printf("Режим передачи по умолчанию: %s\n", cfg.TransferMode.DisplayName())
	fmt.Printf("Размер пользовательского буфера: %d байт\n", cfg.BufferSizeBytes)
	printHelp()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("mydrive> ")
		if !scanner.Scan() {
			fmt.Println("\nВыход")
			return
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		commandParts := strings.Fields(line)
		commandName := strings.ToLower(commandParts[0])

		switch commandName {
		case "help", "h", "?":
			printHelp()
		case "sync":
			if err := runSyncCommand(app, commandParts[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка синхронизации: %v\n", err)
			}
		case "measure":
			if err := app.Measure(); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка замера: %v\n", err)
			}
		case "exit", "quit":
			fmt.Println("Выход")
			return
		default:
			fmt.Printf("Неизвестная команда: %s\n", commandName)
			printHelp()
		}
	}
}

// runSyncCommand выбирает режим передачи для очередной синхронизации.
func runSyncCommand(app *client.Client, args []string) error {
	if len(args) == 0 {
		return app.Sync()
	}
	if len(args) > 1 {
		return fmt.Errorf("команда sync принимает не более одного аргумента: dma или buffered")
	}

	mode, err := config.ParseTransferMode(args[0])
	if err != nil {
		return fmt.Errorf("не удалось разобрать режим передачи: %w", err)
	}

	return app.SyncWithMode(mode)
}

// printHelp показывает все доступные команды клиента.
func printHelp() {
	fmt.Println("Доступные команды:")
	fmt.Println("  sync                     - синхронизировать файлы в режиме из конфига")
	fmt.Println("  sync dma                 - синхронизировать файлы в режиме DMA")
	fmt.Println("  sync buffered            - синхронизировать файлы через пользовательский буфер")
	fmt.Println("  measure                  - принудительно сравнить режимы buffered и dma на одном наборе файлов")
	fmt.Println("  help                     - показать справку")
	fmt.Println("  exit | quit              - завершить программу")
}
