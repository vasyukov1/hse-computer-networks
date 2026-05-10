package main

import (
	"flag"
	"fmt"
	"os"

	"hw04mydrive/internal/config"
	"hw04mydrive/internal/server"
)

// main загружает конфиг, создаёт сервер и запускает прослушивание порта.
func main() {
	configPath := flag.String("config", "./config/server_config.json", "путь к JSON-конфигу сервера")
	flag.Parse()

	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Не удалось загрузить конфиг сервера: %v\n", err)
		os.Exit(1)
	}

	srv, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Не удалось создать сервер: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("MyDrive сервер слушает %s\n", cfg.Address())
	fmt.Printf("Корневая директория хранилища: %s\n", cfg.StorageRoot)

	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка сервера: %v\n", err)
		os.Exit(1)
	}
}
