package config

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// ServerConfig хранит параметры, с которыми запускается сервер.
type ServerConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	StorageRoot string `json:"storage_root"`
}

// Address собирает адрес прослушивания сервера в формате host:port.
func (c ServerConfig) Address() string {
	return net.JoinHostPort(strings.TrimSpace(c.Host), fmt.Sprintf("%d", c.Port))
}

// LoadServer загружает и проверяет серверный конфиг.
func LoadServer(path string) (ServerConfig, error) {
	abs, raw, err := readJSON(path)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("не удалось прочитать конфиг сервера %q: %w", path, err)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ServerConfig{}, fmt.Errorf("не удалось разобрать JSON конфига сервера %q: %w", abs, err)
	}
	if err := cfg.normalize(abs); err != nil {
		return ServerConfig{}, fmt.Errorf("конфиг сервера %q некорректен: %w", abs, err)
	}

	return cfg, nil
}

// normalize приводит серверный конфиг к рабочему виду и проверяет значения.
func (c *ServerConfig) normalize(configPath string) error {
	c.Host = firstNonEmpty(c.Host, "0.0.0.0")

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("поле port должно лежать в диапазоне 1..65535")
	}
	if strings.TrimSpace(c.StorageRoot) == "" {
		return fmt.Errorf("поле storage_root не должно быть пустым")
	}

	root, err := resolvePath(configPath, c.StorageRoot)
	if err != nil {
		return fmt.Errorf("не удалось вычислить путь storage_root: %w", err)
	}
	c.StorageRoot = root

	return nil
}
