package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// TransferMode задает способ отправки файла по TCP.
type TransferMode string

const (
	// TransferModeDMA использует прямую передачу ядром операционной системы.
	TransferModeDMA TransferMode = "dma"
	// TransferModeBuffered сначала читает данные в пользовательский буфер.
	TransferModeBuffered TransferMode = "buffered"
)

// ParseTransferMode переводит строку из конфига или консоли в режим передачи.
func ParseTransferMode(raw string) (TransferMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(TransferModeDMA):
		return TransferModeDMA, nil
	case string(TransferModeBuffered):
		return TransferModeBuffered, nil
	default:
		return "", fmt.Errorf("неизвестный режим передачи %q: допустимы dma и buffered", raw)
	}
}

// String возвращает строковое представление режима передачи.
func (m TransferMode) String() string {
	return string(m)
}

// DisplayName возвращает короткое название режима для вывода на экран и в отчет.
func (m TransferMode) DisplayName() string {
	switch m {
	case TransferModeDMA:
		return "DMA"
	case TransferModeBuffered:
		return "Буферизация"
	default:
		return string(m)
	}
}

// ClientConfig хранит параметры, необходимые клиенту для синхронизации.
type ClientConfig struct {
	ClientID        string       `json:"client_id"`
	SyncDir         string       `json:"sync_dir"`
	ServerHost      string       `json:"server_host"`
	ServerPort      int          `json:"server_port"`
	MaxConnections  int          `json:"max_connections"`
	TransferMode    TransferMode `json:"transfer_mode"`
	BufferSizeBytes int          `json:"buffer_size_bytes"`
}

// Address собирает адрес сервера в формате host:port.
func (c ClientConfig) Address() string {
	return net.JoinHostPort(strings.TrimSpace(c.ServerHost), fmt.Sprintf("%d", c.ServerPort))
}

// LoadClient загружает клиентский конфиг и возвращает его вместе с абсолютным путем.
func LoadClient(path string) (ClientConfig, string, error) {
	abs, raw, err := readJSON(path)
	if err != nil {
		return ClientConfig{}, "", fmt.Errorf("не удалось прочитать конфиг клиента %q: %w", path, err)
	}

	var cfg ClientConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ClientConfig{}, "", fmt.Errorf("не удалось разобрать JSON конфига клиента %q: %w", abs, err)
	}
	if err := cfg.normalize(abs); err != nil {
		return ClientConfig{}, "", fmt.Errorf("конфиг клиента %q некорректен: %w", abs, err)
	}

	return cfg, abs, nil
}

// SaveClient сохраняет нормализованный конфиг клиента на диск.
func SaveClient(path string, cfg ClientConfig) error {
	if err := cfg.normalize(path); err != nil {
		return fmt.Errorf("не удалось нормализовать конфиг клиента перед сохранением: %w", err)
	}

	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("не удалось сериализовать конфиг клиента: %w", err)
	}
	raw = append(raw, '\n')

	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("не удалось записать конфиг клиента %q: %w", path, err)
	}

	return nil
}

// GenerateClientID создает постоянный идентификатор клиента.
func GenerateClientID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("не удалось сгенерировать случайный идентификатор клиента: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

// normalize приводит конфиг клиента к рабочему виду и проверяет границы значений.
func (c *ClientConfig) normalize(configPath string) error {
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ServerHost = firstNonEmpty(c.ServerHost, "127.0.0.1")
	if c.TransferMode == "" {
		c.TransferMode = TransferModeDMA
	}
	if c.BufferSizeBytes == 0 {
		c.BufferSizeBytes = 1 << 20
	}

	if c.ServerPort <= 0 || c.ServerPort > 65535 {
		return fmt.Errorf("поле server_port должно лежать в диапазоне 1..65535")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 32 {
		return fmt.Errorf("поле max_connections должно лежать в диапазоне 1..32")
	}
	if strings.TrimSpace(c.SyncDir) == "" {
		return fmt.Errorf("поле sync_dir не должно быть пустым")
	}
	if c.BufferSizeBytes < 4*1024 {
		return fmt.Errorf("поле buffer_size_bytes должно быть не меньше 4096")
	}

	parsedMode, err := ParseTransferMode(c.TransferMode.String())
	if err != nil {
		return fmt.Errorf("поле transfer_mode задано неверно: %w", err)
	}
	c.TransferMode = parsedMode

	dir, err := resolvePath(configPath, c.SyncDir)
	if err != nil {
		return fmt.Errorf("не удалось вычислить путь sync_dir: %w", err)
	}
	c.SyncDir = dir

	return nil
}
