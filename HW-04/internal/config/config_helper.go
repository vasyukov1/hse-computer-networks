package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// readJSON читает JSON-файл и возвращает абсолютный путь вместе с содержимым.
func readJSON(path string) (string, []byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, fmt.Errorf("не удалось получить абсолютный путь для %q: %w", path, err)
	}

	raw, err := os.ReadFile(abs)
	if err != nil {
		return "", nil, fmt.Errorf("не удалось прочитать файл %q: %w", abs, err)
	}

	return abs, raw, nil
}

// resolvePath превращает путь из конфига в абсолютный путь относительно самого конфига.
func resolvePath(configPath, value string) (string, error) {
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}

	base := filepath.Dir(configPath)
	abs, err := filepath.Abs(filepath.Join(base, value))
	if err != nil {
		return "", fmt.Errorf("не удалось получить абсолютный путь для %q: %w", value, err)
	}

	return filepath.Clean(abs), nil
}

// firstNonEmpty возвращает первую непустую строку после удаления внешних пробелов.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}

	return ""
}
