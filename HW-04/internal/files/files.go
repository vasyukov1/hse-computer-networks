package files

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Meta содержит набор метаданных, нужный для сравнения файлов.
type Meta struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ScanFlatDir считывает все обычные файлы верхнего уровня и возвращает их метаданные.
func ScanFlatDir(root string) ([]Meta, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать директорию %q: %w", root, err)
	}

	metas := make([]Meta, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if err := ValidateFileName(name); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		path := filepath.Join(root, name)
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("не удалось получить информацию о файле %q: %w", path, err)
		}
		sum, err := HashFile(path)
		if err != nil {
			return nil, fmt.Errorf("не удалось вычислить контрольную сумму файла %q: %w", path, err)
		}

		metas = append(metas, Meta{
			Name:   name,
			Size:   info.Size(),
			SHA256: sum,
		})
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].Name < metas[j].Name
	})

	return metas, nil
}

// ValidateFileName запрещает пустые имена и любые попытки выйти из рабочей директории.
func ValidateFileName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("имя файла не должно быть пустым")
	}
	if name != filepath.Base(name) {
		return fmt.Errorf("поддиректории и составные пути не поддерживаются")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("служебные имена . и .. запрещены")
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("имя файла содержит недопустимый нулевой байт")
	}

	return nil
}

// HashFile вычисляет SHA-256 для файла.
func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("не удалось открыть файл %q: %w", path, err)
	}
	defer file.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("не удалось прочитать файл %q во время вычисления SHA-256: %w", path, err)
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}

// ToMap превращает список метаданных в словарь по имени файла.
func ToMap(items []Meta) map[string]Meta {
	result := make(map[string]Meta, len(items))
	for _, item := range items {
		result[item.Name] = item
	}

	return result
}
