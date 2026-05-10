package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hw04mydrive/internal/files"
	"hw04mydrive/internal/protocol"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// sessionStore хранит все активные сессии синхронизации.
type sessionStore struct {
	root string
	mu   sync.RWMutex
	data map[string]*session
}

// newSessionStore создает хранилище активных сессий.
func newSessionStore(root string) *sessionStore {
	return &sessionStore{
		root: root,
		data: make(map[string]*session),
	}
}

// create создает новую сессию для конкретного client_id.
func (s *sessionStore) create(clientID string) (*session, error) {
	userDir := filepath.Join(s.root, clientID)
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		return nil, fmt.Errorf("не удалось создать директорию пользователя %q: %w", userDir, err)
	}

	id, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("не удалось создать идентификатор сессии для %q: %w", clientID, err)
	}
	currentFiles, err := files.ScanFlatDir(userDir)
	if err != nil {
		return nil, fmt.Errorf("не удалось просканировать директорию пользователя %q: %w", userDir, err)
	}

	entity := &session{
		id:           id,
		clientID:     clientID,
		userDir:      userDir,
		currentFiles: files.ToMap(currentFiles),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = entity

	return entity, nil
}

// get возвращает активную сессию по ее идентификатору.
func (s *sessionStore) get(id string) (*session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.data[id]

	return entry, ok
}

// remove удаляет завершенную сессию из хранилища.
func (s *sessionStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
}

// session описывает один раунд синхронизации одного клиента.
type session struct {
	id       string
	clientID string
	userDir  string

	mu            sync.Mutex
	manifestSeen  bool
	currentFiles  map[string]files.Meta
	desiredFiles  map[string]protocol.FileMeta
	uploadNeeded  map[string]protocol.FileMeta
	uploaded      map[string]bool
	deleteAfter   []string
	uploadedBytes int64
	transferMode  string
}

// buildPlan сравнивает серверное состояние с клиентским списком и строит список различий.
func (s *session) buildPlan(manifest protocol.ManifestRequest) (protocol.SyncPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	clientFiles := manifest.Files
	desired := make(map[string]protocol.FileMeta, len(clientFiles))
	upload := make([]protocol.FileMeta, 0)
	for _, file := range clientFiles {
		// На этом шаге сервер убеждается, что клиент не пытается выйти за пределы каталога.
		if err := files.ValidateFileName(file.Name); err != nil {
			return protocol.SyncPlan{}, fmt.Errorf("%s: %w", file.Name, err)
		}
		if file.Size < 0 {
			return protocol.SyncPlan{}, fmt.Errorf("отрицательный размер файла: %s", file.Name)
		}

		desired[file.Name] = file
		current, ok := s.currentFiles[file.Name]
		if manifest.ForceUpload || !ok || current.Size != file.Size || current.SHA256 != file.SHA256 {
			upload = append(upload, file)
		}
	}

	deleteList := make([]string, 0)
	for name := range s.currentFiles {
		if _, ok := desired[name]; !ok {
			deleteList = append(deleteList, name)
		}
	}
	sort.Strings(deleteList)

	s.manifestSeen = true
	s.desiredFiles = desired
	s.uploadNeeded = protocol.ConvertFiles(upload)
	s.uploaded = make(map[string]bool, len(upload))
	s.deleteAfter = deleteList
	s.uploadedBytes = 0
	s.transferMode = manifest.Mode

	return protocol.SyncPlan{
		Upload: upload,
		Delete: deleteList,
	}, nil
}

// storeUpload принимает один файл, пишет его во временный файл и подтверждает только после проверки SHA-256.
func (s *session) storeUpload(upload protocol.UploadRequest, reader io.Reader) error {
	s.mu.Lock()
	if !s.manifestSeen {
		s.mu.Unlock()
		return fmt.Errorf("manifest еще не был отправлен")
	}

	expected, ok := s.uploadNeeded[upload.Name]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("сервер не запрашивал файл %s", upload.Name)
	}
	if expected.Size != upload.Size || expected.SHA256 != upload.SHA256 {
		s.mu.Unlock()
		return fmt.Errorf("метаданные файла %s не совпадают с ожидаемым планом синхронизации", upload.Name)
	}

	path := filepath.Join(s.userDir, upload.Name)
	tmpPath := path + ".part"
	s.transferMode = upload.TransferMode
	s.mu.Unlock()

	file, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("не удалось создать временный файл %q: %w", tmpPath, err)
	}

	// Данные приходят ровно в том объеме, который был заявлен в UploadRequest.
	written, copyErr := io.CopyN(file, reader, upload.Size)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)

		return fmt.Errorf("не удалось принять содержимое файла %s: %w", upload.Name, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)

		return fmt.Errorf("не удалось закрыть временный файл %q: %w", tmpPath, closeErr)
	}
	if written != upload.Size {
		_ = os.Remove(tmpPath)

		return fmt.Errorf("получен неожиданный размер файла %s: %d вместо %d", upload.Name, written, upload.Size)
	}

	sum, err := files.HashFile(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)

		return fmt.Errorf("не удалось проверить контрольную сумму файла %s: %w", upload.Name, err)
	}
	if sum != upload.SHA256 {
		_ = os.Remove(tmpPath)

		return fmt.Errorf("контрольная сумма %s не совпала", upload.Name)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)

		return fmt.Errorf("не удалось заменить временный файл рабочим %q: %w", path, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.uploaded[upload.Name] = true
	s.uploadedBytes += upload.Size
	s.currentFiles[upload.Name] = files.Meta{
		Name:   upload.Name,
		Size:   upload.Size,
		SHA256: upload.SHA256,
	}

	return nil
}

// finish завершает сессию и удаляет устаревшие файлы после успешной передачи всех обязательных данных.
func (s *session) finish() (protocol.SyncDone, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.manifestSeen {
		return protocol.SyncDone{}, fmt.Errorf("manifest не был получен")
	}
	for name := range s.uploadNeeded {
		if !s.uploaded[name] {
			return protocol.SyncDone{}, fmt.Errorf("не все обязательные файлы были загружены: %s", name)
		}
	}

	for _, name := range s.deleteAfter {
		if err := os.Remove(filepath.Join(s.userDir, name)); err != nil && !os.IsNotExist(err) {
			return protocol.SyncDone{}, fmt.Errorf("не удалось удалить устаревший файл %s: %w", name, err)
		}
		delete(s.currentFiles, name)
	}

	return protocol.SyncDone{
		Uploaded:      len(s.uploaded),
		UploadedBytes: s.uploadedBytes,
		Deleted:       append([]string(nil), s.deleteAfter...),
		TransferMode:  s.transferMode,
		Message:       "синхронизация завершена",
	}, nil
}

// randomID создает ID сессии.
func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("не удалось получить случайные байты для идентификатора сессии: %w", err)
	}

	return hex.EncodeToString(buf), nil
}
