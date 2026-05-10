package client

import (
	"fmt"
	"hw04mydrive/internal/config"
	"hw04mydrive/internal/files"
	"hw04mydrive/internal/protocol"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Client управляет сканированием локальной директории и передачей файлов на сервер.
type Client struct {
	cfg config.ClientConfig
}

// SyncMetrics содержит результат одного раунда синхронизации.
type SyncMetrics struct {
	Mode             config.TransferMode
	TotalDuration    time.Duration
	TransferDuration time.Duration
	UploadedFiles    int
	UploadedBytes    int64
	DeletedFiles     int
	DeletedNames     []string
}

// measurementSummary содержит пару замеров для сравнения двух режимов передачи.
type measurementSummary struct {
	Buffered SyncMetrics
	DMA      SyncMetrics
}

// uploadSummary агрегирует результат нескольких параллельных соединений передачи.
type uploadSummary struct {
	uploadedBytes int64
}

// New создает клиента и проверяет, что локальная директория синхронизации существует.
func New(cfg config.ClientConfig) (*Client, error) {
	info, err := os.Stat(cfg.SyncDir)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить сведения о локальной директории %q: %w", cfg.SyncDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("путь sync_dir %q не является директорией", cfg.SyncDir)
	}

	return &Client{cfg: cfg}, nil
}

// Sync выполняет обычную синхронизацию в режиме, указанном в конфиге клиента.
func (c *Client) Sync() error {
	metrics, err := c.runSync(c.cfg.TransferMode, false)
	if err != nil {
		return fmt.Errorf("обычная синхронизация в режиме %s завершилась ошибкой: %w", c.cfg.TransferMode.DisplayName(), err)
	}

	c.printSyncMetrics(metrics)

	return nil
}

// SyncWithMode выполняет обычную синхронизацию в явно указанном режиме передачи.
func (c *Client) SyncWithMode(mode config.TransferMode) error {
	metrics, err := c.runSync(mode, false)
	if err != nil {
		return fmt.Errorf("синхронизация в режиме %s завершилась ошибкой: %w", mode.DisplayName(), err)
	}

	c.printSyncMetrics(metrics)

	return nil
}

// Measure принудительно передает одинаковый набор файлов сначала через пользовательский буфер, затем через DMA.
func (c *Client) Measure() error {
	fmt.Println("Запущен сравнительный замер режимов передачи.")
	fmt.Println("Для чистоты эксперимента оба прогона выполняются с принудительной повторной отправкой файлов.")

	bufferedMetrics, err := c.runSync(config.TransferModeBuffered, true)
	if err != nil {
		return fmt.Errorf("не удалось выполнить замер в режиме буферизации: %w", err)
	}

	dmaMetrics, err := c.runSync(config.TransferModeDMA, true)
	if err != nil {
		return fmt.Errorf("не удалось выполнить замер в режиме DMA: %w", err)
	}

	c.printMeasurementSummary(measurementSummary{
		Buffered: bufferedMetrics,
		DMA:      dmaMetrics,
	})

	return nil
}

// runSync выполняет один полный раунд синхронизации: от manifest до итогового подтверждения сервера.
func (c *Client) runSync(mode config.TransferMode, forceUpload bool) (SyncMetrics, error) {
	manifest, err := c.buildManifest()
	if err != nil {
		return SyncMetrics{}, fmt.Errorf("не удалось построить локальный список файлов: %w", err)
	}

	totalStartedAt := time.Now()

	conn, err := net.Dial("tcp", c.cfg.Address())
	if err != nil {
		return SyncMetrics{}, fmt.Errorf("не удалось открыть управляющее соединение с %s: %w", c.cfg.Address(), err)
	}
	defer conn.Close()

	reader := protocol.NewReader(conn)
	writer := protocol.NewWriter(conn)

	// Сначала клиент открывает управляющее соединение и получает session_id для всех последующих передач.
	if err := writer.WriteJSON(protocol.TypeClientHello, protocol.ClientHello{
		ClientID: c.cfg.ClientID,
		Role:     "control",
	}); err != nil {
		return SyncMetrics{}, fmt.Errorf("не удалось отправить приветственное сообщение управляющего соединения: %w", err)
	}

	var hello protocol.ServerHello
	if err := reader.ReadJSON(protocol.TypeServerHello, &hello); err != nil {
		return SyncMetrics{}, fmt.Errorf("не удалось получить подтверждение управляющего соединения: %w", err)
	}

	manifestRequest := protocol.ManifestRequest{
		Files:       manifest,
		ForceUpload: forceUpload,
		Mode:        mode.String(),
	}
	if err := writer.WriteJSON(protocol.TypeManifest, manifestRequest); err != nil {
		return SyncMetrics{}, fmt.Errorf("не удалось отправить список файлов на сервер: %w", err)
	}

	var plan protocol.SyncPlan
	if err := reader.ReadJSON(protocol.TypeSyncPlan, &plan); err != nil {
		return SyncMetrics{}, fmt.Errorf("не удалось получить список различий от сервера: %w", err)
	}

	fmt.Printf("Режим передачи: %s\n", mode.DisplayName())
	fmt.Printf("Найдено локальных файлов: %d\n", len(manifest))
	fmt.Printf("Нужно передать на сервер: %d\n", len(plan.Upload))
	fmt.Printf("Нужно удалить на сервере: %d\n", len(plan.Delete))

	// Время передачи измеряется отдельно от этапов рукопожатия и сопоставления manifest.
	transferStartedAt := time.Now()
	uploadResult, err := c.uploadFiles(hello.SessionID, plan.Upload, mode)
	if err != nil {
		return SyncMetrics{}, fmt.Errorf("ошибка во время передачи файлов в режиме %s: %w", mode.DisplayName(), err)
	}
	transferDuration := time.Since(transferStartedAt)

	if err := writer.WriteJSON(protocol.TypeSyncDone, protocol.SyncDone{TransferMode: mode.String()}); err != nil {
		return SyncMetrics{}, fmt.Errorf("не удалось отправить серверу сообщение о завершении передачи: %w", err)
	}

	var result protocol.SyncDone
	if err := reader.ReadJSON(protocol.TypeSyncDone, &result); err != nil {
		return SyncMetrics{}, fmt.Errorf("не удалось получить итоговое подтверждение синхронизации: %w", err)
	}

	metrics := SyncMetrics{
		Mode:             mode,
		TotalDuration:    time.Since(totalStartedAt),
		TransferDuration: transferDuration,
		UploadedFiles:    result.Uploaded,
		UploadedBytes:    uploadResult.uploadedBytes,
		DeletedFiles:     len(result.Deleted),
		DeletedNames:     append([]string(nil), result.Deleted...),
	}

	return metrics, nil
}

// buildManifest сканирует локальную директорию и переводит метаданные в формат протокола.
func (c *Client) buildManifest() ([]protocol.FileMeta, error) {
	localFiles, err := files.ScanFlatDir(c.cfg.SyncDir)
	if err != nil {
		return nil, fmt.Errorf("не удалось просканировать локальную директорию %q: %w", c.cfg.SyncDir, err)
	}

	manifest := make([]protocol.FileMeta, 0, len(localFiles))
	for _, item := range localFiles {
		manifest = append(manifest, protocol.FileMeta(item))
	}

	return manifest, nil
}

// uploadFiles запускает несколько соединений передачи и ограничивает их количество значением max_connections.
func (c *Client) uploadFiles(sessionID string, items []protocol.FileMeta, mode config.TransferMode) (uploadSummary, error) {
	if len(items) == 0 {
		return uploadSummary{}, nil
	}

	parallelismLimiter := make(chan struct{}, c.cfg.MaxConnections)
	errorChannel := make(chan error, len(items))

	var uploadedFiles atomic.Int64
	var uploadedBytes atomic.Int64
	var waitGroup sync.WaitGroup

	for _, item := range items {
		fileMeta := item

		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()

			parallelismLimiter <- struct{}{}
			defer func() { <-parallelismLimiter }()

			if err := c.uploadOne(sessionID, fileMeta, mode); err != nil {
				errorChannel <- fmt.Errorf("не удалось передать файл %s: %w", fileMeta.Name, err)

				return
			}

			currentIndex := uploadedFiles.Add(1)
			uploadedBytes.Add(fileMeta.Size)
			fmt.Printf("[%d/%d] Передан %s (%d байт)\n", currentIndex, len(items), fileMeta.Name, fileMeta.Size)
		}()
	}

	waitGroup.Wait()
	close(errorChannel)

	for err := range errorChannel {
		if err != nil {
			return uploadSummary{}, err
		}
	}

	return uploadSummary{uploadedBytes: uploadedBytes.Load()}, nil
}

// uploadOne открывает отдельное соединение передачи, отправляет заголовок файла и затем его содержимое.
func (c *Client) uploadOne(sessionID string, item protocol.FileMeta, mode config.TransferMode) error {
	path := filepath.Join(c.cfg.SyncDir, item.Name)

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("не удалось открыть локальный файл %q: %w", path, err)
	}
	defer file.Close()

	conn, err := net.Dial("tcp", c.cfg.Address())
	if err != nil {
		return fmt.Errorf("не удалось открыть соединение передачи с %s: %w", c.cfg.Address(), err)
	}
	defer conn.Close()

	reader := protocol.NewReader(conn)
	writer := protocol.NewWriter(conn)

	// Каждое файловое соединение привязывается к уже открытой управляющей сессии.
	if err := writer.WriteJSON(protocol.TypeClientHello, protocol.ClientHello{
		ClientID:  c.cfg.ClientID,
		SessionID: sessionID,
		Role:      "upload",
	}); err != nil {
		return fmt.Errorf("не удалось отправить приветственное сообщение файлового соединения: %w", err)
	}

	var hello protocol.ServerHello
	if err := reader.ReadJSON(protocol.TypeServerHello, &hello); err != nil {
		return fmt.Errorf("не удалось получить подтверждение файлового соединения: %w", err)
	}

	uploadRequest := protocol.UploadRequest{
		Name:         item.Name,
		Size:         item.Size,
		SHA256:       item.SHA256,
		TransferMode: mode.String(),
	}
	if err := writer.WriteJSON(protocol.TypeUpload, uploadRequest); err != nil {
		return fmt.Errorf("не удалось отправить заголовок файла %s: %w", item.Name, err)
	}

	sentBytes, err := c.sendFile(conn, file, item.Size, mode)
	if err != nil {
		return fmt.Errorf("не удалось передать содержимое файла %s: %w", item.Name, err)
	}
	if sentBytes != item.Size {
		return fmt.Errorf("передан неожиданный объем файла %s: %d вместо %d", item.Name, sentBytes, item.Size)
	}

	var ack protocol.UploadAck
	if err := reader.ReadJSON(protocol.TypeUploadAck, &ack); err != nil {
		return fmt.Errorf("не удалось получить подтверждение приема файла %s: %w", item.Name, err)
	}
	if !ack.Stored {
		return fmt.Errorf("сервер отклонил файл %s", item.Name)
	}

	return nil
}

// sendFile выбирает подходящий способ передачи: через системную прямую передачу или через пользовательский буфер.
func (c *Client) sendFile(conn net.Conn, file *os.File, expectedSize int64, mode config.TransferMode) (int64, error) {
	switch mode {
	case config.TransferModeDMA:
		return c.sendFileWithDMA(conn, file, expectedSize)
	case config.TransferModeBuffered:
		return c.sendFileWithBuffer(conn, file, expectedSize)
	default:
		return 0, fmt.Errorf("неподдерживаемый режим передачи %s", mode)
	}
}

// sendFileWithDMA передает файл через системный путь *os.File -> *net.TCPConn, который позволяет ядру использовать sendfile.
func (c *Client) sendFileWithDMA(conn net.Conn, file *os.File, expectedSize int64) (int64, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("режим DMA требует именно TCP-соединение")
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("не удалось перейти к началу файла перед DMA-передачей: %w", err)
	}

	sentBytes, err := tcpConn.ReadFrom(file)
	if err != nil {
		return sentBytes, fmt.Errorf("системная прямая передача завершилась ошибкой: %w", err)
	}
	if sentBytes != expectedSize {
		return sentBytes, fmt.Errorf("системная прямая передача отдала %d байт вместо %d", sentBytes, expectedSize)
	}

	return sentBytes, nil
}

// sendFileWithBuffer передает файл через пользовательский буфер фиксированного размера.
func (c *Client) sendFileWithBuffer(conn net.Conn, file *os.File, expectedSize int64) (int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("не удалось перейти к началу файла перед буферизованной передачей: %w", err)
	}

	buffer := make([]byte, c.cfg.BufferSizeBytes)
	sentBytes, err := io.CopyBuffer(conn, file, buffer)
	if err != nil {
		return sentBytes, fmt.Errorf("буферизованная передача завершилась ошибкой: %w", err)
	}
	if sentBytes != expectedSize {
		return sentBytes, fmt.Errorf("буферизованная передача отдала %d байт вместо %d", sentBytes, expectedSize)
	}

	return sentBytes, nil
}

// printSyncMetrics выводит итог одного раунда синхронизации в читаемом виде.
func (c *Client) printSyncMetrics(metrics SyncMetrics) {
	fmt.Printf("Синхронизация завершена.\n")
	fmt.Printf("Режим передачи: %s\n", metrics.Mode.DisplayName())
	fmt.Printf("Всего передано файлов: %d\n", metrics.UploadedFiles)
	fmt.Printf("Всего передано байт: %d\n", metrics.UploadedBytes)
	fmt.Printf("Время передачи файлов: %s\n", metrics.TransferDuration.Round(time.Millisecond))
	fmt.Printf("Полное время синхронизации: %s\n", metrics.TotalDuration.Round(time.Millisecond))

	if metrics.DeletedFiles > 0 {
		fmt.Printf("Удалены устаревшие файлы: %v\n", metrics.DeletedNames)
	}
}

// printMeasurementSummary выводит сравнение двух режимов и их пропускную способность.
func (c *Client) printMeasurementSummary(summary measurementSummary) {
	fmt.Println("Сравнительный замер завершен.")
	fmt.Println()

	c.printOneMeasurement(summary.Buffered)
	c.printOneMeasurement(summary.DMA)

	if summary.DMA.TransferDuration > 0 && summary.Buffered.TransferDuration > 0 {
		speedup := float64(summary.Buffered.TransferDuration) / float64(summary.DMA.TransferDuration)
		fmt.Printf("Ускорение DMA относительно буферизации: %.2fx\n", speedup)
	}
}

// printOneMeasurement выводит строку с длительностью и средней скоростью для одного режима передачи.
func (c *Client) printOneMeasurement(metrics SyncMetrics) {
	megabytes := float64(metrics.UploadedBytes) / (1024.0 * 1024.0)
	seconds := metrics.TransferDuration.Seconds()
	throughput := 0.0
	if seconds > 0 {
		throughput = megabytes / seconds
	}

	fmt.Printf("%s: передано %.2f МБ за %s, средняя скорость %.2f МБ/с\n",
		metrics.Mode.DisplayName(),
		megabytes,
		metrics.TransferDuration.Round(time.Millisecond),
		throughput,
	)
}
