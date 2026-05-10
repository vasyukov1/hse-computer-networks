package server

import (
	"fmt"
	"hw04mydrive/internal/config"
	"hw04mydrive/internal/protocol"
	"net"
	"os"
	"strings"
)

// Server принимает клиентские соединения и распределяет их по активным сессиям.
type Server struct {
	cfg      config.ServerConfig
	sessions *sessionStore
}

// New создает сервер и заранее подготавливает корневую директорию хранилища.
func New(cfg config.ServerConfig) (*Server, error) {
	if err := os.MkdirAll(cfg.StorageRoot, 0o755); err != nil {
		return nil, fmt.Errorf("не удалось создать корневую директорию хранилища %q: %w", cfg.StorageRoot, err)
	}

	return &Server{
		cfg:      cfg,
		sessions: newSessionStore(cfg.StorageRoot),
	}, nil
}

// ListenAndServe запускает прослушивание TCP-порта и принимает неограниченное число соединений.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Address())
	if err != nil {
		return fmt.Errorf("не удалось начать прослушивание на %s: %w", s.cfg.Address(), err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("ошибка при приеме нового соединения: %w", err)
		}

		go s.handleConn(conn)
	}
}

// handleConn читает первое сообщение и определяет, является ли соединение управляющим или файловым.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	reader := protocol.NewReader(conn)
	writer := protocol.NewWriter(conn)

	var hello protocol.ClientHello
	if err := reader.ReadJSON(protocol.TypeClientHello, &hello); err != nil {
		_ = writer.WriteError(fmt.Sprintf("не удалось прочитать client hello: %v", err))

		return
	}

	switch strings.ToLower(strings.TrimSpace(hello.Role)) {
	case "control", "управление":
		s.handleControl(reader, writer, hello)
	case "upload", "передача":
		s.handleUpload(reader, writer, hello)
	default:
		_ = writer.WriteError("неизвестная роль соединения")
	}
}

// handleControl ведет основной раунд синхронизации: manifest, список различий и итоговое подтверждение.
func (s *Server) handleControl(reader *protocol.Reader, writer *protocol.Writer, hello protocol.ClientHello) {
	clientID := strings.TrimSpace(hello.ClientID)
	if clientID == "" {
		_ = writer.WriteError("client_id не должен быть пустым")
		return
	}

	session, err := s.sessions.create(clientID)
	if err != nil {
		_ = writer.WriteError(err.Error())
		return
	}
	defer s.sessions.remove(session.id)

	if err := writer.WriteJSON(protocol.TypeServerHello, protocol.ServerHello{
		SessionID: session.id,
		Message:   "управляющая сессия создана",
	}); err != nil {

		return
	}

	var manifest protocol.ManifestRequest
	if err := reader.ReadJSON(protocol.TypeManifest, &manifest); err != nil {
		_ = writer.WriteError(fmt.Sprintf("не удалось прочитать manifest: %v", err))
		return
	}

	plan, err := session.buildPlan(manifest)
	if err != nil {
		_ = writer.WriteError(err.Error())

		return
	}
	if err := writer.WriteJSON(protocol.TypeSyncPlan, plan); err != nil {

		return
	}

	var doneRequest protocol.SyncDone
	if err := reader.ReadJSON(protocol.TypeSyncDone, &doneRequest); err != nil {
		_ = writer.WriteError(fmt.Sprintf("не удалось прочитать sync done: %v", err))
		return
	}

	result, err := session.finish()
	if err != nil {
		_ = writer.WriteError(err.Error())

		return
	}

	result.TransferMode = manifest.Mode
	_ = writer.WriteJSON(protocol.TypeSyncDone, result)
}

// handleUpload обслуживает отдельное соединение, по которому передается один файл.
func (s *Server) handleUpload(reader *protocol.Reader, writer *protocol.Writer, hello protocol.ClientHello) {
	clientID := strings.TrimSpace(hello.ClientID)
	sessionID := strings.TrimSpace(hello.SessionID)
	if clientID == "" || sessionID == "" {
		_ = writer.WriteError("upload соединение требует client_id и session_id")
		return
	}

	session, ok := s.sessions.get(sessionID)
	if !ok {
		_ = writer.WriteError("session_id не найден")
		return
	}
	if session.clientID != clientID {
		_ = writer.WriteError("client_id не совпадает с активной сессией")
		return
	}

	if err := writer.WriteJSON(protocol.TypeServerHello, protocol.ServerHello{
		SessionID: session.id,
		Message:   "соединение передачи принято",
	}); err != nil {

		return
	}

	var upload protocol.UploadRequest
	if err := reader.ReadJSON(protocol.TypeUpload, &upload); err != nil {
		_ = writer.WriteError(fmt.Sprintf("не удалось прочитать upload request: %v", err))
		return
	}

	if err := session.storeUpload(upload, reader.Buffered()); err != nil {
		_ = writer.WriteError(err.Error())

		return
	}

	_ = writer.WriteJSON(protocol.TypeUploadAck, protocol.UploadAck{
		Name:    upload.Name,
		Stored:  true,
		Message: "файл принят",
	})
}
