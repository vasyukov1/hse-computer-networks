package server

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"hw05chat/internal/app"
	"hw05chat/internal/config"
	"hw05chat/internal/domain"
	"hw05chat/internal/protocol/chatpb"
	"hw05chat/internal/websocket"
)

type Server struct {
	cfg config.Config
	hub *app.Hub
	seq atomic.Int32
}

func New(cfg config.Config, hub *app.Hub) *Server {
	return &Server{cfg: cfg, hub: hub}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Address())
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Address(), err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.URL.Path == "/ws" {
		ws, err := websocket.Upgrade(conn, reader, req)
		if err != nil {
			return
		}
		s.handleWebSocket(ws)
		return
	}

	s.serveHTTP(conn, req)
}

func (s *Server) serveHTTP(conn net.Conn, req *http.Request) {
	writer := bufio.NewWriter(conn)
	defer writer.Flush()

	if req.URL.Path != "/" && req.URL.Path != "/index.html" {
		_, _ = fmt.Fprint(writer, "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found")
		return
	}

	body, err := os.ReadFile(filepath.Join("web", "index.html"))
	if err != nil {
		body = []byte("<!doctype html><meta charset=\"utf-8\"><h1>HW-05 chat</h1><p>web/index.html not found</p>")
	}
	_, _ = fmt.Fprintf(writer,
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		len(body))
	_, _ = writer.Write(body)
}

func (s *Server) handleWebSocket(ws *websocket.Conn) {
	defer ws.CloseWithStatus()

	out := make(chan domain.Message, 32)
	var name string
	var writeMu sync.Mutex
	write := func(resp *chatpb.ServerResponse) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return s.writeResponse(ws, resp)
	}
	writeErr := func(code int32, message string) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return s.writeError(ws, code, message)
	}
	writeDomainErr := func(err error) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return s.writeDomainError(ws, err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range out {
			_ = write(&chatpb.ServerResponse{
				ServerSeq: s.seq.Add(1),
				Ok:        true,
				Message:   messageToPB(msg),
				Info:      "message",
			})
		}
	}()

	defer func() {
		if name != "" {
			s.hub.Leave(name)
		}
		close(out)
		<-done
	}()

	for {
		payload, err := ws.ReadBinary()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				_ = writeErr(500, err.Error())
			}
			return
		}

		var req chatpb.ClientRequest
		if err := proto.Unmarshal(payload, &req); err != nil {
			_ = writeErr(400, "не удалось декодировать protobuf-запрос")
			continue
		}

		switch {
		case req.GetJoin() != nil:
			if name != "" {
				_ = writeErr(409, "этот WebSocket уже присоединен к чату")
				continue
			}
			join := req.GetJoin()
			history, err := s.hub.Join(strings.TrimSpace(join.GetName()), imageFromPB(join.GetIcon()), out)
			if err != nil {
				_ = writeDomainErr(err)
				continue
			}
			name = strings.TrimSpace(join.GetName())
			_ = write(&chatpb.ServerResponse{
				ServerSeq: s.seq.Add(1),
				Ok:        true,
				History:   historyToPB(history),
				Info:      "joined",
			})

		case req.GetSend() != nil:
			send := req.GetSend()
			msg, targets, err := s.hub.Send(name, send.GetText(), strings.TrimSpace(send.GetTo()), imageFromPB(send.GetImage()))
			if err != nil {
				_ = writeDomainErr(err)
				continue
			}
			for _, target := range targets {
				_ = app.TrySend(target, msg)
			}

		case req.GetPing() != nil:
			_ = write(&chatpb.ServerResponse{
				ServerSeq: s.seq.Add(1),
				Ok:        true,
				Info:      "pong",
			})

		default:
			_ = writeErr(400, "запрос не содержит join, send или ping")
		}
	}
}

func (s *Server) writeDomainError(ws *websocket.Conn, err error) error {
	code := int32(400)
	switch {
	case errors.Is(err, domain.ErrNameTaken), errors.Is(err, domain.ErrRecipientMiss):
		code = 404
	case errors.Is(err, domain.ErrChatFull):
		code = 429
	case errors.Is(err, domain.ErrNotJoined):
		code = 403
	}
	return s.writeError(ws, code, err.Error())
}

func (s *Server) writeError(ws *websocket.Conn, code int32, message string) error {
	return s.writeResponse(ws, &chatpb.ServerResponse{
		ServerSeq: s.seq.Add(1),
		Ok:        false,
		Error:     &chatpb.Error{Code: code, Message: message},
		Info:      "error",
	})
}

func (s *Server) writeResponse(ws *websocket.Conn, resp *chatpb.ServerResponse) error {
	payload, err := proto.Marshal(resp)
	if err != nil {
		return err
	}
	return ws.WriteBinary(payload)
}
