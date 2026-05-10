package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Writer формирует управляющие сообщения и отправляет их по TCP.
type Writer struct {
	buf *bufio.Writer
}

// NewWriter создает запись управляющих сообщений поверх любого io.Writer.
func NewWriter(w io.Writer) *Writer {
	return &Writer{buf: bufio.NewWriter(w)}
}

// WriteJSON сериализует структуру в JSON и отправляет ее как одно сообщение.
func (w *Writer) WriteJSON(messageType byte, message any) error {
	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("не удалось сериализовать сообщение типа %d: %w", messageType, err)
	}

	return w.WriteEnvelope(Envelope{Type: messageType, Body: body})
}

// WriteError отправляет человекочитаемое сообщение об ошибке.
func (w *Writer) WriteError(message string) error {
	return w.WriteJSON(TypeError, ErrorMessage{Message: message})
}

// WriteEnvelope записывает длину, тип и полезную нагрузку в одном непрерывном потоке байт.
func (w *Writer) WriteEnvelope(env Envelope) error {
	size := len(env.Body) + 1
	if size > maxFrameSize {
		return fmt.Errorf("сообщение слишком велико для отправки: %d байт", size)
	}

	var sizeBuf [4]byte
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(size))
	if _, err := w.buf.Write(sizeBuf[:]); err != nil {
		return fmt.Errorf("не удалось записать длину сообщения: %w", err)
	}
	if err := w.buf.WriteByte(env.Type); err != nil {
		return fmt.Errorf("не удалось записать тип сообщения: %w", err)
	}
	if _, err := w.buf.Write(env.Body); err != nil {
		return fmt.Errorf("не удалось записать полезную нагрузку сообщения: %w", err)
	}

	if err := w.buf.Flush(); err != nil {
		return fmt.Errorf("не удалось отправить буферизированное сообщение: %w", err)
	}

	return nil
}
