package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Reader вычитывает длину, тип и полезную нагрузку управляющих сообщений.
type Reader struct {
	buf *bufio.Reader
}

// NewReader создает чтение управляющих сообщений поверх любого io.Reader.
func NewReader(r io.Reader) *Reader {
	return &Reader{buf: bufio.NewReader(r)}
}

// ReadEnvelope читает одно сообщение целиком, используя длину из первых четырех байт.
func (r *Reader) ReadEnvelope() (Envelope, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(r.buf, sizeBuf[:]); err != nil {
		return Envelope{}, fmt.Errorf("не удалось прочитать длину сообщения: %w", err)
	}

	size := binary.BigEndian.Uint32(sizeBuf[:])
	if size == 0 {
		return Envelope{}, fmt.Errorf("получено пустое сообщение")
	}
	if size > maxFrameSize {
		return Envelope{}, fmt.Errorf("получено слишком большое сообщение: %d байт", size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r.buf, payload); err != nil {
		return Envelope{}, fmt.Errorf("не удалось дочитать сообщение длиной %d байт: %w", size, err)
	}

	return Envelope{Type: payload[0], Body: payload[1:]}, nil
}

// ReadJSON читает сообщение ожидаемого типа и сразу разбирает его как JSON.
func (r *Reader) ReadJSON(expectedType byte, dst any) error {
	env, err := r.ReadEnvelope()
	if err != nil {
		return fmt.Errorf("не удалось получить управляющее сообщение: %w", err)
	}

	if env.Type == TypeError {
		var msg ErrorMessage
		if err := json.Unmarshal(env.Body, &msg); err != nil {
			return fmt.Errorf("получено сообщение об ошибке, но его не удалось разобрать")
		}

		return errors.New(msg.Message)
	}

	if env.Type != expectedType {
		return fmt.Errorf("ожидался тип сообщения %d, получен %d", expectedType, env.Type)
	}

	if err := json.Unmarshal(env.Body, dst); err != nil {
		return fmt.Errorf("не удалось разобрать JSON сообщения типа %d: %w", expectedType, err)
	}

	return nil
}

// Buffered возвращает внутренний буферизированный поток чтения для чтения содержимого файла.
func (r *Reader) Buffered() *bufio.Reader {
	return r.buf
}
