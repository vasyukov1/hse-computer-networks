package websocket

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const (
	OpcodeContinuation = 0x0
	OpcodeBinary       = 0x2
	OpcodeClose        = 0x8
	OpcodePing         = 0x9
	OpcodePong         = 0xA

	maxPayload = 2 << 20
)

type Conn struct {
	net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func Upgrade(conn net.Conn, reader *bufio.Reader, req *http.Request) (*Conn, error) {
	key := strings.TrimSpace(req.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("missing websocket upgrade")
	}

	accept := websocketAccept(key)
	writer := bufio.NewWriter(conn)
	_, err := fmt.Fprintf(writer,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n", accept)
	if err != nil {
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}

	return &Conn{Conn: conn, reader: reader, writer: writer}, nil
}

func (c *Conn) ReadBinary() ([]byte, error) {
	var message []byte
	inFragmentedMessage := false

	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case OpcodeBinary:
			if fin {
				return payload, nil
			}
			message = append(message[:0], payload...)
			inFragmentedMessage = true
		case OpcodeContinuation:
			if !inFragmentedMessage {
				return nil, errors.New("unexpected websocket continuation frame")
			}
			if len(message)+len(payload) > maxPayload {
				return nil, fmt.Errorf("websocket message too large: %d bytes", len(message)+len(payload))
			}
			message = append(message, payload...)
			if fin {
				return message, nil
			}
		case OpcodePing:
			_ = c.writeFrame(OpcodePong, payload)
		case OpcodeClose:
			_ = c.writeFrame(OpcodeClose, nil)
			return nil, io.EOF
		}
	}
}

func (c *Conn) WriteBinary(payload []byte) error {
	return c.writeFrame(OpcodeBinary, payload)
}

func (c *Conn) CloseWithStatus() error {
	_ = c.writeFrame(OpcodeClose, nil)
	return c.Conn.Close()
}

func (c *Conn) readFrame() (bool, byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return false, 0, nil, err
	}

	fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, ext); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, ext); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}
	if length > maxPayload {
		return false, 0, nil, fmt.Errorf("websocket frame too large: %d bytes", length)
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.reader, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}

func (c *Conn) writeFrame(opcode byte, payload []byte) error {
	first := byte(0x80) | opcode
	if err := c.writer.WriteByte(first); err != nil {
		return err
	}

	length := len(payload)
	switch {
	case length < 126:
		if err := c.writer.WriteByte(byte(length)); err != nil {
			return err
		}
	case length <= 0xffff:
		if err := c.writer.WriteByte(126); err != nil {
			return err
		}
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(length))
		if _, err := c.writer.Write(ext[:]); err != nil {
			return err
		}
	default:
		if err := c.writer.WriteByte(127); err != nil {
			return err
		}
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(length))
		if _, err := c.writer.Write(ext[:]); err != nil {
			return err
		}
	}

	if _, err := c.writer.Write(payload); err != nil {
		return err
	}
	return c.writer.Flush()
}

func websocketAccept(key string) string {
	const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sum := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(sum[:])
}
