package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeMX    = 15
	TypeAAAA  = 28
	TypeOPT   = 41

	ClassIN = 1
)

type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type ResourceRecord struct {
	Name         string
	Type         uint16
	Class        uint16
	TTL          uint32
	RawData      []byte
	Data         string
	IP           net.IP
	MXPreference uint16
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func NewQuery(name string, qtype uint16, recursionDesired bool) Message {
	flags := uint16(0)
	if recursionDesired {
		flags |= 1 << 8
	}
	return Message{
		Header: Header{
			ID:      uint16(rand.Intn(65535)),
			Flags:   flags,
			QDCount: 1,
		},
		Questions: []Question{{
			Name:  normalizeDomain(name),
			Type:  qtype,
			Class: ClassIN,
		}},
	}
}

func (m Message) MarshalBinary() ([]byte, error) {
	if len(m.Questions) != int(m.Header.QDCount) {
		m.Header.QDCount = uint16(len(m.Questions))
	}
	if len(m.Answers) != int(m.Header.ANCount) {
		m.Header.ANCount = uint16(len(m.Answers))
	}
	if len(m.Authorities) != int(m.Header.NSCount) {
		m.Header.NSCount = uint16(len(m.Authorities))
	}
	if len(m.Additionals) != int(m.Header.ARCount) {
		m.Header.ARCount = uint16(len(m.Additionals))
	}

	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], m.Header.ID)
	binary.BigEndian.PutUint16(out[2:4], m.Header.Flags)
	binary.BigEndian.PutUint16(out[4:6], m.Header.QDCount)
	binary.BigEndian.PutUint16(out[6:8], m.Header.ANCount)
	binary.BigEndian.PutUint16(out[8:10], m.Header.NSCount)
	binary.BigEndian.PutUint16(out[10:12], m.Header.ARCount)

	for _, question := range m.Questions {
		name, err := encodeName(question.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, name...)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint16(buf[0:2], question.Type)
		binary.BigEndian.PutUint16(buf[2:4], question.Class)
		out = append(out, buf...)
	}
	return out, nil
}

func ParseMessage(data []byte) (Message, error) {
	if len(data) < 12 {
		return Message{}, fmt.Errorf("слишком короткий DNS пакет: %d", len(data))
	}

	msg := Message{
		Header: Header{
			ID:      binary.BigEndian.Uint16(data[0:2]),
			Flags:   binary.BigEndian.Uint16(data[2:4]),
			QDCount: binary.BigEndian.Uint16(data[4:6]),
			ANCount: binary.BigEndian.Uint16(data[6:8]),
			NSCount: binary.BigEndian.Uint16(data[8:10]),
			ARCount: binary.BigEndian.Uint16(data[10:12]),
		},
	}

	offset := 12
	var err error
	for i := 0; i < int(msg.Header.QDCount); i++ {
		var q Question
		q.Name, offset, err = readName(data, offset, 0)
		if err != nil {
			return Message{}, err
		}
		if offset+4 > len(data) {
			return Message{}, errors.New("обрезанный DNS question")
		}
		q.Type = binary.BigEndian.Uint16(data[offset : offset+2])
		q.Class = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		msg.Questions = append(msg.Questions, q)
	}

	msg.Answers, offset, err = parseRRs(data, offset, int(msg.Header.ANCount))
	if err != nil {
		return Message{}, err
	}
	msg.Authorities, offset, err = parseRRs(data, offset, int(msg.Header.NSCount))
	if err != nil {
		return Message{}, err
	}
	msg.Additionals, offset, err = parseRRs(data, offset, int(msg.Header.ARCount))
	if err != nil {
		return Message{}, err
	}

	return msg, nil
}

func parseRRs(data []byte, offset int, count int) ([]ResourceRecord, int, error) {
	result := make([]ResourceRecord, 0, count)
	for i := 0; i < count; i++ {
		name, nextOffset, err := readName(data, offset, 0)
		if err != nil {
			return nil, offset, err
		}
		offset = nextOffset
		if offset+10 > len(data) {
			return nil, offset, errors.New("обрезанный DNS resource record")
		}

		rr := ResourceRecord{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
			TTL:   binary.BigEndian.Uint32(data[offset+4 : offset+8]),
		}
		rdLen := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(data) {
			return nil, offset, errors.New("RDATA выходит за границы пакета")
		}
		rr.RawData = append([]byte(nil), data[offset:offset+rdLen]...)
		if err := decodeRR(data, offset, &rr); err != nil {
			rr.Data = fmt.Sprintf("unsupported(%d bytes)", rdLen)
		}
		offset += rdLen
		result = append(result, rr)
	}
	return result, offset, nil
}

func decodeRR(packet []byte, rdataOffset int, rr *ResourceRecord) error {
	switch rr.Type {
	case TypeA:
		if len(rr.RawData) != 4 {
			return errors.New("A record требует 4 байта")
		}
		rr.IP = append(net.IP(nil), rr.RawData...)
		rr.Data = rr.IP.String()
	case TypeAAAA:
		if len(rr.RawData) != 16 {
			return errors.New("AAAA record требует 16 байт")
		}
		rr.IP = append(net.IP(nil), rr.RawData...)
		rr.Data = rr.IP.String()
	case TypeNS, TypeCNAME:
		name, _, err := readName(packet, rdataOffset, 0)
		if err != nil {
			return err
		}
		rr.Data = name
	case TypeMX:
		if len(rr.RawData) < 3 {
			return errors.New("MX record слишком короткий")
		}
		rr.MXPreference = binary.BigEndian.Uint16(rr.RawData[0:2])
		name, _, err := readName(packet, rdataOffset+2, 0)
		if err != nil {
			return err
		}
		rr.Data = name
	case TypeOPT:
		rr.Data = fmt.Sprintf("udp-payload=%d", rr.Class)
	default:
		rr.Data = fmt.Sprintf("type=%d len=%d", rr.Type, len(rr.RawData))
	}
	return nil
}

func readName(data []byte, offset int, depth int) (string, int, error) {
	if depth > 10 {
		return "", offset, errors.New("слишком глубокая компрессия DNS name")
	}
	if offset >= len(data) {
		return "", offset, errors.New("DNS name выходит за границы пакета")
	}

	var labels []string
	jumped := false
	for {
		if offset >= len(data) {
			return "", offset, errors.New("DNS name выходит за границы пакета")
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(data) {
				return "", offset, errors.New("обрезанный compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3fff)
			name, _, err := readName(data, ptr, depth+1)
			if err != nil {
				return "", offset, err
			}
			labels = append(labels, name)
			offset += 2
			jumped = true
			break
		}
		offset++
		if offset+length > len(data) {
			return "", offset, errors.New("label выходит за границы DNS пакета")
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	name := strings.Join(labels, ".")
	if jumped {
		return normalizeDomain(name), offset, nil
	}
	return normalizeDomain(name), offset, nil
}

func encodeName(name string) ([]byte, error) {
	name = normalizeDomain(name)
	if name == "." || name == "" {
		return []byte{0}, nil
	}
	parts := strings.Split(name, ".")
	out := make([]byte, 0, len(name)+2)
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		if len(part) > 63 {
			return nil, fmt.Errorf("DNS label слишком длинный: %q", part)
		}
		out = append(out, byte(len(part)))
		out = append(out, []byte(part)...)
	}
	out = append(out, 0)
	return out, nil
}

func normalizeDomain(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	if name == "" {
		return "."
	}
	return strings.ToLower(name)
}

func (h Header) IsResponse() bool {
	return h.Flags&(1<<15) != 0
}

func (h Header) RecursionDesired() bool {
	return h.Flags&(1<<8) != 0
}

func (h Header) RecursionAvailable() bool {
	return h.Flags&(1<<7) != 0
}

func (h Header) Authoritative() bool {
	return h.Flags&(1<<10) != 0
}

func (h Header) Truncated() bool {
	return h.Flags&(1<<9) != 0
}

func (h Header) Opcode() uint16 {
	return (h.Flags >> 11) & 0x0f
}

func (h Header) RCode() uint16 {
	return h.Flags & 0x0f
}

func (h Header) FlagSummary() string {
	flags := make([]string, 0, 5)
	if h.IsResponse() {
		flags = append(flags, "qr")
	} else {
		flags = append(flags, "query")
	}
	if h.Authoritative() {
		flags = append(flags, "aa")
	}
	if h.Truncated() {
		flags = append(flags, "tc")
	}
	if h.RecursionDesired() {
		flags = append(flags, "rd")
	}
	if h.RecursionAvailable() {
		flags = append(flags, "ra")
	}
	return strings.Join(flags, ",")
}

func RCodeString(code uint16) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE(%d)", code)
	}
}

func TypeString(qtype uint16) string {
	switch qtype {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeMX:
		return "MX"
	case TypeAAAA:
		return "AAAA"
	case TypeOPT:
		return "OPT"
	default:
		return fmt.Sprintf("TYPE(%d)", qtype)
	}
}
