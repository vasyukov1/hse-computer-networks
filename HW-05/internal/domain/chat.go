package domain

import (
	"errors"
	"strings"
	"time"
)

const (
	MaxClients      = 100
	MaxTextLen      = 25
	MaxHistoryItems = 50
	MaxImageBytes   = 1 << 20
)

var (
	ErrNameRequired   = errors.New("имя не должно быть пустым")
	ErrNameTaken      = errors.New("пользователь с таким именем уже есть в чате")
	ErrChatFull       = errors.New("в чате уже 100 пользователей")
	ErrNotJoined      = errors.New("сначала нужно присоединиться к чату")
	ErrRecipientMiss  = errors.New("получатель сейчас не в чате")
	ErrTextTooLong    = errors.New("сообщение должно быть не длиннее 25 символов")
	ErrEmptyMessage   = errors.New("нельзя отправить пустое сообщение без изображения")
	ErrImageTooLarge  = errors.New("изображение должно быть не больше 1 МБ")
	ErrBadImageFormat = errors.New("поддерживаются только JPEG и PNG")
)

type Image struct {
	MimeType string
	Data     []byte
	Size     int32
}

type User struct {
	Name string
	Icon *Image
}

type Message struct {
	ID         int32
	From       string
	Text       string
	To         string
	Image      *Image
	SenderIcon *Image
	UnixTime   int64
	Private    bool
}

type History struct {
	Messages  []Message
	Images    []Image
	LastImage *Image
	Users     []User
}

func ValidateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return ErrNameRequired
	}
	return nil
}

func ValidateText(text string, hasImage bool) error {
	if len([]rune(text)) > MaxTextLen {
		return ErrTextTooLong
	}
	if strings.TrimSpace(text) == "" && !hasImage {
		return ErrEmptyMessage
	}
	return nil
}

func ValidateImage(img *Image) error {
	if img == nil {
		return nil
	}
	if len(img.Data) > MaxImageBytes || img.Size > MaxImageBytes {
		return ErrImageTooLarge
	}
	switch img.MimeType {
	case "image/png", "image/jpeg":
		return nil
	default:
		return ErrBadImageFormat
	}
}

func NewMessage(id int32, from, text, to string, image *Image) Message {
	return Message{
		ID:       id,
		From:     from,
		Text:     text,
		To:       to,
		Image:    image,
		UnixTime: time.Now().Unix(),
		Private:  to != "",
	}
}
