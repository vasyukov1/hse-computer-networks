package app

import (
	"errors"
	"sync"

	"hw05chat/internal/domain"
)

type Client struct {
	Name string
	Icon *domain.Image
	Send chan domain.Message
}

type Hub struct {
	mu       sync.RWMutex
	clients  map[string]*Client
	messages []domain.Message
	images   []domain.Image
	nextID   int32
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[string]*Client),
	}
}

func (h *Hub) Join(name string, icon *domain.Image, out chan domain.Message) (domain.History, error) {
	if err := domain.ValidateName(name); err != nil {
		return domain.History{}, err
	}
	if err := domain.ValidateImage(icon); err != nil {
		return domain.History{}, err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.clients) >= domain.MaxClients {
		return domain.History{}, domain.ErrChatFull
	}
	if _, exists := h.clients[name]; exists {
		return domain.History{}, domain.ErrNameTaken
	}

	h.clients[name] = &Client{Name: name, Icon: icon, Send: out}
	return h.historyLocked(), nil
}

func (h *Hub) Leave(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, name)
}

func (h *Hub) Send(from, text, to string, image *domain.Image) (domain.Message, []chan domain.Message, error) {
	if err := domain.ValidateText(text, image != nil); err != nil {
		return domain.Message{}, nil, err
	}
	if err := domain.ValidateImage(image); err != nil {
		return domain.Message{}, nil, err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.clients[from]; !ok {
		return domain.Message{}, nil, domain.ErrNotJoined
	}
	if to != "" {
		if _, ok := h.clients[to]; !ok {
			return domain.Message{}, nil, domain.ErrRecipientMiss
		}
	}

	h.nextID++
	msg := domain.NewMessage(h.nextID, from, text, to, image)
	msg.SenderIcon = h.clients[from].Icon
	h.appendHistoryLocked(msg)

	targets := make([]chan domain.Message, 0, len(h.clients))
	if to == "" {
		for _, client := range h.clients {
			targets = append(targets, client.Send)
		}
		return msg, targets, nil
	}

	targets = append(targets, h.clients[to].Send)
	if to != from {
		targets = append(targets, h.clients[from].Send)
	}
	return msg, targets, nil
}

func (h *Hub) Icon(name string) *domain.Image {
	h.mu.RLock()
	defer h.mu.RUnlock()
	client := h.clients[name]
	if client == nil {
		return nil
	}
	return client.Icon
}

func (h *Hub) historyLocked() domain.History {
	history := domain.History{
		Messages: append([]domain.Message(nil), h.messages...),
		Images:   append([]domain.Image(nil), h.images...),
		Users:    make([]domain.User, 0, len(h.clients)),
	}
	if len(h.images) > 0 {
		last := h.images[len(h.images)-1]
		history.LastImage = &last
	}
	for _, client := range h.clients {
		history.Users = append(history.Users, domain.User{Name: client.Name, Icon: client.Icon})
	}
	return history
}

func (h *Hub) appendHistoryLocked(msg domain.Message) {
	h.messages = append(h.messages, msg)
	if len(h.messages) > domain.MaxHistoryItems {
		h.messages = h.messages[len(h.messages)-domain.MaxHistoryItems:]
	}
	if msg.Image != nil {
		h.images = append(h.images, *msg.Image)
		if len(h.images) > domain.MaxHistoryItems {
			h.images = h.images[len(h.images)-domain.MaxHistoryItems:]
		}
	}
}

func TrySend(ch chan domain.Message, msg domain.Message) error {
	select {
	case ch <- msg:
		return nil
	default:
		return errors.New("канал клиента переполнен")
	}
}
