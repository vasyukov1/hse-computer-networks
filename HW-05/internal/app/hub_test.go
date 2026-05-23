package app

import (
	"errors"
	"testing"

	"hw05chat/internal/domain"
)

func TestJoinRejectsDuplicateName(t *testing.T) {
	hub := NewHub()
	if _, err := hub.Join("alice", nil, make(chan domain.Message, 1)); err != nil {
		t.Fatalf("first join failed: %v", err)
	}
	if _, err := hub.Join("alice", nil, make(chan domain.Message, 1)); !errors.Is(err, domain.ErrNameTaken) {
		t.Fatalf("expected duplicate name error, got %v", err)
	}
}

func TestBroadcastMessageTargetsAllClients(t *testing.T) {
	hub := NewHub()
	alice := make(chan domain.Message, 1)
	bob := make(chan domain.Message, 1)
	_, _ = hub.Join("alice", nil, alice)
	_, _ = hub.Join("bob", nil, bob)

	msg, targets, err := hub.Send("alice", "hello", "", nil)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if msg.Private {
		t.Fatalf("broadcast message should not be private")
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}

func TestPrivateMessageRequiresRecipient(t *testing.T) {
	hub := NewHub()
	_, _ = hub.Join("alice", nil, make(chan domain.Message, 1))

	if _, _, err := hub.Send("alice", "hello", "bob", nil); !errors.Is(err, domain.ErrRecipientMiss) {
		t.Fatalf("expected missing recipient error, got %v", err)
	}
}

func TestHistoryKeepsLastFiftyMessages(t *testing.T) {
	hub := NewHub()
	out := make(chan domain.Message, 100)
	history, err := hub.Join("alice", nil, out)
	if err != nil {
		t.Fatalf("join failed: %v", err)
	}
	if len(history.Messages) != 0 {
		t.Fatalf("new chat should have empty history")
	}

	for i := 0; i < 60; i++ {
		if _, _, err := hub.Send("alice", "x", "", nil); err != nil {
			t.Fatalf("send %d failed: %v", i, err)
		}
	}

	history, err = hub.Join("bob", nil, make(chan domain.Message, 1))
	if err != nil {
		t.Fatalf("second join failed: %v", err)
	}
	if len(history.Messages) != domain.MaxHistoryItems {
		t.Fatalf("expected %d messages, got %d", domain.MaxHistoryItems, len(history.Messages))
	}
	if history.Messages[0].ID != 11 {
		t.Fatalf("expected first retained message id 11, got %d", history.Messages[0].ID)
	}
}
