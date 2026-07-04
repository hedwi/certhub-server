package services

import (
	"context"
	"errors"
	"testing"
)

func TestRequireACMEActive(t *testing.T) {
	active := true
	ctx := WithCertJobScope(context.Background(), func() bool { return active })

	if err := requireACMEActive(ctx); err != nil {
		t.Fatalf("expected active scope, got %v", err)
	}

	active = false
	if err := requireACMEActive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestRequireACMEActive_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := requireACMEActive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
