package redis

import "testing"

func TestCloseWithoutInit(t *testing.T) {
	if err := Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if got := Client(); got != nil {
		t.Fatalf("expected nil client after close, got %#v", got)
	}
}
