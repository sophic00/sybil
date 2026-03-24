package redis

import (
	"sync"
	"testing"
)

func TestCloseWithoutInit(t *testing.T) {
	if err := Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if got := Client(); got != nil {
		t.Fatalf("expected nil client after close, got %#v", got)
	}
}

func TestConcurrentClientAndCloseWithoutInit(t *testing.T) {
	_ = Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = Client()
		}()
		go func() {
			defer wg.Done()
			_ = Close()
		}()
	}
	wg.Wait()

	if got := Client(); got != nil {
		t.Fatalf("expected nil client after concurrent close/client, got %#v", got)
	}
}
