package journal

import (
	"testing"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/paths"
)

func TestJournalIsDurableBoundedAndGenerationSafe(t *testing.T) {
	root, _ := paths.New(t.TempDir())
	j, err := Open(root, 2)
	if err != nil {
		t.Fatal(err)
	}
	for n, key := range []string{"a", "b", "c"} {
		if err := j.Put(Receipt{ActionKey: key, NodeGeneration: 3, Outcome: "succeeded", CompletedAt: time.Unix(int64(n), 0)}); err != nil {
			t.Fatal(err)
		}
	}
	j, err = Open(root, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := j.Get("a"); ok {
		t.Fatal("oldest receipt should be evicted")
	}
	if _, ok := j.Get("c"); !ok {
		t.Fatal("newest receipt missing")
	}
	if err := j.Put(Receipt{ActionKey: "c", NodeGeneration: 4, CompletedAt: time.Now()}); err == nil {
		t.Fatal("expected generation conflict")
	}
}

func TestJournalRejectsUnboundedResult(t *testing.T) {
	root, _ := paths.New(t.TempDir())
	j, _ := Open(root, 2)
	if err := j.Put(Receipt{ActionKey: "big", Result: map[string]any{"data": string(make([]byte, maxReceiptBytes))}}); err == nil {
		t.Fatal("expected oversized receipt rejection")
	}
}
