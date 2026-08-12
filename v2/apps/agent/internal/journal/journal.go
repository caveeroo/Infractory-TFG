package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/paths"
)

const (
	defaultLimit    = 256
	maxReceiptBytes = 64 << 10
)

type Receipt struct {
	ActionKey      string         `json:"actionKey"`
	NodeGeneration int64          `json:"nodeGeneration"`
	Outcome        string         `json:"outcome"`
	Result         map[string]any `json:"result"`
	ErrorCode      string         `json:"errorCode,omitempty"`
	ErrorMessage   string         `json:"errorMessage,omitempty"`
	CompletedAt    time.Time      `json:"completedAt"`
}

type fileData struct {
	Version  int       `json:"version"`
	Receipts []Receipt `json:"receipts"`
}

type Journal struct {
	mu       sync.Mutex
	root     paths.Root
	limit    int
	receipts map[string]Receipt
}

func Open(root paths.Root, limit int) (*Journal, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	j := &Journal{root: root, limit: limit, receipts: map[string]Receipt{}}
	p, err := root.Path("receipts.json")
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return j, nil
		}
		return nil, fmt.Errorf("read receipt journal: %w", err)
	}
	var data fileData
	if err := json.Unmarshal(b, &data); err != nil || data.Version != 1 {
		return nil, errors.New("receipt journal is corrupt or unsupported")
	}
	for _, r := range data.Receipts {
		j.receipts[r.ActionKey] = r
	}
	return j, nil
}

func (j *Journal) Get(actionKey string) (Receipt, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.receipts[actionKey]
	return r, ok
}

func (j *Journal) Put(receipt Receipt) error {
	if receipt.ActionKey == "" {
		return errors.New("action key is required")
	}
	encodedReceipt, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	if len(encodedReceipt) > maxReceiptBytes {
		return errors.New("receipt exceeds the 64 KiB durability limit")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if old, exists := j.receipts[receipt.ActionKey]; exists && old.NodeGeneration != receipt.NodeGeneration {
		return errors.New("action key was previously used by a different node generation")
	}
	j.receipts[receipt.ActionKey] = receipt
	items := make([]Receipt, 0, len(j.receipts))
	for _, r := range j.receipts {
		items = append(items, r)
	}
	sort.Slice(items, func(a, b int) bool { return items[a].CompletedAt.After(items[b].CompletedAt) })
	if len(items) > j.limit {
		items = items[:j.limit]
		j.receipts = make(map[string]Receipt, len(items))
		for _, r := range items {
			j.receipts[r.ActionKey] = r
		}
	}
	b, err := json.Marshal(fileData{Version: 1, Receipts: items})
	if err != nil {
		return err
	}
	return j.root.AtomicWrite(0600, b, "receipts.json")
}
