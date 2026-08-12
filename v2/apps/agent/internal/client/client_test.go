package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/protocol"
)

func TestClientUsesBearerAndLongPoll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/v1/tasks/next" || r.URL.Query().Get("wait") != "30" {
			t.Errorf("unexpected URL %s", r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer device" {
			t.Errorf("missing bearer")
		}
		_ = json.NewEncoder(w).Encode(protocol.Task{TaskID: "task", ActionKey: "action", Kind: protocol.TaskInspectHost})
	}))
	defer server.Close()
	a := New(server.URL, server.Client())
	a.SetDeviceToken("device")
	task, err := a.NextTask(context.Background())
	if err != nil || task.ActionKey != "action" {
		t.Fatalf("task=%#v err=%v", task, err)
	}
}

func TestControlPlaneClockOffsetIsUnknownUntilBoundedDateMeasurement(t *testing.T) {
	a := New("https://control.invalid", http.DefaultClient)
	if a.ClockOffsetSeconds() != nil {
		t.Fatal("clock offset must start unknown")
	}
	received := time.Now().UTC().Truncate(time.Second)
	started := received.Add(-2 * time.Second)
	a.recordControlPlaneDate(started.Add(4*time.Second).Format(http.TimeFormat), started, received)
	offset := a.ClockOffsetSeconds()
	if offset == nil || *offset != 3 {
		t.Fatalf("midpoint-derived offset = %#v, want 3 seconds", offset)
	}
	// An excessively slow response cannot support a bounded midpoint estimate;
	// retain the last trustworthy sample instead of replacing it with false data.
	a.recordControlPlaneDate(started.Add(time.Minute).Format(http.TimeFormat), started, started.Add(6*time.Second))
	if got := a.ClockOffsetSeconds(); got == nil || *got != 3 {
		t.Fatalf("unbounded exchange replaced trustworthy sample: %#v", got)
	}
	a.mu.Lock()
	a.clockMeasuredAt = time.Now().Add(-maxClockMeasurementAge - time.Second)
	a.mu.Unlock()
	if got := a.ClockOffsetSeconds(); got != nil {
		t.Fatalf("stale clock measurement must become unknown: %#v", got)
	}
}
