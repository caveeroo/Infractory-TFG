package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/host"
	"github.com/infractory/infractory/v2/agent/internal/journal"
	"github.com/infractory/infractory/v2/agent/internal/paths"
	"github.com/infractory/infractory/v2/agent/internal/protocol"
)

type fakeAPI struct {
	completed    []protocol.CompleteTaskRequest
	heartbeats   int
	rotated      protocol.RotateDeviceTokenResponse
	currentToken string
}

func (*fakeAPI) Enroll(context.Context, protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	return protocol.EnrollResponse{}, nil
}
func (f *fakeAPI) Heartbeat(context.Context, protocol.HeartbeatRequest) error {
	f.heartbeats++
	return nil
}
func (*fakeAPI) NextTask(context.Context) (*protocol.Task, error)               { return nil, nil }
func (*fakeAPI) Event(context.Context, string, protocol.TaskEventRequest) error { return nil }
func (f *fakeAPI) Complete(_ context.Context, _ string, r protocol.CompleteTaskRequest) error {
	f.completed = append(f.completed, r)
	return nil
}
func (f *fakeAPI) RotateDeviceToken(context.Context) (protocol.RotateDeviceTokenResponse, error) {
	return f.rotated, nil
}
func (f *fakeAPI) SetDeviceToken(token string) { f.currentToken = token }

type fakeExecutor struct{ count int }
type fakeObserver struct {
	synchronized bool
	offset       *float64
}
type fakeFullObserver struct{ count int }

func (f fakeObserver) Inspect(context.Context) (host.Observation, error) {
	return host.Observation{Capabilities: protocol.Capabilities{OS: "ubuntu-24.04", Architecture: "amd64", TunAvailable: true, NTPSynchronized: f.synchronized, ClockOffsetSeconds: f.offset}}, nil
}

func TestMutatingTaskRequiresSynchronizedMeasuredClock(t *testing.T) {
	root, _ := paths.New(t.TempDir())
	j, _ := journal.Open(root, 10)
	now := time.Unix(1000, 0)
	task := protocol.Task{
		TaskID: "11111111-1111-4111-8111-111111111111", ActionKey: "clock-fenced-action-key",
		LeaseToken: "01234567890123456789012345678901", LeaseExpiresAt: now.Add(time.Hour), Deadline: now.Add(time.Hour),
		Kind: protocol.TaskApplyWorkload, Payload: json.RawMessage(`{}`),
	}

	for name, observer := range map[string]fakeObserver{
		"unsynchronized": {},
		"unknown offset": {synchronized: true},
		"outside bound":  {synchronized: true, offset: pointer(5.1)},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			executor := &fakeExecutor{}
			s := &Service{API: api, Root: root, Journal: j, Inspector: observer, Executor: executor, Now: func() time.Time { return now }}
			if err := s.handleTask(context.Background(), task); err != nil {
				t.Fatal(err)
			}
			if executor.count != 0 || api.completed[0].ErrorCode != "CLOCK_UNSAFE" {
				t.Fatalf("unsafe task execution was not fenced: executor=%d completion=%#v", executor.count, api.completed)
			}
		})
	}

	api := &fakeAPI{}
	executor := &fakeExecutor{}
	s := &Service{API: api, Root: root, Journal: j, Inspector: fakeObserver{synchronized: true, offset: pointer(5)}, Executor: executor, Now: func() time.Time { return now }}
	if err := s.handleTask(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if executor.count != 1 {
		t.Fatal("safe boundary clock did not permit the mutating task")
	}
}

func pointer(value float64) *float64 { return &value }

func (f *fakeExecutor) Execute(context.Context, protocol.Task) (map[string]any, error) {
	f.count++
	return map[string]any{"ok": true}, nil
}

func (f *fakeFullObserver) Observe(context.Context) (map[string]any, error) {
	f.count++
	return map[string]any{"full": true}, nil
}

func TestHeartbeatUsesFullObservationOnlyWhenRequested(t *testing.T) {
	root, _ := paths.New(t.TempDir())
	api := &fakeAPI{}
	full := &fakeFullObserver{}
	now := time.Unix(1000, 0)
	s := &Service{
		API:          api,
		Root:         root,
		Inspector:    fakeObserver{},
		FullObserver: full,
		Now:          func() time.Time { return now },
		credentials:  Credentials{Generation: 1},
	}
	for i := 0; i < 3; i++ {
		if err := s.sendHeartbeat(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	if full.count != 0 {
		t.Fatalf("routine 15-second heartbeats performed %d full observations", full.count)
	}
	if err := s.sendHeartbeat(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if full.count != 1 || api.heartbeats != 4 {
		t.Fatalf("full observations=%d heartbeats=%d", full.count, api.heartbeats)
	}
	if s.fullObservationDue() {
		t.Fatal("full observation became due immediately after it completed")
	}
	now = now.Add(fullObservationInterval)
	if !s.fullObservationDue() {
		t.Fatal("full observation was not due after 60 seconds")
	}
}

func TestAutomaticTokenRotationBeforeExpiry(t *testing.T) {
	root, _ := paths.New(t.TempDir())
	now := time.Unix(1000, 0)
	api := &fakeAPI{rotated: protocol.RotateDeviceTokenResponse{DeviceToken: "01234567890123456789012345678901", ExpiresAt: now.Add(30 * 24 * time.Hour)}}
	s := &Service{API: api, Auth: api, Root: root, Now: func() time.Time { return now }, credentials: Credentials{NodeID: "node", DeviceToken: "old-token-that-is-at-least-32-bytes", TokenExpires: now.Add(time.Hour)}}
	if err := s.rotateBeforeExpiry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.currentToken != api.rotated.DeviceToken || s.Credentials().DeviceToken != api.rotated.DeviceToken {
		t.Fatal("rotated token was not installed atomically")
	}
}

func TestStaleAndDuplicateTasksDoNotExecute(t *testing.T) {
	root, _ := paths.New(t.TempDir())
	j, _ := journal.Open(root, 10)
	api := &fakeAPI{}
	executor := &fakeExecutor{}
	now := time.Unix(1000, 0)
	s := &Service{API: api, Root: root, Journal: j, Inspector: fakeObserver{}, Executor: executor, Now: func() time.Time { return now }, credentials: Credentials{Generation: 4}}
	base := protocol.Task{TaskID: "11111111-1111-1111-1111-111111111111", ActionKey: "action-key-that-is-long", LeaseToken: "01234567890123456789012345678901", LeaseExpiresAt: now.Add(time.Hour), Deadline: now.Add(time.Hour), Kind: protocol.TaskInspectHost, Payload: json.RawMessage(`{}`)}
	stale := base
	stale.NodeGeneration = 3
	if err := s.handleTask(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	if executor.count != 0 || api.completed[0].Outcome != "stale" {
		t.Fatal("stale task executed")
	}
	base.NodeGeneration = 4
	if err := s.handleTask(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if err := s.handleTask(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if executor.count != 1 {
		t.Fatalf("duplicate executed %d times", executor.count)
	}
	if api.heartbeats != 3 {
		t.Fatalf("expected observation after every completion, got %d", api.heartbeats)
	}
	conflict := base
	conflict.NodeGeneration = 5
	if err := s.handleTask(context.Background(), conflict); err != nil {
		t.Fatal(err)
	}
	if executor.count != 1 || api.completed[len(api.completed)-1].ErrorCode != "ACTION_KEY_CONFLICT" {
		t.Fatal("action key generation conflict was not fenced")
	}
}
