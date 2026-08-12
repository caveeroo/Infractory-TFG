package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/host"
	"github.com/infractory/infractory/v2/agent/internal/journal"
	"github.com/infractory/infractory/v2/agent/internal/paths"
	"github.com/infractory/infractory/v2/agent/internal/protocol"
)

const heartbeatInterval = 15 * time.Second
const fullObservationInterval = 60 * time.Second
const maxClockOffsetSeconds = 5

type ControlPlane interface {
	Enroll(context.Context, protocol.EnrollRequest) (protocol.EnrollResponse, error)
	Heartbeat(context.Context, protocol.HeartbeatRequest) error
	NextTask(context.Context) (*protocol.Task, error)
	Event(context.Context, string, protocol.TaskEventRequest) error
	Complete(context.Context, string, protocol.CompleteTaskRequest) error
}

type TaskExecutor interface {
	Execute(context.Context, protocol.Task) (map[string]any, error)
}
type Observer interface {
	Inspect(context.Context) (host.Observation, error)
}
type FullObserver interface {
	Observe(context.Context) (map[string]any, error)
}

type DeviceAuth interface {
	RotateDeviceToken(context.Context) (protocol.RotateDeviceTokenResponse, error)
	SetDeviceToken(string)
}

type Credentials struct {
	NodeID       string    `json:"nodeId"`
	DeviceToken  string    `json:"deviceToken"`
	TokenExpires time.Time `json:"tokenExpiresAt"`
	Generation   int64     `json:"generation"`
}

type Service struct {
	API                 ControlPlane
	Root                paths.Root
	Journal             *journal.Journal
	Inspector           Observer
	FullObserver        FullObserver
	Executor            TaskExecutor
	Auth                DeviceAuth
	Version             string
	Logger              *slog.Logger
	Now                 func() time.Time
	credentials         Credentials
	mu                  sync.RWMutex
	rotationMu          sync.Mutex
	observationMu       sync.Mutex
	lastRotationAttempt time.Time
	lastFullObservation time.Time
}

func (s *Service) LoadCredentials() error {
	p, err := s.Root.Path("credentials.json")
	if err != nil {
		return err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("decode credentials: %w", err)
	}
	if c.NodeID == "" || len(c.DeviceToken) < 32 {
		return errors.New("stored credentials are invalid")
	}
	s.SetCredentials(c)
	return nil
}

func (s *Service) SaveCredentials(c Credentials) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := s.Root.AtomicWrite(0600, b, "credentials.json"); err != nil {
		return err
	}
	s.SetCredentials(c)
	return nil
}

func (s *Service) SetCredentials(c Credentials) { s.mu.Lock(); defer s.mu.Unlock(); s.credentials = c }
func (s *Service) Credentials() Credentials     { s.mu.RLock(); defer s.mu.RUnlock(); return s.credentials }

func (s *Service) Enroll(ctx context.Context, token string) (Credentials, error) {
	if len(strings.TrimSpace(token)) < 32 {
		return Credentials{}, errors.New("enrollment token is too short")
	}
	observation, err := s.Inspector.Inspect(ctx)
	if err != nil {
		return Credentials{}, err
	}
	public, _, err := s.ensureIdentity()
	if err != nil {
		return Credentials{}, err
	}
	response, err := s.API.Enroll(ctx, protocol.EnrollRequest{Token: strings.TrimSpace(token), PublicKey: base64.StdEncoding.EncodeToString(public), Capabilities: observation.Capabilities})
	if err != nil {
		return Credentials{}, err
	}
	c := Credentials{NodeID: response.NodeID, DeviceToken: response.DeviceToken, TokenExpires: response.ExpiresAt, Generation: 0}
	if err := s.SaveCredentials(c); err != nil {
		return Credentials{}, err
	}
	return c, nil
}

func (s *Service) ensureIdentity() ([]byte, []byte, error) {
	pubPath, _ := s.Root.Path("identity.pub")
	keyPath, _ := s.Root.Path("identity.key")
	if pub, err := os.ReadFile(pubPath); err == nil {
		key, err := os.ReadFile(keyPath)
		return pub, key, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := s.Root.AtomicWrite(0600, key, "identity.key"); err != nil {
		return nil, nil, err
	}
	if err := s.Root.AtomicWrite(0644, pub, "identity.pub"); err != nil {
		return nil, nil, err
	}
	return pub, key, nil
}

func (s *Service) Run(ctx context.Context) error {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	go func() {
		for {
			if err := s.pollOnce(ctx); err != nil && ctx.Err() == nil {
				s.Logger.Warn("task poll failed", "error", err)
				select {
				case <-time.After(time.Second):
				case <-ctx.Done():
					return
				}
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
	if err := s.sendHeartbeat(ctx, true); err != nil {
		s.Logger.Warn("initial heartbeat failed", "error", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			if err := s.sendHeartbeat(ctx, s.fullObservationDue()); err != nil {
				s.Logger.Warn("heartbeat failed", "error", err)
			}
		}
	}
}

func (s *Service) sendHeartbeat(ctx context.Context, full bool) error {
	s.observationMu.Lock()
	defer s.observationMu.Unlock()
	if err := s.rotateBeforeExpiry(ctx); err != nil && s.Logger != nil {
		s.Logger.Warn("automatic device token rotation failed", "error", err)
	}
	o, err := s.Inspector.Inspect(ctx)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(o)
	observation := map[string]any{}
	_ = json.Unmarshal(raw, &observation)
	if full && s.FullObserver != nil {
		if full, fullErr := s.FullObserver.Observe(ctx); fullErr == nil {
			observation = full
			s.lastFullObservation = s.Now().UTC()
		} else if s.Logger != nil {
			s.Logger.Warn("full observation failed; sending host observation", "error", fullErr)
		}
	}
	c := s.Credentials()
	return s.API.Heartbeat(ctx, protocol.HeartbeatRequest{Generation: c.Generation, AgentVersion: s.Version, Capabilities: o.Capabilities, Observation: observation})
}

func (s *Service) fullObservationDue() bool {
	s.observationMu.Lock()
	defer s.observationMu.Unlock()
	return s.lastFullObservation.IsZero() || s.Now().UTC().Sub(s.lastFullObservation) >= fullObservationInterval
}

func (s *Service) rotateBeforeExpiry(ctx context.Context) error {
	if s.Auth == nil {
		return nil
	}
	c := s.Credentials()
	now := s.Now().UTC()
	if c.TokenExpires.IsZero() || c.TokenExpires.Sub(now) > 24*time.Hour {
		return nil
	}
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()
	if !s.lastRotationAttempt.IsZero() && now.Sub(s.lastRotationAttempt) < 30*time.Second {
		return nil
	}
	s.lastRotationAttempt = now
	response, err := s.Auth.RotateDeviceToken(ctx)
	if err != nil {
		return err
	}
	if len(response.DeviceToken) < 32 || response.ExpiresAt.Before(now.Add(time.Hour)) {
		return errors.New("control plane returned an invalid rotated device token")
	}
	c.DeviceToken = response.DeviceToken
	c.TokenExpires = response.ExpiresAt
	if err := s.SaveCredentials(c); err != nil {
		return err
	}
	s.Auth.SetDeviceToken(response.DeviceToken)
	return nil
}

func (s *Service) pollOnce(ctx context.Context) error {
	task, err := s.API.NextTask(ctx)
	if err != nil {
		return err
	}
	if task == nil {
		return nil
	}
	return s.handleTask(ctx, *task)
}

func (s *Service) handleTask(ctx context.Context, task protocol.Task) error {
	now := s.Now().UTC()
	c := s.Credentials()
	if task.ActionKey == "" || task.TaskID == "" || len(task.LeaseToken) < 32 {
		return errors.New("received malformed task")
	}
	if task.NodeGeneration < c.Generation {
		return s.completeAndObserve(ctx, task, journal.Receipt{ActionKey: task.ActionKey, NodeGeneration: task.NodeGeneration, Outcome: "stale", Result: map[string]any{"currentGeneration": c.Generation}, ErrorCode: "STALE_GENERATION", ErrorMessage: "task generation is older than the enrolled node"})
	}
	if !task.Deadline.After(now) || !task.LeaseExpiresAt.After(now) {
		return s.completeAndObserve(ctx, task, journal.Receipt{ActionKey: task.ActionKey, NodeGeneration: task.NodeGeneration, Outcome: "stale", Result: map[string]any{}, ErrorCode: "EXPIRED_TASK", ErrorMessage: "task deadline or lease has expired"})
	}
	if prior, ok := s.Journal.Get(task.ActionKey); ok {
		if prior.NodeGeneration != task.NodeGeneration {
			return s.completeAndObserve(ctx, task, journal.Receipt{ActionKey: task.ActionKey, NodeGeneration: task.NodeGeneration, Outcome: "failed", Result: map[string]any{}, ErrorCode: "ACTION_KEY_CONFLICT", ErrorMessage: "action key was already used by a different node generation"})
		}
		return s.completeAndObserve(ctx, task, prior)
	}
	if isMutatingTask(task.Kind) {
		observation, inspectErr := s.Inspector.Inspect(ctx)
		if inspectErr != nil {
			return s.completeAndObserve(ctx, task, journal.Receipt{ActionKey: task.ActionKey, NodeGeneration: task.NodeGeneration, Outcome: "failed", Result: map[string]any{}, ErrorCode: "CLOCK_SAFETY_UNKNOWN", ErrorMessage: "mutating task blocked because host clock safety could not be inspected"})
		}
		offset := observation.Capabilities.ClockOffsetSeconds
		if !observation.Capabilities.NTPSynchronized || offset == nil || *offset < -maxClockOffsetSeconds || *offset > maxClockOffsetSeconds {
			return s.completeAndObserve(ctx, task, journal.Receipt{ActionKey: task.ActionKey, NodeGeneration: task.NodeGeneration, Outcome: "failed", Result: map[string]any{"ntpSynchronized": observation.Capabilities.NTPSynchronized, "clockOffsetSeconds": offset}, ErrorCode: "CLOCK_UNSAFE", ErrorMessage: "mutating task blocked until NTP is synchronized and the measured control-plane clock offset is within 5 seconds"})
		}
	}
	if task.NodeGeneration > c.Generation {
		c.Generation = task.NodeGeneration
		if err := s.SaveCredentials(c); err != nil {
			return err
		}
	}
	_ = s.API.Event(ctx, task.TaskID, protocol.TaskEventRequest{LeaseToken: task.LeaseToken, Sequence: 0, Level: "info", Message: "Task started"})
	limit := task.Deadline
	if task.LeaseExpiresAt.Before(limit) {
		limit = task.LeaseExpiresAt
	}
	taskCtx, cancel := context.WithDeadline(ctx, limit)
	defer cancel()
	result, executeErr := s.Executor.Execute(taskCtx, task)
	receipt := journal.Receipt{ActionKey: task.ActionKey, NodeGeneration: task.NodeGeneration, Outcome: "succeeded", Result: result, CompletedAt: s.Now().UTC()}
	if executeErr != nil {
		receipt.Outcome = "failed"
		receipt.ErrorCode = errorCode(executeErr)
		receipt.ErrorMessage = truncate(executeErr.Error(), 8192)
		if receipt.Result == nil {
			receipt.Result = map[string]any{}
		}
	}
	if err := s.Journal.Put(receipt); err != nil {
		return fmt.Errorf("persist receipt before completion: %w", err)
	}
	return s.completeAndObserve(ctx, task, receipt)
}

func isMutatingTask(kind protocol.TaskKind) bool {
	switch kind {
	case protocol.TaskEnsurePrerequisites, protocol.TaskEnsureNebula, protocol.TaskApplyWorkload, protocol.TaskRemoveWorkload, protocol.TaskCleanupNode, protocol.TaskUpgradeAgent:
		return true
	default:
		return false
	}
}

func (s *Service) completeReceipt(ctx context.Context, task protocol.Task, r journal.Receipt) error {
	return s.API.Complete(ctx, task.TaskID, protocol.CompleteTaskRequest{LeaseToken: task.LeaseToken, Outcome: r.Outcome, Result: r.Result, ErrorCode: r.ErrorCode, ErrorMessage: r.ErrorMessage})
}
func (s *Service) completeAndObserve(ctx context.Context, task protocol.Task, r journal.Receipt) error {
	completeErr := s.completeReceipt(ctx, task, r)
	observationErr := s.sendHeartbeat(ctx, true)
	if observationErr != nil && s.Logger != nil {
		s.Logger.Warn("post-task observation failed", "error", observationErr)
	}
	return completeErr
}
func errorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "TASK_DEADLINE_EXCEEDED"
	}
	return "TASK_EXECUTION_FAILED"
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
