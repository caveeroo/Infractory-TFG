package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/protocol"
)

const (
	maxResponse            = 2 << 20
	maxClockMeasurementAge = 2 * time.Minute
)

type API struct {
	baseURL string
	http    *http.Client
	token   string
	// clockOffsetSeconds is server time minus the local midpoint of a bounded
	// HTTPS exchange. Nil means the control-plane clock has not been measured.
	clockOffsetSeconds *float64
	clockMeasuredAt    time.Time
	mu                 sync.RWMutex
}

func New(baseURL string, h *http.Client) *API {
	return &API{baseURL: strings.TrimRight(baseURL, "/"), http: h}
}

func (a *API) SetDeviceToken(token string) { a.mu.Lock(); defer a.mu.Unlock(); a.token = token }

func (a *API) ClockOffsetSeconds() *float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	age := time.Since(a.clockMeasuredAt)
	if a.clockOffsetSeconds == nil || a.clockMeasuredAt.IsZero() || age < 0 || age > maxClockMeasurementAge {
		return nil
	}
	offset := *a.clockOffsetSeconds
	return &offset
}

func (a *API) Enroll(ctx context.Context, request protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var response protocol.EnrollResponse
	err := a.doJSON(ctx, http.MethodPost, "/agent/v1/enroll", request, &response, false)
	return response, err
}

func (a *API) Heartbeat(ctx context.Context, request protocol.HeartbeatRequest) error {
	return a.doJSON(ctx, http.MethodPost, "/agent/v1/heartbeat", request, nil, true)
}

func (a *API) NextTask(ctx context.Context) (*protocol.Task, error) {
	var task protocol.Task
	status, err := a.request(ctx, http.MethodGet, "/agent/v1/tasks/next?wait=30", nil, &task, true)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return &task, nil
}

func (a *API) Event(ctx context.Context, taskID string, event protocol.TaskEventRequest) error {
	return a.doJSON(ctx, http.MethodPost, "/agent/v1/tasks/"+url.PathEscape(taskID)+"/events", event, nil, true)
}

func (a *API) Complete(ctx context.Context, taskID string, complete protocol.CompleteTaskRequest) error {
	return a.doJSON(ctx, http.MethodPost, "/agent/v1/tasks/"+url.PathEscape(taskID)+"/complete", complete, nil, true)
}

func (a *API) RotateDeviceToken(ctx context.Context) (protocol.RotateDeviceTokenResponse, error) {
	var result protocol.RotateDeviceTokenResponse
	err := a.doJSON(ctx, http.MethodPost, "/agent/v1/device-token/rotate", struct{}{}, &result, true)
	return result, err
}

func (a *API) RequestNebulaCertificate(ctx context.Context, request map[string]any) (map[string]any, error) {
	result := map[string]any{}
	err := a.doJSON(ctx, http.MethodPost, "/agent/v1/nebula-certificate-requests", request, &result, true)
	return result, err
}

func (a *API) doJSON(ctx context.Context, method, path string, input, output any, authenticated bool) error {
	_, err := a.request(ctx, method, path, input, output, authenticated)
	return err
}

func (a *API) request(ctx context.Context, method, path string, input, output any, authenticated bool) (int, error) {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		a.mu.RLock()
		token := a.token
		a.mu.RUnlock()
		if token == "" {
			return 0, errors.New("device token is unavailable")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	startedAt := time.Now()
	response, err := a.http.Do(req)
	if err != nil {
		return 0, err
	}
	a.recordControlPlaneDate(response.Header.Get("Date"), startedAt, time.Now())
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponse+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return response.StatusCode, err
	}
	if len(b) > maxResponse {
		return response.StatusCode, errors.New("control plane response exceeded limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("control plane returned %d: %s", response.StatusCode, safeMessage(b))
	}
	if output != nil && response.StatusCode != http.StatusNoContent {
		if err := json.Unmarshal(b, output); err != nil {
			return response.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}
	return response.StatusCode, nil
}

func (a *API) recordControlPlaneDate(dateHeader string, startedAt, receivedAt time.Time) {
	serverTime, err := http.ParseTime(dateHeader)
	roundTrip := receivedAt.Sub(startedAt)
	if err != nil || roundTrip < 0 || roundTrip > 5*time.Second {
		return
	}
	midpoint := startedAt.Add(roundTrip / 2)
	// HTTP Date has one-second resolution. Reporting fractional precision would
	// imply accuracy the measurement does not have.
	offset := math.Round(serverTime.Sub(midpoint).Seconds())
	a.mu.Lock()
	a.clockOffsetSeconds = &offset
	a.clockMeasuredAt = receivedAt
	a.mu.Unlock()
}

func safeMessage(b []byte) string {
	var p struct{ Title, Detail string }
	if json.Unmarshal(b, &p) == nil {
		if p.Detail != "" {
			return p.Detail
		}
		if p.Title != "" {
			return p.Title
		}
	}
	return http.StatusText(http.StatusBadRequest)
}
