package tasks

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/protocol"
)

const (
	maxProbes       = 32
	maxProbeBody    = 4 << 10
	maxProbeError   = 7 << 10
	defaultProbeGap = time.Second
)

var probeServicePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

type probeDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type probeFailure struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

type probeSetError struct{ Failures []probeFailure }

func (e *probeSetError) Error() string {
	type report struct {
		Failures []probeFailure `json:"failures"`
		Omitted  int            `json:"omitted,omitempty"`
	}
	for included := len(e.Failures); included >= 0; included-- {
		body, _ := json.Marshal(report{Failures: e.Failures[:included], Omitted: len(e.Failures) - included})
		message := "workload health probes failed: " + string(body)
		if len(message) <= maxProbeError {
			return message
		}
	}
	return `workload health probes failed: {"failures":[],"omitted":` + strconv.Itoa(len(e.Failures)) + "}"
}

type composeProcess struct {
	Service string `json:"Service"`
	State   string `json:"State"`
	Health  string `json:"Health"`
}

func validateProbes(probes []protocol.Probe) error {
	if len(probes) > maxProbes {
		return fmt.Errorf("at most %d health probes are allowed", maxProbes)
	}
	seen := map[string]bool{}
	for _, probe := range probes {
		if probe.TimeoutSeconds < 1 || probe.TimeoutSeconds > 60 {
			return fmt.Errorf("%s probe %q timeout must be between 1 and 60 seconds", probe.Kind, probe.Target)
		}
		if probe.Target == "" || len(probe.Target) > 2048 {
			return fmt.Errorf("%s probe target is empty or too long", probe.Kind)
		}
		key := probe.Kind + "\x00" + probe.Target
		if seen[key] {
			return fmt.Errorf("duplicate %s probe %q", probe.Kind, probe.Target)
		}
		seen[key] = true
		switch probe.Kind {
		case "container":
			if !probeServicePattern.MatchString(probe.Target) {
				return fmt.Errorf("invalid container service target %q", probe.Target)
			}
		case "http":
			u, err := url.Parse(probe.Target)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
				return fmt.Errorf("invalid HTTP probe target %q", probe.Target)
			}
		case "tcp":
			host, port, err := net.SplitHostPort(probe.Target)
			if err != nil || host == "" || port == "" {
				return fmt.Errorf("TCP probe target %q must be host:port", probe.Target)
			}
			portNumber, err := strconv.Atoi(port)
			if err != nil || portNumber < 1 || portNumber > 65535 {
				return fmt.Errorf("TCP probe target %q has an invalid port", probe.Target)
			}
		case "command":
			return errors.New("command health probes are forbidden")
		default:
			return fmt.Errorf("unsupported health probe kind %q", probe.Kind)
		}
	}
	return nil
}

func (e *Executor) waitForProbes(ctx context.Context, project, composePath string, probes []protocol.Probe, timeout time.Duration) error {
	if len(probes) == 0 {
		return nil
	}
	if err := validateProbes(probes); err != nil {
		return err
	}
	if timeout <= 0 {
		return errors.New("health probe window must be positive")
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	gap := e.ProbeRetryInterval
	if gap <= 0 {
		gap = defaultProbeGap
	}
	var failures []probeFailure
	var lastCompletedFailures []probeFailure
	for {
		failures = e.evaluateProbes(probeCtx, project, composePath, probes)
		if len(failures) == 0 {
			return nil
		}
		if probeCtx.Err() != nil {
			if len(lastCompletedFailures) != 0 {
				return &probeSetError{Failures: lastCompletedFailures}
			}
			return &probeSetError{Failures: failures}
		}
		lastCompletedFailures = failures
		timer := time.NewTimer(gap)
		select {
		case <-probeCtx.Done():
			timer.Stop()
			return &probeSetError{Failures: lastCompletedFailures}
		case <-timer.C:
		}
	}
}

func (e *Executor) evaluateProbes(ctx context.Context, project, composePath string, probes []protocol.Probe) []probeFailure {
	failures := make([]probeFailure, 0)
	for _, probe := range probes {
		probeCtx, cancel := context.WithTimeout(ctx, time.Duration(probe.TimeoutSeconds)*time.Second)
		err := e.evaluateProbe(probeCtx, project, composePath, probe)
		cancel()
		if err != nil {
			failures = append(failures, probeFailure{Kind: probe.Kind, Target: probe.Target, Reason: boundedReason(err)})
		}
	}
	sort.Slice(failures, func(i, j int) bool {
		if failures[i].Kind == failures[j].Kind {
			return failures[i].Target < failures[j].Target
		}
		return failures[i].Kind < failures[j].Kind
	})
	return failures
}

func (e *Executor) evaluateProbe(ctx context.Context, project, composePath string, probe protocol.Probe) error {
	switch probe.Kind {
	case "container":
		result, err := e.compose(ctx, "-p", project, "-f", composePath, "ps", "--format", "json", probe.Target)
		if err != nil {
			return fmt.Errorf("inspect container: %w", err)
		}
		processes, err := parseComposeProcesses(result.Stdout)
		if err != nil {
			return err
		}
		for _, process := range processes {
			if process.Service != probe.Target {
				continue
			}
			if !strings.EqualFold(process.State, "running") {
				return fmt.Errorf("service state is %q", process.State)
			}
			if process.Health != "" && !strings.EqualFold(process.Health, "healthy") {
				return fmt.Errorf("service health is %q", process.Health)
			}
			return nil
		}
		return errors.New("service is absent")
	case "http":
		client := e.ProbeHTTPClient
		if client == nil {
			transport := &http.Transport{
				DialContext:           (&net.Dialer{Timeout: time.Duration(probe.TimeoutSeconds) * time.Second}).DialContext,
				TLSHandshakeTimeout:   time.Duration(probe.TimeoutSeconds) * time.Second,
				ResponseHeaderTimeout: time.Duration(probe.TimeoutSeconds) * time.Second,
			}
			client = &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.Target, nil)
		if err != nil {
			return err
		}
		request.Header.Set("User-Agent", "infractory-agent-health/1")
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("HTTP request: %w", err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxProbeBody))
		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return fmt.Errorf("HTTP status %d", response.StatusCode)
		}
		return nil
	case "tcp":
		dialer := e.ProbeDialer
		if dialer == nil {
			dialer = &net.Dialer{Timeout: time.Duration(probe.TimeoutSeconds) * time.Second}
		}
		connection, err := dialer.DialContext(ctx, "tcp", probe.Target)
		if err != nil {
			return fmt.Errorf("TCP connect: %w", err)
		}
		return connection.Close()
	default:
		return fmt.Errorf("unsupported probe kind %q", probe.Kind)
	}
}

func parseComposeProcesses(raw string) ([]composeProcess, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	var list []composeProcess
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &list); err != nil {
			return nil, fmt.Errorf("decode Compose process list: %w", err)
		}
		return list, nil
	}
	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var process composeProcess
		if err := json.Unmarshal(scanner.Bytes(), &process); err != nil {
			return nil, fmt.Errorf("decode Compose process: %w", err)
		}
		list = append(list, process)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

func boundedReason(err error) string {
	reason := err.Error()
	if len(reason) > 512 {
		return reason[:512]
	}
	return reason
}

func (e *Executor) workloadHealthWindow(timeoutSeconds int) time.Duration {
	if e.ProbeWindowOverride > 0 {
		return e.ProbeWindowOverride
	}
	return time.Duration(timeoutSeconds) * time.Second
}

func (e *Executor) recoverWorkloadRelease(ctx context.Context, project, failedCompose, current string, base []string, timeoutSeconds int, healthWindow time.Duration, cause error) error {
	failedGeneration := filepath.Base(filepath.Dir(failedCompose))
	recoveryWindow := healthWindow
	if recoveryWindow > time.Minute {
		recoveryWindow = time.Minute
	}
	if recoveryWindow <= 0 {
		recoveryWindow = time.Minute
	}
	if current == failedGeneration {
		return fmt.Errorf("release %s failed health verification and no distinct previous release is available: %w", failedGeneration, cause)
	}
	if current == "" {
		cleanupCtx, cancelCleanup := context.WithTimeout(ctx, recoveryWindow)
		_, cleanupErr := e.compose(cleanupCtx, "-p", project, "-f", failedCompose, "down", "--remove-orphans")
		cancelCleanup()
		if cleanupErr != nil {
			return fmt.Errorf("release %s failed and no previous release is available; stopping the failed release also failed: %v; original failure: %w", failedGeneration, cleanupErr, cause)
		}
		return fmt.Errorf("release %s failed and no previous release is available; the failed release was stopped: %w", failedGeneration, cause)
	}
	previousGeneration, err := strconv.ParseInt(current, 10, 64)
	if err != nil || previousGeneration < 1 {
		return fmt.Errorf("release %s failed and the previous release pointer is corrupt: %w", failedGeneration, cause)
	}
	previousCompose := mustPath(e.Root, append(base, current, "compose.yml")...)
	if _, err := os.Stat(previousCompose); err != nil {
		return fmt.Errorf("release %s failed and previous release %s cannot be read: %v; original failure: %w", failedGeneration, current, err, cause)
	}
	rollbackTimeoutSeconds := timeoutSeconds
	if rollbackTimeoutSeconds > 60 {
		rollbackTimeoutSeconds = 60
	}
	rollbackCtx, cancelRollback := context.WithTimeout(ctx, recoveryWindow)
	_, rollbackErr := e.compose(rollbackCtx, "-p", project, "-f", previousCompose, "up", "-d", "--wait", "--wait-timeout", strconv.Itoa(rollbackTimeoutSeconds), "--remove-orphans")
	cancelRollback()
	if rollbackErr != nil {
		return fmt.Errorf("release %s failed; rollback to release %s also failed: %v; original failure: %w", failedGeneration, current, rollbackErr, cause)
	}

	probeBytes, readErr := os.ReadFile(mustPath(e.Root, append(base, current, "probes.json")...))
	if errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("release %s failed; rollback to release %s succeeded and passed Compose health verification (no explicit probes were recorded): %w", failedGeneration, current, cause)
	}
	if readErr != nil {
		return fmt.Errorf("release %s failed; rollback to release %s ran, but its health definition could not be read: %v; original failure: %w", failedGeneration, current, readErr, cause)
	}
	var previousProbes []protocol.Probe
	if err := json.Unmarshal(probeBytes, &previousProbes); err != nil {
		return fmt.Errorf("release %s failed; rollback to release %s ran, but its health definition is corrupt: %v; original failure: %w", failedGeneration, current, err, cause)
	}
	if err := e.waitForProbes(ctx, project, previousCompose, previousProbes, recoveryWindow); err != nil {
		return fmt.Errorf("release %s failed; rollback to release %s ran but rollback health verification failed: %v; original failure: %w", failedGeneration, current, err, cause)
	}
	return fmt.Errorf("release %s failed; rollback to release %s succeeded and passed health verification: %w", failedGeneration, current, cause)
}
