package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/paths"
	"github.com/infractory/infractory/v2/agent/internal/protocol"
	"github.com/infractory/infractory/v2/agent/internal/runner"
)

type scriptedRunner struct {
	mu    sync.Mutex
	calls [][]string
	run   func(name string, args []string) (runner.Result, error)
}

func (r *scriptedRunner) Run(_ context.Context, name string, args ...string) (runner.Result, error) {
	r.mu.Lock()
	r.calls = append(r.calls, append([]string{name}, args...))
	r.mu.Unlock()
	if r.run == nil {
		return runner.Result{}, nil
	}
	return r.run(name, args)
}

func TestValidateProbesRejectsUnsafeOrInvalidDefinitions(t *testing.T) {
	tests := []protocol.Probe{
		{Kind: "command", Target: "true", TimeoutSeconds: 1},
		{Kind: "container", Target: "../api", TimeoutSeconds: 1},
		{Kind: "http", Target: "file:///etc/passwd", TimeoutSeconds: 1},
		{Kind: "tcp", Target: "127.0.0.1:70000", TimeoutSeconds: 1},
		{Kind: "tcp", Target: "127.0.0.1:80", TimeoutSeconds: 0},
	}
	for _, probe := range tests {
		if err := validateProbes([]protocol.Probe{probe}); err == nil {
			t.Fatalf("expected probe to be rejected: %#v", probe)
		}
	}
	duplicate := protocol.Probe{Kind: "container", Target: "api", TimeoutSeconds: 1}
	if err := validateProbes([]protocol.Probe{duplicate, duplicate}); err == nil {
		t.Fatal("expected duplicate probes to be rejected")
	}
}

func TestParseComposeProcessesAcceptsArrayAndJSONLines(t *testing.T) {
	for _, raw := range []string{
		`[{"Service":"api","State":"running","Health":"healthy"}]`,
		"{\"Service\":\"api\",\"State\":\"running\",\"Health\":\"healthy\"}\n{\"Service\":\"worker\",\"State\":\"running\",\"Health\":\"\"}\n",
	} {
		processes, err := parseComposeProcesses(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(processes) == 0 || processes[0].Service != "api" {
			t.Fatalf("unexpected process list: %#v", processes)
		}
	}
}

func TestEvaluateContainerHTTPAndTCPProbes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
		close(accepted)
	}()

	commands := &scriptedRunner{run: func(_ string, args []string) (runner.Result, error) {
		if containsArgument(args, "ps") {
			return runner.Result{Stdout: `[{"Service":"api","State":"running","Health":"healthy"}]`}, nil
		}
		return runner.Result{}, nil
	}}
	executor := &Executor{Runner: commands, ComposeBinary: "/var/lib/infractory/bin/docker-compose"}
	probes := []protocol.Probe{
		{Kind: "container", Target: "api", TimeoutSeconds: 1},
		{Kind: "http", Target: server.URL, TimeoutSeconds: 1},
		{Kind: "tcp", Target: listener.Addr().String(), TimeoutSeconds: 1},
	}
	if failures := executor.evaluateProbes(context.Background(), "project", "/confined/compose.yml", probes); len(failures) != 0 {
		t.Fatalf("healthy probes failed: %#v", failures)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("TCP probe did not connect")
	}
}

func TestWaitForProbesReportsBoundedExactFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unhealthy", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	executor := &Executor{
		Runner:             &scriptedRunner{},
		ComposeBinary:      "/var/lib/infractory/bin/docker-compose",
		ProbeRetryInterval: time.Millisecond,
	}
	err := executor.waitForProbes(context.Background(), "project", "/confined/compose.yml", []protocol.Probe{{Kind: "http", Target: server.URL, TimeoutSeconds: 1}}, 20*time.Millisecond)
	var probeErr *probeSetError
	if !errors.As(err, &probeErr) || len(probeErr.Failures) != 1 {
		t.Fatalf("expected exact probe failure, got %v", err)
	}
	if probeErr.Failures[0].Reason != "HTTP status 503" || len(err.Error()) > maxProbeError {
		t.Fatalf("unexpected bounded failure: %v", err)
	}
	if !strings.Contains(err.Error(), `"reason":"HTTP status 503"`) {
		t.Fatalf("probe report lost its exact reason: %v", err)
	}
}

func TestApplyWorkloadRollsBackAndVerifiesPreviousReleaseHealth(t *testing.T) {
	root, _ := paths.New(t.TempDir())
	id := "11111111-1111-4111-8111-111111111111"
	writePriorRelease(t, root, id, []protocol.Probe{{Kind: "container", Target: "api", TimeoutSeconds: 1}})

	commands := &scriptedRunner{run: func(_ string, args []string) (runner.Result, error) {
		if containsArgument(args, "ps") {
			if strings.Contains(argumentAfter(args, "-f"), string(filepath.Separator)+"1"+string(filepath.Separator)) {
				return runner.Result{Stdout: `[{"Service":"api","State":"running","Health":"healthy"}]`}, nil
			}
			return runner.Result{Stdout: `[{"Service":"api","State":"running","Health":"unhealthy"}]`}, nil
		}
		return runner.Result{}, nil
	}}
	executor := &Executor{
		Root:                root,
		Runner:              commands,
		ComposeBinary:       "/var/lib/infractory/bin/docker-compose",
		ProbeRetryInterval:  time.Millisecond,
		ProbeWindowOverride: 15 * time.Millisecond,
	}
	_, err := executor.applyWorkload(context.Background(), workloadPayload(id, 2, []protocol.Probe{{Kind: "container", Target: "api", TimeoutSeconds: 1}}))
	if err == nil || !strings.Contains(err.Error(), "rollback to release 1 succeeded and passed health verification") || !strings.Contains(err.Error(), `service health is \"unhealthy\"`) {
		t.Fatalf("expected truthful successful rollback result, got %v", err)
	}
	current, readErr := os.Readlink(mustPath(root, "environments", id, "deployments", id, "current"))
	if readErr != nil || current != "1" {
		t.Fatalf("current release moved despite failed update: %q %v", current, readErr)
	}
	if !runnerCalledWithComposePath(commands, string(filepath.Separator)+"1"+string(filepath.Separator)+"compose.yml", "up") {
		t.Fatalf("previous release was not reapplied: %#v", commands.calls)
	}
}

func TestApplyWorkloadReportsRollbackFailure(t *testing.T) {
	root, _ := paths.New(t.TempDir())
	id := "22222222-2222-4222-8222-222222222222"
	writePriorRelease(t, root, id, nil)
	commands := &scriptedRunner{run: func(_ string, args []string) (runner.Result, error) {
		composePath := argumentAfter(args, "-f")
		if containsArgument(args, "ps") {
			return runner.Result{Stdout: `[{"Service":"api","State":"exited","Health":""}]`}, nil
		}
		if containsArgument(args, "up") && strings.Contains(composePath, string(filepath.Separator)+"1"+string(filepath.Separator)) {
			return runner.Result{}, errors.New("rollback compose failed")
		}
		return runner.Result{}, nil
	}}
	executor := &Executor{Root: root, Runner: commands, ComposeBinary: "/var/lib/infractory/bin/docker-compose", ProbeRetryInterval: time.Millisecond, ProbeWindowOverride: 10 * time.Millisecond}
	_, err := executor.applyWorkload(context.Background(), workloadPayload(id, 2, []protocol.Probe{{Kind: "container", Target: "api", TimeoutSeconds: 1}}))
	if err == nil || !strings.Contains(err.Error(), "rollback to release 1 also failed") || !strings.Contains(err.Error(), "rollback compose failed") {
		t.Fatalf("expected rollback failure to be reported, got %v", err)
	}
}

func writePriorRelease(t *testing.T, root paths.Root, id string, probes []protocol.Probe) {
	t.Helper()
	base := []string{"environments", id, "deployments", id}
	compose := []byte("services:\n  api:\n    image: image@sha256:" + strings.Repeat("a", 64) + "\n")
	if err := root.AtomicWrite(0600, compose, append(base, "1", "compose.yml")...); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(probes)
	if err := root.AtomicWrite(0600, encoded, append(base, "1", "probes.json")...); err != nil {
		t.Fatal(err)
	}
	if err := atomicSymlink("1", mustPath(root, append(base, "current")...)); err != nil {
		t.Fatal(err)
	}
}

func workloadPayload(id string, generation int64, probes []protocol.Probe) protocol.ApplyWorkloadPayload {
	return protocol.ApplyWorkloadPayload{
		EnvironmentID:  id,
		DeploymentID:   id,
		Generation:     generation,
		ComposeYAML:    "services:\n  api:\n    image: image:tag\n",
		ResolvedImages: map[string]string{"api": "image@sha256:" + strings.Repeat("b", 64)},
		Probes:         probes,
		TimeoutSeconds: 1,
	}
}

func containsArgument(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}

func argumentAfter(args []string, target string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == target {
			return args[index+1]
		}
	}
	return ""
}

func runnerCalledWithComposePath(r *scriptedRunner, pathFragment, command string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, call := range r.calls {
		if containsArgument(call, command) && strings.Contains(argumentAfter(call, "-f"), pathFragment) {
			return true
		}
	}
	return false
}
