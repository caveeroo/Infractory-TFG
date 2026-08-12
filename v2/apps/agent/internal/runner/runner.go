package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const maxOutput = 1 << 20

type Result struct {
	Stdout   string        `json:"stdout,omitempty"`
	Stderr   string        `json:"stderr,omitempty"`
	ExitCode int           `json:"exitCode"`
	Duration time.Duration `json:"-"`
}

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (Result, error) {
	if strings.TrimSpace(name) == "" || strings.ContainsRune(name, '\x00') {
		return Result{}, errors.New("invalid executable")
	}
	for _, arg := range args {
		if strings.ContainsRune(arg, '\x00') {
			return Result{}, errors.New("command argument contains NUL")
		}
	}
	started := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := Result{Stdout: stdout.String(), Stderr: stderr.String(), Duration: time.Since(started)}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, fmt.Errorf("%s exited with status %d", name, result.ExitCode)
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	result.ExitCode = -1
	return result, fmt.Errorf("start %s: %w", name, err)
}

type limitedBuffer struct{ b bytes.Buffer }

func (w *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := maxOutput - w.b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.b.Write(p)
	}
	return n, nil
}
func (w *limitedBuffer) String() string { return w.b.String() }
