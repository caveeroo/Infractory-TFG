package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/runner"
)

type fakeRunner struct{ calls [][]string }

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (runner.Result, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	switch name + " " + first(args) {
	case "docker version":
		return runner.Result{Stdout: "27.2.0\n"}, nil
	case "docker compose":
		return runner.Result{Stdout: "2.29.2\n"}, nil
	case "timedatectl show":
		return runner.Result{Stdout: "yes\n"}, nil
	default:
		return runner.Result{}, nil
	}
}
func first(a []string) string {
	if len(a) == 0 {
		return ""
	}
	return a[0]
}

func TestInspectSupportedHost(t *testing.T) {
	dir := t.TempDir()
	osr := filepath.Join(dir, "os-release")
	tun := filepath.Join(dir, "tun")
	init := filepath.Join(dir, "comm")
	if err := os.WriteFile(osr, []byte("ID=ubuntu\nVERSION_ID=24.04\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tun, nil, 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(init, []byte("systemd\n"), 0600)
	r := &fakeRunner{}
	offset := 1.5
	i := Inspector{Runner: r, OSRelease: osr, TUNPath: tun, ProcOneComm: init, Architecture: "amd64", Now: func() time.Time { return time.Unix(1, 0) }, ClockOffset: func() *float64 { return &offset }}
	got, err := i.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities.OS != "ubuntu-24.04" || got.Capabilities.DockerVersion == nil {
		t.Fatalf("unexpected: %#v", got)
	}
	if !got.Capabilities.NTPSynchronized || got.Capabilities.ClockOffsetSeconds == nil || *got.Capabilities.ClockOffsetSeconds != offset {
		t.Fatalf("clock capability was not measured truthfully: %#v", got.Capabilities)
	}
}

func TestInspectReportsClockOffsetUnknownRatherThanZero(t *testing.T) {
	dir := t.TempDir()
	osr := filepath.Join(dir, "os-release")
	tun := filepath.Join(dir, "tun")
	init := filepath.Join(dir, "comm")
	_ = os.WriteFile(osr, []byte("ID=debian\nVERSION_ID=12\n"), 0600)
	_ = os.WriteFile(tun, nil, 0600)
	_ = os.WriteFile(init, []byte("systemd\n"), 0600)
	got, err := (Inspector{Runner: &fakeRunner{}, OSRelease: osr, TUNPath: tun, ProcOneComm: init, Architecture: "arm64", Now: time.Now}).Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities.ClockOffsetSeconds != nil {
		t.Fatalf("unmeasured clock offset must be unknown, got %#v", got.Capabilities.ClockOffsetSeconds)
	}
}

func TestInspectRejectsUnsupportedHostWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	osr := filepath.Join(dir, "os-release")
	tun := filepath.Join(dir, "tun")
	init := filepath.Join(dir, "comm")
	_ = os.WriteFile(osr, []byte("ID=fedora\nVERSION_ID=42\n"), 0600)
	_ = os.WriteFile(tun, nil, 0600)
	_ = os.WriteFile(init, []byte("systemd\n"), 0600)
	r := &fakeRunner{}
	i := Inspector{Runner: r, OSRelease: osr, TUNPath: tun, ProcOneComm: init, Architecture: "amd64", Now: time.Now}
	if _, err := i.Inspect(context.Background()); err == nil {
		t.Fatal("expected unsupported OS")
	}
	if len(r.calls) != 0 {
		t.Fatalf("inspection mutated/called commands: %#v", r.calls)
	}
}
