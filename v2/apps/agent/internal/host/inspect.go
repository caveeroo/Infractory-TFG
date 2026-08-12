package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/protocol"
	"github.com/infractory/infractory/v2/agent/internal/runner"
)

type Inspector struct {
	Runner        runner.CommandRunner
	OSRelease     string
	TUNPath       string
	ProcOneComm   string
	Architecture  string
	ComposeBinary string
	Now           func() time.Time
	// ClockOffset returns control-plane time minus local time from a recent,
	// bounded HTTPS Date measurement. Nil means the offset is unknown.
	ClockOffset func() *float64
}

type Observation struct {
	Capabilities      protocol.Capabilities `json:"capabilities"`
	Hostname          string                `json:"hostname"`
	Systemd           bool                  `json:"systemd"`
	DockerActive      bool                  `json:"dockerActive"`
	NebulaActive      bool                  `json:"nebulaActive"`
	ClockSynchronized bool                  `json:"clockSynchronized"`
	ObservedAt        time.Time             `json:"observedAt"`
}

func NewInspector(r runner.CommandRunner) Inspector {
	return Inspector{Runner: r, OSRelease: "/etc/os-release", TUNPath: "/dev/net/tun", ProcOneComm: "/proc/1/comm", Architecture: runtime.GOARCH, Now: time.Now}
}

func (i Inspector) Inspect(ctx context.Context) (Observation, error) {
	osData, err := os.ReadFile(i.OSRelease)
	if err != nil {
		return Observation{}, fmt.Errorf("read os-release: %w", err)
	}
	fields := parseOSRelease(string(osData))
	osName := fields["ID"] + "-" + fields["VERSION_ID"]
	if osName != "ubuntu-22.04" && osName != "ubuntu-24.04" && osName != "debian-12" {
		return Observation{}, fmt.Errorf("unsupported operating system %q", osName)
	}
	if i.Architecture != "amd64" && i.Architecture != "arm64" {
		return Observation{}, fmt.Errorf("unsupported architecture %q", i.Architecture)
	}
	if _, err := os.Stat(i.TUNPath); err != nil {
		return Observation{}, errors.New("/dev/net/tun is unavailable")
	}
	initName, initErr := os.ReadFile(i.ProcOneComm)
	if initErr != nil || strings.TrimSpace(string(initName)) != "systemd" {
		return Observation{}, errors.New("systemd must be PID 1")
	}
	hostname, _ := os.Hostname()
	dockerVersion := commandVersion(ctx, i.Runner, "docker", "version", "--format", "{{.Server.Version}}")
	var composeVersion *string
	if i.ComposeBinary != "" {
		composeVersion = commandVersion(ctx, i.Runner, i.ComposeBinary, "version", "--short")
	} else {
		composeVersion = commandVersion(ctx, i.Runner, "docker", "compose", "version", "--short")
	}
	systemd := commandOK(ctx, i.Runner, "systemctl", "--version")
	if !systemd {
		return Observation{}, errors.New("systemd is required")
	}
	clockSynchronized := false
	if result, err := i.Runner.Run(ctx, "timedatectl", "show", "--property=NTPSynchronized", "--value"); err == nil {
		clockSynchronized = strings.TrimSpace(result.Stdout) == "yes"
	}
	now := i.Now().UTC()
	var clockOffset *float64
	if i.ClockOffset != nil {
		clockOffset = i.ClockOffset()
	}
	return Observation{
		Capabilities: protocol.Capabilities{
			OS: osName, Architecture: i.Architecture,
			DockerVersion: dockerVersion, ComposeVersion: composeVersion,
			TunAvailable: true, NTPSynchronized: clockSynchronized,
			ClockOffsetSeconds: clockOffset,
		},
		Hostname: hostname, Systemd: true,
		DockerActive:      commandOK(ctx, i.Runner, "systemctl", "is-active", "--quiet", "docker.service"),
		NebulaActive:      commandOK(ctx, i.Runner, "systemctl", "is-active", "--quiet", "nebula.service"),
		ClockSynchronized: clockSynchronized,
		ObservedAt:        now,
	}, nil
}

func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, "\"'")
		if unquoted, err := strconv.Unquote("\"" + strings.ReplaceAll(value, "\"", "\\\"") + "\""); err == nil {
			value = unquoted
		}
		m[key] = value
	}
	return m
}

func commandVersion(ctx context.Context, r runner.CommandRunner, name string, args ...string) *string {
	result, err := r.Run(ctx, name, args...)
	if err != nil {
		return nil
	}
	value := strings.TrimSpace(result.Stdout)
	if value == "" {
		return nil
	}
	return &value
}

func commandOK(ctx context.Context, r runner.CommandRunner, name string, args ...string) bool {
	_, err := r.Run(ctx, name, args...)
	return err == nil
}
