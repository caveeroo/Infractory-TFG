package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	agentservice "github.com/infractory/infractory/v2/agent/internal/agent"
	"github.com/infractory/infractory/v2/agent/internal/client"
	"github.com/infractory/infractory/v2/agent/internal/config"
	"github.com/infractory/infractory/v2/agent/internal/host"
	"github.com/infractory/infractory/v2/agent/internal/journal"
	"github.com/infractory/infractory/v2/agent/internal/paths"
	"github.com/infractory/infractory/v2/agent/internal/runner"
	"github.com/infractory/infractory/v2/agent/internal/tasks"
	"golang.org/x/term"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	if len(args) == 0 || args[0] != "run" {
		return errors.New("usage: infractory-agent run --config /absolute/config.json")
	}
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/infractory-agent/config.json", "absolute JSON configuration path")
	stateOverride := flags.String("state-dir", "", "override state root (tests/development only)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments; enrollment tokens are never accepted on the command line")
	}
	if os.Geteuid() != 0 {
		return errors.New("infractory-agent must run as root")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *stateOverride != "" {
		cfg.StateDir = *stateOverride
		if err := cfg.Validate(); err != nil {
			return err
		}
	}
	root, err := paths.New(cfg.StateDir)
	if err != nil {
		return err
	}
	if err := root.Ensure(); err != nil {
		return err
	}
	j, err := journal.Open(root, 256)
	if err != nil {
		return err
	}
	httpClient, err := cfg.HTTPClient()
	if err != nil {
		return err
	}
	api := client.New(cfg.ControlPlaneURL, httpClient)
	commandRunner := runner.ExecRunner{}
	inspector := host.NewInspector(commandRunner)
	inspector.ClockOffset = api.ClockOffsetSeconds
	composeBinary, _ := root.Path("bin", "docker-compose")
	composeURL, composeSHA, err := pinnedCompose(runtime.GOARCH)
	if err != nil {
		return err
	}
	inspector.ComposeBinary = composeBinary
	service := &agentservice.Service{API: api, Auth: api, Root: root, Journal: j, Inspector: inspector, Version: version, Logger: slog.Default()}
	executor := &tasks.Executor{Root: root, Runner: commandRunner, Inspector: inspector, Certificates: api, Tokens: api, HTTPClient: httpClient, ComposeBinary: composeBinary, ComposeURL: composeURL, ComposeSHA256: composeSHA}
	service.FullObserver = executor
	executor.SaveToken = func(token string) error {
		credentials := service.Credentials()
		credentials.DeviceToken = token
		if err := service.SaveCredentials(credentials); err != nil {
			return err
		}
		api.SetDeviceToken(token)
		return nil
	}
	service.Executor = executor
	if err := service.LoadCredentials(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		token, err := readEnrollmentToken(cfg.EnrollmentTokenFile)
		if err != nil {
			return err
		}
		if _, err := service.Enroll(context.Background(), token); err != nil {
			return err
		}
		if cfg.EnrollmentTokenFile != "" {
			if err := os.Remove(cfg.EnrollmentTokenFile); err != nil {
				return fmt.Errorf("remove consumed enrollment token: %w", err)
			}
		}
	}
	credentials := service.Credentials()
	api.SetDeviceToken(credentials.DeviceToken)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return service.Run(ctx)
}

func pinnedCompose(architecture string) (string, string, error) {
	const base = "https://github.com/docker/compose/releases/download/v2.39.1/"
	switch architecture {
	case "amd64":
		return base + "docker-compose-linux-x86_64", "a5ea28722d5da628b59226626f7d6c33c89a7ed19e39f750645925242044c9d2", nil
	case "arm64":
		return base + "docker-compose-linux-aarch64", "7b2627ed76f7dcb0d93f649f185af912372229b4c09762a3cd1db5be5255632b", nil
	default:
		return "", "", fmt.Errorf("unsupported architecture %q", architecture)
	}
}

func readEnrollmentToken(path string) (string, error) {
	if path != "" {
		st, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return "", errors.New("enrollment token file must be regular and mode 0600 or stricter")
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 {
			return "", errors.New("enrollment token file must be owned by root")
		}
		b, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	fmt.Fprint(os.Stderr, "Enrollment token: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if errors.Is(err, io.EOF) && strings.TrimSpace(line) != "" {
		err = nil
	}
	return strings.TrimSpace(line), err
}
