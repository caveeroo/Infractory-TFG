package tasks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infractory/infractory/v2/agent/internal/paths"
	"github.com/infractory/infractory/v2/agent/internal/protocol"
	"github.com/infractory/infractory/v2/agent/internal/runner"
)

func TestNormalizeComposePreservesSafeFieldsAndPinsImages(t *testing.T) {
	raw := `services:
  api:
    image: example/api:latest
    environment:
      MODE: production
    ports:
      - "8443:443"
networks:
  default: {}
`
	got, err := normalizeCompose(raw, map[string]string{"api": "example/api@sha256:" + strings.Repeat("a", 64)}, []protocol.AllowedPort{{Protocol: "tcp", Port: 8443}}, "")
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !strings.Contains(text, "environment:") || !strings.Contains(text, "networks:") || !strings.Contains(text, "@sha256:") {
		t.Fatalf("normalized Compose lost fields:\n%s", text)
	}
}

func TestNormalizeComposeRejectsDangerousCapabilities(t *testing.T) {
	cases := []string{
		"services:\n  x:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    privileged: true\n",
		"services:\n  x:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    network_mode: host\n",
		"services:\n  x:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    volumes: [/var/run/docker.sock:/var/run/docker.sock]\n",
		"services:\n  x:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    volumes: [/etc:/mnt]\n",
		"services:\n  x:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    ports: ['80:80']\n",
	}
	for _, raw := range cases {
		if _, err := normalizeCompose(raw, nil, nil, ""); err == nil {
			t.Fatalf("expected rejection:\n%s", raw)
		}
	}
}

type recordingRunner struct{ calls [][]string }

type recordingCertificateRequester struct{ request map[string]any }

func (r *recordingCertificateRequester) RequestNebulaCertificate(_ context.Context, request map[string]any) (map[string]any, error) {
	r.request = request
	return map[string]any{"certificate": "test-certificate", "caCertificate": "test-ca"}, nil
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (runner.Result, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return runner.Result{}, nil
}

func TestApplyWorkloadUsesOnlyArgvAndConfinedFiles(t *testing.T) {
	rootPath := t.TempDir()
	root, _ := paths.New(rootPath)
	commands := &recordingRunner{}
	executor := &Executor{Root: root, Runner: commands, ComposeBinary: "/var/lib/infractory/bin/docker-compose"}
	id := "11111111-1111-4111-8111-111111111111"
	_, err := executor.applyWorkload(context.Background(), protocol.ApplyWorkloadPayload{EnvironmentID: id, DeploymentID: id, Generation: 1, ComposeYAML: "services:\n  api:\n    image: image:tag\n", ResolvedImages: map[string]string{"api": "image@sha256:" + strings.Repeat("b", 64)}, SecretFiles: []protocol.SecretFile{{Target: "/var/lib/infractory/environments/" + id + "/deployments/" + id + "/1/secrets/api/token", ContentBase64: "c2VjcmV0"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(commands.calls) != 2 || commands.calls[0][0] != executor.ComposeBinary || commands.calls[1][0] != executor.ComposeBinary {
		t.Fatalf("unexpected calls: %#v", commands.calls)
	}
	secret := filepath.Join(rootPath, "environments", id, "deployments", id, "1", "secrets", "api", "token")
	st, err := os.Stat(secret)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0400 {
		t.Fatalf("secret mode %o", st.Mode().Perm())
	}
}

func TestEnsureNebulaAcceptsInitialGenerationZero(t *testing.T) {
	root, _ := paths.New(t.TempDir())
	commands := &recordingRunner{}
	certificates := &recordingCertificateRequester{}
	executor := &Executor{Root: root, Runner: commands, Certificates: certificates}
	environmentID := "11111111-1111-4111-8111-111111111111"

	result, err := executor.ensureNebula(context.Background(), 0, protocol.EnsureNebulaPayload{
		EnvironmentID: environmentID,
		Groups:        []string{"redirector", "web"},
		ConfigYAML:    "firewall:\n  inbound: []\n  outbound: []\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["generation"] != int64(0) {
		t.Fatalf("expected initial generation zero, got %#v", result["generation"])
	}
	requested, ok := certificates.request["requestedGroups"].([]string)
	if !ok || len(requested) != 2 || requested[0] != "redirector" || requested[1] != "web" {
		t.Fatalf("role-derived certificate groups were not forwarded: %#v", certificates.request)
	}
}
