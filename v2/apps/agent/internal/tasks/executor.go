package tasks

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/host"
	"github.com/infractory/infractory/v2/agent/internal/paths"
	"github.com/infractory/infractory/v2/agent/internal/protocol"
	"github.com/infractory/infractory/v2/agent/internal/runner"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
)

var identifierPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

const pathsRootPrefix = "/var/lib/infractory"

type CertificateRequester interface {
	RequestNebulaCertificate(context.Context, map[string]any) (map[string]any, error)
}

type TokenRotator interface {
	RotateDeviceToken(context.Context) (protocol.RotateDeviceTokenResponse, error)
}

type TokenSaver func(string) error

type Executor struct {
	Root                paths.Root
	Runner              runner.CommandRunner
	Inspector           host.Inspector
	Certificates        CertificateRequester
	Tokens              TokenRotator
	SaveToken           TokenSaver
	HTTPClient          *http.Client
	ProbeHTTPClient     *http.Client
	ProbeDialer         probeDialer
	ProbeRetryInterval  time.Duration
	ProbeWindowOverride time.Duration
	ComposeBinary       string
	ComposeURL          string
	ComposeSHA256       string
}

func (e *Executor) Observe(ctx context.Context) (map[string]any, error) {
	return e.collectObservation(ctx, true)
}

func (e *Executor) Execute(ctx context.Context, task protocol.Task) (map[string]any, error) {
	switch task.Kind {
	case protocol.TaskInspectHost:
		return e.inspect(ctx)
	case protocol.TaskCollectObservation:
		var p protocol.CollectObservationPayload
		if err := decode(task.Payload, &p); err != nil {
			return nil, err
		}
		return e.collectObservation(ctx, p.IncludeWorkloads)
	case protocol.TaskEnsurePrerequisites:
		var p protocol.EnsurePrerequisitesPayload
		if err := decode(task.Payload, &p); err != nil {
			return nil, err
		}
		return e.ensurePrerequisites(ctx, p)
	case protocol.TaskEnsureNebula:
		var p protocol.EnsureNebulaPayload
		if err := decode(task.Payload, &p); err != nil {
			return nil, err
		}
		return e.ensureNebula(ctx, task.NodeGeneration, p)
	case protocol.TaskApplyWorkload:
		var p protocol.ApplyWorkloadPayload
		if err := decode(task.Payload, &p); err != nil {
			return nil, err
		}
		return e.applyWorkload(ctx, p)
	case protocol.TaskRemoveWorkload:
		var p protocol.RemoveWorkloadPayload
		if err := decode(task.Payload, &p); err != nil {
			return nil, err
		}
		return e.removeWorkload(ctx, p)
	case protocol.TaskCleanupNode:
		var p protocol.CleanupNodePayload
		if err := decode(task.Payload, &p); err != nil {
			return nil, err
		}
		return e.cleanupNode(ctx, p)
	case protocol.TaskTailWorkloadLogs:
		var p protocol.TailWorkloadLogsPayload
		if err := decode(task.Payload, &p); err != nil {
			return nil, err
		}
		return e.tailLogs(ctx, p)
	case protocol.TaskRotateDeviceToken:
		return e.rotateToken(ctx)
	case protocol.TaskUpgradeAgent:
		var p protocol.UpgradeAgentPayload
		if err := decode(task.Payload, &p); err != nil {
			return nil, err
		}
		return e.upgrade(ctx, p)
	default:
		return nil, fmt.Errorf("unsupported task kind %q", task.Kind)
	}
}

func decode(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid task payload: %w", err)
	}
	return nil
}

func (e *Executor) inspect(ctx context.Context) (map[string]any, error) {
	o, err := e.Inspector.Inspect(ctx)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(o)
	result := map[string]any{}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (e *Executor) collectObservation(ctx context.Context, includeWorkloads bool) (map[string]any, error) {
	result, err := e.inspect(ctx)
	if err != nil {
		return nil, err
	}
	deployments := map[string]any{}
	if !includeWorkloads {
		return result, nil
	}
	envs, err := e.Root.Path("environments")
	if err != nil {
		return nil, err
	}
	environmentEntries, err := os.ReadDir(envs)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	observedCount := 0
	truncatedCount := 0
	for _, environment := range environmentEntries {
		if !environment.IsDir() {
			continue
		}
		directory := filepath.Join(envs, environment.Name(), "deployments")
		unit := "infractory-nebula-" + strings.ReplaceAll(environment.Name(), "-", "") + ".service"
		active := false
		if _, unitErr := e.Runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); unitErr == nil {
			active = true
		}
		result["nebulaNetworks"] = appendAny(result["nebulaNetworks"], map[string]any{"environmentId": environment.Name(), "active": active})
		entries, _ := os.ReadDir(directory)
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if observedCount >= 64 {
				truncatedCount++
				continue
			}
			observedCount++
			compose, _, err := findDeployment(e.Root, entry.Name())
			if err != nil {
				continue
			}
			project := "infractory-" + strings.ReplaceAll(entry.Name(), "-", "")
			observed, runErr := e.compose(ctx, "-p", project, "-f", compose, "ps", "--format", "json")
			if runErr != nil {
				deployments[entry.Name()] = map[string]any{"health": "unknown", "error": "observation failed"}
			} else {
				output := observed.Stdout
				if len(output) > 2048 {
					output = output[:2048]
				}
				deployments[entry.Name()] = map[string]any{"health": "observed", "composePs": output, "truncated": len(observed.Stdout) > len(output)}
			}
		}
	}
	result["deployments"] = deployments
	result["truncatedDeploymentCount"] = truncatedCount
	return result, nil
}

func appendAny(value any, item any) []any {
	if items, ok := value.([]any); ok {
		return append(items, item)
	}
	return []any{item}
}

func (e *Executor) ensurePrerequisites(ctx context.Context, p protocol.EnsurePrerequisitesPayload) (map[string]any, error) {
	packages := []string{"ca-certificates"}
	if p.Docker {
		packages = append(packages, "docker.io")
	}
	if p.Nebula {
		packages = append(packages, "nebula")
	}
	if _, err := e.Runner.Run(ctx, "apt-get", "update"); err != nil {
		return nil, fmt.Errorf("apt metadata update: %w", err)
	}
	args := []string{"-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confold", "install"}
	args = append(args, packages...)
	if _, err := e.Runner.Run(ctx, "apt-get", args...); err != nil {
		return nil, fmt.Errorf("install signed distribution packages: %w", err)
	}
	services := []string{}
	if p.Docker {
		services = append(services, "docker.service")
	}
	for _, service := range services {
		if _, err := e.Runner.Run(ctx, "systemctl", "enable", service); err != nil {
			return nil, err
		}
	}
	if p.Docker {
		if err := e.ensureComposeBinary(ctx); err != nil {
			return nil, err
		}
	}
	return map[string]any{"packages": packages}, nil
}

func (e *Executor) ensureComposeBinary(ctx context.Context) error {
	if e.HTTPClient == nil || e.ComposeURL == "" || len(e.ComposeSHA256) != 64 || e.ComposeBinary == "" {
		return errors.New("pinned Docker Compose artifact is not configured")
	}
	if existing, err := os.ReadFile(e.ComposeBinary); err == nil {
		sum := sha256.Sum256(existing)
		if hex.EncodeToString(sum[:]) == e.ComposeSHA256 {
			return nil
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.ComposeURL, nil)
	if err != nil {
		return err
	}
	downloadClient := *e.HTTPClient
	downloadClient.Timeout = 0
	response, err := downloadClient.Do(req)
	if err != nil {
		return fmt.Errorf("download pinned Docker Compose: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Docker Compose download returned %d", response.StatusCode)
	}
	artifact, err := io.ReadAll(io.LimitReader(response.Body, (100<<20)+1))
	if err != nil {
		return err
	}
	if len(artifact) > 100<<20 {
		return errors.New("Docker Compose artifact exceeds 100 MiB")
	}
	sum := sha256.Sum256(artifact)
	if hex.EncodeToString(sum[:]) != e.ComposeSHA256 {
		return errors.New("Docker Compose checksum mismatch")
	}
	expected, err := e.Root.Path("bin", "docker-compose")
	if err != nil || e.ComposeBinary != expected {
		return errors.New("Docker Compose binary must be the confined agent binary")
	}
	if err := e.Root.AtomicWrite(0755, artifact, "bin", "docker-compose"); err != nil {
		return err
	}
	if _, err := e.Runner.Run(ctx, e.ComposeBinary, "version", "--short"); err != nil {
		return fmt.Errorf("validate Docker Compose binary: %w", err)
	}
	return nil
}

func (e *Executor) compose(ctx context.Context, args ...string) (runner.Result, error) {
	if e.ComposeBinary == "" {
		return runner.Result{}, errors.New("Docker Compose binary is not configured")
	}
	return e.Runner.Run(ctx, e.ComposeBinary, args...)
}

func (e *Executor) ensureNebula(ctx context.Context, generation int64, p protocol.EnsureNebulaPayload) (map[string]any, error) {
	if err := validID(p.EnvironmentID); err != nil {
		return nil, err
	}
	// A freshly enrolled node starts at generation zero. Negative generations
	// are invalid; zero is the first valid, fenced configuration generation.
	if generation < 0 || p.ConfigYAML == "" {
		return nil, errors.New("Nebula generation and config are required")
	}
	base := []string{"environments", p.EnvironmentID, "nebula"}
	statePath := mustPath(e.Root, append(base, "state.json")...)
	var prior struct {
		Generation int64  `json:"generation"`
		Digest     string `json:"digest"`
	}
	if state, readErr := os.ReadFile(statePath); readErr == nil {
		if json.Unmarshal(state, &prior) != nil {
			return nil, errors.New("Nebula state metadata is corrupt")
		}
		if generation < prior.Generation {
			return nil, errors.New("Nebula task generation is stale")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	keyPath, _ := e.Root.Path(append(base, "host.key")...)
	pubPath, _ := e.Root.Path(append(base, "host.pub")...)
	privatePEM, publicPEM, err := ensureNebulaKeypair(keyPath, pubPath)
	if err != nil {
		return nil, err
	}
	certificatePEM := p.Certificate
	if certificatePEM == "" && prior.Generation == generation {
		if existing, readErr := os.ReadFile(mustPath(e.Root, append(base, "host.crt")...)); readErr == nil {
			certificatePEM = string(existing)
		}
	}
	if certificatePEM == "" {
		if e.Certificates == nil {
			return nil, errors.New("certificate requester is unavailable")
		}
		response, err := e.Certificates.RequestNebulaCertificate(ctx, map[string]any{
			"environmentId": p.EnvironmentID, "publicKey": string(publicPEM), "requestedGroups": p.Groups,
		})
		if err != nil {
			return nil, fmt.Errorf("request Nebula certificate: %w", err)
		}
		certificatePEM, _ = response["certificate"].(string)
		if p.CACertificate == "" {
			p.CACertificate, _ = response["caCertificate"].(string)
		}
		if certificatePEM == "" {
			return nil, errors.New("certificate response did not contain certificate")
		}
	}
	if p.CACertificate == "" {
		return nil, errors.New("Nebula CA certificate is unavailable")
	}
	configYAML, err := normalizeNebulaConfig(p.ConfigYAML, map[string]string{"ca": mustPath(e.Root, append(base, "ca.crt")...), "cert": mustPath(e.Root, append(base, "host.crt")...), "key": mustPath(e.Root, append(base, "host.key")...)})
	if err != nil {
		return nil, err
	}
	digestBytes := sha256.Sum256(bytes.Join([][]byte{configYAML, []byte(p.CACertificate), []byte(certificatePEM), publicPEM}, []byte{0}))
	digest := hex.EncodeToString(digestBytes[:])
	if generation == prior.Generation && prior.Digest != "" && digest != prior.Digest {
		return nil, errors.New("Nebula generation is immutable and already contains different content")
	}
	for name, item := range map[string]struct {
		mode os.FileMode
		data []byte
	}{
		"config.yml": {0600, configYAML}, "ca.crt": {0600, []byte(p.CACertificate)}, "host.crt": {0600, []byte(certificatePEM)}, "host.key": {0600, privatePEM}, "host.pub": {0644, publicPEM},
	} {
		if err := e.Root.AtomicWrite(item.mode, item.data, append(base, name)...); err != nil {
			return nil, err
		}
	}
	if _, err := e.Runner.Run(ctx, "nebula", "-test", "-config", mustPath(e.Root, append(base, "config.yml")...)); err != nil {
		return nil, fmt.Errorf("validate Nebula configuration: %w", err)
	}
	unit := "infractory-nebula-" + strings.ReplaceAll(p.EnvironmentID, "-", "")
	_, _ = e.Runner.Run(ctx, "systemctl", "stop", unit+".service")
	if _, err := e.Runner.Run(ctx, "systemd-run", "--unit", unit, "--property", "Restart=always", "--collect", "nebula", "-config", mustPath(e.Root, append(base, "config.yml")...)); err != nil {
		return nil, err
	}
	stateJSON, _ := json.Marshal(map[string]any{"generation": generation, "digest": digest})
	if err := e.Root.AtomicWrite(0600, stateJSON, append(base, "state.json")...); err != nil {
		return nil, err
	}
	return map[string]any{"environmentId": p.EnvironmentID, "generation": generation, "publicKey": string(publicPEM), "unit": unit + ".service"}, nil
}

func normalizeNebulaConfig(raw string, pkiPaths map[string]string) ([]byte, error) {
	var config map[string]any
	if err := yaml.Unmarshal([]byte(raw), &config); err != nil {
		return nil, fmt.Errorf("parse Nebula configuration: %w", err)
	}
	firewall, ok := config["firewall"].(map[string]any)
	if !ok {
		return nil, errors.New("Nebula configuration requires a typed firewall")
	}
	if _, ok := firewall["inbound"]; !ok {
		return nil, errors.New("Nebula firewall requires inbound rules")
	}
	if _, ok := firewall["outbound"]; !ok {
		return nil, errors.New("Nebula firewall requires outbound rules")
	}
	if _, present := config["unsafe_routes"]; present {
		return nil, errors.New("Nebula unsafe routes are not supported")
	}
	if ssh, ok := config["sshd"].(map[string]any); ok {
		if enabled, _ := ssh["enabled"].(bool); enabled {
			return nil, errors.New("Nebula embedded SSH is forbidden")
		}
	}
	config["sshd"] = map[string]any{"enabled": false}
	config["pki"] = map[string]any{"ca": pkiPaths["ca"], "cert": pkiPaths["cert"], "key": pkiPaths["key"]}
	return yaml.Marshal(config)
}

func ensureNebulaKeypair(keyPath, pubPath string) ([]byte, []byte, error) {
	if key, err := os.ReadFile(keyPath); err == nil {
		pub, err := os.ReadFile(pubPath)
		return key, pub, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	private := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, private); err != nil {
		return nil, nil, err
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, private), cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, public), nil
}

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
	Extra    map[string]any            `yaml:",inline"`
}
type composeService struct {
	Image       string         `yaml:"image"`
	Privileged  bool           `yaml:"privileged"`
	NetworkMode string         `yaml:"network_mode"`
	Volumes     []string       `yaml:"volumes"`
	Ports       []any          `yaml:"ports"`
	Command     any            `yaml:"command"`
	Entrypoint  any            `yaml:"entrypoint"`
	Extra       map[string]any `yaml:",inline"`
}

func normalizeCompose(raw string, resolved map[string]string, allowedPorts []protocol.AllowedPort, allowedHostPrefix string) ([]byte, error) {
	var c composeFile
	decoder := yaml.NewDecoder(strings.NewReader(raw))
	decoder.KnownFields(false)
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse Compose: %w", err)
	}
	if len(c.Services) == 0 {
		return nil, errors.New("Compose must define at least one service")
	}
	for key, value := range c.Extra {
		switch key {
		case "version", "networks":
		case "volumes":
			if definitions, ok := value.(map[string]any); ok {
				for name, rawDefinition := range definitions {
					if definition, ok := rawDefinition.(map[string]any); ok && len(definition) > 0 {
						return nil, fmt.Errorf("volume %s uses driver options or external state", name)
					}
				}
			} else {
				return nil, errors.New("top-level volumes must be a map")
			}
		default:
			return nil, fmt.Errorf("top-level Compose field %s is not allowed", key)
		}
	}
	allowed := map[string]bool{}
	for _, p := range allowedPorts {
		allowed[strconv.Itoa(p.Port)+"/"+p.Protocol] = true
	}
	for name, service := range c.Services {
		if service.Privileged || service.NetworkMode != "" {
			return nil, fmt.Errorf("service %s requests a forbidden capability", name)
		}
		allowedServiceFields := map[string]bool{"command": true, "depends_on": true, "deploy": true, "environment": true, "healthcheck": true, "hostname": true, "labels": true, "networks": true, "read_only": true, "restart": true, "stop_grace_period": true, "tmpfs": true, "user": true, "working_dir": true}
		for field := range service.Extra {
			if !allowedServiceFields[field] {
				return nil, fmt.Errorf("service %s uses unsupported or unsafe field %s", name, field)
			}
		}
		for _, volume := range service.Volumes {
			source := strings.SplitN(volume, ":", 2)[0]
			if source == "/var/run/docker.sock" || source == "/run/docker.sock" {
				return nil, errors.New("Docker socket mounts are forbidden")
			}
			cleanSource := filepath.Clean(source)
			if strings.HasPrefix(source, "/") {
				if allowedHostPrefix == "" || !strings.HasPrefix(cleanSource, allowedHostPrefix+string(filepath.Separator)) {
					return nil, fmt.Errorf("service %s uses a host path outside its immutable release", name)
				}
			} else if strings.HasPrefix(cleanSource, ".."+string(filepath.Separator)) || cleanSource == ".." || strings.HasPrefix(source, "~") {
				return nil, fmt.Errorf("service %s uses a relative path outside its release", name)
			}
		}
		for _, port := range service.Ports {
			value, err := publishedPort(port)
			if err != nil {
				return nil, fmt.Errorf("service %s has invalid port: %w", name, err)
			}
			if !allowed[value] {
				return nil, fmt.Errorf("service %s publishes undeclared port %s", name, value)
			}
		}
		if digest, ok := resolved[name]; ok {
			service.Image = digest
		}
		if !regexp.MustCompile(`@sha256:[a-f0-9]{64}$`).MatchString(service.Image) {
			return nil, fmt.Errorf("service %s image is not resolved to a digest", name)
		}
		c.Services[name] = service
	}
	return yaml.Marshal(c)
}

func publishedPort(value any) (string, error) {
	if m, ok := value.(map[string]any); ok {
		published := fmt.Sprint(m["published"])
		protocolValue := fmt.Sprint(m["protocol"])
		if protocolValue == "<nil>" || protocolValue == "" {
			protocolValue = "tcp"
		}
		port, err := strconv.Atoi(published)
		if err != nil || port < 1 || port > 65535 {
			return "", errors.New("published port is invalid")
		}
		return strconv.Itoa(port) + "/" + protocolValue, nil
	}
	raw := fmt.Sprint(value)
	protocolValue := "tcp"
	if before, after, ok := strings.Cut(raw, "/"); ok {
		raw = before
		protocolValue = after
	}
	parts := strings.Split(raw, ":")
	if len(parts) < 2 {
		return "", errors.New("container-only ports are not public exposures")
	}
	published := parts[len(parts)-2]
	port, err := strconv.Atoi(published)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("published port is invalid")
	}
	return strconv.Itoa(port) + "/" + protocolValue, nil
}

func (e *Executor) applyWorkload(ctx context.Context, p protocol.ApplyWorkloadPayload) (map[string]any, error) {
	if err := validID(p.EnvironmentID); err != nil {
		return nil, err
	}
	if err := validID(p.DeploymentID); err != nil {
		return nil, err
	}
	if p.Generation < 1 {
		return nil, errors.New("workload generation must be positive")
	}
	if err := validateProbes(p.Probes); err != nil {
		return nil, fmt.Errorf("validate workload probes: %w", err)
	}
	probeManifest, err := json.Marshal(p.Probes)
	if err != nil {
		return nil, fmt.Errorf("encode workload probes: %w", err)
	}
	releaseHostPrefix := filepath.Join(pathsRootPrefix, "environments", p.EnvironmentID, "deployments", p.DeploymentID, strconv.FormatInt(p.Generation, 10))
	compose, err := normalizeCompose(p.ComposeYAML, p.ResolvedImages, p.AllowedPorts, releaseHostPrefix)
	if err != nil {
		return nil, err
	}
	base := []string{"environments", p.EnvironmentID, "deployments", p.DeploymentID}
	current, _ := os.Readlink(mustPath(e.Root, append(base, "current")...))
	if current != "" {
		currentGeneration, parseErr := strconv.ParseInt(current, 10, 64)
		if parseErr != nil || currentGeneration < 1 {
			return nil, errors.New("workload current release pointer is corrupt")
		}
		if p.Generation < currentGeneration {
			return nil, errors.New("workload task generation is stale")
		}
	}
	stageName := ".stage-" + strconv.FormatInt(p.Generation, 10)
	_ = e.Root.Remove(append(base, stageName)...)
	if err := e.Root.AtomicWrite(0600, compose, append(base, stageName, "compose.yml")...); err != nil {
		return nil, err
	}
	if err := e.Root.AtomicWrite(0600, probeManifest, append(base, stageName, "probes.json")...); err != nil {
		return nil, err
	}
	for _, secret := range p.SecretFiles {
		expectedPrefix := filepath.Join(pathsRootPrefix, "environments", p.EnvironmentID, "deployments", p.DeploymentID, strconv.FormatInt(p.Generation, 10)) + string(filepath.Separator)
		if !strings.HasPrefix(filepath.Clean(secret.Target), expectedPrefix) {
			return nil, errors.New("secret target must be inside this deployment generation")
		}
		rel := strings.TrimPrefix(filepath.Clean(secret.Target), expectedPrefix)
		if rel == "" || rel == "." {
			return nil, errors.New("secret target must name a file")
		}
		content, decodeErr := base64.StdEncoding.DecodeString(secret.ContentBase64)
		if decodeErr != nil {
			return nil, errors.New("secret content is not valid base64")
		}
		if err := e.Root.AtomicWrite(0400, content, append(base, stageName, rel)...); err != nil {
			return nil, err
		}
	}
	composePath := mustPath(e.Root, append(base, stageName, "compose.yml")...)
	if _, err := e.compose(ctx, "-f", composePath, "config", "--quiet"); err != nil {
		return nil, fmt.Errorf("validate Compose: %w", err)
	}
	releaseName := strconv.FormatInt(p.Generation, 10)
	stagePath := mustPath(e.Root, append(base, stageName)...)
	releasePath := mustPath(e.Root, append(base, releaseName)...)
	if _, err := os.Stat(releasePath); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(stagePath, releasePath); err != nil {
			return nil, err
		}
	} else if err == nil {
		existing, readErr := os.ReadFile(filepath.Join(releasePath, "compose.yml"))
		if readErr != nil {
			return nil, readErr
		}
		existingProbes, readErr := os.ReadFile(filepath.Join(releasePath, "probes.json"))
		if readErr != nil {
			return nil, readErr
		}
		if !bytes.Equal(existing, compose) || !bytes.Equal(existingProbes, probeManifest) {
			return nil, errors.New("workload generation is immutable and already contains different content")
		}
		_ = e.Root.Remove(append(base, stageName)...)
	} else {
		return nil, err
	}
	timeout := p.TimeoutSeconds
	if timeout <= 0 || timeout > 900 {
		timeout = 120
	}
	project := "infractory-" + strings.ReplaceAll(p.DeploymentID, "-", "")
	finalCompose := filepath.Join(releasePath, "compose.yml")
	healthWindow := e.workloadHealthWindow(timeout)
	applyCtx, cancelApply := context.WithTimeout(ctx, healthWindow)
	defer cancelApply()
	if _, err := e.compose(applyCtx, "-p", project, "-f", finalCompose, "up", "-d", "--wait", "--wait-timeout", strconv.Itoa(timeout), "--remove-orphans"); err != nil {
		cancelApply()
		return nil, e.recoverWorkloadRelease(ctx, project, finalCompose, current, base, timeout, healthWindow, fmt.Errorf("apply Compose release: %w", err))
	}
	if err := e.waitForProbes(applyCtx, project, finalCompose, p.Probes, healthWindow); err != nil {
		cancelApply()
		return nil, e.recoverWorkloadRelease(ctx, project, finalCompose, current, base, timeout, healthWindow, err)
	}
	if err := atomicSymlink(releaseName, mustPath(e.Root, append(base, "current")...)); err != nil {
		return nil, e.recoverWorkloadRelease(ctx, project, finalCompose, current, base, timeout, healthWindow, fmt.Errorf("activate release pointer: %w", err))
	}
	return map[string]any{"deploymentId": p.DeploymentID, "generation": p.Generation, "project": project, "health": "healthy", "probesPassed": len(p.Probes)}, nil
}

func (e *Executor) removeWorkload(ctx context.Context, p protocol.RemoveWorkloadPayload) (map[string]any, error) {
	if err := validID(p.DeploymentID); err != nil {
		return nil, err
	}
	composePath, base, err := findDeployment(e.Root, p.DeploymentID)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{"deploymentId": p.DeploymentID, "removed": true, "alreadyAbsent": true}, nil
	}
	if err != nil {
		return nil, err
	}
	project := "infractory-" + strings.ReplaceAll(p.DeploymentID, "-", "")
	args := []string{"-p", project, "-f", composePath, "down", "--remove-orphans"}
	if p.RemoveOwnedVolumes {
		args = append(args, "--volumes")
	}
	if _, err := e.compose(ctx, args...); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(base); err != nil {
		return nil, err
	}
	return map[string]any{"deploymentId": p.DeploymentID, "removed": true}, nil
}

func (e *Executor) cleanupNode(ctx context.Context, p protocol.CleanupNodePayload) (map[string]any, error) {
	if err := validID(p.EnvironmentID); err != nil {
		return nil, err
	}
	env, _ := e.Root.Path("environments", p.EnvironmentID)
	deployments := filepath.Join(env, "deployments")
	entries, _ := os.ReadDir(deployments)
	for _, entry := range entries {
		if entry.IsDir() {
			_, _, err := findDeployment(e.Root, entry.Name())
			if err == nil {
				if _, err = e.removeWorkload(ctx, protocol.RemoveWorkloadPayload{DeploymentID: entry.Name()}); err != nil {
					return nil, err
				}
			}
		}
	}
	_, _ = e.Runner.Run(ctx, "systemctl", "stop", "infractory-nebula-"+strings.ReplaceAll(p.EnvironmentID, "-", "")+".service")
	if err := e.Root.Remove("environments", p.EnvironmentID); err != nil {
		return nil, err
	}
	return map[string]any{"environmentId": p.EnvironmentID, "cleaned": true}, nil
}

func (e *Executor) tailLogs(ctx context.Context, p protocol.TailWorkloadLogsPayload) (map[string]any, error) {
	if err := validID(p.DeploymentID); err != nil {
		return nil, err
	}
	compose, _, err := findDeployment(e.Root, p.DeploymentID)
	if err != nil {
		return nil, err
	}
	args := []string{"-p", "infractory-" + strings.ReplaceAll(p.DeploymentID, "-", ""), "-f", compose, "logs", "--no-color", "--tail", "1000"}
	if p.Since != nil {
		args = append(args, "--since", p.Since.UTC().Format(time.RFC3339))
	}
	r, err := e.compose(ctx, args...)
	if err != nil {
		return nil, err
	}
	logs := r.Stdout
	if len(logs) > 48<<10 {
		logs = logs[len(logs)-(48<<10):]
	}
	return map[string]any{"logs": logs, "truncated": len(r.Stdout) > len(logs)}, nil
}

func (e *Executor) rotateToken(ctx context.Context) (map[string]any, error) {
	if e.Tokens == nil || e.SaveToken == nil {
		return nil, errors.New("token rotation is unavailable")
	}
	response, err := e.Tokens.RotateDeviceToken(ctx)
	if err != nil {
		return nil, err
	}
	if err := e.SaveToken(response.DeviceToken); err != nil {
		return nil, err
	}
	return map[string]any{"expiresAt": response.ExpiresAt}, nil
}

func (e *Executor) upgrade(ctx context.Context, p protocol.UpgradeAgentPayload) (map[string]any, error) {
	if e.HTTPClient == nil {
		return nil, errors.New("upgrade HTTP client unavailable")
	}
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("upgrade URL must be HTTPS")
	}
	if len(p.SHA256) != 64 {
		return nil, errors.New("invalid upgrade checksum")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	downloadClient := *e.HTTPClient
	downloadClient.Timeout = 0
	response, err := downloadClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upgrade download returned %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, (128<<20)+1)
	binary, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(binary)
	if hex.EncodeToString(sum[:]) != p.SHA256 {
		return nil, errors.New("upgrade checksum mismatch")
	}
	if len(binary) > 128<<20 {
		return nil, errors.New("upgrade exceeded size limit")
	}
	stageName := "infractory-agent.next"
	if err := e.Root.AtomicWrite(0755, binary, "bin", stageName); err != nil {
		return nil, err
	}
	stage := mustPath(e.Root, "bin", stageName)
	target := mustPath(e.Root, "bin", "infractory-agent")
	validation, err := e.Runner.Run(ctx, stage, "version")
	if err != nil {
		return nil, fmt.Errorf("validate upgraded binary: %w", err)
	}
	if strings.TrimSpace(validation.Stdout) != p.Version {
		return nil, fmt.Errorf("upgraded binary reported version %q, expected %q", strings.TrimSpace(validation.Stdout), p.Version)
	}
	if err := os.Rename(stage, target); err != nil {
		return nil, err
	}
	if directory, openErr := os.Open(filepath.Dir(target)); openErr == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	unit := "infractory-agent-restart-" + strconv.FormatInt(time.Now().Unix(), 10)
	if _, restartErr := e.Runner.Run(ctx, "systemd-run", "--unit", unit, "--on-active=60s", "systemctl", "restart", "infractory-agent.service"); restartErr != nil {
		return nil, fmt.Errorf("agent binary was replaced but restart scheduling failed; manually restart infractory-agent.service: %w", restartErr)
	}
	return map[string]any{"version": p.Version, "restartScheduled": true}, nil
}

func validID(value string) error {
	if !identifierPattern.MatchString(value) || strings.Contains(value, "..") {
		return errors.New("invalid identifier")
	}
	return nil
}
func mustPath(root paths.Root, parts ...string) string {
	p, err := root.Path(parts...)
	if err != nil {
		panic(err)
	}
	return p
}
func atomicSymlink(target, path string) error {
	tmp := path + ".new"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var errCorruptDeploymentState = errors.New("deployment state is corrupt")

func findDeployment(root paths.Root, deploymentID string) (string, string, error) {
	envs, _ := root.Path("environments")
	entries, err := os.ReadDir(envs)
	if err != nil {
		return "", "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, env := range entries {
		if !env.IsDir() {
			continue
		}
		base, _ := root.Path("environments", env.Name(), "deployments", deploymentID)
		info, statErr := os.Stat(base)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return "", "", statErr
		}
		if !info.IsDir() {
			return "", base, fmt.Errorf("%w: deployment path is not a directory", errCorruptDeploymentState)
		}
		current := filepath.Join(base, "current")
		target, readErr := os.Readlink(current)
		if readErr != nil {
			return "", base, fmt.Errorf("%w: read current release: %v", errCorruptDeploymentState, readErr)
		}
		generation, parseErr := strconv.ParseInt(target, 10, 64)
		if parseErr != nil || generation < 1 {
			return "", base, fmt.Errorf("%w: current release target %q is invalid", errCorruptDeploymentState, target)
		}
		resolved, resolveErr := root.Resolve("environments", env.Name(), "deployments", deploymentID, target, "compose.yml")
		if resolveErr != nil {
			return "", base, fmt.Errorf("%w: resolve current Compose file: %v", errCorruptDeploymentState, resolveErr)
		}
		return resolved, base, nil
	}
	return "", "", os.ErrNotExist
}
