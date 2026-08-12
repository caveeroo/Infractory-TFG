package config

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultStateDir = "/var/lib/infractory"

type Config struct {
	ControlPlaneURL     string `json:"controlPlaneUrl"`
	StateDir            string `json:"stateDir,omitempty"`
	EnrollmentTokenFile string `json:"enrollmentTokenFile,omitempty"`
	CABundle            string `json:"caBundle,omitempty"`
	ServerFingerprint   string `json:"serverFingerprint,omitempty"`
	AgentVersion        string `json:"agentVersion,omitempty"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	u, err := url.Parse(c.ControlPlaneURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("controlPlaneUrl must be an absolute HTTPS URL without query or fragment")
	}
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("stateDir must be absolute")
	}
	if c.EnrollmentTokenFile != "" && !filepath.IsAbs(c.EnrollmentTokenFile) {
		return errors.New("enrollmentTokenFile must be absolute")
	}
	if c.CABundle != "" && c.ServerFingerprint != "" {
		return errors.New("configure caBundle or serverFingerprint, not both")
	}
	if c.CABundle != "" && !filepath.IsAbs(c.CABundle) {
		return errors.New("caBundle must be absolute")
	}
	if c.ServerFingerprint != "" {
		fp := strings.ReplaceAll(strings.ToLower(c.ServerFingerprint), ":", "")
		if len(fp) != sha256.Size*2 {
			return errors.New("serverFingerprint must be a SHA-256 certificate fingerprint")
		}
		if _, err := hex.DecodeString(fp); err != nil {
			return errors.New("serverFingerprint must be hexadecimal")
		}
	}
	return nil
}

func (c Config) HTTPClient() (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CABundle != "" {
		pem, err := os.ReadFile(c.CABundle)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA bundle contained no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if c.ServerFingerprint != "" {
		expected := strings.ReplaceAll(strings.ToLower(c.ServerFingerprint), ":", "")
		tlsConfig.InsecureSkipVerify = true // Verification is performed below against an explicit pin.
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("TLS peer supplied no certificate")
			}
			actual := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(actual[:]) != expected {
				return errors.New("TLS server certificate fingerprint mismatch")
			}
			return nil
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.ResponseHeaderTimeout = 35 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many HTTPS redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("refusing to follow a non-HTTPS redirect")
		}
		return nil
	}}, nil
}
