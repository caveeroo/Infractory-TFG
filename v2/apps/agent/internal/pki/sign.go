package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
)

const maxRequest = 2 << 20

type SignRequest struct {
	Kind          string    `json:"kind"`
	CACertificate string    `json:"caCertificate"`
	CAPrivateKey  string    `json:"caPrivateKey"`
	CAPassphrase  string    `json:"caPassphrase,omitempty"`
	PublicKey     string    `json:"publicKey"`
	Name          string    `json:"name"`
	Networks      []string  `json:"networks"`
	Groups        []string  `json:"groups,omitempty"`
	NotBefore     time.Time `json:"notBefore"`
	NotAfter      time.Time `json:"notAfter"`
}

type CreateCARequest struct {
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Network   string    `json:"network"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}
type CreateCAResponse struct {
	CACertificate string `json:"caCertificate"`
	CAPrivateKey  string `json:"caPrivateKey"`
	Fingerprint   string `json:"fingerprint"`
}

type SignResponse struct {
	Certificate string `json:"certificate"`
	Fingerprint string `json:"fingerprint"`
}

func Handle(in io.Reader, out io.Writer, now time.Time) error {
	b, err := io.ReadAll(io.LimitReader(in, maxRequest+1))
	if err != nil {
		return err
	}
	if len(b) > maxRequest {
		return errors.New("PKI request exceeds 2 MiB")
	}
	var envelope struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(b, &envelope) != nil {
		return errors.New("decode PKI request")
	}
	switch envelope.Kind {
	case "createCa":
		var request CreateCARequest
		if err := strictDecode(b, &request); err != nil {
			return err
		}
		response, err := CreateCA(request, now)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(response)
	case "sign":
		var request SignRequest
		if err := strictDecode(b, &request); err != nil {
			return err
		}
		response, err := Sign(request, now)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(response)
	default:
		return errors.New("PKI request kind must be createCa or sign")
	}
}

func strictDecode(b []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode PKI request: %w", err)
	}
	return nil
}

func CreateCA(request CreateCARequest, now time.Time) (CreateCAResponse, error) {
	if request.Name == "" || len(request.Name) > 253 {
		return CreateCAResponse{}, errors.New("CA name is required")
	}
	network, err := netip.ParsePrefix(request.Network)
	if err != nil {
		return CreateCAResponse{}, errors.New("CA network must be a valid prefix")
	}
	notBefore := request.NotBefore
	if notBefore.IsZero() {
		notBefore = now.Add(-time.Minute)
	}
	notAfter := request.NotAfter
	if notAfter.IsZero() {
		notAfter = now.Add(365 * 24 * time.Hour)
	}
	if !notAfter.After(notBefore) || notAfter.Sub(notBefore) > 2*365*24*time.Hour {
		return CreateCAResponse{}, errors.New("CA validity must be positive and no longer than two years")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return CreateCAResponse{}, err
	}
	tbs := &cert.TBSCertificate{Version: cert.Version2, Name: request.Name, Networks: []netip.Prefix{network}, NotBefore: notBefore, NotAfter: notAfter, PublicKey: public, IsCA: true, Curve: cert.Curve_CURVE25519}
	ca, err := tbs.Sign(nil, cert.Curve_CURVE25519, private)
	if err != nil {
		return CreateCAResponse{}, fmt.Errorf("create CA: %w", err)
	}
	pem, err := ca.MarshalPEM()
	if err != nil {
		return CreateCAResponse{}, err
	}
	fingerprint, err := ca.Fingerprint()
	if err != nil {
		return CreateCAResponse{}, err
	}
	return CreateCAResponse{CACertificate: string(pem), CAPrivateKey: string(cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, private)), Fingerprint: fingerprint}, nil
}

func Sign(request SignRequest, now time.Time) (SignResponse, error) {
	if request.Name == "" || len(request.Name) > 253 || len(request.Networks) == 0 {
		return SignResponse{}, errors.New("name and at least one network are required")
	}
	ca, _, err := cert.UnmarshalCertificateFromPEM([]byte(request.CACertificate))
	if err != nil {
		return SignResponse{}, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !ca.IsCA() || ca.Expired(now) {
		return SignResponse{}, errors.New("CA certificate is not a valid current authority")
	}
	key, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM([]byte(request.CAPrivateKey))
	if errors.Is(err, cert.ErrPrivateKeyEncrypted) {
		if request.CAPassphrase == "" {
			return SignResponse{}, errors.New("encrypted CA private key requires caPassphrase in the stdin request")
		}
		curve, key, _, err = cert.DecryptAndUnmarshalSigningPrivateKey([]byte(request.CAPassphrase), []byte(request.CAPrivateKey))
	}
	if err != nil {
		return SignResponse{}, fmt.Errorf("parse CA private key: %w", err)
	}
	if err := ca.VerifyPrivateKey(curve, key); err != nil {
		return SignResponse{}, errors.New("CA private key does not match certificate")
	}
	pub, _, pubCurve, err := cert.UnmarshalPublicKeyFromPEM([]byte(request.PublicKey))
	if err != nil {
		return SignResponse{}, fmt.Errorf("parse host public key: %w", err)
	}
	if pubCurve != curve {
		return SignResponse{}, errors.New("host key curve does not match CA curve")
	}
	networks := make([]netip.Prefix, 0, len(request.Networks))
	for _, raw := range request.Networks {
		network, err := netip.ParsePrefix(raw)
		if err != nil {
			return SignResponse{}, fmt.Errorf("invalid network %q", raw)
		}
		networks = append(networks, network)
	}
	notBefore := request.NotBefore
	if notBefore.IsZero() {
		notBefore = now.Add(-time.Minute)
	}
	notAfter := request.NotAfter
	if notAfter.IsZero() {
		notAfter = now.Add(90 * 24 * time.Hour)
	}
	if notBefore.Before(ca.NotBefore()) || !notAfter.After(notBefore) || notAfter.After(ca.NotAfter()) {
		return SignResponse{}, errors.New("requested validity is outside the CA validity window")
	}
	tbs := &cert.TBSCertificate{Version: ca.Version(), Name: request.Name, Networks: networks, Groups: request.Groups, NotBefore: notBefore, NotAfter: notAfter, PublicKey: pub, IsCA: false, Curve: curve}
	host, err := tbs.Sign(ca, curve, key)
	if err != nil {
		return SignResponse{}, fmt.Errorf("sign host certificate: %w", err)
	}
	pem, err := host.MarshalPEM()
	if err != nil {
		return SignResponse{}, err
	}
	fingerprint, err := host.Fingerprint()
	if err != nil {
		return SignResponse{}, err
	}
	return SignResponse{Certificate: string(pem), Fingerprint: fingerprint}, nil
}
