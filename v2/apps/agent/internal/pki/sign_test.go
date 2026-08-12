package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

func TestHandleSignsUsingOnlyStreams(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	caPub, caPriv := ed25519Pair(t)
	caTBS := &cert.TBSCertificate{Version: cert.Version2, Name: "test-ca", Networks: mustPrefixes(t, "10.42.0.0/16"), Groups: []string{"worker"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), PublicKey: caPub, IsCA: true, Curve: cert.Curve_CURVE25519}
	ca, err := caTBS.Sign(nil, cert.Curve_CURVE25519, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := ca.MarshalPEM()
	hostPub, _ := x25519Pair(t)
	request := SignRequest{Kind: "sign", CACertificate: string(caPEM), CAPrivateKey: string(cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, caPriv)), PublicKey: string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, hostPub)), Name: "node", Networks: []string{"10.42.0.2/16"}, Groups: []string{"worker"}, NotBefore: now, NotAfter: now.Add(time.Hour)}
	b, _ := json.Marshal(request)
	var out bytes.Buffer
	if err := Handle(bytes.NewReader(b), &out, now); err != nil {
		t.Fatal(err)
	}
	var response SignResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	host, _, err := cert.UnmarshalCertificateFromPEM([]byte(response.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	if !host.CheckSignature(ca.PublicKey()) {
		t.Fatal("signed certificate did not verify")
	}
}

func TestCreateCAThenSignOverStreams(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	create := CreateCARequest{Kind: "createCa", Name: "environment", Network: "10.44.0.0/16", NotBefore: now, NotAfter: now.Add(24 * time.Hour)}
	b, _ := json.Marshal(create)
	var out bytes.Buffer
	if err := Handle(bytes.NewReader(b), &out, now); err != nil {
		t.Fatal(err)
	}
	var ca CreateCAResponse
	if err := json.Unmarshal(out.Bytes(), &ca); err != nil {
		t.Fatal(err)
	}
	certificate, _, err := cert.UnmarshalCertificateFromPEM([]byte(ca.CACertificate))
	if err != nil || !certificate.IsCA() {
		t.Fatalf("invalid CA: %v", err)
	}
	hostPub, _ := x25519Pair(t)
	sign := SignRequest{Kind: "sign", CACertificate: ca.CACertificate, CAPrivateKey: ca.CAPrivateKey, PublicKey: string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, hostPub)), Name: "node", Networks: []string{"10.44.0.2/16"}, NotBefore: now, NotAfter: now.Add(time.Hour)}
	b, _ = json.Marshal(sign)
	out.Reset()
	if err := Handle(bytes.NewReader(b), &out, now); err != nil {
		t.Fatal(err)
	}
}

func ed25519Pair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}
func x25519Pair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := certPublic(private)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}
func certPublic(private []byte) ([]byte, error) {
	return curve25519.X25519(private, curve25519.Basepoint)
}
func mustPrefixes(t *testing.T, raw ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}
