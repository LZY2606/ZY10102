package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"localpki/internal/model"
)

type Failure struct{ Steps []model.CheckStep }

func (f Failure) Error() string {
	for _, step := range f.Steps {
		if !step.OK {
			return step.Name + ": " + step.Detail
		}
	}
	return "validation failed"
}

func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("time is required")
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC(), nil
	}
	return time.Parse("2006-01-02T15:04", value)
}

func keySpecName(spec model.KeySpec) string {
	switch spec.Type {
	case "RSA":
		if spec.Bits == 0 {
			return "RSA-2048"
		}
		return fmt.Sprintf("RSA-%d", spec.Bits)
	case "EC":
		curve := spec.Curve
		if curve == "" {
			curve = "P256"
		}
		return "EC-" + curve
	case "Ed25519":
		return "Ed25519"
	default:
		return spec.Type
	}
}

func generateKey(spec model.KeySpec) (crypto.Signer, error) {
	switch spec.Type {
	case "RSA":
		bits := spec.Bits
		if bits == 0 {
			bits = 2048
		}
		return rsa.GenerateKey(rand.Reader, bits)
	case "EC":
		curve := spec.Curve
		if curve == "" || curve == "P256" {
			return ecdsa.GenerateKey(ellipticCurveP256(), rand.Reader)
		}
		if curve == "P384" {
			return ecdsa.GenerateKey(ellipticCurveP384(), rand.Reader)
		}
		return nil, errors.New("unsupported EC curve")
	case "Ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	default:
		return nil, errors.New("unsupported key type")
	}
}

func ellipticCurveP256() elliptic.Curve { return elliptic.P256() }
func ellipticCurveP384() elliptic.Curve { return elliptic.P384() }

func sigAlgoForKey(key crypto.Signer, requested string) (x509.SignatureAlgorithm, string, error) {
	requested = strings.ToUpper(strings.ReplaceAll(requested, " ", ""))
	switch key.(type) {
	case *rsa.PrivateKey:
		switch requested {
		case "", "SHA256-RSA", "SHA256WITHRSA":
			return x509.SHA256WithRSA, "SHA256-RSA", nil
		case "SHA384-RSA":
			return x509.SHA384WithRSA, "SHA384-RSA", nil
		case "SHA512-RSA":
			return x509.SHA512WithRSA, "SHA512-RSA", nil
		}
	case *ecdsa.PrivateKey:
		curve := key.(*ecdsa.PrivateKey).Curve.Params().Name
		if requested == "" || requested == "SHA256-ECDSA" || requested == "ECDSAWITHSHA256" {
			if curve == "P-384" {
				return x509.ECDSAWithSHA384, "SHA384-ECDSA", nil
			}
			return x509.ECDSAWithSHA256, "SHA256-ECDSA", nil
		}
		if requested == "SHA384-ECDSA" {
			return x509.ECDSAWithSHA384, "SHA384-ECDSA", nil
		}
	case ed25519.PrivateKey:
		if requested == "" || requested == "ED25519" {
			return x509.PureEd25519, "Ed25519", nil
		}
	}
	return x509.UnknownSignatureAlgorithm, "", fmt.Errorf("unsupported signature policy mapping %q for key %T", requested, key)
}

func mapKeyUsage(names []string, isCA bool) (x509.KeyUsage, error) {
	var usage x509.KeyUsage
	known := map[string]x509.KeyUsage{
		"digitalsignature":  x509.KeyUsageDigitalSignature,
		"contentcommitment": x509.KeyUsageContentCommitment,
		"keyencipherment":   x509.KeyUsageKeyEncipherment,
		"dataencipherment":  x509.KeyUsageDataEncipherment,
		"keyagreement":      x509.KeyUsageKeyAgreement,
		"keycertsign":       x509.KeyUsageCertSign,
		"crlsign":           x509.KeyUsageCRLSign,
		"encipheronly":      x509.KeyUsageEncipherOnly,
		"decipheronly":      x509.KeyUsageDecipherOnly,
	}
	for _, name := range names {
		v, ok := known[strings.ToLower(strings.ReplaceAll(name, " ", ""))]
		if !ok {
			return 0, fmt.Errorf("unknown key usage %q", name)
		}
		usage |= v
	}
	if isCA {
		usage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if !isCA && usage == 0 {
		usage = x509.KeyUsageDigitalSignature
	}
	return usage, nil
}

func mapEKUs(names []string) ([]x509.ExtKeyUsage, []string, error) {
	known := map[string]x509.ExtKeyUsage{
		"serverauth":      x509.ExtKeyUsageServerAuth,
		"clientauth":      x509.ExtKeyUsageClientAuth,
		"codesigning":     x509.ExtKeyUsageCodeSigning,
		"emailprotection": x509.ExtKeyUsageEmailProtection,
		"ocspsigning":     x509.ExtKeyUsageOCSPSigning,
	}
	ekus := []x509.ExtKeyUsage{}
	unknown := []string{}
	seen := map[x509.ExtKeyUsage]bool{}
	for _, name := range names {
		n := strings.ToLower(strings.ReplaceAll(name, " ", ""))
		if v, ok := known[n]; ok {
			if !seen[v] {
				ekus = append(ekus, v)
				seen[v] = true
			}
		} else {
			unknown = append(unknown, name)
		}
	}
	return ekus, unknown, nil
}

func serialToBig(v int64) *big.Int { return big.NewInt(v) }

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func parseIPs(values []string) ([]net.IP, error) {
	out := []net.IP{}
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", value)
		}
		out = append(out, ip)
	}
	return out, nil
}

func parseURIs(values []string) ([]*url.URL, error) {
	out := []*url.URL{}
	for _, value := range values {
		u, err := url.Parse(value)
		if err != nil || u.Scheme == "" || u.Host == "" && u.Path == "" {
			return nil, fmt.Errorf("invalid URI %q", value)
		}
		out = append(out, u)
	}
	return out, nil
}

func validEmail(value string) bool { _, err := mail.ParseAddress(value); return err == nil }

func dnsInTree(name, constraint string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	constraint = strings.ToLower(strings.TrimSuffix(constraint, "."))
	if strings.HasPrefix(constraint, ".") {
		return name == strings.TrimPrefix(constraint, ".") || strings.HasSuffix(name, constraint)
	}
	return name == constraint || strings.HasSuffix(name, "."+constraint)
}

func ipInConstraint(ip net.IP, network string) bool {
	_, n, err := net.ParseCIDR(network)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}

func emailInTree(value, constraint string) bool {
	value = strings.ToLower(value)
	constraint = strings.ToLower(constraint)
	if strings.Contains(constraint, "@") {
		return value == constraint
	}
	if i := strings.Index(value, "@"); i >= 0 {
		domain := value[i+1:]
		return domain == constraint || strings.HasSuffix(domain, "."+constraint)
	}
	return false
}

func uriInTree(value, constraint string) bool {
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	constraint = strings.ToLower(strings.TrimPrefix(constraint, "."))
	return host == constraint || strings.HasSuffix(host, "."+constraint)
}

func customExtensions(exts []model.CustomExtension) ([]pkixExt, error) {
	out := []pkixExt{}
	seen := map[string]bool{}
	for _, e := range exts {
		oid := strings.TrimSpace(e.OID)
		if seen[oid] {
			return nil, fmt.Errorf("duplicate custom extension OID %s", oid)
		}
		seen[oid] = true
		id, err := parseOID(oid)
		if err != nil {
			return nil, err
		}
		data, err := hex.DecodeString(strings.TrimSpace(e.Hex))
		if err != nil {
			return nil, fmt.Errorf("extension %s hex: %w", oid, err)
		}
		out = append(out, pkixExt{ID: id, Critical: e.Critical, Value: data})
	}
	return out, nil
}

type pkixExt struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

func parseOID(value string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(value, ".")
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q", value)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("invalid OID %q", value)
	}
	return oid, nil
}

func oidString(id asn1.ObjectIdentifier) string { return id.String() }

func toPKIXExtensions(exts []pkixExt) []pkix.Extension {
	out := make([]pkix.Extension, 0, len(exts))
	for _, e := range exts {
		out = append(out, pkix.Extension{Id: e.ID, Critical: e.Critical, Value: e.Value})
	}
	return out
}
