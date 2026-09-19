package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"localpki/internal/keystore"
	"localpki/internal/model"
	"localpki/internal/store"
)

type Service struct {
	store *store.Store
	keys  *keystore.LocalStore
	mu    sync.Mutex
}

func NewService(st *store.Store, keys *keystore.LocalStore) *Service {
	return &Service{store: st, keys: keys}
}

func (s *Service) State() model.State  { return s.store.Snapshot() }
func (s *Service) Store() *store.Store { return s.store }

func (s *Service) RecoverStartup() {
	st := s.store.Snapshot()
	for _, intent := range st.Intents {
		if s.intentAlreadyApplied(intent) {
			_ = s.store.RemoveIntentOnly(intent.ID)
		}
	}
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

func dnToPKIX(d model.DN) pkix.Name {
	return pkix.Name{
		CommonName:         d.CommonName,
		Organization:       nonEmpty(d.Organization),
		OrganizationalUnit: nonEmpty(d.OrganizationalUnit),
		Country:            nonEmpty(d.Country),
		Locality:           nonEmpty(d.Locality),
		Province:           nonEmpty(d.Province),
	}
}

func nonEmpty(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return []string{v}
}

func certModel(kind, name, requestID, templateID, parentID, keyRef string, serial int64, der []byte, policyVersion int, createdAt string, status string) (model.Certificate, error) {
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return model.Certificate{}, err
	}
	return model.Certificate{
		ID: newID("cert"), Kind: kind, Name: name, RequestID: requestID, TemplateID: templateID, ParentID: parentID,
		KeyRef: keyRef, Serial: fmt.Sprintf("%d", serial), DER: der,
		NotBefore: parsed.NotBefore.UTC().Format(time.RFC3339Nano), NotAfter: parsed.NotAfter.UTC().Format(time.RFC3339Nano),
		SignatureAlgorithm: sigName(parsed.SignatureAlgorithm), Fingerprint: fingerprint(der),
		SubjectKeyID: hex.EncodeToString(parsed.SubjectKeyId), AuthorityKeyID: hex.EncodeToString(parsed.AuthorityKeyId),
		Status: status, PolicyVersion: policyVersion, CreatedAt: createdAt,
	}, nil
}

func sigName(algo x509.SignatureAlgorithm) string {
	switch algo {
	case x509.SHA256WithRSA:
		return "SHA256-RSA"
	case x509.SHA384WithRSA:
		return "SHA384-RSA"
	case x509.SHA512WithRSA:
		return "SHA512-RSA"
	case x509.ECDSAWithSHA256:
		return "SHA256-ECDSA"
	case x509.ECDSAWithSHA384:
		return "SHA384-ECDSA"
	case x509.PureEd25519:
		return "Ed25519"
	default:
		return algo.String()
	}
}

func signerKeyName(key crypto.Signer) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-384":
			return "EC-P384"
		default:
			return "EC-P256"
		}
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return key.Public().(fmt.Stringer).String()
	}
}

func publicKeyName(key crypto.PublicKey) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve.Params().Name {
		case "P-384":
			return "EC-P384"
		default:
			return "EC-P256"
		}
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", key)
	}
}

func containsFold(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, v := range values {
		if strings.ToLower(strings.TrimSpace(v)) == target {
			return true
		}
	}
	return false
}

func requirePolicyKey(policy model.Policy, name string) error {
	if !containsFold(policy.AllowedKeyTypes, name) {
		return fmt.Errorf("key type %s is not allowed by policy v%d", name, policy.Version)
	}
	return nil
}

func requirePolicySig(policy model.Policy, name string) error {
	if !containsFold(policy.AllowedSigAlgos, name) {
		return fmt.Errorf("signature algorithm %s is not allowed by policy v%d", name, policy.Version)
	}
	return nil
}

func parseCertificate(c model.Certificate) (*x509.Certificate, error) {
	return x509.ParseCertificate(c.DER)
}

func timeBounds(input model.SubjectRequest) (time.Time, time.Time, error) {
	nb, err := parseTime(input.NotBefore)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("notBefore: %w", err)
	}
	na, err := parseTime(input.NotAfter)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("notAfter: %w", err)
	}
	if !na.After(nb) {
		return nb, na, errors.New("notAfter must be later than notBefore")
	}
	return nb, na, nil
}

func checkValidityPolicy(input model.SubjectRequest, policy model.Policy, nb, na time.Time) model.CheckStep {
	duration := na.Sub(nb)
	min := time.Duration(policy.MinValidityHours) * time.Hour
	max := time.Duration(policy.MaxValidityDays) * 24 * time.Hour
	if duration < min {
		return failStep("validity policy", fmt.Sprintf("duration %s is below minimum %s", duration, min))
	}
	if duration > max {
		return failStep("validity policy", fmt.Sprintf("duration %s exceeds maximum %s", duration, max))
	}
	return okStep("validity policy", fmt.Sprintf("%s is within policy v%d", duration, policy.Version))
}

func checkNesting(childNB, childNA time.Time, parent *x509.Certificate) model.CheckStep {
	if childNB.Before(parent.NotBefore) || childNA.After(parent.NotAfter) {
		return failStep("validity nesting", fmt.Sprintf("child %s..%s is not nested in parent %s..%s", childNB, childNA, parent.NotBefore, parent.NotAfter))
	}
	return okStep("validity nesting", "boundaries are inclusive; equality with notBefore or notAfter is accepted")
}

func okStep(name, detail string) model.CheckStep {
	return model.CheckStep{Name: name, OK: true, Detail: detail}
}
func failStep(name, detail string) model.CheckStep {
	return model.CheckStep{Name: name, OK: false, Detail: detail}
}

func failure(steps []model.CheckStep) error {
	for _, step := range steps {
		if !step.OK {
			return Failure{Steps: steps}
		}
	}
	return nil
}

func buildBaseTemplate(input model.SubjectRequest, isCA bool, nb, na time.Time, serial int64) (*x509.Certificate, []pkixExt, error) {
	if strings.TrimSpace(input.Subject.CommonName) == "" {
		return nil, nil, errors.New("subject common_name is required")
	}
	usage, err := mapKeyUsage(input.KeyUsage, isCA)
	if err != nil {
		return nil, nil, err
	}
	ips, err := parseIPs(input.IPAddresses)
	if err != nil {
		return nil, nil, err
	}
	uris, err := parseURIs(input.URIs)
	if err != nil {
		return nil, nil, err
	}
	for _, email := range input.EmailAddresses {
		if !validEmail(email) {
			return nil, nil, fmt.Errorf("invalid email address %q", email)
		}
	}
	exts, err := customExtensions(input.CustomExtensions)
	if err != nil {
		return nil, nil, err
	}
	ekus, unknownEKUs, err := mapEKUs(input.EKUs)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serialToBig(serial), Subject: dnToPKIX(input.Subject), NotBefore: nb, NotAfter: na,
		KeyUsage: usage, ExtKeyUsage: ekus, UnknownExtKeyUsage: parseUnknownEKUs(unknownEKUs),
		DNSNames: input.DNSNames, IPAddresses: ips, EmailAddresses: input.EmailAddresses, URIs: uris,
		BasicConstraintsValid: true, IsCA: isCA, ExtraExtensions: toPKIXExtensions(exts),
	}
	if isCA {
		tpl.MaxPathLen = input.MaxPathLen
		tpl.MaxPathLenZero = input.MaxPathLen == 0
		nc, err := buildNameConstraints(input.NameConstraints)
		if err != nil {
			return nil, nil, err
		}
		tpl.PermittedDNSDomains = nc.PermittedDNSDomains
		tpl.ExcludedDNSDomains = nc.ExcludedDNSDomains
		tpl.PermittedIPRanges = nc.PermittedIPRanges
		tpl.ExcludedIPRanges = nc.ExcludedIPRanges
		tpl.PermittedEmailAddresses = nc.PermittedEmailAddresses
		tpl.ExcludedEmailAddresses = nc.ExcludedEmailAddresses
		tpl.PermittedURIDomains = nc.PermittedURIDomains
		tpl.ExcludedURIDomains = nc.ExcludedURIDomains
	}
	return tpl, exts, nil
}

func parseUnknownEKUs(values []string) []asn1.ObjectIdentifier {
	out := []asn1.ObjectIdentifier{}
	for _, value := range values {
		id, err := parseOID(value)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out
}
