package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"localpki/internal/model"
	"localpki/internal/store"
)

func (s *Service) UpdatePolicy(next model.Policy) (model.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.store.Policy()
	next.Version = current.Version + 1
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if next.MaxValidityDays <= 0 || next.MinValidityHours < 0 {
		return model.Policy{}, errors.New("validity limits must be positive")
	}
	if len(next.AllowedSigAlgos) == 0 || len(next.AllowedKeyTypes) == 0 {
		return model.Policy{}, errors.New("policy must allow at least one signature algorithm and key type")
	}
	_, err := s.store.Commit("policy.updated", "update-policy", store.PolicyUpdatedPayload{Policy: next}, "", func(st *model.State, raw any) error {
		st.Policy = raw.(store.PolicyUpdatedPayload).Policy
		return nil
	})
	return next, err
}

func (s *Service) EnrollRoot(input model.SubjectRequest) (model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy := s.store.Policy()
	state := s.store.Snapshot()
	nb, na, err := timeBounds(input)
	if err != nil {
		return model.Certificate{}, err
	}
	keyName := keySpecName(input.Key)
	steps := []model.CheckStep{checkValidityPolicy(input, policy, nb, na), checkKeyUsagePolicy(input, true)}
	if err := requirePolicyKey(policy, keyName); err != nil {
		steps = append(steps, failStep("key type policy", err.Error()))
	}
	if err := requirePolicySig(policy, defaultSigName(input, keyName)); err != nil {
		steps = append(steps, failStep("signature policy", err.Error()))
	}
	if err := failure(steps); err != nil {
		return model.Certificate{}, Failure{Steps: steps}
	}
	keyRef := newKeyRef("root")
	signer, err := s.keys.Generate(keyRef, input.Key.Type, input.Key.Curve, input.Key.Bits)
	if err != nil {
		return model.Certificate{}, err
	}
	algo, algoName, err := sigAlgoForKey(signer, input.SignatureAlgorithm)
	if err != nil {
		return model.Certificate{}, err
	}
	if err := requirePolicySig(policy, algoName); err != nil {
		return model.Certificate{}, err
	}
	serial := state.NextSerial
	tpl, _, err := buildBaseTemplate(input, true, nb, na, serial)
	if err != nil {
		return model.Certificate{}, err
	}
	if tpl.MaxPathLen == 0 && !tpl.MaxPathLenZero {
		tpl.MaxPathLen = -1
	}
	if input.MaxPathLen == 0 {
		tpl.MaxPathLenZero = false
	}
	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return model.Certificate{}, err
	}
	sum := sha256.Sum256(pubDER)
	tpl.SubjectKeyId = sum[:]
	tpl.AuthorityKeyId = sum[:]
	tpl.SignatureAlgorithm = algo
	if err := checkCriticalExtensions(tpl, policy); err != nil {
		return model.Certificate{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		return model.Certificate{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	cert, err := certModel("root", nameOrSubject(input.Name, input.Subject), "", "", "", "", serial, der, policy.Version, now, "accepted")
	if err != nil {
		return model.Certificate{}, err
	}
	if err := s.keys.Rename(keyRef, "root-"+cert.ID+".pem"); err != nil {
		return model.Certificate{}, err
	}
	_, err = s.store.Commit("root.enrolled", "enroll-root", store.RootEnrolledPayload{Certificate: cert}, "", func(st *model.State, raw any) error {
		c := raw.(store.RootEnrolledPayload).Certificate
		if st.Serials[c.Serial] {
			return fmt.Errorf("serial %s is already occupied", c.Serial)
		}
		st.Serials[c.Serial] = true
		st.Certificates[c.ID] = c
		if n := serialNumber(c.Serial) + 1; n > st.NextSerial {
			st.NextSerial = n
		}
		return nil
	})
	return cert, err
}

func (s *Service) RegisterTemplate(input model.SubjectRequest) (model.IntermediateTemplate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy := s.store.Policy()
	keyName := keySpecName(input.Key)
	if err := requirePolicyKey(policy, keyName); err != nil {
		return model.IntermediateTemplate{}, err
	}
	if _, _, err := timeBounds(input); err != nil {
		return model.IntermediateTemplate{}, err
	}
	if _, err := buildNameConstraints(input.NameConstraints); err != nil {
		return model.IntermediateTemplate{}, err
	}
	if input.MaxPathLen < 0 {
		return model.IntermediateTemplate{}, errors.New("pathLen must be zero or positive")
	}
	templateID := newID("tmpl")
	keyRef := "intermediate-" + templateID + ".pem"
	signer, err := s.keys.Generate(keyRef, input.Key.Type, input.Key.Curve, input.Key.Bits)
	if err != nil {
		return model.IntermediateTemplate{}, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return model.IntermediateTemplate{}, err
	}
	tpl := model.IntermediateTemplate{
		ID: templateID, Name: nameOrSubject(input.Name, input.Subject), Subject: input.Subject, KeyRef: "",
		PublicKeyDER: pubDER, MaxPathLen: input.MaxPathLen, NameConstraints: input.NameConstraints,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	_, err = s.store.Commit("template.registered", "register-template", store.TemplateRegisteredPayload{Template: tpl}, "", func(st *model.State, raw any) error {
		p := raw.(store.TemplateRegisteredPayload).Template
		st.Templates[p.ID] = p
		return nil
	})
	return tpl, err
}

func defaultSigName(input model.SubjectRequest, keyName string) string {
	if input.SignatureAlgorithm != "" {
		return strings.ToUpper(input.SignatureAlgorithm)
	}
	if keyName == "EC-P384" {
		return "SHA384-ECDSA"
	}
	if keyName == "Ed25519" {
		return "Ed25519"
	}
	if strings.HasPrefix(keyName, "EC-") {
		return "SHA256-ECDSA"
	}
	return "SHA256-RSA"
}

func nameOrSubject(name string, dn model.DN) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return dn.CommonName
}

func newKeyRef(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "-" + fmt.Sprintf("%x.pem", b)
}

func serialNumber(value string) int64 {
	var n int64
	for _, r := range value {
		n = n*10 + int64(r-'0')
	}
	return n
}

func checkCriticalExtensions(tpl *x509.Certificate, policy model.Policy) error {
	allowed := map[string]bool{"2.5.29.15": true, "2.5.29.19": true, "2.5.29.30": true}
	for _, oid := range policy.AllowedCriticalExtensions {
		allowed[oid] = true
	}
	for _, ext := range tpl.ExtraExtensions {
		if ext.Critical && !allowed[ext.Id.String()] {
			return fmt.Errorf("critical extension %s is not permitted by policy", ext.Id)
		}
	}
	return nil
}

func findCertificate(st model.State, id string) (model.Certificate, error) {
	c, ok := st.Certificates[id]
	if !ok {
		return model.Certificate{}, fmt.Errorf("certificate %s not found", id)
	}
	return c, nil
}

func acceptedParent(st model.State, id string) (*x509.Certificate, model.Certificate, error) {
	c, err := findCertificate(st, id)
	if err != nil {
		return nil, model.Certificate{}, err
	}
	if c.Status != "accepted" {
		return nil, c, fmt.Errorf("issuer %s is %s", id, c.Status)
	}
	parsed, err := x509.ParseCertificate(c.DER)
	if err != nil {
		return nil, c, err
	}
	return parsed, c, nil
}

func (s *Service) parentSigner(c model.Certificate) (crypto.Signer, error) {
	if strings.HasSuffix(c.KeyRef, ".pem") {
		return s.keys.Load(c.KeyRef)
	}
	refs := []string{"intermediate-" + c.ID + ".pem", "root-" + c.ID + ".pem", "leaf-" + c.ID + ".pem"}
	if c.TemplateID != "" {
		refs = append([]string{"intermediate-" + c.TemplateID + ".pem"}, refs...)
	}
	if c.RequestID != "" {
		refs = append([]string{"leaf-" + c.RequestID + ".pem"}, refs...)
	}
	var firstErr error
	for _, ref := range refs {
		key, err := s.keys.Load(ref)
		if err == nil {
			return key, nil
		}
		firstErr = err
	}
	return nil, firstErr
}

func checkSANPolicy(input model.SubjectRequest, policy model.Policy) error {
	if input.Purpose == "leaf" && policy.RequireLeafSAN &&
		len(input.DNSNames)+len(input.IPAddresses)+len(input.EmailAddresses)+len(input.URIs) == 0 {
		return errors.New("leaf certificate requires at least one subjectAltName")
	}
	if !policy.AllowWildcardDNS {
		for _, name := range input.DNSNames {
			if strings.HasPrefix(name, "*.") {
				return errors.New("wildcard DNS names are disabled by policy")
			}
		}
	}
	for _, name := range input.DNSNames {
		if strings.TrimSpace(name) == "" {
			return errors.New("empty DNS name")
		}
	}
	return nil
}

func checkKeyUsagePolicy(input model.SubjectRequest, isCA bool) model.CheckStep {
	usage, err := mapKeyUsage(input.KeyUsage, isCA)
	if err != nil {
		return failStep("key usage", err.Error())
	}
	if isCA && usage&x509.KeyUsageCertSign == 0 {
		return failStep("key usage", "CA must assert keyCertSign")
	}
	if !isCA && usage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) == 0 {
		return failStep("key usage", "leaf must assert digitalSignature or keyEncipherment")
	}
	return okStep("key usage", "required usages are present")
}

func sortCertIDs(ids []string) { sort.Strings(ids) }
