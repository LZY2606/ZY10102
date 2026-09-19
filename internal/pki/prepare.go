package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"localpki/internal/model"
	"localpki/internal/store"
)

type Prepared struct{ Request model.Request }

func (s *Service) PrepareCandidate(input model.SubjectRequest, idempotencyKey string) (model.Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.store.Snapshot()
	if idempotencyKey != "" {
		if req, ok := findRequestByIdempotency(state, idempotencyKey); ok {
			hash, _ := store.CanonicalJSON(input)
			if req.PayloadHash == hash && req.PolicyVersion == state.Policy.Version {
				return req, nil
			}
			return model.Request{}, fmt.Errorf("%w: idempotency key %s already has a different request or policy version", store.ErrConflict, idempotencyKey)
		}
	}
	policy := state.Policy
	nb, na, err := timeBounds(input)
	if err != nil {
		return model.Request{}, err
	}
	steps := []model.CheckStep{checkValidityPolicy(input, policy, nb, na), checkKeyUsagePolicy(input, input.Purpose != "leaf")}
	isCA := input.Purpose == "intermediate"
	if input.Purpose != "leaf" && input.Purpose != "intermediate" {
		return model.Request{}, errors.New("purpose must be leaf or intermediate")
	}
	if err := requirePolicyKey(policy, keySpecName(input.Key)); err != nil {
		steps = append(steps, failStep("key type policy", err.Error()))
	}
	if err := requirePolicySig(policy, defaultSigName(input, keySpecName(input.Key))); err != nil {
		steps = append(steps, failStep("signature policy", err.Error()))
	}
	if err := checkSANPolicy(input, policy); err != nil {
		steps = append(steps, failStep("subject alternative names", err.Error()))
	}
	if isCA && input.MaxPathLen < 0 {
		steps = append(steps, failStep("pathLen", "intermediate pathLen must be zero or positive"))
	}
	if _, err := buildNameConstraints(input.NameConstraints); err != nil {
		steps = append(steps, failStep("name constraints syntax", err.Error()))
	}
	var subjectKey crypto.Signer
	var subjectKeyRef string
	var template *model.IntermediateTemplate
	if isCA {
		t, ok := state.Templates[input.TemplateID]
		if !ok {
			return model.Request{}, fmt.Errorf("intermediate template %s not found", input.TemplateID)
		}
		template = &t
		subjectKey, err = s.keys.Load("intermediate-" + t.ID + ".pem")
		if err != nil {
			return model.Request{}, err
		}
		cloned := input
		cloned.Subject = t.Subject
		cloned.NameConstraints = t.NameConstraints
		cloned.MaxPathLen = t.MaxPathLen
		input = cloned
	} else {
		subjectKeyRef = newKeyRef("leaf-generating")
		subjectKey, err = s.keys.Generate(subjectKeyRef, input.Key.Type, input.Key.Curve, input.Key.Bits)
		if err != nil {
			return model.Request{}, err
		}
	}
	issuerIDs := normalizedIssuers(input)
	if len(issuerIDs) == 0 {
		return model.Request{}, errors.New("at least one issuer is required")
	}
	type preparedParent struct {
		cert   model.Certificate
		parsed *x509.Certificate
		signer crypto.Signer
	}
	parents := make([]preparedParent, 0, len(issuerIDs))
	for _, issuerID := range issuerIDs {
		parentParsed, parentCert, err := acceptedParent(state, issuerID)
		if err != nil {
			steps = append(steps, failStep("issuer availability", err.Error()))
			continue
		}
		parentSigner, err := s.parentSigner(parentCert)
		if err != nil {
			steps = append(steps, failStep("issuer availability", err.Error()))
			continue
		}
		steps = append(steps, checkNesting(nb, na, parentParsed))
		if isCA {
			steps = append(steps, checkPathLenConstraint(parentParsed, input.MaxPathLen))
			if err := validateChildConstraints(input.NameConstraints, parentParsed); err != nil {
				steps = append(steps, failStep("name constraints nesting", err.Error()))
			}
		}
		names := identityFromInput(input)
		if err := validateNameConstraints(names, parentParsed); err != nil {
			steps = append(steps, failStep("name constraints", err.Error()))
		}
		if !parentParsed.IsCA {
			steps = append(steps, failStep("issuer key usage", "issuer is not a CA"))
		} else if parentParsed.KeyUsage&x509.KeyUsageCertSign == 0 {
			steps = append(steps, failStep("issuer key usage", "issuer lacks keyCertSign"))
		}
		if parentParsed.NotBefore.After(nb) || parentParsed.NotAfter.Before(na) {
			steps = append(steps, failStep("validity nesting", "candidate validity escapes issuer validity"))
		}
		parents = append(parents, preparedParent{cert: parentCert, parsed: parentParsed, signer: parentSigner})
	}
	steps = append(steps, okStep("serial uniqueness", "serial numbers are reserved only by the candidate event"))
	if err := failure(steps); err != nil {
		return model.Request{}, Failure{Steps: steps}
	}
	baseAlgo, baseAlgoName, err := sigAlgoForKey(subjectKey, input.SignatureAlgorithm)
	if err != nil {
		return model.Request{}, err
	}
	if err := requirePolicySig(policy, baseAlgoName); err != nil {
		return model.Request{}, err
	}
	serialStart := state.NextSerial
	baseTpl, _, err := buildBaseTemplate(input, isCA, nb, na, serialStart)
	if err != nil {
		return model.Request{}, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(subjectKey.Public())
	if err != nil {
		return model.Request{}, err
	}
	pubSum := sha256.Sum256(pubDER)
	baseTpl.SubjectKeyId = pubSum[:]
	baseTpl.AuthorityKeyId = pubSum[:]
	baseTpl.SignatureAlgorithm = baseAlgo
	if err := checkCriticalExtensions(baseTpl, policy); err != nil {
		return model.Request{}, err
	}
	baselineDER, err := x509.CreateCertificate(rand.Reader, baseTpl, baseTpl, subjectKey.Public(), subjectKey)
	if err != nil {
		return model.Request{}, err
	}
	baselineCert, err := x509.ParseCertificate(baselineDER)
	if err != nil {
		return model.Request{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	reqID := newID("req")
	if !isCA {
		leafRef := "leaf-" + reqID + ".pem"
		if err := s.keys.Rename(subjectKeyRef, leafRef); err != nil {
			return model.Request{}, err
		}
		subjectKeyRef = leafRef
	}
	certIDs := []string{}
	certs := []model.Certificate{}
	diffByCert := map[string][]model.ExtensionDiff{}
	for index, parent := range parents {
		serial := serialStart + int64(index)
		if state.Serials[fmt.Sprintf("%d", serial)] {
			return model.Request{}, fmt.Errorf("serial %d is already occupied", serial)
		}
		tpl, _, err := buildBaseTemplate(input, isCA, nb, na, serial)
		if err != nil {
			return model.Request{}, err
		}
		tpl.SubjectKeyId = pubSum[:]
		tpl.AuthorityKeyId = parent.parsed.SubjectKeyId
		tpl.SignatureAlgorithm = baseAlgo
		if err := checkCriticalExtensions(tpl, policy); err != nil {
			return model.Request{}, err
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent.parsed, subjectKey.Public(), parent.signer)
		if err != nil {
			return model.Request{}, err
		}
		kind := "intermediate"
		if !isCA {
			kind = "leaf"
		}
		name := nameOrSubject(input.Name, input.Subject)
		if template != nil {
			name = template.Name
		}
		persistedKeyRef := subjectKeyRef
		cert, err := certModel(kind, name, reqID, input.TemplateID, parent.cert.ID, persistedKeyRef, serial, der, policy.Version, now, "pending")
		if err != nil {
			return model.Request{}, err
		}
		if !isCA {
			cert.KeyRef = ""
		}
		diff := diffExtensions(baselineCert, mustParse(der))
		diffByCert[cert.ID] = diff
		certIDs = append(certIDs, cert.ID)
		certs = append(certs, cert)
	}
	if template != nil {
		for i := range certs {
			certs[i].KeyRef = ""
		}
	}
	sortCertIDs(certIDs)
	payloadHash, _ := store.CanonicalJSON(input)
	req := model.Request{
		ID: reqID, IdempotencyKey: idempotencyKey, PayloadHash: payloadHash, Input: input,
		Status: "pending", CandidateCertIDs: certIDs, PolicyVersion: policy.Version,
		Checks: finalizeOK(steps), ExtensionDiffs: diffByCert[candidateDefault(certIDs)],
		ExtensionDiffsByCert: diffByCert, CreatedAt: now,
	}
	payload := store.CandidatePreparedPayload{Request: req, Certificates: certs}
	_, err = s.store.Commit("candidate.prepared", "prepare-candidate", payload, "", func(st *model.State, raw any) error {
		p := raw.(store.CandidatePreparedPayload)
		if _, exists := st.Requests[p.Request.ID]; exists {
			return fmt.Errorf("duplicate request %s", p.Request.ID)
		}
		for _, c := range p.Certificates {
			if st.Serials[c.Serial] {
				return fmt.Errorf("serial %s is already occupied", c.Serial)
			}
		}
		for _, c := range p.Certificates {
			st.Serials[c.Serial] = true
			st.Certificates[c.ID] = c
			if n := serialNumber(c.Serial) + 1; n > st.NextSerial {
				st.NextSerial = n
			}
		}
		st.Requests[p.Request.ID] = p.Request
		return nil
	})
	return req, err
}

func normalizedIssuers(input model.SubjectRequest) []string {
	values := input.IssuerIDs
	if len(values) == 0 && input.IssuerID != "" {
		values = []string{input.IssuerID}
	}
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	return out
}

func identityFromInput(input model.SubjectRequest) identitySet {
	ips, _ := parseIPs(input.IPAddresses)
	return identitySet{dns: input.DNSNames, emails: input.EmailAddresses, ips: ips, uris: input.URIs}
}

func checkPathLenConstraint(parent *x509.Certificate, requested int) model.CheckStep {
	if !parent.IsCA {
		return failStep("pathLen", "issuer is not a CA")
	}
	if parent.MaxPathLen == 0 && parent.MaxPathLenZero {
		return failStep("pathLen", "issuer pathLen=0 cannot issue another CA")
	}
	if parent.MaxPathLen > 0 && requested > parent.MaxPathLen-1 {
		return failStep("pathLen", fmt.Sprintf("requested pathLen %d does not fit issuer remaining pathLen %d", requested, parent.MaxPathLen-1))
	}
	return okStep("pathLen", fmt.Sprintf("requested pathLen %d fits issuer budget", requested))
}

func finalizeOK(steps []model.CheckStep) []model.CheckStep {
	names := map[string]bool{}
	out := []model.CheckStep{}
	for _, step := range steps {
		names[step.Name] = true
		if step.OK {
			out = append(out, step)
		} else {
			out = append(out, step)
		}
	}
	if !names["signature algorithm"] {
		out = append(out, okStep("signature algorithm", "candidate signature matches active policy"))
	}
	return out
}

func mustParse(der []byte) *x509.Certificate { c, _ := x509.ParseCertificate(der); return c }
func candidateDefault(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}
func findRequestByIdempotency(st model.State, key string) (model.Request, bool) {
	for _, req := range st.Requests {
		if req.IdempotencyKey == key {
			return req, true
		}
	}
	return model.Request{}, false
}
