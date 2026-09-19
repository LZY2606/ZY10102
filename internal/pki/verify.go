package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"localpki/internal/model"
)

func (s *Service) VerifyCertificate(certID string, verifyAtRaw string) (model.VerificationReport, error) {
	at, err := parseTime(verifyAtRaw)
	if err != nil {
		return model.VerificationReport{}, err
	}
	st := s.store.Snapshot()
	start, ok := st.Certificates[certID]
	if !ok {
		return model.VerificationReport{}, fmt.Errorf("certificate %s not found", certID)
	}
	paths := s.enumeratePaths(st, start, map[string]bool{})
	chains := make([]model.ChainResult, 0, len(paths))
	for _, path := range paths {
		chain, qualified, reason := verifyPath(path, at)
		chain.Qualified = qualified
		chain.Reason = reason
		chains = append(chains, chain)
	}
	sort.SliceStable(chains, func(i, j int) bool {
		if chains[i].Qualified != chains[j].Qualified {
			return chains[i].Qualified
		}
		return chainOrderKey(chains[i]) < chainOrderKey(chains[j])
	})
	for i := range chains {
		chains[i].ID = fmt.Sprintf("chain-%d", i+1)
	}
	report := model.VerificationReport{
		CertID: certID, VerifyAt: at.UTC().Format(time.RFC3339Nano),
		BoundaryRule: "closed interval: verifyAt equal to notBefore or notAfter is accepted",
		Chains:       chains,
	}
	for i := range chains {
		if chains[i].Qualified {
			chains[i].Default = true
			report.DefaultChain = &chains[i]
			break
		}
	}
	return report, nil
}

type parsedPathEntry struct {
	cert   model.Certificate
	parsed *x509.Certificate
}

func (s *Service) enumeratePaths(st model.State, start model.Certificate, seen map[string]bool) [][]parsedPathEntry {
	if seen[start.ID] {
		return nil
	}
	seen[start.ID] = true
	defer delete(seen, start.ID)
	parsed, err := x509.ParseCertificate(start.DER)
	if err != nil {
		return nil
	}
	entry := parsedPathEntry{cert: start, parsed: parsed}
	if start.Kind == "root" || start.ParentID == "" {
		return [][]parsedPathEntry{{entry}}
	}
	alternatives := equivalentCertificates(st, start)
	out := [][]parsedPathEntry{}
	for _, alt := range alternatives {
		altParsed, err := x509.ParseCertificate(alt.DER)
		if err != nil {
			continue
		}
		altEntry := parsedPathEntry{cert: alt, parsed: altParsed}
		if alt.Kind == "root" || alt.ParentID == "" {
			out = append(out, []parsedPathEntry{altEntry})
			continue
		}
		parent, ok := st.Certificates[alt.ParentID]
		if !ok {
			continue
		}
		for _, parentPath := range s.enumeratePaths(st, parent, seen) {
			out = append(out, append([]parsedPathEntry{altEntry}, parentPath...))
		}
	}
	return uniquePaths(out)
}

func equivalentCertificates(st model.State, current model.Certificate) []model.Certificate {
	if current.Kind == "leaf" && current.RequestID != "" {
		req := st.Requests[current.RequestID]
		out := make([]model.Certificate, 0, len(req.CandidateCertIDs))
		for _, id := range req.CandidateCertIDs {
			if c, ok := st.Certificates[id]; ok && c.Status != "rejected" {
				out = append(out, c)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return out
	}
	if current.TemplateID != "" {
		out := []model.Certificate{}
		for _, c := range st.Certificates {
			if c.TemplateID == current.TemplateID && c.Kind == "intermediate" && c.Status != "rejected" {
				out = append(out, c)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return out
	}
	return []model.Certificate{current}
}

func uniquePaths(paths [][]parsedPathEntry) [][]parsedPathEntry {
	seen := map[string]bool{}
	out := [][]parsedPathEntry{}
	for _, path := range paths {
		ids := make([]string, 0, len(path))
		for _, entry := range path {
			ids = append(ids, entry.cert.ID)
		}
		key := strings.Join(ids, "|")
		if !seen[key] {
			seen[key] = true
			out = append(out, path)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return pathIDKey(out[i]) < pathIDKey(out[j]) })
	return out
}

func pathIDKey(path []parsedPathEntry) string {
	ids := make([]string, 0, len(path))
	for _, entry := range path {
		ids = append(ids, entry.cert.ID)
	}
	return strings.Join(ids, "|")
}

func verifyPath(path []parsedPathEntry, at time.Time) (model.ChainResult, bool, string) {
	links := make([]model.ChainLink, 0, len(path))
	for _, entry := range path {
		c := entry.cert
		links = append(links, model.ChainLink{
			CertID: c.ID, Subject: entry.parsed.Subject.String(), Issuer: entry.parsed.Issuer.String(),
			Serial: c.Serial, Fingerprint: c.Fingerprint, Status: c.Status,
		})
	}
	chain := model.ChainResult{Links: links}
	for _, entry := range path {
		c := entry.cert
		if c.Status == "revoked" {
			return chain, false, "chain contains revoked certificate " + c.ID
		}
		if at.Before(entry.parsed.NotBefore) || at.After(entry.parsed.NotAfter) {
			return chain, false, "certificate " + c.ID + " is outside its inclusive validity interval"
		}
	}
	for i := 0; i < len(path)-1; i++ {
		child := path[i].parsed
		parent := path[i+1].parsed
		if err := child.CheckSignatureFrom(parent); err != nil {
			return chain, false, "signature from " + path[i+1].cert.ID + " is invalid: " + err.Error()
		}
		if !parent.IsCA || parent.KeyUsage&x509.KeyUsageCertSign == 0 {
			return chain, false, "issuer " + path[i+1].cert.ID + " is not permitted to sign certificates"
		}
		if err := validateNameConstraints(identityFromCertificate(child), parent); err != nil {
			return chain, false, err.Error()
		}
		if child.IsCA {
			if parent.MaxPathLenZero {
				return chain, false, "issuer pathLen=0 cannot have a CA child"
			}
			if parent.MaxPathLen > 0 && child.MaxPathLen > parent.MaxPathLen-1 {
				return chain, false, "child pathLen does not fit issuer pathLen budget"
			}
		}
	}
	root := path[len(path)-1]
	if root.cert.Kind == "root" {
		if err := root.parsed.CheckSignatureFrom(root.parsed); err != nil {
			return chain, false, "root self-signature is invalid: " + err.Error()
		}
	}
	return chain, true, "qualified"
}

func chainOrderKey(chain model.ChainResult) string {
	parts := make([]string, 0, len(chain.Links))
	for _, link := range chain.Links {
		parts = append(parts, link.Fingerprint)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}
