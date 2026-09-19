package pki_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localpki/internal/keystore"
	"localpki/internal/model"
	"localpki/internal/pki"
	"localpki/internal/store"
)

type fixture struct {
	dir string
	svc *pki.Service
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keystore.New(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	return fixture{dir: dir, svc: pki.NewService(st, keys)}
}

func timeWindow(days int) (string, string) {
	nb := time.Now().UTC().Add(-24 * time.Hour)
	na := nb.Add(time.Duration(days) * 24 * time.Hour)
	return nb.Format(time.RFC3339Nano), na.Format(time.RFC3339Nano)
}

func (f fixture) root(t *testing.T, name, permitted string) model.Certificate {
	t.Helper()
	nb, na := timeWindow(3650)
	root, err := f.svc.EnrollRoot(model.SubjectRequest{
		Purpose: "root", Name: name, Subject: model.DN{CommonName: name, Organization: "Test"},
		Key: model.KeySpec{Type: "EC", Curve: "P256"}, NotBefore: nb, NotAfter: na, MaxPathLen: 2,
		KeyUsage:        []string{"keyCertSign", "cRLSign"},
		NameConstraints: model.NameConstraints{PermittedDNS: []string{permitted}},
	})
	if err != nil {
		t.Fatalf("EnrollRoot: %v", err)
	}
	return root
}

func (f fixture) template(t *testing.T, name string, pathLen int, permitted ...string) model.IntermediateTemplate {
	t.Helper()
	nb, na := timeWindow(365)
	tpl, err := f.svc.RegisterTemplate(model.SubjectRequest{
		Purpose: "intermediate", Name: name, Subject: model.DN{CommonName: name},
		Key: model.KeySpec{Type: "EC", Curve: "P256"}, NotBefore: nb, NotAfter: na,
		MaxPathLen: pathLen, NameConstraints: model.NameConstraints{PermittedDNS: permitted},
	})
	if err != nil {
		t.Fatalf("RegisterTemplate: %v", err)
	}
	return tpl
}

func TestPrepareIdempotencyAndCrossSigningChains(t *testing.T) {
	f := newFixture(t)
	root1 := f.root(t, "Root One", ".example.test")
	root2 := f.root(t, "Root Two", ".example.test")
	tpl := f.template(t, "Shared Intermediate", 0, "app.example.test")
	nb, na := timeWindow(365)

	makeIntermediate := func(issuer string) model.Request {
		req, err := f.svc.PrepareCandidate(model.SubjectRequest{
			Purpose: "intermediate", Name: tpl.Name, TemplateID: tpl.ID, IssuerID: issuer,
			Subject: tpl.Subject, Key: model.KeySpec{Type: "EC", Curve: "P256"}, NotBefore: nb, NotAfter: na,
			MaxPathLen: 0, NameConstraints: tpl.NameConstraints, KeyUsage: []string{"keyCertSign", "cRLSign"},
		}, "")
		if err != nil {
			t.Fatalf("PrepareCandidate intermediate: %v", err)
		}
		return req
	}
	req1 := makeIntermediate(root1.ID)
	if _, err := f.svc.AcceptRequest(req1.ID); err != nil {
		t.Fatal(err)
	}
	req2 := makeIntermediate(root2.ID)
	if _, err := f.svc.AcceptRequest(req2.ID); err != nil {
		t.Fatal(err)
	}
	st := f.svc.State()
	intermediate := st.Certificates[st.Requests[req1.ID].CertID]

	leafNB := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	leafNA := leafNB.Add(30 * 24 * time.Hour)
	leafReq, err := f.svc.PrepareCandidate(model.SubjectRequest{
		Purpose: "leaf", Name: "App Leaf", Subject: model.DN{CommonName: "app.example.test"},
		Key: model.KeySpec{Type: "EC", Curve: "P256"}, IssuerID: intermediate.ID,
		NotBefore: leafNB.Format(time.RFC3339Nano), NotAfter: leafNA.Format(time.RFC3339Nano),
		DNSNames: []string{"app.example.test"}, EKUs: []string{"serverAuth"},
	}, "stable-key-1")
	if err != nil {
		t.Fatalf("leaf PrepareCandidate: %v", err)
	}
	again, err := f.svc.PrepareCandidate(leafReq.Input, "stable-key-1")
	if err != nil {
		t.Fatalf("idempotent repeat: %v", err)
	}
	if again.ID != leafReq.ID {
		t.Fatalf("repeat created new request: %s != %s", again.ID, leafReq.ID)
	}
	if _, err := f.svc.AcceptRequest(leafReq.ID); err != nil {
		t.Fatal(err)
	}
	leafReq = f.svc.State().Requests[leafReq.ID]

	report, err := f.svc.VerifyCertificate(leafReq.CertID, leafNB.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	qualified := 0
	for _, chain := range report.Chains {
		if chain.Qualified {
			qualified++
		}
	}
	if qualified != 2 {
		t.Fatalf("expected 2 qualified cross-signed chains, got %d: %+v", qualified, report.Chains)
	}
	if report.DefaultChain == nil {
		t.Fatal("expected stable default chain")
	}
	firstDefault := report.DefaultChain.ID

	reportAtEnd, err := f.svc.VerifyCertificate(leafReq.CertID, leafNA.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if reportAtEnd.DefaultChain == nil {
		t.Fatal("verifyAt equal to notAfter must remain valid")
	}
	reportAgain, err := f.svc.VerifyCertificate(leafReq.CertID, leafNB.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if reportAgain.DefaultChain.ID != firstDefault {
		t.Fatalf("default chain is not stable: %s != %s", reportAgain.DefaultChain.ID, firstDefault)
	}
}

func TestPolicyValidationNameConstraintsAndIdempotencyConflict(t *testing.T) {
	f := newFixture(t)
	root := f.root(t, "Strict Root", ".example.test")
	_ = f.template(t, "CA", 0, "app.example.test")
	nb, na := timeWindow(30)
	_, err := f.svc.PrepareCandidate(model.SubjectRequest{
		Purpose: "leaf", Name: "Bad Leaf", Subject: model.DN{CommonName: "evil.example.org"},
		Key: model.KeySpec{Type: "EC", Curve: "P256"}, IssuerID: root.ID,
		NotBefore: nb, NotAfter: na, DNSNames: []string{"evil.example.org"},
	}, "")
	var failure pki.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("expected validation failure, got %v", err)
	}

	good := model.SubjectRequest{Purpose: "leaf", Name: "Good", Subject: model.DN{CommonName: "good.example.test"},
		Key: model.KeySpec{Type: "EC", Curve: "P256"}, IssuerID: root.ID, NotBefore: nb, NotAfter: na, DNSNames: []string{"good.example.test"}}
	first, err := f.svc.PrepareCandidate(good, "same-key")
	if err != nil {
		t.Fatal(err)
	}
	policy := f.svc.State().Policy
	policy.AllowedSigAlgos = []string{"Ed25519"}
	if _, err := f.svc.UpdatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.PrepareCandidate(good, "same-key")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected conflict after policy change, got %v", err)
	}
	if first.Status != "pending" {
		t.Fatalf("original candidate changed: %s", first.Status)
	}
}

func TestSerialRejectionDoesNotReuseAndRevocation(t *testing.T) {
	f := newFixture(t)
	root := f.root(t, "Root", ".example.test")
	nb, na := timeWindow(30)
	req, err := f.svc.PrepareCandidate(model.SubjectRequest{
		Purpose: "leaf", Name: "Rejected", Subject: model.DN{CommonName: "rejected.example.test"},
		Key: model.KeySpec{Type: "EC", Curve: "P256"}, IssuerID: root.ID, NotBefore: nb, NotAfter: na,
		DNSNames: []string{"rejected.example.test"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	occupied := f.svc.State().Serials[req.CandidateCertIDs[0][:0]+"1"]
	if !occupied {
		t.Fatal("serial should be occupied by candidate event")
	}
	if _, err := f.svc.RejectRequest(req.ID, "test reject"); err != nil {
		t.Fatal(err)
	}

	req2, err := f.svc.PrepareCandidate(model.SubjectRequest{
		Purpose: "leaf", Name: "Next", Subject: model.DN{CommonName: "next.example.test"},
		Key: model.KeySpec{Type: "EC", Curve: "P256"}, IssuerID: root.ID, NotBefore: nb, NotAfter: na,
		DNSNames: []string{"next.example.test"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if req2.CandidateCertIDs != nil && f.svc.State().Certificates[req2.CandidateCertIDs[0]].Serial == "1" {
		t.Fatal("rejected serial was reused")
	}
	if _, err := f.svc.AcceptRequest(req2.ID); err != nil {
		t.Fatal(err)
	}
	acceptedReq := f.svc.State().Requests[req2.ID]
	if _, err := f.svc.RevokeCertificate(acceptedReq.CertID, "test"); err != nil {
		t.Fatal(err)
	}
	report, err := f.svc.VerifyCertificate(acceptedReq.CertID, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range report.Chains {
		if chain.Qualified {
			t.Fatal("revoked certificate verified as qualified")
		}
	}
}

func TestNoPrivateKeyFileExported(t *testing.T) {
	f := newFixture(t)
	_ = f.root(t, "Root", ".example.test")
	entries, err := os.ReadDir(filepath.Join(f.dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected local private key files")
	}
	exportPath := filepath.Join(f.dir, "export.zip")
	file, err := os.Create(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Store().Export(file); err != nil {
		t.Fatal(err)
	}
	file.Close()
	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range [][]byte{[]byte("PRIVATE KEY"), []byte(".pem"), []byte("keys/")} {
		if bytes.Contains(data, marker) {
			t.Fatalf("export contains private marker %q", marker)
		}
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, ".json") {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte(`"key_ref": ""`)) == false && bytes.Contains(body, []byte("key_ref")) {
				t.Fatalf("export event %s carries a non-empty local key reference", f.Name)
			}
		}
	}
}
