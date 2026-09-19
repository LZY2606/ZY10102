package app_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localpki/internal/app"
	"localpki/internal/keystore"
	"localpki/internal/model"
	"localpki/internal/pki"
	"localpki/internal/store"
)

func setup(t *testing.T) (string, *httptest.Server) {
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
	service := pki.NewService(st, keys)
	server := app.New(service, filepath.Join("..", "..", "web"))
	return dir, httptest.NewServer(server.Routes())
}

func postJSON(t *testing.T, url string, value any) *http.Response {
	t.Helper()
	return requestJSON(t, http.MethodPost, url, value)
}

func requestJSON(t *testing.T, method, url string, value any) *http.Response {
	t.Helper()
	data, _ := json.Marshal(value)
	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestHTTPEndToEndAndPolicyConflict(t *testing.T) {
	_, ts := setup(t)
	defer ts.Close()
	nb := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	na := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339Nano)
	rootRes := postJSON(t, ts.URL+"/api/roots", model.SubjectRequest{
		Purpose: "root", Name: "Web Root", Subject: model.DN{CommonName: "Web Root"}, Key: model.KeySpec{Type: "EC", Curve: "P256"},
		NotBefore: nb, NotAfter: na, MaxPathLen: 2, KeyUsage: []string{"keyCertSign", "cRLSign"},
		NameConstraints: model.NameConstraints{PermittedDNS: []string{".example.test"}},
	})
	if rootRes.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(rootRes.Body)
		t.Fatalf("root status %d: %s", rootRes.StatusCode, body)
	}
	var root model.Certificate
	if err := json.NewDecoder(rootRes.Body).Decode(&root); err != nil {
		t.Fatal(err)
	}
	rootRes.Body.Close()
	if root.ID == "" {
		t.Fatal("missing root id")
	}

	leafNB := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339Nano)
	leafNA := time.Now().UTC().Add(72 * time.Hour).Format(time.RFC3339Nano)
	input := model.SubjectRequest{Purpose: "leaf", Name: "Web Leaf", Subject: model.DN{CommonName: "web.example.test"},
		Key: model.KeySpec{Type: "EC", Curve: "P256"}, IssuerID: root.ID, NotBefore: leafNB, NotAfter: leafNA, DNSNames: []string{"web.example.test"}, EKUs: []string{"serverAuth"}}
	reqBody := map[string]any{"idempotency_key": "http-key", "input": input}
	res := postJSON(t, ts.URL+"/api/requests", reqBody)
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("prepare %d: %s", res.StatusCode, b)
	}
	var req model.Request
	json.NewDecoder(res.Body).Decode(&req)
	res.Body.Close()

	res2 := postJSON(t, ts.URL+"/api/requests", reqBody)
	defer res2.Body.Close()
	var repeated model.Request
	json.NewDecoder(res2.Body).Decode(&repeated)
	if repeated.ID != req.ID {
		t.Fatal("HTTP idempotency returned a new request")
	}

	res = postJSON(t, ts.URL+"/api/requests/"+req.ID+"/accept", map[string]string{})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("accept status %d", res.StatusCode)
	}

	policyRes := requestJSON(t, http.MethodPut, ts.URL+"/api/policy", model.Policy{AllowedSigAlgos: []string{"Ed25519"}, AllowedKeyTypes: []string{"Ed25519"}, MaxValidityDays: 1, MinValidityHours: 1, RequireLeafSAN: true, AllowWildcardDNS: false, RequireAKI: true})
	policyRes.Body.Close()
	if policyRes.StatusCode != http.StatusOK {
		t.Fatalf("policy status %d", policyRes.StatusCode)
	}
	conflict := postJSON(t, ts.URL+"/api/requests", reqBody)
	defer conflict.Body.Close()
	if conflict.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 after policy change, got %d", conflict.StatusCode)
	}

	bad := reqBody
	bad["idempotency_key"] = "bad-key"
	bad["input"] = model.SubjectRequest{Purpose: "leaf", Name: "Bad", Subject: model.DN{CommonName: "bad.example.org"}, Key: model.KeySpec{Type: "Ed25519"}, IssuerID: root.ID, NotBefore: leafNB, NotAfter: leafNA, DNSNames: []string{"bad.example.org"}}
	invalid := postJSON(t, ts.URL+"/api/requests", bad)
	defer invalid.Body.Close()
	if invalid.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 validation failure, got %d", invalid.StatusCode)
	}

	verifyRes := postJSON(t, ts.URL+"/api/verify", map[string]string{"cert_id": req.CandidateCertIDs[0], "verify_at": leafNB})
	defer verifyRes.Body.Close()
	if verifyRes.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(verifyRes.Body)
		t.Fatalf("verify %d: %s", verifyRes.StatusCode, b)
	}
	var report model.VerificationReport
	json.NewDecoder(verifyRes.Body).Decode(&report)
	if report.DefaultChain == nil || !strings.Contains(report.BoundaryRule, "notAfter") {
		t.Fatalf("bad boundary report: %+v", report)
	}
}

func TestHTTPExportImportAndStaticPage(t *testing.T) {
	dir, ts := setup(t)
	defer ts.Close()
	nb := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	na := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	res := postJSON(t, ts.URL+"/api/roots", model.SubjectRequest{Purpose: "root", Name: "Export Root", Subject: model.DN{CommonName: "Export Root"}, Key: model.KeySpec{Type: "Ed25519"}, NotBefore: nb, NotAfter: na, MaxPathLen: 1, KeyUsage: []string{"keyCertSign"}})
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("root %d", res.StatusCode)
	}
	exportRes, err := http.Get(ts.URL + "/api/export")
	if err != nil {
		t.Fatal(err)
	}
	defer exportRes.Body.Close()
	bundle, _ := io.ReadAll(exportRes.Body)
	if _, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle))); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bundle, []byte("PRIVATE KEY")) {
		t.Fatal("bundle leaks private key")
	}

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	part, err := mw.CreateFormFile("bundle", "bundle.zip")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(bundle)
	mw.Close()
	importRes, err := http.Post(ts.URL+"/api/import", mw.FormDataContentType(), body)
	if err != nil {
		t.Fatal(err)
	}
	defer importRes.Body.Close()
	if importRes.StatusCode != http.StatusConflict {
		t.Fatalf("non-empty import expected 409, got %d", importRes.StatusCode)
	}
	page, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer page.Body.Close()
	html, _ := io.ReadAll(page.Body)
	if !bytes.Contains(html, []byte("隔离 PKI")) {
		t.Fatal("static page missing")
	}
	_ = dir
}
