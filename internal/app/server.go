package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"localpki/internal/model"
	"localpki/internal/pki"
	"localpki/internal/store"
)

type Server struct {
	service *pki.Service
	webRoot string
}

func New(service *pki.Service, webRoot string) *Server {
	s := &Server{service: service, webRoot: webRoot}
	s.service.RecoverStartup()
	return s
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("PUT /api/policy", s.handlePolicy)
	mux.HandleFunc("POST /api/roots", s.handleRoot)
	mux.HandleFunc("POST /api/templates", s.handleTemplate)
	mux.HandleFunc("POST /api/requests", s.handlePrepare)
	mux.HandleFunc("POST /api/requests/{id}/accept", s.handleAccept)
	mux.HandleFunc("POST /api/requests/{id}/reject", s.handleReject)
	mux.HandleFunc("POST /api/certificates/{id}/revoke", s.handleRevoke)
	mux.HandleFunc("POST /api/recovery/{intentID}", s.handleRecovery)
	mux.HandleFunc("POST /api/verify", s.handleVerify)
	mux.HandleFunc("GET /api/certificates/{id}/der", s.handleDER)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/export", s.handleExport)
	mux.HandleFunc("POST /api/import", s.handleImport)
	mux.Handle("GET /", http.FileServer(http.Dir(s.webRoot)))
	return logRequests(mux)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.service.State())
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	var input model.Policy
	if err := decode(r, &input); err != nil {
		writeError(w, err)
		return
	}
	policy, err := s.service.UpdatePolicy(input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	var input model.SubjectRequest
	if err := decode(r, &input); err != nil {
		writeError(w, err)
		return
	}
	cert, err := s.service.EnrollRoot(input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, cert)
}

func (s *Server) handleTemplate(w http.ResponseWriter, r *http.Request) {
	var input model.SubjectRequest
	if err := decode(r, &input); err != nil {
		writeError(w, err)
		return
	}
	tpl, err := s.service.RegisterTemplate(input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, tpl)
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IdempotencyKey string               `json:"idempotency_key"`
		Input          model.SubjectRequest `json:"input"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	candidate, err := s.service.PrepareCandidate(req.Input, req.IdempotencyKey)
	status := http.StatusCreated
	if err != nil {
		writeError(w, err)
		return
	}
	_ = status
	writeJSON(w, http.StatusOK, candidate)
}

func (s *Server) handleAccept(w http.ResponseWriter, r *http.Request) {
	req, err := s.service.AcceptRequest(r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decode(r, &body)
	req, err := s.service.RejectRequest(r.PathValue("id"), body.Reason)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decode(r, &body)
	cert, err := s.service.RevokeCertificate(r.PathValue("id"), body.Reason)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (s *Server) handleRecovery(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, err)
		return
	}
	if err := s.service.ResolveRecovery(r.PathValue("intentID"), body.Action); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.service.State())
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CertID   string `json:"cert_id"`
		VerifyAt string `json:"verify_at"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, err)
		return
	}
	report, err := s.service.VerifyCertificate(body.CertID, body.VerifyAt)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleDER(w http.ResponseWriter, r *http.Request) {
	cert, ok := s.service.State().Certificates[r.PathValue("id")]
	if !ok {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(cert.ID)+".cer"))
	_, _ = w.Write(cert.DER)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.service.Store().Events()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=localpki-export.zip")
	if err := s.service.Store().Export(w); err != nil {
		writeError(w, err)
	}
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, err)
		return
	}
	file, _, err := r.FormFile("bundle")
	if err != nil {
		writeError(w, err)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 32<<20))
	if err != nil {
		writeError(w, err)
		return
	}
	reader := bytes.NewReader(data)
	if err := s.service.Store().Import(reader, int64(len(data))); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.service.State())
}

func decode(r *http.Request, target any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return &HTTPError{Status: http.StatusBadRequest, Message: err.Error()}
	}
	if dec.More() {
		return &HTTPError{Status: http.StatusBadRequest, Message: "unexpected extra JSON"}
	}
	return nil
}

type HTTPError struct {
	Status  int
	Message string
}

func (e *HTTPError) Error() string { return e.Message }

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var he *HTTPError
	if errors.As(err, &he) {
		status = he.Status
	}
	var failure pki.Failure
	if errors.As(err, &failure) {
		status = http.StatusUnprocessableEntity
		writeJSON(w, status, map[string]any{"error": err.Error(), "checks": failure.Steps})
		return
	}
	if errors.Is(err, store.ErrConflict) {
		status = http.StatusConflict
	}
	if errors.Is(err, store.ErrNotFound) {
		status = http.StatusNotFound
	}
	if errors.Is(err, store.ErrCorrupt) {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]any{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
