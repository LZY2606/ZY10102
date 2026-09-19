package store

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"localpki/internal/model"
)

type PolicyUpdatedPayload struct{ Policy model.Policy }
type RootEnrolledPayload struct{ Certificate model.Certificate }
type TemplateRegisteredPayload struct{ Template model.IntermediateTemplate }

type CandidatePreparedPayload struct {
	Request      model.Request       `json:"request"`
	Certificates []model.Certificate `json:"certificates"`
}

type RequestAcceptedPayload struct {
	RequestID string `json:"request_id"`
	At        string `json:"at"`
}

type RequestRejectedPayload struct {
	RequestID string `json:"request_id"`
	Reason    string `json:"reason"`
	At        string `json:"at"`
}

type CertificateRevokedPayload struct {
	CertID string `json:"cert_id"`
	Reason string `json:"reason"`
	At     string `json:"at"`
}

type IntentAbortedPayload struct {
	IntentID  string `json:"intent_id"`
	Operation string `json:"operation"`
	Reason    string `json:"reason"`
	At        string `json:"at"`
}

func ApplyEvent(st *model.State, ev model.Event) error {
	ensureMaps(st)
	switch ev.Type {
	case "policy.updated":
		var p PolicyUpdatedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		st.Policy = p.Policy
	case "root.enrolled":
		var p RootEnrolledPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		c := p.Certificate
		if st.Serials[c.Serial] {
			return fmt.Errorf("%w: serial %s reused", ErrCorrupt, c.Serial)
		}
		st.Serials[c.Serial] = true
		st.Certificates[c.ID] = c
		if n := serialInt(c.Serial) + 1; n > st.NextSerial {
			st.NextSerial = n
		}
	case "template.registered":
		var p TemplateRegisteredPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		st.Templates[p.Template.ID] = p.Template
	case "candidate.prepared":
		var p CandidatePreparedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if _, exists := st.Requests[p.Request.ID]; exists {
			return fmt.Errorf("%w: duplicate request %s", ErrCorrupt, p.Request.ID)
		}
		for _, c := range p.Certificates {
			if st.Serials[c.Serial] {
				return fmt.Errorf("%w: serial %s reused", ErrCorrupt, c.Serial)
			}
		}
		for _, c := range p.Certificates {
			st.Serials[c.Serial] = true
			st.Certificates[c.ID] = c
			if n := serialInt(c.Serial) + 1; n > st.NextSerial {
				st.NextSerial = n
			}
		}
		st.Requests[p.Request.ID] = p.Request
	case "request.accepted":
		var p RequestAcceptedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		r, ok := st.Requests[p.RequestID]
		if !ok {
			return fmt.Errorf("%w: request %s", ErrCorrupt, p.RequestID)
		}
		r.Status = "accepted"
		r.DecidedAt = p.At
		st.Requests[r.ID] = r
		for _, id := range r.CandidateCertIDs {
			c := st.Certificates[id]
			c.Status = "accepted"
			st.Certificates[id] = c
		}
		if r.CertID == "" && len(r.CandidateCertIDs) > 0 {
			r.CertID = r.CandidateCertIDs[0]
			st.Requests[r.ID] = r
		}
	case "request.rejected":
		var p RequestRejectedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		r, ok := st.Requests[p.RequestID]
		if !ok {
			return fmt.Errorf("%w: request %s", ErrCorrupt, p.RequestID)
		}
		r.Status = "rejected"
		r.DecidedAt = p.At
		r.RejectionReason = p.Reason
		st.Requests[r.ID] = r
		for _, id := range r.CandidateCertIDs {
			c := st.Certificates[id]
			c.Status = "rejected"
			st.Certificates[id] = c
		}
	case "certificate.revoked":
		var p CertificateRevokedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		c, ok := st.Certificates[p.CertID]
		if !ok {
			return fmt.Errorf("%w: certificate %s", ErrCorrupt, p.CertID)
		}
		c.Status = "revoked"
		c.RevokedAt = p.At
		c.RevocationReason = p.Reason
		st.Certificates[c.ID] = c
		for _, r := range st.Requests {
			if r.CertID == c.ID || containsID(r.CandidateCertIDs, c.ID) {
				r.Status = "revoked"
				st.Requests[r.ID] = r
			}
		}
	case "intent.aborted":
		var p IntentAbortedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		delete(st.Intents, p.IntentID)
	default:
		return fmt.Errorf("%w: unknown event type %s", ErrCorrupt, ev.Type)
	}
	if ev.Seq >= st.EventSeq {
		st.EventSeq = ev.Seq + 1
	}
	return nil
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func (s *Store) Events() ([]model.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readEventsLocked()
}

func (s *Store) readEventsLocked() ([]model.Event, error) {
	files, err := filepath.Glob(filepath.Join(s.root, "events", "[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	out := make([]model.Event, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var ev model.Event
		if err := json.Unmarshal(data, &ev); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func (s *Store) Export(w io.Writer) error {
	s.mu.Lock()
	events, err := s.readEventsLocked()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	policy := s.state.Policy
	s.mu.Unlock()

	zw := zip.NewWriter(w)
	manifest := map[string]any{
		"format":                "localpki-export-v1",
		"created_at":            time.Now().UTC().Format(time.RFC3339Nano),
		"event_count":           len(events),
		"private_keys_included": false,
	}
	if err := writeZipJSON(zw, "manifest.json", manifest); err != nil {
		return err
	}
	if err := writeZipJSON(zw, "policy-snapshot.json", PolicySnapshot{At: time.Now().UTC().Format(time.RFC3339Nano), Policy: policy, Root: chainRoot(events)}); err != nil {
		return err
	}
	for _, ev := range events {
		name := fmt.Sprintf("events/%012d.json", ev.Seq)
		if err := writeZipJSON(zw, name, ev); err != nil {
			return err
		}
	}
	materials := map[string]string{}
	for _, ev := range events {
		for _, c := range eventPublicCerts(ev) {
			materials[fmt.Sprintf("certificates/%s.der", c.ID)] = hex.EncodeToString(c.DER)
		}
	}
	keys := make([]string, 0, len(materials))
	for k := range materials {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := writeZipString(zw, k, materials[k]); err != nil {
			return err
		}
	}
	proofRoot := chainRoot(events)
	proof := map[string]any{"event_count": len(events), "root": proofRoot, "algorithm": "sha256(canonical event headers and payload)"}
	if err := writeZipJSON(zw, "proof.json", proof); err != nil {
		return err
	}
	return zw.Close()
}

func (s *Store) Import(r io.ReaderAt, size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.state.Certificates) != 0 || len(s.state.Requests) != 0 || s.state.NextSerial != 1 {
		return fmt.Errorf("%w: import target is not empty", ErrConflict)
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return err
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") {
			return fmt.Errorf("unsafe zip member %q", f.Name)
		}
		files[f.Name] = f
	}
	names := make([]string, 0, len(files))
	for name := range files {
		if strings.HasPrefix(name, "events/") && strings.HasSuffix(name, ".json") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var prev string
	seen := map[string]bool{}
	loaded := make([]model.Event, 0, len(names))
	for i, name := range names {
		ev, err := readZipEvent(files[name])
		if err != nil {
			return err
		}
		if ev.Seq != int64(i+1) {
			return fmt.Errorf("%w: reordered or missing event at %s", ErrCorrupt, name)
		}
		if seen[ev.ID] {
			return fmt.Errorf("%w: duplicate event %s", ErrCorrupt, ev.ID)
		}
		seen[ev.ID] = true
		if HashEvent(ev) != ev.Hash || ev.PrevHash != prev {
			return fmt.Errorf("%w: invalid proof at event %d", ErrCorrupt, ev.Seq)
		}
		probe := emptyState()
		if err := ApplyEvent(probe, ev); err != nil {
			return err
		}
		loaded = append(loaded, ev)
		prev = ev.ID + ":" + ev.Hash
	}
	for _, ev := range loaded {
		if err := s.writeEvent(ev); err != nil {
			return err
		}
	}
	return s.replay()
}

func writeZipJSON(zw *zip.Writer, name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeZipString(zw, name, string(data)+"\n")
}

func writeZipString(zw *zip.Writer, name, value string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, value)
	return err
}

func readZipEvent(f *zip.File) (model.Event, error) {
	rc, err := f.Open()
	if err != nil {
		return model.Event{}, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, 32<<20))
	if err != nil {
		return model.Event{}, err
	}
	var ev model.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		return ev, err
	}
	return ev, nil
}

func eventPublicCerts(ev model.Event) []model.Certificate {
	switch ev.Type {
	case "root.enrolled":
		var p RootEnrolledPayload
		if json.Unmarshal(ev.Payload, &p) == nil {
			return []model.Certificate{p.Certificate}
		}
	case "candidate.prepared":
		var p CandidatePreparedPayload
		if json.Unmarshal(ev.Payload, &p) == nil {
			return p.Certificates
		}
	}
	return nil
}

func chainRoot(events []model.Event) string {
	if len(events) == 0 {
		return ""
	}
	return events[len(events)-1].ID + ":" + events[len(events)-1].Hash
}

func PublicSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ExportBytes(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func serialInt(value string) int64 {
	var n int64
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int64(r-'0')
	}
	return n
}
