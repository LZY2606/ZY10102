package pki

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"localpki/internal/model"
	"localpki/internal/store"
)

func (s *Service) AcceptRequest(requestID string) (model.Request, error) {
	s.mu.Lock()
	state := s.store.Snapshot()
	req, ok := state.Requests[requestID]
	s.mu.Unlock()
	if !ok {
		return model.Request{}, fmt.Errorf("%w: request %s", store.ErrNotFound, requestID)
	}
	if req.Status != "pending" {
		return req, nil
	}
	intent := model.Intent{ID: "intent-" + req.ID, Operation: "accept-request", RequestID: req.ID}
	raw, _ := json.Marshal(req)
	intent.PayloadHash, _ = store.CanonicalJSON(json.RawMessage(raw))
	if err := s.store.WriteIntent(intent); err != nil {
		return model.Request{}, err
	}
	return s.finishAccept(req.ID, intent.ID)
}

func (s *Service) finishAccept(requestID, intentID string) (model.Request, error) {
	_, err := s.store.Commit("request.accepted", "accept-request", store.RequestAcceptedPayload{
		RequestID: requestID, At: time.Now().UTC().Format(time.RFC3339Nano),
	}, intentID, func(st *model.State, raw any) error {
		p := raw.(store.RequestAcceptedPayload)
		r, ok := st.Requests[p.RequestID]
		if !ok {
			return fmt.Errorf("%w: request %s", store.ErrNotFound, p.RequestID)
		}
		r.Status = "accepted"
		r.DecidedAt = p.At
		if r.CertID == "" && len(r.CandidateCertIDs) > 0 {
			r.CertID = r.CandidateCertIDs[0]
		}
		st.Requests[r.ID] = r
		for _, id := range r.CandidateCertIDs {
			c := st.Certificates[id]
			c.Status = "accepted"
			st.Certificates[id] = c
		}
		return nil
	})
	if err != nil {
		return model.Request{}, err
	}
	return s.store.Snapshot().Requests[requestID], nil
}

func (s *Service) RejectRequest(requestID, reason string) (model.Request, error) {
	s.mu.Lock()
	state := s.store.Snapshot()
	req, ok := state.Requests[requestID]
	s.mu.Unlock()
	if !ok {
		return model.Request{}, fmt.Errorf("%w: request %s", store.ErrNotFound, requestID)
	}
	if req.Status == "rejected" {
		return req, nil
	}
	if req.Status != "pending" {
		return req, nil
	}
	intent := model.Intent{ID: "intent-" + req.ID, Operation: "reject-request", RequestID: req.ID}
	if err := s.store.WriteIntent(intent); err != nil {
		return model.Request{}, err
	}
	_, err := s.store.Commit("request.rejected", "reject-request", store.RequestRejectedPayload{
		RequestID: requestID, Reason: reason, At: time.Now().UTC().Format(time.RFC3339Nano),
	}, intent.ID, func(st *model.State, raw any) error {
		p := raw.(store.RequestRejectedPayload)
		r, ok := st.Requests[p.RequestID]
		if !ok {
			return fmt.Errorf("%w: request %s", store.ErrNotFound, p.RequestID)
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
		return nil
	})
	if err != nil {
		return model.Request{}, err
	}
	state = s.store.Snapshot()
	if state.Requests[requestID].Input.Purpose == "leaf" {
		_ = s.keys.Delete("leaf-" + requestID + ".pem")
	}
	return state.Requests[requestID], nil
}

func (s *Service) RevokeCertificate(certID, reason string) (model.Certificate, error) {
	s.mu.Lock()
	state := s.store.Snapshot()
	c, ok := state.Certificates[certID]
	s.mu.Unlock()
	if !ok {
		return model.Certificate{}, fmt.Errorf("%w: certificate %s", store.ErrNotFound, certID)
	}
	if c.Status == "revoked" {
		return c, nil
	}
	if c.Status != "accepted" {
		return model.Certificate{}, fmt.Errorf("%w: only accepted certificates can be revoked", store.ErrConflict)
	}
	intent := model.Intent{ID: "intent-revoke-" + c.ID, Operation: "revoke-certificate", CertID: c.ID}
	if err := s.store.WriteIntent(intent); err != nil {
		return model.Certificate{}, err
	}
	_, err := s.store.Commit("certificate.revoked", "revoke-certificate", store.CertificateRevokedPayload{
		CertID: certID, Reason: reason, At: time.Now().UTC().Format(time.RFC3339Nano),
	}, intent.ID, func(st *model.State, raw any) error {
		p := raw.(store.CertificateRevokedPayload)
		c, ok := st.Certificates[p.CertID]
		if !ok {
			return fmt.Errorf("%w: certificate %s", store.ErrNotFound, p.CertID)
		}
		c.Status = "revoked"
		c.RevokedAt = p.At
		c.RevocationReason = p.Reason
		st.Certificates[c.ID] = c
		for _, r := range st.Requests {
			if r.CertID == c.ID || contains(r.CandidateCertIDs, c.ID) {
				r.Status = "revoked"
				st.Requests[r.ID] = r
			}
		}
		return nil
	})
	if err != nil {
		return model.Certificate{}, err
	}
	return s.store.Snapshot().Certificates[certID], nil
}

func (s *Service) ResolveRecovery(intentID, action string) error {
	state := s.store.Snapshot()
	intent, ok := state.Intents[intentID]
	if !ok {
		return fmt.Errorf("%w: intent %s", store.ErrNotFound, intentID)
	}
	if s.intentAlreadyApplied(intent) {
		return s.store.RemoveIntentOnly(intentID)
	}
	switch action {
	case "commit":
		switch intent.Operation {
		case "accept-request":
			_, err := s.finishAccept(intent.RequestID, intent.ID)
			return err
		case "reject-request":
			_, err := s.RejectRequest(intent.RequestID, "resolved after interrupted write")
			return err
		case "revoke-certificate":
			_, err := s.RevokeCertificate(intent.CertID, "resolved after interrupted write")
			return err
		default:
			return s.abortIntent(intent, "unsupported interrupted operation")
		}
	case "abort":
		return s.abortIntent(intent, "operator aborted interrupted write")
	default:
		return errors.New("action must be commit or abort")
	}
}

func (s *Service) abortIntent(intent model.Intent, reason string) error {
	_, err := s.store.Commit("intent.aborted", "abort-intent", store.IntentAbortedPayload{
		IntentID: intent.ID, Operation: intent.Operation, Reason: reason, At: time.Now().UTC().Format(time.RFC3339Nano),
	}, intent.ID, func(st *model.State, raw any) error {
		p := raw.(store.IntentAbortedPayload)
		delete(st.Intents, p.IntentID)
		return nil
	})
	return err
}

func (s *Service) intentAlreadyApplied(intent model.Intent) bool {
	state := s.store.Snapshot()
	switch intent.Operation {
	case "accept-request":
		return state.Requests[intent.RequestID].Status == "accepted"
	case "reject-request":
		return state.Requests[intent.RequestID].Status == "rejected"
	case "revoke-certificate":
		return state.Certificates[intent.CertID].Status == "revoked"
	}
	return false
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
