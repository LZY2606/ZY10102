package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"localpki/internal/model"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrCorrupt  = errors.New("event log corrupt")
)

type Hooks struct {
	BeforeCommit func(event model.Event) error
	AfterCommit  func(event model.Event) error
}

type Store struct {
	root  string
	mu    sync.Mutex
	state *model.State
	hooks Hooks
}

type PolicySnapshot struct {
	At     string       `json:"at"`
	Policy model.Policy `json:"policy"`
	Root   string       `json:"event_log_hash_chain_root"`
}

type Proof struct {
	Events []model.Event  `json:"events"`
	Policy PolicySnapshot `json:"policy_snapshot"`
}

func Open(root string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(root, "events"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o700); err != nil {
		return nil, err
	}
	st := &Store{root: root, state: emptyState()}
	if err := st.loadSnapshot(); err != nil && !errors.Is(err, os.ErrNotExist) {
		st.state = emptyState()
	}
	if err := st.replay(); err != nil {
		return nil, err
	}
	if err := st.loadIntents(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) SetHooks(hooks Hooks) { s.hooks = hooks }

func emptyState() *model.State {
	policy := model.DefaultPolicy()
	return &model.State{
		EventSeq:     1,
		NextSerial:   1,
		Policy:       policy,
		Certificates: map[string]model.Certificate{},
		Requests:     map[string]model.Request{},
		Templates:    map[string]model.IntermediateTemplate{},
		Serials:      map[string]bool{},
		Intents:      map[string]model.Intent{},
	}
}

func (s *Store) Snapshot() model.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state)
}

func (s *Store) Policy() model.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Policy
}

func (s *Store) AllocateSerial() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.NextSerial
}

func (s *Store) Commit(eventType, operation string, payload any, intentID string, mutate func(*model.State, any) error) (model.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	encoded, err := json.Marshal(payload)
	if err != nil {
		return model.Event{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ev := model.Event{
		Seq:      s.state.EventSeq,
		ID:       fmt.Sprintf("evt-%012d", s.state.EventSeq),
		Type:     eventType,
		At:       now,
		PrevHash: s.lastHash(),
		Payload:  encoded,
	}
	ev.Hash = HashEvent(ev)

	proposed := cloneState(s.state)
	if mutate != nil {
		if err := mutate(&proposed, payload); err != nil {
			return model.Event{}, err
		}
	}
	proposed.EventSeq = ev.Seq + 1
	if s.hooks.BeforeCommit != nil {
		if err := s.hooks.BeforeCommit(ev); err != nil {
			return model.Event{}, err
		}
	}
	if err := s.writeEvent(ev); err != nil {
		return model.Event{}, err
	}
	s.state = &proposed
	if err := s.writeSnapshot(); err != nil {
		return ev, fmt.Errorf("event committed but snapshot refresh failed: %w", err)
	}
	if intentID != "" {
		_ = os.Remove(s.intentPath(intentID))
		delete(s.state.Intents, intentID)
		if err := s.writeSnapshot(); err != nil {
			return ev, fmt.Errorf("event committed but intent cleanup failed: %w", err)
		}
	}
	if s.hooks.AfterCommit != nil {
		if err := s.hooks.AfterCommit(ev); err != nil {
			return ev, fmt.Errorf("event committed but post-commit verification failed: %w", err)
		}
	}
	_ = operation
	return ev, nil
}

func (s *Store) WriteIntent(intent model.Intent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	intent.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if intent.ID == "" {
		intent.ID = fmt.Sprintf("intent-%012d", s.state.EventSeq)
	}
	if err := atomicJSON(s.intentPath(intent.ID), intent); err != nil {
		return err
	}
	s.state.Intents[intent.ID] = intent
	s.state.Recovery = nil
	return s.writeSnapshot()
}

func (s *Store) RemoveIntentOnly(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Intents[id]; !ok {
		return ErrNotFound
	}
	if err := os.Remove(s.intentPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(s.state.Intents, id)
	return s.writeSnapshot()
}

func (s *Store) MarkRecovery(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := append([]string(nil), ids...)
	sort.Strings(cp)
	s.state.Recovery = cp
	return s.writeSnapshot()
}

func (s *Store) lastHash() string {
	if s.state.EventSeq == 1 {
		return ""
	}
	data, err := os.ReadFile(s.eventPath(s.state.EventSeq - 1))
	if err != nil {
		panic(err)
	}
	var ev model.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		panic(err)
	}
	return ev.ID + ":" + ev.Hash
}

func (s *Store) writeEvent(ev model.Event) error {
	path := s.eventPath(ev.Seq)
	tmp := filepath.Join(s.root, "tmp", fmt.Sprintf("%012d-%d.tmp", ev.Seq, time.Now().UnixNano()))
	if err := atomicJSON(tmp, ev); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) eventPath(seq int64) string {
	return filepath.Join(s.root, "events", fmt.Sprintf("%012d.json", seq))
}

func (s *Store) intentPath(id string) string {
	return filepath.Join(s.root, "events", id+".intent.json")
}

func (s *Store) loadSnapshot() error {
	data, err := os.ReadFile(filepath.Join(s.root, "state.snapshot.json"))
	if err != nil {
		return err
	}
	var st model.State
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	ensureMaps(&st)
	s.state = &st
	return nil
}

func (s *Store) writeSnapshot() error {
	return atomicJSON(filepath.Join(s.root, "state.snapshot.json"), s.state)
}

func (s *Store) replay() error {
	files, err := filepath.Glob(filepath.Join(s.root, "events", "[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].json"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	s.state = emptyState()
	var prev string
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		var ev model.Event
		if err := json.Unmarshal(data, &ev); err != nil {
			return fmt.Errorf("%w: %v: %v", ErrCorrupt, file, err)
		}
		if ev.Seq != s.state.EventSeq {
			return fmt.Errorf("%w: expected seq %d got %d", ErrCorrupt, s.state.EventSeq, ev.Seq)
		}
		want := HashEvent(ev)
		if want != ev.Hash || ev.PrevHash != prev {
			return fmt.Errorf("%w: event %d hash chain mismatch", ErrCorrupt, ev.Seq)
		}
		if err := ApplyEvent(s.state, ev); err != nil {
			return err
		}
		prev = ev.ID + ":" + ev.Hash
	}
	return s.writeSnapshot()
}

func (s *Store) loadIntents() error {
	files, err := filepath.Glob(filepath.Join(s.root, "events", "*.intent.json"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	recovery := []string{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		var intent model.Intent
		if err := json.Unmarshal(data, &intent); err != nil {
			return err
		}
		if intent.ID == "" {
			intent.ID = strings.TrimSuffix(filepath.Base(file), ".intent.json")
		}
		if s.staleIntent(intent) {
			s.state.Intents[intent.ID] = intent
			recovery = append(recovery, intent.ID)
		} else {
			_ = os.Remove(file)
		}
	}
	sort.Strings(recovery)
	s.state.Recovery = recovery
	return s.writeSnapshot()
}

func (s *Store) staleIntent(intent model.Intent) bool {
	return intent.ID != ""
}

func ensureMaps(st *model.State) {
	if st.Certificates == nil {
		st.Certificates = map[string]model.Certificate{}
	}
	if st.Requests == nil {
		st.Requests = map[string]model.Request{}
	}
	if st.Templates == nil {
		st.Templates = map[string]model.IntermediateTemplate{}
	}
	if st.Serials == nil {
		st.Serials = map[string]bool{}
	}
	if st.Intents == nil {
		st.Intents = map[string]model.Intent{}
	}
}

func atomicJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return err
	}
	if f, err := os.Open(tmp); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	return os.Rename(tmp, path)
}

func cloneState(in *model.State) model.State {
	data, _ := json.Marshal(in)
	var out model.State
	_ = json.Unmarshal(data, &out)
	ensureMaps(&out)
	return out
}

func HashEvent(ev model.Event) string {
	payloadBytes := ev.Payload
	if len(bytes.TrimSpace(payloadBytes)) > 0 {
		var canonical any
		if err := json.Unmarshal(payloadBytes, &canonical); err == nil {
			if compact, err := json.Marshal(canonical); err == nil {
				payloadBytes = compact
			}
		}
	}
	payloadHash := sha256.Sum256(payloadBytes)
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n%s\n%s\n%s", ev.Seq, ev.ID, ev.Type, ev.At, ev.PrevHash, hex.EncodeToString(payloadHash[:]))
	return hex.EncodeToString(h.Sum(nil))
}

func CanonicalJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return "", err
	}
	sum := sha256.Sum256(compact.Bytes())
	return hex.EncodeToString(sum[:]), nil
}
