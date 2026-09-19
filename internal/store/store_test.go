package store_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"localpki/internal/model"
	"localpki/internal/store"
)

func commitTestEvent(t *testing.T, st *store.Store, intentID string) (model.Event, error) {
	t.Helper()
	cert := model.Certificate{ID: "cert-x", Kind: "root", Name: "x", Serial: "1", DER: []byte{1, 2, 3}, Status: "accepted"}
	return st.Commit("root.enrolled", "enroll-root", store.RootEnrolledPayload{Certificate: cert}, intentID, func(st *model.State, raw any) error {
		c := raw.(store.RootEnrolledPayload).Certificate
		st.Certificates[c.ID] = c
		st.Serials[c.Serial] = true
		st.NextSerial = 2
		return nil
	})
}

func TestBeforeCommitFailureLeavesNoPartialState(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetHooks(store.Hooks{BeforeCommit: func(model.Event) error { return errors.New("simulated disk failure") }})
	if _, err := commitTestEvent(t, st, ""); err == nil {
		t.Fatal("expected commit failure")
	}
	st.SetHooks(store.Hooks{})
	snap := st.Snapshot()
	if len(snap.Certificates) != 0 || len(snap.Serials) != 0 {
		t.Fatalf("partial mutation leaked: %+v", snap)
	}
	reopened, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	snap = reopened.Snapshot()
	if len(snap.Certificates) != 0 || snap.EventSeq != 1 {
		t.Fatalf("partial event leaked: %+v", snap)
	}
}

func TestAfterCommitFailureRemainsDurableAfterRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetHooks(store.Hooks{AfterCommit: func(model.Event) error { return errors.New("simulated post-commit failure") }})
	if _, err := commitTestEvent(t, st, ""); err == nil {
		t.Fatal("expected post-commit error")
	}
	st.SetHooks(store.Hooks{})
	reopened, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	snap := reopened.Snapshot()
	if len(snap.Certificates) != 1 || snap.EventSeq != 2 {
		t.Fatalf("durable event was lost: %+v", snap)
	}
}

func TestInterruptedIntentAppearsAsRecovering(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	intent := model.Intent{ID: "intent-1", Operation: "accept-request", RequestID: "req-1"}
	if err := st.WriteIntent(intent); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	snap := reopened.Snapshot()
	if len(snap.Intents) != 1 || len(snap.Recovery) != 1 || snap.Recovery[0] != "intent-1" {
		t.Fatalf("expected recovering intent, got %+v", snap.Intents)
	}
}

func TestExportImportDetectsTruncationReorderDuplicate(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commitTestEvent(t, st, ""); err != nil {
		t.Fatal(err)
	}
	cert2 := model.Certificate{ID: "cert-y", Kind: "root", Name: "y", Serial: "2", DER: []byte{4}, Status: "accepted"}
	_, err = st.Commit("root.enrolled", "enroll-root", store.RootEnrolledPayload{Certificate: cert2}, "", func(st *model.State, raw any) error {
		c := raw.(store.RootEnrolledPayload).Certificate
		st.Certificates[c.ID] = c
		st.Serials[c.Serial] = true
		st.NextSerial = 3
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	if err := st.Export(&bundle); err != nil {
		t.Fatal(err)
	}

	truncated := bytes.Clone(bundle.Bytes())
	truncated = truncated[:len(truncated)-20]
	if err := importIntoEmpty(t, dir, truncated); err == nil {
		t.Fatal("truncated zip accepted")
	}

	reordered := mutateZip(t, bundle.Bytes(), func(files map[string][]byte) {
		one := files["events/000000000001.json"]
		files["events/000000000001.json"] = files["events/000000000002.json"]
		files["events/000000000002.json"] = one
	})
	if err := importIntoEmpty(t, dir, reordered); err == nil || !strings.Contains(err.Error(), "reordered") {
		t.Fatalf("expected reorder error, got %v", err)
	}

	duplicate := mutateZip(t, bundle.Bytes(), func(files map[string][]byte) {
		files["events/000000000002.json"] = files["events/000000000001.json"]
	})
	if err := importIntoEmpty(t, dir, duplicate); err == nil {
		t.Fatal("duplicate event accepted")
	}
}

func importIntoEmpty(t *testing.T, dir string, data []byte) error {
	t.Helper()
	target := filepath.Join(dir, "imported-"+filepath.Base(t.TempDir()))
	st, err := store.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	return st.Import(bytes.NewReader(data), int64(len(data)))
}

func mutateZip(t *testing.T, data []byte, mutate func(map[string][]byte)) []byte {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = b
	}
	mutate(files)
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func sortStrings(values []string) {
	for i := range values {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}

func TestImportRejectsNonEmptyTarget(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commitTestEvent(t, st, ""); err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	if err := st.Export(&bundle); err != nil {
		t.Fatal(err)
	}
	if err := st.Import(bytes.NewReader(bundle.Bytes()), int64(bundle.Len())); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "db", "events", "000000000003.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("import into non-empty target left a partial event")
	}
}
