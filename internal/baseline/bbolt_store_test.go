package baseline

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alibaba/CredAgent/api/gen/enclave"
)

// ─── test helpers ─────────────────────────────────────────────────────────────

// newBLT creates a fully-populated CredentialBaseline for BoltDB tests.
func newBLT(sha, path, content, strategy string) *CredentialBaseline {
	return NewCredentialBaseline(
		sha,
		FileMetadata{TargetPath: path},
		&AccessRule{VerificationStrategy: strategy},
		[]byte(content),
	)
}

// newBLTWithPerms creates a CredentialBaseline with file permissions.
func newBLTWithPerms(sha, path, content, strategy string, uid, gid, mode uint32) *CredentialBaseline {
	return NewCredentialBaseline(
		sha,
		FileMetadata{TargetPath: path, Permissions: &FilePerms{UID: uid, GID: gid, Mode: mode}},
		&AccessRule{VerificationStrategy: strategy},
		[]byte(content),
	)
}

// newBLTWithBinaries creates a CredentialBaseline with allowed binaries.
func newBLTWithBinaries(sha, path, content, strategy string, bins, sha256s []string) *CredentialBaseline {
	return NewCredentialBaseline(
		sha,
		FileMetadata{TargetPath: path},
		&AccessRule{
			VerificationStrategy:  strategy,
			AllowedPrograms:       bins,
			AllowedProgramsSha256: sha256s,
			Measure:               len(sha256s) > 0,
		},
		[]byte(content),
	)
}

// newLegacyBaseline creates an *enclave.CredentialBaseline for PersistentBaselineStore tests.
func newLegacyBaseline(sha, path, content, strategy string) *enclave.CredentialBaseline {
	return &enclave.CredentialBaseline{
		Sha:                  sha,
		TargetPath:           path,
		EncryptedData:        []byte(content),
		VerificationStrategy: strategy,
	}
}

// bltContent returns the file content of a CredentialBaseline, failing the test on error.
func bltContent(t *testing.T, bl *CredentialBaseline) []byte {
	t.Helper()
	c, err := bl.FileContent()
	if err != nil {
		t.Fatalf("FileContent() error: %v", err)
	}
	return c
}

// bltRule returns the rule of a CredentialBaseline, failing on error.
func bltRule(t *testing.T, bl *CredentialBaseline) *AccessRule {
	t.Helper()
	r, err := bl.Rule()
	if err != nil {
		t.Fatalf("Rule() error: %v", err)
	}
	return r
}

// ─── BasicCRUD ────────────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_BasicCRUD(t *testing.T) {
	tempDir := t.TempDir()
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "baseline.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	bl := newBLTWithPerms("sha256-test-hash", "/tmp/test-file", "test secret data", "ONE_TIME_USE", 1000, 1000, 0644)
	if err := store.Save(bl); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if count := store.Count(); count != 1 {
		t.Errorf("Count: want 1, got %d", count)
	}

	// GetBySha
	r := store.GetBySha("sha256-test-hash")
	if r == nil {
		t.Fatal("GetBySha returned nil")
	}
	if r.Metadata().TargetPath != "/tmp/test-file" {
		t.Errorf("TargetPath: %s", r.Metadata().TargetPath)
	}

	// Get by path
	r = store.Get("/tmp/test-file")
	if r == nil {
		t.Fatal("Get returned nil")
	}
	if r.SHA() != "sha256-test-hash" {
		t.Errorf("SHA: %s", r.SHA())
	}

	// Delete
	if err := store.Delete("sha256-test-hash"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if count := store.Count(); count != 0 {
		t.Errorf("Count after delete: want 0, got %d", count)
	}
	if store.GetBySha("sha256-test-hash") != nil {
		t.Error("baseline should not exist after delete")
	}
}

// ─── Encryption persistence ───────────────────────────────────────────────────

func TestBoltDBBaselineStore_EncryptionPersistence(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "baseline.db")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	store, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	secrets := []string{
		"secret content 1 - this should be encrypted",
		"secret content 2 - this should also be encrypted",
		"secret content 3 - another encrypted entry",
	}
	for i, s := range secrets {
		if err := store.Save(newBLT(fmt.Sprintf("sha-%d", i), fmt.Sprintf("/tmp/f%d", i), s, "ONE_TIME_USE")); err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}

	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for i, s := range secrets {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("plaintext secret %d found in database file", i)
		}
	}
	t.Logf("Saved %d entries; secrets not visible in db file", len(secrets))
}

// ─── Read after persistence ───────────────────────────────────────────────────

func TestBoltDBBaselineStore_ReadAfterPersistence(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "baseline.db")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	originals := []struct {
		sha, path, content, strategy string
	}{
		{"sha-r1", "/tmp/read-test-1", "read test secret 1", "ONE_TIME_USE"},
		{"sha-r2", "/tmp/read-test-2", "read test secret 2", "SPEC_VERIFICATION"},
		{"sha-r3", "/tmp/read-test-3", "read test secret 3", "PID_BIND"},
	}

	orig, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("open orig: %v", err)
	}
	for _, o := range originals {
		if err := orig.Save(newBLT(o.sha, o.path, o.content, o.strategy)); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	orig.Close()

	reopened, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	if cnt := reopened.Count(); cnt != len(originals) {
		t.Errorf("Count: want %d, got %d", len(originals), cnt)
	}

	for _, o := range originals {
		r := reopened.GetBySha(o.sha)
		if r == nil {
			t.Fatalf("not found sha=%s", o.sha)
		}
		if r.Metadata().TargetPath != o.path {
			t.Errorf("TargetPath mismatch sha=%s", o.sha)
		}
		if r.SHA() != o.sha {
			t.Errorf("SHA mismatch sha=%s", o.sha)
		}
		if string(bltContent(t, r)) != o.content {
			t.Errorf("content mismatch sha=%s", o.sha)
		}
		if bltRule(t, r).VerificationStrategy != o.strategy {
			t.Errorf("strategy mismatch sha=%s", o.sha)
		}
	}
}

// ─── MultipleBaselines ────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_MultipleBaselines(t *testing.T) {
	tempDir := t.TempDir()
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "baseline.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	inputs := []struct{ sha, path, strategy string }{
		{"sha256-1", "/tmp/test-file-1", "ONE_TIME_USE"},
		{"sha256-2", "/tmp/test-file-2", "SPEC_VERIFICATION"},
		{"sha256-3", "/tmp/test-file-3", "PID_BIND"},
	}
	for _, inp := range inputs {
		if err := store.Save(newBLT(inp.sha, inp.path, "secret", inp.strategy)); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	if count := store.Count(); count != 3 {
		t.Errorf("Count: want 3, got %d", count)
	}
	if len(store.ListAll()) != 3 {
		t.Error("ListAll: want 3")
	}
	for _, inp := range inputs {
		r := store.GetBySha(inp.sha)
		if r == nil || r.Metadata().TargetPath != inp.path {
			t.Errorf("GetBySha failed for %s", inp.sha)
		}
	}
}

// ─── Persistence across close/reopen ─────────────────────────────────────────

func TestBoltDBBaselineStore_Persistence(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "baseline.db")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	s1, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("open s1: %v", err)
	}
	if err := s1.Save(newBLT("sha256-persist", "/tmp/persist-test", "persistent secret", "ONE_TIME_USE")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	s1.Close()

	s2, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("reopen s2: %v", err)
	}
	defer s2.Close()

	r := s2.GetBySha("sha256-persist")
	if r == nil {
		t.Fatal("GetBySha returned nil after reopen")
	}
	if r.Metadata().TargetPath != "/tmp/persist-test" {
		t.Errorf("TargetPath: %s", r.Metadata().TargetPath)
	}
	if string(bltContent(t, r)) != "persistent secret" {
		t.Error("content mismatch")
	}
}

// ─── Legacy JSON migration ────────────────────────────────────────────────────

func TestBoltDBBaselineStore_LegacyMigration(t *testing.T) {
	tempDir := t.TempDir()
	legacyPath := filepath.Join(tempDir, "baseline_legacy.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	legacyStore, err := NewPersistentBaselineStore(legacyPath, masterKey)
	if err != nil {
		t.Fatalf("legacy store: %v", err)
	}
	if err := legacyStore.Save(newLegacyBaseline("sha256-legacy", "/tmp/legacy-file", "legacy secret", "ONE_TIME_USE")); err != nil {
		t.Fatalf("legacy Save: %v", err)
	}

	store, err := NewBoltDBBaselineStore(legacyPath, masterKey, legacyPath)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer store.Close()

	r := store.GetBySha("sha256-legacy")
	if r == nil {
		t.Fatal("migrated baseline not found")
	}
	if r.Metadata().TargetPath != "/tmp/legacy-file" {
		t.Errorf("TargetPath: %s", r.Metadata().TargetPath)
	}
	if string(bltContent(t, r)) != "legacy secret" {
		t.Error("content mismatch after migration")
	}

	// Verify persistence: close and reopen.
	store.Close()
	s2, err := NewBoltDBBaselineStore(legacyPath, masterKey, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.GetBySha("sha256-legacy") == nil {
		t.Error("baseline missing after reopen")
	}
}

func TestBoltDBBaselineStore_NoLegacyMigration(t *testing.T) {
	tempDir := t.TempDir()
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	s1, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "baseline.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s1.Close()
	if count := s1.Count(); count != 0 {
		t.Errorf("empty store count: %d", count)
	}

	// Non-existent legacy path should not cause an error.
	s2, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "baseline2.db"), masterKey, "/nonexistent/path")
	if err != nil {
		t.Fatalf("open with missing legacy: %v", err)
	}
	defer s2.Close()
	if count := s2.Count(); count != 0 {
		t.Errorf("store count should be 0, got %d", count)
	}
}

// ─── Update ───────────────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_Update(t *testing.T) {
	tempDir := t.TempDir()
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "baseline.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.Save(newBLT("sha256-update", "/tmp/update-test", "original data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := store.Set("/tmp/update-test", newBLT("sha256-update", "/tmp/update-test", "updated data", "SPEC_VERIFICATION")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	r := store.GetBySha("sha256-update")
	if r == nil {
		t.Fatal("not found after update")
	}
	if bltRule(t, r).VerificationStrategy != "SPEC_VERIFICATION" {
		t.Errorf("strategy: %s", bltRule(t, r).VerificationStrategy)
	}
	if string(bltContent(t, r)) != "updated data" {
		t.Error("content mismatch")
	}
}

// ─── NeedsMigration / IsMigrated ─────────────────────────────────────────────

func TestBoltDBBaselineStore_NeedsMigration(t *testing.T) {
	tempDir := t.TempDir()
	legacyPath := filepath.Join(tempDir, "baseline.enc")

	if NeedsMigration(legacyPath) {
		t.Error("NeedsMigration should be false for non-existent file")
	}

	f, _ := os.Create(legacyPath)
	f.Close()

	if !NeedsMigration(legacyPath) {
		t.Error("NeedsMigration should be true for non-BoltDB file")
	}
	if IsMigrated(legacyPath) {
		t.Error("IsMigrated should be false for non-BoltDB file")
	}

	boltPath := filepath.Join(tempDir, "bolt.db")
	masterKey, _ := generateRandomMasterKey()
	store, err := NewBoltDBBaselineStore(boltPath, masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	store.Close()

	if !IsMigrated(boltPath) {
		t.Error("IsMigrated should be true for BoltDB file")
	}
	if NeedsMigration(boltPath) {
		t.Error("NeedsMigration should be false for BoltDB file")
	}
}

func TestBoltDBBaselineStore_IsMigrated(t *testing.T) {
	tempDir := t.TempDir()
	masterKey, _ := generateRandomMasterKey()

	// Real BoltDB file.
	boltPath := filepath.Join(tempDir, "real_bolt.db")
	store, err := NewBoltDBBaselineStore(boltPath, masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	store.Close()
	if !IsMigrated(boltPath) {
		t.Error("real BoltDB should be migrated")
	}
	if NeedsMigration(boltPath) {
		t.Error("real BoltDB should not need migration")
	}

	// Legacy encrypted JSON file.
	legacyPath := filepath.Join(tempDir, "baseline_legacy.enc")
	legacyStore, err := NewPersistentBaselineStore(legacyPath, masterKey)
	if err != nil {
		t.Fatalf("legacy store: %v", err)
	}
	if err := legacyStore.Save(newLegacyBaseline("sha-t", "/tmp/t", "data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("legacy Save: %v", err)
	}
	if IsMigrated(legacyPath) {
		t.Error("legacy JSON should NOT be migrated")
	}
	if !NeedsMigration(legacyPath) {
		t.Error("legacy JSON should need migration")
	}

	// Non-existent file.
	if IsMigrated("/nonexistent/path") {
		t.Error("non-existent file should not be migrated")
	}
}

// ─── NoRedundantMigration ─────────────────────────────────────────────────────

func TestBoltDBBaselineStore_NoRedundantMigration(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "baseline.db")
	masterKey, _ := generateRandomMasterKey()

	s1, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s1.Save(newBLT("sha256-test", "/tmp/test", "test secret", "ONE_TIME_USE")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	s1.Close()

	// Re-open with same path as legacy — should NOT migrate, just open.
	s2, err := NewBoltDBBaselineStore(dbPath, masterKey, dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	r := s2.GetBySha("sha256-test")
	if r == nil {
		t.Fatal("baseline missing after no-op migration")
	}
	if r.Metadata().TargetPath != "/tmp/test" {
		t.Errorf("TargetPath: %s", r.Metadata().TargetPath)
	}
}

// ─── NilBaseline ─────────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_NilBaseline(t *testing.T) {
	tempDir := t.TempDir()
	masterKey := []byte("01234567890123456789012345678901")
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "baseline.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.Save(nil); err != nil {
		t.Errorf("Save(nil) should not error: %v", err)
	}
	if err := store.Set("/tmp/path", nil); err != nil {
		t.Errorf("Set(nil) should not error: %v", err)
	}
	if store.Get("/nonexistent") != nil {
		t.Error("Get non-existent should return nil")
	}
	if store.GetBySha("nonexistent") != nil {
		t.Error("GetBySha non-existent should return nil")
	}
	if err := store.Delete("nonexistent"); err != nil {
		t.Errorf("Delete non-existent should not error: %v", err)
	}
}

// ─── LegacyMigrationTestCase3 ─────────────────────────────────────────────────

func TestBoltDBBaselineStore_LegacyMigrationTestCase3(t *testing.T) {
	tempDir := t.TempDir()
	legacyPath := filepath.Join(tempDir, "baseline_legacy.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	type entry struct {
		sha, path, content string
		bins, sha256s      []string
		uid, gid, mode     uint32
		strategy           string
	}
	entries := []entry{
		{"sha256-migration-test-1", "/tmp/migration-test-1", "migration test secret 1",
			[]string{"/bin/cat", "/usr/bin/head"}, []string{"sha256-test1", "sha256-test2"},
			1000, 1000, 0644, "ONE_TIME_USE"},
		{"sha256-migration-test-2", "/tmp/migration-test-2", "migration test secret 2",
			[]string{"/usr/bin/python3", "/usr/bin/perl"}, []string{"sha256-test3", "sha256-test4"},
			1001, 1001, 0600, "SPEC_VERIFICATION"},
		{"sha256-migration-test-3", "/tmp/migration-test-3", "migration test secret 3",
			[]string{"/usr/bin/mysql", "/usr/bin/psql", "/bin/sh"}, []string{"sha256-test5", "sha256-test6", "sha256-test7"},
			1002, 1002, 0640, "PID_BIND"},
	}

	// Create legacy store.
	legacyStore, err := NewPersistentBaselineStore(legacyPath, masterKey)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	for i, e := range entries {
		lb := &enclave.CredentialBaseline{
			Sha:                   e.sha,
			TargetPath:            e.path,
			EncryptedData:         []byte(e.content),
			AllowedBinaries:       e.bins,
			AllowedBinariesSha256: e.sha256s,
			VerificationStrategy:  e.strategy,
			Permissions:           &enclave.FilePerms{Uid: e.uid, Gid: e.gid, Mode: e.mode},
		}
		if err := legacyStore.Save(lb); err != nil {
			t.Fatalf("legacy Save %d: %v", i, err)
		}
	}

	originalInfo, _ := os.Stat(legacyPath)
	originalModTime := originalInfo.ModTime()
	originalContent, _ := os.ReadFile(legacyPath)

	// Migrate.
	migratedStore, err := NewBoltDBBaselineStore(legacyPath, masterKey, legacyPath)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer migratedStore.Close()

	// Verify count.
	if cnt := migratedStore.Count(); cnt != len(entries) {
		t.Errorf("Count after migration: want %d, got %d", len(entries), cnt)
	}

	// Verify each entry.
	for i, e := range entries {
		r := migratedStore.GetBySha(e.sha)
		if r == nil {
			r = migratedStore.Get(e.path)
		}
		if r == nil {
			t.Fatalf("entry %d not found after migration", i)
		}
		if r.Metadata().TargetPath != e.path {
			t.Errorf("entry %d TargetPath: %s", i, r.Metadata().TargetPath)
		}
		if string(bltContent(t, r)) != e.content {
			t.Errorf("entry %d content mismatch", i)
		}
		rule := bltRule(t, r)
		if rule.VerificationStrategy != e.strategy {
			t.Errorf("entry %d strategy: %s", i, rule.VerificationStrategy)
		}
		for j, bin := range e.bins {
			if j >= len(rule.AllowedPrograms) || rule.AllowedPrograms[j] != bin {
				t.Errorf("entry %d AllowedPrograms[%d]: %s", i, j, bin)
			}
		}
		for j, s := range e.sha256s {
			if j >= len(rule.AllowedProgramsSha256) || rule.AllowedProgramsSha256[j] != s {
				t.Errorf("entry %d AllowedProgramsSha256[%d]: %s", i, j, s)
			}
		}
		// Measure must be derived from sha256s.
		if rule.Measure != (len(e.sha256s) > 0) {
			t.Errorf("entry %d Measure: got %v, want %v", i, rule.Measure, len(e.sha256s) > 0)
		}
	}

	// File must have changed.
	newInfo, _ := os.Stat(legacyPath)
	if newInfo.ModTime().Equal(originalModTime) {
		t.Error("file modtime should have changed after migration")
	}
	newContent, _ := os.ReadFile(legacyPath)
	if bytes.Equal(originalContent, newContent) {
		t.Error("file content should have changed after migration")
	}

	// Reopen and verify persistence.
	migratedStore.Close()
	reopened, err := NewBoltDBBaselineStore(legacyPath, masterKey, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	if cnt := reopened.Count(); cnt != len(entries) {
		t.Errorf("Count after reopen: want %d, got %d", len(entries), cnt)
	}
	for i, e := range entries {
		r := reopened.GetBySha(e.sha)
		if r == nil {
			r = reopened.Get(e.path)
		}
		if r == nil {
			t.Fatalf("entry %d missing after reopen", i)
		}
		if r.Metadata().TargetPath != e.path {
			t.Errorf("entry %d TargetPath after reopen", i)
		}
		if string(bltContent(t, r)) != e.content {
			t.Errorf("entry %d content mismatch after reopen", i)
		}
	}
	t.Logf("Migration test passed: %d entries verified", len(entries))
}

// ─── Exists ───────────────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_Exists(t *testing.T) {
	tempDir := t.TempDir()
	masterKey := []byte("01234567890123456789012345678901")
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "exists.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if store.Exists("sha-nonexistent") {
		t.Error("Exists should be false for empty store")
	}

	if err := store.Save(newBLT("sha-exists-test", "/tmp/exists-test", "data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !store.Exists("sha-exists-test") {
		t.Error("Exists should be true")
	}
	if store.Exists("sha-nonexistent") {
		t.Error("Exists should be false for non-existent SHA")
	}
	if store.Exists("") {
		t.Error("Exists should be false for empty SHA")
	}

	if err := store.Delete("sha-exists-test"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if store.Exists("sha-exists-test") {
		t.Error("Exists should be false after delete")
	}
}

// ─── CloseMultiple ────────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_CloseMultiple(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "close.db")
	masterKey := []byte("01234567890123456789012345678901")

	store, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Save(newBLT("sha-close", "/tmp/close-test", "data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	store.Close()
	store.Close() // second close must not panic

	s2, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.GetBySha("sha-close") == nil {
		t.Error("data should persist after close-close-reopen")
	}
}

// ─── ConcurrentAccess ────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	masterKey := []byte("01234567890123456789012345678901")
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "concurrent.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.Save(newBLT("sha-concurrent", "/tmp/concurrent", "initial data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("initial Save: %v", err)
	}

	numOps := 30
	done := make(chan bool, numOps*2)

	for i := 0; i < numOps; i++ {
		go func(idx int) {
			store.Save(newBLT(fmt.Sprintf("sha-concurrent-%d", idx), fmt.Sprintf("/tmp/concurrent-%d", idx), "data", "ONE_TIME_USE")) //nolint:errcheck
			done <- true
		}(i)
	}
	for i := 0; i < numOps; i++ {
		go func() {
			store.Get("/tmp/concurrent")
			store.GetBySha("sha-concurrent")
			store.Count()
			store.ListAll()
			store.Exists("sha-concurrent")
			done <- true
		}()
	}
	for i := 0; i < numOps*2; i++ {
		<-done
	}
	if store.Count() < 1 {
		t.Error("Count should be at least 1")
	}
	if store.GetBySha("sha-concurrent") == nil {
		t.Error("original baseline should still exist")
	}
}

// ─── ListAllEmpty ─────────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_ListAllEmpty(t *testing.T) {
	tempDir := t.TempDir()
	masterKey := []byte("01234567890123456789012345678901")
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "listall_empty.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	if len(store.ListAll()) != 0 {
		t.Error("ListAll should be empty for new store")
	}
}

// ─── SaveEmptySHA ─────────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_SaveEmptySHA(t *testing.T) {
	tempDir := t.TempDir()
	masterKey := []byte("01234567890123456789012345678901")
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "emptysha.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	bl := newBLT("", "/tmp/empty-sha-test", "data", "ONE_TIME_USE")
	err = store.Save(bl)
	if err == nil {
		t.Error("Save with empty SHA should return error")
	}
	if err != nil && !strings.Contains(err.Error(), "SHA is empty") {
		t.Errorf("unexpected error: %v", err)
	}
	if store.Count() != 0 {
		t.Errorf("Count should be 0, got %d", store.Count())
	}
}

// ─── SaveDuplicateSHA ─────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_SaveDuplicateSHA(t *testing.T) {
	tempDir := t.TempDir()
	masterKey := []byte("01234567890123456789012345678901")
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "dup_sha.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.Save(newBLT("sha-dup", "/tmp/dup-1", "first data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := store.Save(newBLT("sha-dup", "/tmp/dup-2", "second data", "SPEC_VERIFICATION")); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	if store.Count() != 1 {
		t.Errorf("Count: want 1 after overwrite, got %d", store.Count())
	}
	r := store.GetBySha("sha-dup")
	if r == nil {
		t.Fatal("GetBySha returned nil")
	}
	if r.Metadata().TargetPath != "/tmp/dup-2" {
		t.Errorf("TargetPath: want /tmp/dup-2, got %s", r.Metadata().TargetPath)
	}
	if string(bltContent(t, r)) != "second data" {
		t.Error("content should be from second save")
	}
}

// ─── DeleteTwice ─────────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_DeleteTwice(t *testing.T) {
	tempDir := t.TempDir()
	masterKey := []byte("01234567890123456789012345678901")
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "del_twice.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.Save(newBLT("sha-del-twice", "/tmp/del-twice", "data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Delete("sha-del-twice"); err != nil {
		t.Fatalf("first Delete: %v", err)
	}
	if store.Exists("sha-del-twice") {
		t.Error("should not exist after first delete")
	}
	if err := store.Delete("sha-del-twice"); err != nil {
		t.Errorf("second Delete should not error: %v", err)
	}
}

// ─── InvalidMasterKey ────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_InvalidMasterKey(t *testing.T) {
	tempDir := t.TempDir()

	// Short key — store creation succeeds, but Save should fail during encryption.
	shortStore, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "short.db"), []byte("short-key"), "")
	if err != nil {
		t.Fatalf("store creation should succeed: %v", err)
	}
	defer shortStore.Close()
	if err := shortStore.Save(newBLT("sha", "/tmp/t", "data", "ONE_TIME_USE")); err == nil {
		t.Error("Save with short key should fail")
	}
}

// ─── CorruptedData ────────────────────────────────────────────────────────────
// With the 3-bucket model, fileMetadata is unencrypted so it is always readable.
// Rule and fileContent are encrypted; they fail with a wrong key.

func TestBoltDBBaselineStore_CorruptedData(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "corrupted.db")
	masterKey := []byte("01234567890123456789012345678901")

	store, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Save(newBLT("sha-corrupted", "/tmp/corrupted", "valid data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	store.Close()

	// Reopen with wrong key.
	wrongKey := []byte("different-key-01234567890123456789")
	s2, err := NewBoltDBBaselineStore(dbPath, wrongKey, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	// Metadata is unencrypted — GetBySha returns a baseline with metadata.
	r := s2.GetBySha("sha-corrupted")
	if r == nil {
		t.Fatal("GetBySha should return metadata-only baseline even with wrong key")
	}
	if r.Metadata().TargetPath != "/tmp/corrupted" {
		t.Errorf("TargetPath: %s", r.Metadata().TargetPath)
	}

	// Rule must fail to decrypt.
	if _, err := r.Rule(); err == nil {
		t.Error("Rule() should fail with wrong key")
	}
	// FileContent must fail to decrypt.
	if _, err := r.FileContent(); err == nil {
		t.Error("FileContent() should fail with wrong key")
	}
}

// ─── EmptyDatabasePath ────────────────────────────────────────────────────────

func TestBoltDBBaselineStore_EmptyDatabasePath(t *testing.T) {
	masterKey := []byte("01234567890123456789012345678901")
	_, err := NewBoltDBBaselineStore("", masterKey, "")
	if err == nil {
		t.Error("should return error for empty path")
	}
	if err != nil && !strings.Contains(err.Error(), "no database path") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ─── GenerateShaFromPath ──────────────────────────────────────────────────────

func TestBoltDBBaselineStore_GenerateShaFromPath(t *testing.T) {
	sha1 := generateShaFromPath("/tmp/test-file-1")
	if len(sha1) != 12 {
		t.Errorf("SHA length: want 12, got %d", len(sha1))
	}
	if sha1 != generateShaFromPath("/tmp/test-file-1") {
		t.Error("same path should produce same SHA")
	}
	sha2 := generateShaFromPath("/tmp/test-file-2")
	if sha1 == sha2 {
		t.Error("different paths should produce different SHAs")
	}
	if len(generateShaFromPath("")) != 12 {
		t.Error("empty path should still produce 12-char SHA")
	}
}

// ─── MigrationWithEmptySHA ────────────────────────────────────────────────────

func TestBoltDBBaselineStore_MigrationWithEmptySHA(t *testing.T) {
	tempDir := t.TempDir()
	legacyPath := filepath.Join(tempDir, "legacy_no_sha.enc")
	masterKey := []byte("01234567890123456789012345678901")

	legacyStore, err := NewPersistentBaselineStore(legacyPath, masterKey)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	lb := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/no-sha-test",
		EncryptedData:        []byte("data without sha"),
		Sha:                  "", // empty SHA
		VerificationStrategy: "ONE_TIME_USE",
	}
	legacyStore.Save(lb) //nolint:errcheck

	migrated, err := NewBoltDBBaselineStore(legacyPath, masterKey, legacyPath)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer migrated.Close()

	all := migrated.ListAll()
	if len(all) == 0 {
		t.Error("migration should preserve data even without original SHA")
	}

	expectedSha := generateShaFromPath("/tmp/no-sha-test")
	if migrated.Exists(expectedSha) {
		t.Logf("Generated SHA '%s' for baseline without SHA", expectedSha)
	}
}

// ─── LargeEncryptedData ───────────────────────────────────────────────────────

func TestBoltDBBaselineStore_LargeEncryptedData(t *testing.T) {
	tempDir := t.TempDir()
	masterKey := []byte("01234567890123456789012345678901")
	store, err := NewBoltDBBaselineStore(filepath.Join(tempDir, "large.db"), masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	bl := NewCredentialBaseline("sha-large", FileMetadata{TargetPath: "/tmp/large"}, &AccessRule{}, largeData)
	if err := store.Save(bl); err != nil {
		t.Fatalf("Save: %v", err)
	}

	r := store.GetBySha("sha-large")
	if r == nil {
		t.Fatal("not found")
	}
	c := bltContent(t, r)
	if len(c) != 1024 {
		t.Errorf("content length: want 1024, got %d", len(c))
	}
	for i := range largeData {
		if c[i] != largeData[i] {
			t.Errorf("content mismatch at byte %d", i)
			break
		}
	}
}

// ─── BucketNotFound (reopen after close) ─────────────────────────────────────

func TestBoltDBBaselineStore_BucketNotFound(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "bucket.db")
	masterKey := []byte("01234567890123456789012345678901")

	store, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Save(newBLT("sha-bucket", "/tmp/bucket", "data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	store.Close()

	s2, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.GetBySha("sha-bucket") == nil {
		t.Error("data should persist after reopen")
	}
}

// ─── ListAllWithCorruptedData ─────────────────────────────────────────────────
// With the 3-bucket model, metadata is unencrypted so ListAll returns metadata
// baselines even with the wrong key. Sensitive data (rule/content) remains protected.

func TestBoltDBBaselineStore_ListAllWithCorruptedData(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "listall_corrupted.db")
	masterKey := []byte("01234567890123456789012345678901")

	store, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Save(newBLT("sha-valid", "/tmp/valid-test", "valid data", "ONE_TIME_USE")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	store.Close()

	// Reopen with wrong key.
	wrongKey := []byte("different-key-01234567890123456789")
	s2, err := NewBoltDBBaselineStore(dbPath, wrongKey, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	// Metadata is unencrypted: ListAll and Get still return baselines.
	all := s2.ListAll()
	if len(all) == 0 {
		t.Error("ListAll should return metadata baselines even with wrong key")
	}
	r := s2.Get("/tmp/valid-test")
	if r == nil {
		t.Error("Get should return metadata baseline even with wrong key")
	}

	// But rule and content must be inaccessible.
	if r != nil {
		if _, err := r.Rule(); err == nil {
			t.Error("Rule() should fail with wrong key")
		}
		if _, err := r.FileContent(); err == nil {
			t.Error("FileContent() should fail with wrong key")
		}
	}
}

// ─── DeepCopy ────────────────────────────────────────────────────────────────
// BoltDB always decrypts fresh on each read, so modifications to a retrieved
// baseline's content do not affect subsequent reads.

func TestBoltDBBaselineStore_DeepCopy(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "deepcopy.db")
	masterKey := []byte("01234567890123456789012345678901")

	store, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	originalData := []byte("original deep copy test data")
	if err := store.Save(NewCredentialBaseline("sha-deepcopy", FileMetadata{TargetPath: "/tmp/deepcopy"}, &AccessRule{}, originalData)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Get and mutate content.
	r1 := store.Get("/tmp/deepcopy")
	if r1 == nil {
		t.Fatal("Get returned nil")
	}
	c1 := bltContent(t, r1)
	c1[0] = 'X' // mutate the returned slice

	// Second read must return original data (BoltDB re-decrypts from disk).
	r2 := store.Get("/tmp/deepcopy")
	if r2 == nil {
		t.Fatal("second Get returned nil")
	}
	if string(bltContent(t, r2)) != string(originalData) {
		t.Error("Get should return fresh data each call — mutation must not affect store")
	}

	// Same for GetBySha.
	r3 := store.GetBySha("sha-deepcopy")
	c3 := bltContent(t, r3)
	c3[0] = 'Y'

	r4 := store.GetBySha("sha-deepcopy")
	if string(bltContent(t, r4)) != string(originalData) {
		t.Error("GetBySha should return fresh data each call")
	}
}
