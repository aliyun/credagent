package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRandomPassword(t *testing.T) {
	pw, err := generateRandomPassword(8)
	if err != nil {
		t.Fatalf("generateRandomPassword(8) error: %v", err)
	}
	if len(pw) != 8 {
		t.Fatalf("password length = %d, want 8 (%q)", len(pw), pw)
	}
	for _, c := range pw {
		if !strings.ContainsRune(passwordCharset, c) {
			t.Errorf("password %q contains char %q not in charset", pw, c)
		}
	}

	// Two calls should (overwhelmingly likely) differ — confirms non-constant output.
	pw2, _ := generateRandomPassword(8)
	if pw == pw2 {
		t.Errorf("two random passwords identical: %q (randomness suspect)", pw)
	}

	if _, err := generateRandomPassword(0); err == nil {
		t.Error("generateRandomPassword(0) should error")
	}
}

func TestAutoInitMasterKey_CreatesKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "engine", "master.key")
	baselineFile := filepath.Join(dir, "lib", "baseline.enc")

	if err := autoInitMasterKey(keyFile, baselineFile); err != nil {
		t.Fatalf("autoInitMasterKey error: %v", err)
	}

	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("master key not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("master key perms = %o, want 0600", perm)
	}

	encoded, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read master key: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("master key not base64: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("decoded master key length = %d, want 32", len(raw))
	}

	// Baseline did not pre-exist; nothing to back up, and it is NOT created here
	// (NewBaselineStoreFromPath handles that later).
	if _, err := os.Stat(baselineFile); !os.IsNotExist(err) {
		t.Errorf("baseline should not exist after auto-init, got err=%v", err)
	}
}

func TestAutoInitMasterKey_BackupsExistingBaseline(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	baselineFile := filepath.Join(dir, "baseline.enc")

	// A pre-existing baseline encrypted under some prior (now-missing) key.
	oldContent := []byte("pretend-encrypted-baseline-from-previous-key")
	if err := os.WriteFile(baselineFile, oldContent, 0600); err != nil {
		t.Fatal(err)
	}

	if err := autoInitMasterKey(keyFile, baselineFile); err != nil {
		t.Fatalf("autoInitMasterKey error: %v", err)
	}

	// Original baseline path must be free (so NewBaselineStoreFromPath creates fresh).
	if _, err := os.Stat(baselineFile); !os.IsNotExist(err) {
		t.Errorf("original baseline should have been renamed away, err=%v", err)
	}

	// A timestamped backup should exist with the original content.
	matches, err := filepath.Glob(baselineFile + ".bak.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 backup, got %d: %v", len(matches), matches)
	}
	got, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(got) != string(oldContent) {
		t.Errorf("backup content = %q, want %q", got, oldContent)
	}

	// Key file must have been generated.
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("master key not created: %v", err)
	}
}

func TestAutoInitMasterKey_KeyDirCreated(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "nested", "deep", "master.key")
	if err := autoInitMasterKey(keyFile, ""); err != nil {
		t.Fatalf("autoInitMasterKey error: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("master key not created in nested dir: %v", err)
	}
}

func TestUniqueBackupPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.enc")

	bp1, err := uniqueBackupPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bp1, path+".bak.") {
		t.Errorf("backup path %q missing expected prefix", bp1)
	}

	// Occupy bp1; next call must pick a different path.
	if err := os.WriteFile(bp1, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	bp2, err := uniqueBackupPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if bp2 == bp1 {
		t.Errorf("uniqueBackupPath returned occupied path %q", bp2)
	}
}
