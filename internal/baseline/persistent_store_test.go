package baseline

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aliyun/credagent/api/gen/enclave"
)

// generateRandomMasterKey creates a random 32-byte master key for testing
func generateRandomMasterKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256 requires 32-byte key
	_, err := rand.Read(key)
	return key, err
}

func TestPersistentBaselineStore_Encryption(t *testing.T) {
	// Create a temporary file for testing
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_store.enc")

	// Generate a random master key for testing
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	// Create a new persistent baseline store
	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Create a test baseline
	testBaseline := &enclave.CredentialBaseline{
		TargetPath:    "/tmp/test-file",
		EncryptedData: []byte("test secret data"),
		Sha:           "sha256-test-hash", // Add SHA for new Delete(sha) interface
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0644,
		},
		AllowedBinaries:       []string{"/bin/cat", "/usr/bin/head"},
		AllowedBinariesSha256: []string{"sha256-test1", "sha256-test2"},
		VerificationStrategy:  "ONE_TIME_USE",
	}

	// Test saving the baseline
	err = store.Save(testBaseline)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Verify the baseline is accessible in memory
	retrievedBaseline := store.Get("/tmp/test-file")
	if retrievedBaseline == nil {
		t.Fatal("Failed to retrieve baseline from memory")
	}

	if retrievedBaseline.GetTargetPath() != "/tmp/test-file" {
		t.Errorf("Expected TargetPath '/tmp/test-file', got '%s'", retrievedBaseline.GetTargetPath())
	}

	// Verify the file was created and contains encrypted data
	fileInfo, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("Failed to stat store file: %v", err)
	}

	if fileInfo.Size() == 0 {
		t.Fatal("Store file is empty, encryption may not have worked")
	}

	// Check that the file contains encrypted data (not plaintext)
	encryptedData, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("Failed to read store file: %v", err)
	}

	// The encrypted data should not contain the plaintext "test secret data"
	plaintextString := string(testBaseline.GetEncryptedData())
	if string(encryptedData) == plaintextString {
		t.Fatal("File appears to contain plaintext instead of encrypted data")
	}

	// Create a new store instance to test loading from file
	newStore, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create new persistent baseline store: %v", err)
	}

	// Verify the baseline is loaded from file
	loadedBaseline := newStore.Get("/tmp/test-file")
	if loadedBaseline == nil {
		t.Fatal("Failed to load baseline from file")
	}

	if loadedBaseline.GetTargetPath() != "/tmp/test-file" {
		t.Errorf("Expected TargetPath '/tmp/test-file' after reload, got '%s'", loadedBaseline.GetTargetPath())
	}

	if string(loadedBaseline.GetEncryptedData()) != plaintextString {
		t.Errorf("Expected encrypted data to match original, got different value")
	}

	// Test deletion (now uses SHA as parameter)
	err = newStore.Delete("sha256-test-hash")
	if err != nil {
		t.Fatalf("Failed to delete baseline: %v", err)
	}

	// Verify deletion
	deletedBaseline := newStore.Get("/tmp/test-file")
	if deletedBaseline != nil {
		t.Fatal("Baseline still exists after deletion")
	}

	// Verify deletion persisted to file by creating another instance
	finalStore, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create final persistent baseline store: %v", err)
	}

	finalBaseline := finalStore.Get("/tmp/test-file")
	if finalBaseline != nil {
		t.Fatal("Baseline still exists after deletion and reload")
	}
}

func TestPersistentBaselineStore_MultipleBaselines(t *testing.T) {
	// Create a temporary file for testing
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_store_multiple.enc")

	// Generate a random master key for testing
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	// Create a new persistent baseline store
	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Create multiple test baselines
	baselines := []*enclave.CredentialBaseline{
		{
			TargetPath:    "/tmp/test-file-1",
			EncryptedData: []byte("secret data 1"),
			Permissions: &enclave.FilePerms{
				Uid:  1000,
				Gid:  1000,
				Mode: 0644,
			},
			AllowedBinaries:       []string{"/bin/cat"},
			AllowedBinariesSha256: []string{"sha256-test1"},
			VerificationStrategy:  "ONE_TIME_USE",
		},
		{
			TargetPath:    "/tmp/test-file-2",
			EncryptedData: []byte("secret data 2"),
			Permissions: &enclave.FilePerms{
				Uid:  1001,
				Gid:  1001,
				Mode: 0600,
			},
			AllowedBinaries:       []string{"/usr/bin/head", "/usr/bin/tail"},
			AllowedBinariesSha256: []string{"sha256-test2", "sha256-test3"},
			VerificationStrategy:  "SPEC_VERIFICATION",
		},
	}

	// Save all baselines
	for _, baseline := range baselines {
		err = store.Save(baseline)
		if err != nil {
			t.Fatalf("Failed to save baseline: %v", err)
		}
	}

	// Verify all baselines are accessible
	for _, baseline := range baselines {
		retrievedBaseline := store.Get(baseline.GetTargetPath())
		if retrievedBaseline == nil {
			t.Fatalf("Failed to retrieve baseline for path: %s", baseline.GetTargetPath())
		}
	}

	// Reload from file and verify all baselines are still there
	reloadStore, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create reloaded baseline store: %v", err)
	}

	for _, baseline := range baselines {
		retrievedBaseline := reloadStore.Get(baseline.GetTargetPath())
		if retrievedBaseline == nil {
			t.Fatalf("Failed to retrieve baseline from reloaded store for path: %s", baseline.GetTargetPath())
		}

		if string(retrievedBaseline.GetEncryptedData()) != string(baseline.GetEncryptedData()) {
			t.Errorf("Encrypted data mismatch after reload for %s", baseline.GetTargetPath())
		}
	}
}

func TestPersistentBaselineStore_EncryptionSecurity(t *testing.T) {
	// Create a temporary file for testing
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_store_security.enc")

	// Generate two different master keys
	masterKey1, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key 1: %v", err)
	}

	masterKey2, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key 2: %v", err)
	}

	// Create a test baseline
	testBaseline := &enclave.CredentialBaseline{
		TargetPath:    "/tmp/security-test",
		EncryptedData: []byte("sensitive security data"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:       []string{"/bin/cat"},
		AllowedBinariesSha256: []string{"sha256-test"},
		VerificationStrategy:  "PID_BIND",
	}

	// Create store with first key and save baseline
	store1, err := NewPersistentBaselineStore(storePath, masterKey1)
	if err != nil {
		t.Fatalf("Failed to create first baseline store: %v", err)
	}

	err = store1.Save(testBaseline)
	if err != nil {
		t.Fatalf("Failed to save baseline with first key: %v", err)
	}

	// Try to load with different key - this should fail
	store2, err := NewPersistentBaselineStore(storePath, masterKey2)
	if err == nil {
		// If no error occurred, the decryption might have produced garbage data
		// Let's check if the loaded data is correct
		retrievedBaseline := store2.Get("/tmp/security-test")
		if retrievedBaseline != nil {
			// If it retrieved something, check if it's the correct data
			if retrievedBaseline.GetTargetPath() != testBaseline.GetTargetPath() {
				// This is expected - the wrong key should fail to decrypt properly
				// But we can't guarantee what kind of error we get, so let's just log
				t.Log("Different key failed to decrypt properly (expected behavior)")
			} else {
				// This would be bad - the wrong key successfully decrypted
				t.Error("Different master key was able to decrypt data - this is a security issue!")
			}
		}
	} else {
		// This is the expected behavior - different key should fail to load
		t.Logf("Loading with different key failed as expected: %v", err)
	}

	// Verify that the original key still works
	store3, err := NewPersistentBaselineStore(storePath, masterKey1)
	if err != nil {
		t.Fatalf("Failed to create third baseline store with original key: %v", err)
	}

	retrievedBaseline := store3.Get("/tmp/security-test")
	if retrievedBaseline == nil {
		t.Fatal("Original key failed to load baseline - data may be corrupted")
	}

	if retrievedBaseline.GetTargetPath() != testBaseline.GetTargetPath() {
		t.Errorf("TargetPath mismatch with original key: expected %s, got %s",
			testBaseline.GetTargetPath(), retrievedBaseline.GetTargetPath())
	}
}

// TestPersistentBaselineStore_GetBySha tests GetBySha method
func TestPersistentBaselineStore_GetBySha(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_getbysha.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Create test baseline with SHA
	testBaseline := &enclave.CredentialBaseline{
		TargetPath:    "/tmp/getbysha-test",
		EncryptedData: []byte("getbysha secret data"),
		Sha:           "sha256-getbysha-test",
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0644,
		},
		AllowedBinaries:      []string{"/bin/cat"},
		VerificationStrategy: "ONE_TIME_USE",
	}

	err = store.Save(testBaseline)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Test GetBySha - should find the baseline
	retrieved := store.GetBySha("sha256-getbysha-test")
	if retrieved == nil {
		t.Fatal("GetBySha should return baseline for existing SHA")
	}
	if retrieved.GetTargetPath() != "/tmp/getbysha-test" {
		t.Errorf("Expected TargetPath '/tmp/getbysha-test', got '%s'", retrieved.GetTargetPath())
	}
	if retrieved.GetSha() != "sha256-getbysha-test" {
		t.Errorf("Expected SHA 'sha256-getbysha-test', got '%s'", retrieved.GetSha())
	}

	// Test GetBySha - non-existent SHA
	retrieved = store.GetBySha("nonexistent-sha")
	if retrieved != nil {
		t.Error("GetBySha should return nil for non-existent SHA")
	}

	// Test GetBySha - empty SHA
	retrieved = store.GetBySha("")
	if retrieved != nil {
		t.Error("GetBySha should return nil for empty SHA")
	}

	// Test persistence - reload and verify GetBySha still works
	store2, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to reload persistent baseline store: %v", err)
	}

	retrieved = store2.GetBySha("sha256-getbysha-test")
	if retrieved == nil {
		t.Fatal("GetBySha should return baseline after reload")
	}
	if retrieved.GetTargetPath() != "/tmp/getbysha-test" {
		t.Errorf("Expected TargetPath '/tmp/getbysha-test' after reload, got '%s'", retrieved.GetTargetPath())
	}
}

// TestPersistentBaselineStore_GetAll tests GetAll method
func TestPersistentBaselineStore_GetAll(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_getall.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Test GetAll on empty store
	allBaselines := store.GetAll()
	if allBaselines == nil {
		t.Error("GetAll should return non-nil map for empty store")
	}
	if len(allBaselines) != 0 {
		t.Errorf("GetAll should return empty map for empty store, got %d entries", len(allBaselines))
	}

	// Add multiple baselines
	baselines := []*enclave.CredentialBaseline{
		{
			TargetPath:           "/tmp/getall-1",
			EncryptedData:        []byte("secret 1"),
			Sha:                  "sha-getall-1",
			VerificationStrategy: "ONE_TIME_USE",
		},
		{
			TargetPath:           "/tmp/getall-2",
			EncryptedData:        []byte("secret 2"),
			Sha:                  "sha-getall-2",
			VerificationStrategy: "SPEC_VERIFICATION",
		},
		{
			TargetPath:           "/tmp/getall-3",
			EncryptedData:        []byte("secret 3"),
			Sha:                  "sha-getall-3",
			VerificationStrategy: "PID_BIND",
		},
	}

	for _, bl := range baselines {
		err = store.Save(bl)
		if err != nil {
			t.Fatalf("Failed to save baseline: %v", err)
		}
	}

	// Test GetAll returns all baselines
	allBaselines = store.GetAll()
	if len(allBaselines) != 3 {
		t.Errorf("GetAll should return 3 entries, got %d", len(allBaselines))
	}

	// Verify each baseline exists in the returned map
	for _, bl := range baselines {
		retrieved, exists := allBaselines[bl.GetTargetPath()]
		if !exists {
			t.Errorf("GetAll should contain baseline for path %s", bl.GetTargetPath())
		}
		if retrieved.GetSha() != bl.GetSha() {
			t.Errorf("SHA mismatch for path %s: expected %s, got %s",
				bl.GetTargetPath(), bl.GetSha(), retrieved.GetSha())
		}
	}

	// Test that GetAll returns deep copies (modify returned data should not affect store)
	retrieved := allBaselines["/tmp/getall-1"]
	retrieved.EncryptedData[0] = 'X'

	// Get again and verify original data unchanged
	original := store.Get("/tmp/getall-1")
	if original == nil {
		t.Fatal("Get should return baseline after modification attempt")
	}
	if string(original.GetEncryptedData()) != "secret 1" {
		t.Error("GetAll should return deep copies - original data should be unchanged")
	}
}

// TestPersistentBaselineStore_ListAll tests ListAll method
func TestPersistentBaselineStore_ListAll(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_listall.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Test ListAll on empty store
	allList := store.ListAll()
	if allList == nil {
		t.Error("ListAll should return non-nil slice for empty store")
	}
	if len(allList) != 0 {
		t.Errorf("ListAll should return empty slice for empty store, got %d entries", len(allList))
	}

	// Add multiple baselines
	baselines := []*enclave.CredentialBaseline{
		{
			TargetPath:           "/tmp/listall-1",
			EncryptedData:        []byte("list secret 1"),
			Sha:                  "sha-listall-1",
			VerificationStrategy: "ONE_TIME_USE",
		},
		{
			TargetPath:           "/tmp/listall-2",
			EncryptedData:        []byte("list secret 2"),
			Sha:                  "sha-listall-2",
			VerificationStrategy: "SPEC_VERIFICATION",
		},
	}

	for _, bl := range baselines {
		err = store.Save(bl)
		if err != nil {
			t.Fatalf("Failed to save baseline: %v", err)
		}
	}

	// Test ListAll returns all baselines as slice
	allList = store.ListAll()
	if len(allList) != 2 {
		t.Errorf("ListAll should return 2 entries, got %d", len(allList))
	}

	// Verify ListAll returns deep copies
	for i, retrieved := range allList {
		// Modify the returned data
		retrieved.EncryptedData[0] = 'X'

		// Get original from store
		original := store.Get(retrieved.GetTargetPath())
		if original == nil {
			t.Fatalf("Failed to get original baseline %d", i)
		}

		// Check original is unchanged
		if string(original.GetEncryptedData()) == string(retrieved.GetEncryptedData()) {
			t.Errorf("ListAll entry %d should be deep copy - modification affected store", i)
		}
	}
}

// TestPersistentBaselineStore_Count tests Count method
func TestPersistentBaselineStore_Count(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_count.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Test Count on empty store
	if count := store.Count(); count != 0 {
		t.Errorf("Count should be 0 for empty store, got %d", count)
	}

	// Add baselines
	baselines := []*enclave.CredentialBaseline{
		{
			TargetPath:           "/tmp/count-1",
			EncryptedData:        []byte("count secret 1"),
			Sha:                  "sha-count-1",
			VerificationStrategy: "ONE_TIME_USE",
		},
		{
			TargetPath:           "/tmp/count-2",
			EncryptedData:        []byte("count secret 2"),
			Sha:                  "sha-count-2",
			VerificationStrategy: "SPEC_VERIFICATION",
		},
		{
			TargetPath:           "/tmp/count-3",
			EncryptedData:        []byte("count secret 3"),
			Sha:                  "sha-count-3",
			VerificationStrategy: "PID_BIND",
		},
	}

	for _, bl := range baselines {
		err = store.Save(bl)
		if err != nil {
			t.Fatalf("Failed to save baseline: %v", err)
		}
	}

	// Test Count after adding
	if count := store.Count(); count != 3 {
		t.Errorf("Count should be 3 after adding baselines, got %d", count)
	}

	// Delete one baseline
	err = store.Delete("sha-count-2")
	if err != nil {
		t.Fatalf("Failed to delete baseline: %v", err)
	}

	// Test Count after deletion
	if count := store.Count(); count != 2 {
		t.Errorf("Count should be 2 after deletion, got %d", count)
	}

	// Verify Count persists after reload
	store2, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to reload store: %v", err)
	}
	if count := store2.Count(); count != 2 {
		t.Errorf("Count should be 2 after reload, got %d", count)
	}
}

// TestPersistentBaselineStore_Set tests Set method
func TestPersistentBaselineStore_Set(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_set.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Initial save
	baseline1 := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/set-test",
		EncryptedData:        []byte("initial set data"),
		Sha:                  "sha-set-initial",
		VerificationStrategy: "ONE_TIME_USE",
	}
	err = store.Save(baseline1)
	if err != nil {
		t.Fatalf("Failed to save initial baseline: %v", err)
	}

	// Update using Set with same target path but different SHA
	baseline2 := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/set-test",
		EncryptedData:        []byte("updated set data"),
		Sha:                  "sha-set-updated",
		VerificationStrategy: "SPEC_VERIFICATION",
	}
	err = store.Set("/tmp/set-test", baseline2)
	if err != nil {
		t.Fatalf("Failed to set baseline: %v", err)
	}

	// Verify update - old SHA should not exist
	retrieved := store.GetBySha("sha-set-initial")
	if retrieved != nil {
		t.Error("Old SHA should be removed after Set")
	}

	// New SHA should exist
	retrieved = store.GetBySha("sha-set-updated")
	if retrieved == nil {
		t.Fatal("New SHA should exist after Set")
	}
	if retrieved.GetTargetPath() != "/tmp/set-test" {
		t.Errorf("Expected TargetPath '/tmp/set-test', got '%s'", retrieved.GetTargetPath())
	}
	if retrieved.GetVerificationStrategy() != "SPEC_VERIFICATION" {
		t.Errorf("Expected strategy 'SPEC_VERIFICATION', got '%s'", retrieved.GetVerificationStrategy())
	}

	// Count should still be 1
	if count := store.Count(); count != 1 {
		t.Errorf("Count should be 1 after Set, got %d", count)
	}

	// Verify Set persists to file
	store2, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to reload store: %v", err)
	}
	retrieved = store2.GetBySha("sha-set-updated")
	if retrieved == nil {
		t.Fatal("Updated baseline should persist after reload")
	}
	if string(retrieved.GetEncryptedData()) != "updated set data" {
		t.Errorf("Updated data should persist: expected 'updated set data', got '%s'",
			string(retrieved.GetEncryptedData()))
	}
}

// TestPersistentBaselineStore_DeepCopy tests that returned data is deep copy
func TestPersistentBaselineStore_DeepCopy(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_deepcopy.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	originalData := []byte("original secret for deep copy test")
	baseline := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/deepcopy-test",
		EncryptedData:        originalData,
		Sha:                  "sha-deepcopy",
		VerificationStrategy: "ONE_TIME_USE",
	}
	err = store.Save(baseline)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Get and modify via Get
	retrieved := store.Get("/tmp/deepcopy-test")
	if retrieved == nil {
		t.Fatal("Get should return baseline")
	}
	retrieved.EncryptedData[0] = 'X'

	// Get again - should have original data
	retrieved2 := store.Get("/tmp/deepcopy-test")
	if retrieved2 == nil {
		t.Fatal("Get should return baseline again")
	}
	if string(retrieved2.GetEncryptedData()) != "original secret for deep copy test" {
		t.Error("Get should return deep copy - original data should be unchanged")
	}

	// Test GetBySha deep copy
	retrieved = store.GetBySha("sha-deepcopy")
	if retrieved == nil {
		t.Fatal("GetBySha should return baseline")
	}
	retrieved.EncryptedData[0] = 'Y'

	retrieved2 = store.GetBySha("sha-deepcopy")
	if retrieved2 == nil {
		t.Fatal("GetBySha should return baseline again")
	}
	if string(retrieved2.GetEncryptedData()) != "original secret for deep copy test" {
		t.Error("GetBySha should return deep copy - original data should be unchanged")
	}
}

// TestPersistentBaselineStore_EmptySHA tests handling baseline with empty SHA
func TestPersistentBaselineStore_EmptySHA(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_emptysha.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Save baseline with empty SHA
	baseline := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/no-sha-persistent",
		EncryptedData:        []byte("data without sha in persistent"),
		Sha:                  "", // Empty SHA
		VerificationStrategy: "ONE_TIME_USE",
	}
	err = store.Save(baseline)
	if err != nil {
		t.Fatalf("Failed to save baseline with empty SHA: %v", err)
	}

	// Should be accessible by Get (targetPath)
	retrieved := store.Get("/tmp/no-sha-persistent")
	if retrieved == nil {
		t.Error("Should be able to Get baseline with empty SHA by targetPath")
	}

	// Should not be accessible by GetBySha (empty SHA)
	retrieved = store.GetBySha("")
	if retrieved != nil {
		t.Error("GetBySha with empty SHA should return nil")
	}

	// Save another baseline with SHA to verify mixed storage
	baselineWithSha := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/with-sha-persistent",
		EncryptedData:        []byte("data with sha"),
		Sha:                  "sha-with-sha-persistent",
		VerificationStrategy: "SPEC_VERIFICATION",
	}
	err = store.Save(baselineWithSha)
	if err != nil {
		t.Fatalf("Failed to save baseline with SHA: %v", err)
	}

	// Count should count both
	if count := store.Count(); count != 2 {
		t.Errorf("Count should be 2 (one empty SHA, one with SHA), got %d", count)
	}

	// Reload and verify persistence
	store2, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to reload store: %v", err)
	}

	// Empty SHA baseline should still be accessible by Get
	retrieved = store2.Get("/tmp/no-sha-persistent")
	if retrieved == nil {
		t.Error("Empty SHA baseline should persist and be accessible by Get")
	}

	// With SHA baseline should be accessible by GetBySha
	retrieved = store2.GetBySha("sha-with-sha-persistent")
	if retrieved == nil {
		t.Error("SHA baseline should persist and be accessible by GetBySha")
	}
}

// TestPersistentBaselineStore_DeleteNonExistent tests deleting non-existent SHA
func TestPersistentBaselineStore_DeleteNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_delete_nonexistent.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Add a baseline
	baseline := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/delete-test",
		EncryptedData:        []byte("delete test data"),
		Sha:                  "sha-delete-test",
		VerificationStrategy: "ONE_TIME_USE",
	}
	err = store.Save(baseline)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Delete non-existent SHA should not error
	err = store.Delete("nonexistent-sha")
	if err != nil {
		t.Errorf("Delete non-existent SHA should not return error: %v", err)
	}

	// Original baseline should still exist
	retrieved := store.GetBySha("sha-delete-test")
	if retrieved == nil {
		t.Error("Original baseline should still exist after deleting non-existent SHA")
	}

	// Count should still be 1
	if count := store.Count(); count != 1 {
		t.Errorf("Count should still be 1, got %d", count)
	}
}

// TestPersistentBaselineStore_DeleteEmptySHA tests deleting with empty SHA parameter
func TestPersistentBaselineStore_DeleteEmptySHA(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_delete_empty.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Add a baseline
	baseline := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/delete-empty-test",
		EncryptedData:        []byte("delete empty test data"),
		Sha:                  "sha-delete-empty",
		VerificationStrategy: "ONE_TIME_USE",
	}
	err = store.Save(baseline)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Delete with empty SHA should not error and should not delete anything
	err = store.Delete("")
	if err != nil {
		t.Errorf("Delete with empty SHA should not return error: %v", err)
	}

	// Original baseline should still exist
	retrieved := store.GetBySha("sha-delete-empty")
	if retrieved == nil {
		t.Error("Original baseline should still exist after deleting with empty SHA")
	}

	// Count should still be 1
	if count := store.Count(); count != 1 {
		t.Errorf("Count should still be 1, got %d", count)
	}
}

// TestPersistentBaselineStore_SetNilBaseline tests Set with nil baseline
func TestPersistentBaselineStore_SetNilBaseline(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_set_nil.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Add a baseline first
	baseline := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/set-nil-test",
		EncryptedData:        []byte("set nil test data"),
		Sha:                  "sha-set-nil",
		VerificationStrategy: "ONE_TIME_USE",
	}
	err = store.Save(baseline)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Set with nil baseline should not error
	err = store.Set("/tmp/set-nil-test", nil)
	if err != nil {
		t.Errorf("Set with nil baseline should not return error: %v", err)
	}

	// Original baseline should still exist (nil Set doesn't delete)
	retrieved := store.Get("/tmp/set-nil-test")
	if retrieved == nil {
		t.Error("Original baseline should still exist after Set nil")
	}

	// Count should still be 1
	if count := store.Count(); count != 1 {
		t.Errorf("Count should still be 1, got %d", count)
	}
}

// TestPersistentBaselineStore_NonExistentDirectory tests saving to non-existent directory
func TestPersistentBaselineStore_NonExistentDirectory(t *testing.T) {
	tempDir := t.TempDir()
	// Create a nested path that doesn't exist
	storePath := filepath.Join(tempDir, "nonexistent", "nested", "dir", "baseline.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store with non-existent directory: %v", err)
	}

	// Add a baseline
	baseline := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/nested-dir-test",
		EncryptedData:        []byte("nested dir test data"),
		Sha:                  "sha-nested-dir",
		VerificationStrategy: "ONE_TIME_USE",
	}
	err = store.Save(baseline)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Verify file was created in nested directory
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		t.Fatal("Store file should be created in nested directory")
	}

	// Reload and verify
	store2, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to reload store from nested directory: %v", err)
	}
	retrieved := store2.Get("/tmp/nested-dir-test")
	if retrieved == nil {
		t.Error("Baseline should be accessible after reload from nested directory")
	}
}

// TestPersistentBaselineStore_ConcurrentAccess tests concurrent read/write safety
func TestPersistentBaselineStore_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "baseline_concurrent.enc")
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create persistent baseline store: %v", err)
	}

	// Initial baseline
	baseline := &enclave.CredentialBaseline{
		TargetPath:           "/tmp/concurrent-test",
		EncryptedData:        []byte("initial concurrent data"),
		Sha:                  "sha-concurrent",
		VerificationStrategy: "ONE_TIME_USE",
	}
	err = store.Save(baseline)
	if err != nil {
		t.Fatalf("Failed to save initial baseline: %v", err)
	}

	// Concurrent operations
	numOps := 50
	done := make(chan bool, numOps*2)

	// Concurrent writes
	for i := 0; i < numOps; i++ {
		go func(idx int) {
			bl := &enclave.CredentialBaseline{
				TargetPath:           filepath.Join("/tmp", fmt.Sprintf("concurrent-%d", idx)),
				EncryptedData:        []byte(fmt.Sprintf("concurrent data %d", idx)),
				Sha:                  fmt.Sprintf("sha-concurrent-%d", idx),
				VerificationStrategy: "ONE_TIME_USE",
			}
			store.Save(bl)
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numOps; i++ {
		go func() {
			store.Get("/tmp/concurrent-test")
			store.GetBySha("sha-concurrent")
			store.Count()
			store.ListAll()
			done <- true
		}()
	}

	// Wait for all operations
	for i := 0; i < numOps*2; i++ {
		<-done
	}

	// Verify final state is consistent
	if count := store.Count(); count < 1 {
		t.Errorf("Count should be at least 1, got %d", count)
	}

	// Original baseline should still be accessible
	retrieved := store.GetBySha("sha-concurrent")
	if retrieved == nil {
		t.Error("Original baseline should still be accessible after concurrent operations")
	}
}

func TestPersistentBaselineStore_EmptyAndInvalidFiles(t *testing.T) {
	// Create a temporary file for testing
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "nonexistent_store.enc")

	// Generate a master key
	masterKey, err := generateRandomMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	// Creating a store with a non-existent file should succeed (empty store)
	store, err := NewPersistentBaselineStore(storePath, masterKey)
	if err != nil {
		t.Fatalf("Failed to create baseline store with non-existent file: %v", err)
	}

	// Get on non-existent baseline should return nil
	nilBaseline := store.Get("/nonexistent/path")
	if nilBaseline != nil {
		t.Error("Get on non-existent path should return nil")
	}

	// Save a baseline
	testBaseline := &enclave.CredentialBaseline{
		TargetPath:    "/tmp/empty-test",
		EncryptedData: []byte("empty test data"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0644,
		},
		AllowedBinaries:       []string{"/bin/cat"},
		AllowedBinariesSha256: []string{"sha256-test"},
		VerificationStrategy:  "ONE_TIME_USE",
	}

	err = store.Save(testBaseline)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Verify it's accessible
	retrievedBaseline := store.Get("/tmp/empty-test")
	if retrievedBaseline == nil {
		t.Fatal("Failed to retrieve saved baseline")
	}
}
