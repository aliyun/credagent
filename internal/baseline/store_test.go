package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func storeTestBL(sha, path, content, strategy string) *CredentialBaseline {
	return NewCredentialBaseline(
		sha,
		FileMetadata{TargetPath: path},
		&AccessRule{VerificationStrategy: strategy},
		[]byte(content),
	)
}

func storeGetContent(t *testing.T, bl *CredentialBaseline) []byte {
	t.Helper()
	c, err := bl.FileContent()
	require.NoError(t, err)
	return c
}

// ─── InMemoryBaselineStore tests ──────────────────────────────────────────────

func TestInMemoryBaselineStore_BasicCRUD(t *testing.T) {
	store := NewInMemoryBaselineStore()
	assert.Equal(t, 0, store.Count(), "new store should be empty")

	bl1 := storeTestBL("sha256-test-hash-1", "/tmp/test-file-1", "secret data 1", "ONE_TIME_USE")
	require.NoError(t, store.Save(bl1))
	assert.Equal(t, 1, store.Count())

	// GetBySha
	retrieved := store.GetBySha("sha256-test-hash-1")
	require.NotNil(t, retrieved)
	assert.Equal(t, "/tmp/test-file-1", retrieved.Metadata().TargetPath)
	assert.Equal(t, "sha256-test-hash-1", retrieved.SHA())

	// Get by targetPath
	retrieved = store.Get("/tmp/test-file-1")
	require.NotNil(t, retrieved)
	assert.Equal(t, "sha256-test-hash-1", retrieved.SHA())

	// Delete
	require.NoError(t, store.Delete("sha256-test-hash-1"))
	assert.Equal(t, 0, store.Count())
	assert.Nil(t, store.GetBySha("sha256-test-hash-1"))
}

func TestInMemoryBaselineStore_MultipleBaselines(t *testing.T) {
	store := NewInMemoryBaselineStore()

	inputs := []struct{ sha, path, content string }{
		{"sha-1", "/tmp/file-1", "secret 1"},
		{"sha-2", "/tmp/file-2", "secret 2"},
		{"sha-3", "/tmp/file-3", "secret 3"},
	}

	for _, inp := range inputs {
		require.NoError(t, store.Save(storeTestBL(inp.sha, inp.path, inp.content, "ONE_TIME_USE")))
	}
	assert.Equal(t, 3, store.Count())

	all := store.ListAll()
	assert.Len(t, all, 3)

	for _, inp := range inputs {
		retrieved := store.GetBySha(inp.sha)
		require.NotNil(t, retrieved, "should find sha=%s", inp.sha)
		assert.Equal(t, inp.path, retrieved.Metadata().TargetPath)
		assert.Equal(t, inp.sha, retrieved.SHA())
	}
}

func TestInMemoryBaselineStore_UpdateSamePath(t *testing.T) {
	store := NewInMemoryBaselineStore()

	bl1 := storeTestBL("sha-original", "/tmp/test-file", "original data", "ONE_TIME_USE")
	require.NoError(t, store.Save(bl1))

	// Update with different SHA but same path — old SHA must be evicted.
	bl2 := storeTestBL("sha-updated", "/tmp/test-file", "updated data", "SPEC_VERIFICATION")
	require.NoError(t, store.Save(bl2))

	assert.Equal(t, 1, store.Count())
	assert.Nil(t, store.GetBySha("sha-original"), "old SHA should be gone")

	retrieved := store.GetBySha("sha-updated")
	require.NotNil(t, retrieved)
	assert.Equal(t, "updated data", string(storeGetContent(t, retrieved)))
}

func TestInMemoryBaselineStore_Set(t *testing.T) {
	store := NewInMemoryBaselineStore()

	require.NoError(t, store.Save(storeTestBL("sha-set-1", "/tmp/set-test", "initial data", "ONE_TIME_USE")))

	bl2 := storeTestBL("sha-set-2", "/tmp/set-test", "set data", "SPEC_VERIFICATION")
	require.NoError(t, store.Set("/tmp/set-test", bl2))

	assert.Equal(t, 1, store.Count())
	retrieved := store.GetBySha("sha-set-2")
	require.NotNil(t, retrieved)
	assert.Equal(t, "set data", string(storeGetContent(t, retrieved)))
}

func TestInMemoryBaselineStore_NilBaseline(t *testing.T) {
	store := NewInMemoryBaselineStore()

	assert.NoError(t, store.Save(nil))
	assert.NoError(t, store.Set("/tmp/path", nil))
	assert.Equal(t, 0, store.Count())
}

func TestInMemoryBaselineStore_EmptySHA(t *testing.T) {
	store := NewInMemoryBaselineStore()

	bl := storeTestBL("", "/tmp/no-sha", "data without sha", "ONE_TIME_USE")
	require.NoError(t, store.Save(bl))

	// Empty SHA must not be indexed.
	assert.Equal(t, 0, store.Count())
	assert.Nil(t, store.GetBySha(""))
	assert.Nil(t, store.Get("/tmp/no-sha"))
}

func TestInMemoryBaselineStore_DeleteNonExistent(t *testing.T) {
	store := NewInMemoryBaselineStore()
	assert.NoError(t, store.Delete("nonexistent-sha"))
}

func TestInMemoryBaselineStore_GetNonExistent(t *testing.T) {
	store := NewInMemoryBaselineStore()
	assert.Nil(t, store.GetBySha("nonexistent-sha"))
	assert.Nil(t, store.Get("/nonexistent/path"))
}

func TestInMemoryBaselineStore_DeepCopy(t *testing.T) {
	store := NewInMemoryBaselineStore()

	originalContent := []byte("original secret")
	bl := NewCredentialBaseline("sha-deep-copy", FileMetadata{TargetPath: "/tmp/deep-copy-test"}, &AccessRule{}, originalContent)
	require.NoError(t, store.Save(bl))

	// Modify a retrieved baseline's content — store must be unaffected.
	r1 := store.GetBySha("sha-deep-copy")
	require.NotNil(t, r1)
	c1 := storeGetContent(t, r1)
	c1[0] = 'X'

	r2 := store.GetBySha("sha-deep-copy")
	require.NotNil(t, r2)
	assert.Equal(t, "original secret", string(storeGetContent(t, r2)), "store content should be unmodified")

	// Also test Get.
	r3 := store.Get("/tmp/deep-copy-test")
	require.NotNil(t, r3)
	assert.Equal(t, "original secret", string(storeGetContent(t, r3)))
}

// ─── NewBaselineStoreFromPath tests ──────────────────────────────────────────

func TestNewBaselineStoreFromPath_EmptyPath(t *testing.T) {
	store, err := NewBaselineStoreFromPath("", []byte("test-master-key"))
	require.NoError(t, err)
	require.NotNil(t, store)
	assert.Equal(t, 0, store.Count())
}

func TestNewBaselineStoreFromPath_BoltDBFile(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "baseline.db")
	masterKey, err := generateRandomMasterKey()
	require.NoError(t, err)

	// Seed a BoltDB file.
	boltStore, err := NewBoltDBBaselineStore(dbPath, masterKey, "")
	require.NoError(t, err)
	require.NoError(t, boltStore.Save(storeTestBL("sha-from-path", "/tmp/from-path-test", "test data", "ONE_TIME_USE")))
	boltStore.Close()

	// Open via NewBaselineStoreFromPath.
	store, err := NewBaselineStoreFromPath(dbPath, masterKey)
	require.NoError(t, err)
	require.NotNil(t, store)

	retrieved := store.GetBySha("sha-from-path")
	require.NotNil(t, retrieved)
	assert.Equal(t, "/tmp/from-path-test", retrieved.Metadata().TargetPath)
}

func TestNewBaselineStoreFromPath_LegacyMigration(t *testing.T) {
	tempDir := t.TempDir()
	legacyPath := filepath.Join(tempDir, "baseline.enc")
	masterKey, err := generateRandomMasterKey()
	require.NoError(t, err)

	// Create v0 legacy file.
	legacyStore, err := NewPersistentBaselineStore(legacyPath, masterKey)
	require.NoError(t, err)
	require.NoError(t, legacyStore.Save(newLegacyBaseline("sha-legacy-path", "/tmp/legacy-path-test", "legacy data", "ONE_TIME_USE")))

	// Open via NewBaselineStoreFromPath — should auto-migrate.
	store, err := NewBaselineStoreFromPath(legacyPath, masterKey)
	require.NoError(t, err)
	require.NotNil(t, store)

	retrieved := store.GetBySha("sha-legacy-path")
	require.NotNil(t, retrieved)
	assert.Equal(t, "/tmp/legacy-path-test", retrieved.Metadata().TargetPath)
}

func TestNewBaselineStoreFromPath_NewFile(t *testing.T) {
	tempDir := t.TempDir()
	newPath := filepath.Join(tempDir, "new_baseline.db")
	masterKey, err := generateRandomMasterKey()
	require.NoError(t, err)

	store, err := NewBaselineStoreFromPath(newPath, masterKey)
	require.NoError(t, err)
	require.NotNil(t, store)
	assert.Equal(t, 0, store.Count())

	_, err = os.Stat(newPath)
	assert.NoError(t, err, "BoltDB file should have been created")
}
