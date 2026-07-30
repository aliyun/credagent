package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAdminPasswordStore(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	assert.NoError(t, err)
	assert.NotNil(t, store)
	assert.Equal(t, passwordFile, store.passwordFile)
}

func TestNewAdminPasswordStore_ExistingFile(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store1, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)
	require.NotNil(t, store1)

	err = store1.SetPassword("testpassword")
	require.NoError(t, err)

	store2, err := NewAdminPasswordStore(passwordFile)
	assert.NoError(t, err)
	assert.NotNil(t, store2)

	assert.True(t, store2.VerifyPassword("testpassword"))
}

func TestAdminPasswordStore_SetPassword(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	err = store.SetPassword("mysecretpassword")
	assert.NoError(t, err)

	assert.True(t, store.IsPasswordSet())
	assert.NotNil(t, store.passwordHash)
	assert.NotNil(t, store.salt)

	_, err = os.Stat(passwordFile)
	assert.NoError(t, err)
}

func TestAdminPasswordStore_SetPassword_Twice(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	err = store.SetPassword("password1")
	require.NoError(t, err)

	err = store.SetPassword("password2")
	assert.NoError(t, err)

	assert.False(t, store.VerifyPassword("password1"))
	assert.True(t, store.VerifyPassword("password2"))
}

func TestAdminPasswordStore_VerifyPassword_Correct(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	testPassword := "correctpassword"
	err = store.SetPassword(testPassword)
	require.NoError(t, err)

	assert.True(t, store.VerifyPassword(testPassword))
}

func TestAdminPasswordStore_VerifyPassword_Incorrect(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	err = store.SetPassword("correctpassword")
	require.NoError(t, err)

	assert.False(t, store.VerifyPassword("wrongpassword"))
	assert.False(t, store.VerifyPassword(""))
}

func TestAdminPasswordStore_VerifyPassword_NotSet(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	assert.False(t, store.VerifyPassword("anypassword"))
	assert.False(t, store.VerifyPassword(""))
}

func TestAdminPasswordStore_IsPasswordSet(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	assert.False(t, store.IsPasswordSet())

	err = store.SetPassword("testpassword")
	require.NoError(t, err)
	assert.True(t, store.IsPasswordSet())
}

func TestAdminPasswordStore_HashArgon2id_Deterministic(t *testing.T) {
	password := "testpassword"
	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	hash1 := hashArgon2id(password, salt)
	hash2 := hashArgon2id(password, salt)
	assert.Equal(t, hash1, hash2)

	salt2 := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	hash3 := hashArgon2id(password, salt2)
	assert.NotEqual(t, hash1, hash3)
}

func TestAdminPasswordStore_Persistence(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store1, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	testPassword := "persistentpassword"
	err = store1.SetPassword(testPassword)
	require.NoError(t, err)

	store2, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	assert.True(t, store2.VerifyPassword(testPassword))
}

func TestAdminPasswordStore_LoadFromFile_Corrupted(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	err := os.WriteFile(passwordFile, []byte("corrupted json"), 0600)
	require.NoError(t, err)

	_, err = NewAdminPasswordStore(passwordFile)
	assert.Error(t, err)
}

func TestAdminPasswordStore_EmptyPassword(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	err = store.SetPassword("")
	require.NoError(t, err)
	assert.True(t, store.IsPasswordSet())

	assert.True(t, store.VerifyPassword(""))
	assert.False(t, store.VerifyPassword("nonempty"))
}

func TestAdminPasswordStore_RateLimiting(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	err = store.SetPassword("correct")
	require.NoError(t, err)

	// Exhaust failed attempts
	for i := 0; i < maxFailedAttempts; i++ {
		assert.False(t, store.VerifyPassword("wrong"))
	}

	// Now even the correct password should be rate-limited
	assert.False(t, store.VerifyPassword("correct"))

	// Wait for backoff to expire
	store.mu.Lock()
	store.lastFailedAt = time.Now().Add(-2 * maxBackoffDuration)
	store.mu.Unlock()

	// Should work again after backoff expires
	assert.True(t, store.VerifyPassword("correct"))

	// Failed counter should be reset after successful verification
	assert.False(t, store.VerifyPassword("wrong"))
	assert.Equal(t, 1, store.failedAttempts)
}

func TestAdminPasswordStore_PersistenceAlgorithmField(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)

	err = store.SetPassword("testpass")
	require.NoError(t, err)

	// Read the saved file and verify it contains the algorithm field
	jsonData, err := os.ReadFile(passwordFile)
	require.NoError(t, err)

	var data AdminPasswordData
	err = json.Unmarshal(jsonData, &data)
	require.NoError(t, err)
	assert.Equal(t, "argon2id", data.Algorithm)
}

func TestAdminPasswordStore_LegacySHA256Migration(t *testing.T) {
	tempDir := t.TempDir()
	passwordFile := filepath.Join(tempDir, "admin_password.json")

	// Simulate a legacy SHA-256 password file (no algorithm field)
	password := "legacypassword"
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	combined := append([]byte(password), salt...)
	hash := sha256.Sum256(combined)

	legacyData := AdminPasswordData{
		Hash: hex.EncodeToString(hash[:]),
		Salt: hex.EncodeToString(salt),
		// Algorithm intentionally omitted — legacy format
	}
	jsonData, err := json.MarshalIndent(legacyData, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(passwordFile, jsonData, 0600)
	require.NoError(t, err)

	// Load the legacy file
	store, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)
	assert.Equal(t, algoSHA256, store.algorithm)

	// Wrong password should fail
	assert.False(t, store.VerifyPassword("wrongpassword"))

	// Correct password should succeed and trigger migration
	assert.True(t, store.VerifyPassword(password))

	// Verify the file has been migrated to argon2id
	migratedJson, err := os.ReadFile(passwordFile)
	require.NoError(t, err)
	var migratedData AdminPasswordData
	err = json.Unmarshal(migratedJson, &migratedData)
	require.NoError(t, err)
	assert.Equal(t, "argon2id", migratedData.Algorithm)

	// Salt should have changed (new random salt for argon2id)
	assert.NotEqual(t, hex.EncodeToString(salt), migratedData.Salt)

	// Password should still work after migration
	assert.True(t, store.VerifyPassword(password))
	assert.False(t, store.VerifyPassword("wrongpassword"))

	// Reload from file — should work with argon2id now
	store2, err := NewAdminPasswordStore(passwordFile)
	require.NoError(t, err)
	assert.Equal(t, algoArgon2id, store2.algorithm)
	assert.True(t, store2.VerifyPassword(password))
}
