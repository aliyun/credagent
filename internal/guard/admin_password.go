package guard

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/alibaba/CredAgent/pkg/crypto"
	"github.com/alibaba/CredAgent/pkg/logger"
	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32

	algoArgon2id = "argon2id"
	algoSHA256   = "sha256"

	maxFailedAttempts   = 5
	baseBackoffDuration = 1 * time.Second
	maxBackoffDuration  = 30 * time.Second
)

// AdminPasswordStore manages the administrator password with salt and hash
type AdminPasswordStore struct {
	passwordFile   string
	passwordHash   []byte
	salt           []byte
	algorithm      string
	failedAttempts int
	lastFailedAt   time.Time
	mu             sync.RWMutex
}

// AdminPasswordData represents the structure of the stored password data
type AdminPasswordData struct {
	Hash      string `json:"hash"`
	Salt      string `json:"salt"`
	Algorithm string `json:"algorithm,omitempty"`
}

// NewAdminPasswordStore creates a new admin password store
func NewAdminPasswordStore(passwordFile string) (*AdminPasswordStore, error) {
	store := &AdminPasswordStore{
		passwordFile: passwordFile,
	}

	if err := store.loadFromFile(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load admin password from file: %w", err)
		}
		logger.Info("Admin password file does not exist yet: %s", passwordFile)
	}

	return store, nil
}

// SetPassword sets the admin password with a new salt and argon2id hash
func (s *AdminPasswordStore) SetPassword(password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	s.passwordHash = hashArgon2id(password, salt)
	s.salt = salt
	s.algorithm = algoArgon2id
	s.failedAttempts = 0

	return s.saveToFile()
}

// VerifyPassword verifies if the provided password matches the stored password.
// Includes rate limiting with exponential backoff on repeated failures.
// If the stored hash uses the legacy SHA-256 algorithm, a successful verification
// triggers an automatic migration to argon2id.
func (s *AdminPasswordStore) VerifyPassword(password string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.passwordHash == nil || s.salt == nil {
		logger.Warn("Admin password not set, access denied")
		return false
	}

	// Rate limiting: enforce backoff if too many recent failures
	if s.failedAttempts >= maxFailedAttempts {
		backoff := s.calcBackoff()
		elapsed := time.Since(s.lastFailedAt)
		if elapsed < backoff {
			remaining := backoff - elapsed
			logger.Warn("Password verification rate-limited. Too many failed attempts (%d). Retry after %.0fs",
				s.failedAttempts, remaining.Seconds())
			return false
		}
	}

	var match bool
	if s.algorithm == algoSHA256 {
		providedHash := hashSHA256(password, s.salt)
		match = subtle.ConstantTimeCompare(s.passwordHash, providedHash) == 1
		crypto.ZeroBytes(providedHash)
	} else {
		providedHash := hashArgon2id(password, s.salt)
		match = subtle.ConstantTimeCompare(s.passwordHash, providedHash) == 1
		crypto.ZeroBytes(providedHash)
	}

	if match {
		s.failedAttempts = 0
		if s.algorithm == algoSHA256 {
			s.upgradeToArgon2id(password)
		}
		return true
	}

	s.failedAttempts++
	s.lastFailedAt = time.Now()
	logger.Warn("Failed admin password attempt (%d/%d)", s.failedAttempts, maxFailedAttempts)
	return false
}

// IsPasswordSet checks if an admin password has been set
func (s *AdminPasswordStore) IsPasswordSet() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.passwordHash != nil && s.salt != nil
}

func hashArgon2id(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

func hashSHA256(password string, salt []byte) []byte {
	combined := append([]byte(password), salt...)
	hash := sha256.Sum256(combined)
	crypto.ZeroBytes(combined)
	return hash[:]
}

// upgradeToArgon2id migrates a legacy SHA-256 hash to argon2id in place.
// Caller must hold s.mu.
func (s *AdminPasswordStore) upgradeToArgon2id(password string) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		logger.Error("Failed to generate salt for argon2id migration: %v", err)
		return
	}

	crypto.ZeroBytes(s.passwordHash)
	s.passwordHash = hashArgon2id(password, salt)
	s.salt = salt
	s.algorithm = algoArgon2id

	if err := s.saveToFile(); err != nil {
		logger.Error("Failed to persist argon2id migration: %v", err)
		return
	}
	logger.Info("Successfully migrated admin password from SHA-256 to argon2id")
}

func (s *AdminPasswordStore) calcBackoff() time.Duration {
	excess := s.failedAttempts - maxFailedAttempts
	d := baseBackoffDuration
	for i := 0; i < excess; i++ {
		d *= 2
		if d > maxBackoffDuration {
			return maxBackoffDuration
		}
	}
	return d
}

func (s *AdminPasswordStore) saveToFile() error {
	dir := filepath.Dir(s.passwordFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for password file: %w", err)
	}

	data := AdminPasswordData{
		Hash:      hex.EncodeToString(s.passwordHash),
		Salt:      hex.EncodeToString(s.salt),
		Algorithm: s.algorithm,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal admin password data: %w", err)
	}

	return os.WriteFile(s.passwordFile, jsonData, 0600)
}

func (s *AdminPasswordStore) loadFromFile() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	jsonData, err := os.ReadFile(s.passwordFile)
	if err != nil {
		return err
	}

	var data AdminPasswordData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("failed to unmarshal admin password data: %w", err)
	}

	salt, err := hex.DecodeString(data.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err := hex.DecodeString(data.Hash)
	if err != nil {
		return fmt.Errorf("failed to decode hash: %w", err)
	}

	s.passwordHash = hash
	s.salt = salt

	if data.Algorithm == "" {
		s.algorithm = algoSHA256
		logger.Warn("Loaded legacy SHA-256 password hash — will auto-migrate to argon2id on next successful verification")
	} else {
		s.algorithm = data.Algorithm
	}

	logger.Info("Successfully loaded admin password hash from: %s (algorithm: %s)", s.passwordFile, s.algorithm)
	return nil
}
