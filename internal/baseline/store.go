package baseline

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/alibaba/CredAgent/pkg/logger"
)

// BaselineStore defines the interface for the credential baseline store.
// All methods operate on the Go-native CredentialBaseline type; protobuf messages
// are only used at the gRPC boundary and must never leak into the store layer.
type BaselineStore interface {
	// Save stores a credential baseline (insert or overwrite by SHA).
	Save(baseline *CredentialBaseline) error

	// Get retrieves a credential baseline by target path.
	Get(targetPath string) *CredentialBaseline

	// GetBySha retrieves a credential baseline by its SHA identifier.
	GetBySha(sha string) *CredentialBaseline

	// Delete removes a credential baseline by SHA.
	Delete(sha string) error

	// Count returns the number of baselines in the store.
	Count() int

	// ListAll returns all stored baselines.
	ListAll() []*CredentialBaseline

	// Set updates an existing credential baseline (semantically equivalent to Save).
	Set(targetPath string, baseline *CredentialBaseline) error
}

// ─── InMemoryBaselineStore ────────────────────────────────────────────────────

// InMemoryBaselineStore implements BaselineStore using an in-memory SHA-indexed map.
// All CredentialBaseline objects stored here have all fields pre-populated (no lazy loading).
type InMemoryBaselineStore struct {
	shaIndex map[string]*CredentialBaseline
	mu       sync.RWMutex
}

// NewInMemoryBaselineStore creates a new, empty in-memory baseline store.
func NewInMemoryBaselineStore() *InMemoryBaselineStore {
	return &InMemoryBaselineStore{
		shaIndex: make(map[string]*CredentialBaseline),
	}
}

// Save stores a credential baseline.  Baselines with an empty SHA are ignored.
// If a baseline with the same target path already exists under a different SHA,
// the old entry is removed first.
func (s *InMemoryBaselineStore) Save(bl *CredentialBaseline) error {
	if bl == nil || bl.SHA() == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove old entry for the same target path (different SHA).
	if old := s.findByTargetPathLocked(bl.Metadata().TargetPath); old != nil && old.SHA() != bl.SHA() {
		delete(s.shaIndex, old.SHA())
	}

	s.shaIndex[bl.SHA()] = cloneBaseline(bl)
	return nil
}

// Delete removes the baseline with the given SHA.
func (s *InMemoryBaselineStore) Delete(sha string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.shaIndex, sha)
	return nil
}

// Get retrieves a baseline by target path.
func (s *InMemoryBaselineStore) Get(targetPath string) *CredentialBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if bl := s.findByTargetPathLocked(targetPath); bl != nil {
		return cloneBaseline(bl)
	}
	return nil
}

// GetBySha retrieves a baseline by its SHA identifier.
func (s *InMemoryBaselineStore) GetBySha(sha string) *CredentialBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if bl, ok := s.shaIndex[sha]; ok {
		return cloneBaseline(bl)
	}
	return nil
}

// Count returns the number of baselines in the store.
func (s *InMemoryBaselineStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.shaIndex)
}

// ListAll returns deep copies of all baselines.
func (s *InMemoryBaselineStore) ListAll() []*CredentialBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*CredentialBaseline, 0, len(s.shaIndex))
	for _, bl := range s.shaIndex {
		result = append(result, cloneBaseline(bl))
	}
	return result
}

// Set updates or inserts a baseline.
func (s *InMemoryBaselineStore) Set(_ string, bl *CredentialBaseline) error {
	return s.Save(bl)
}

// findByTargetPathLocked is NOT thread-safe; the caller must hold at least a read lock.
func (s *InMemoryBaselineStore) findByTargetPathLocked(targetPath string) *CredentialBaseline {
	for _, bl := range s.shaIndex {
		if bl.Metadata().TargetPath == targetPath {
			return bl
		}
	}
	return nil
}

// cloneBaseline returns a deep copy of a CredentialBaseline.
// Rule and fileContent are copied by value so mutations do not affect the store.
func cloneBaseline(src *CredentialBaseline) *CredentialBaseline {
	if src == nil {
		return nil
	}

	dst := &CredentialBaseline{
		shaIdentifier: src.shaIdentifier,
		metadata:      src.metadata,
		ruleLoaded:    src.ruleLoaded,
		contentLoaded: src.contentLoaded,
	}

	if src.metadata.Permissions != nil {
		p := *src.metadata.Permissions
		dst.metadata.Permissions = &p
	}

	if src.rule != nil {
		r := *src.rule
		r.AllowedPrograms = cloneStringSlice(src.rule.AllowedPrograms)
		r.AllowedProgramsSha256 = cloneStringSlice(src.rule.AllowedProgramsSha256)
		dst.rule = &r
	}

	if src.fileContent != nil {
		c := make([]byte, len(src.fileContent))
		copy(c, src.fileContent)
		dst.fileContent = c
	}

	return dst
}

// cloneStringSlice returns a copy of a string slice.
func cloneStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	c := make([]string, len(s))
	copy(c, s)
	return c
}

// ─── NewBaselineStoreFromPath ─────────────────────────────────────────────────

// NewBaselineStoreFromPath creates a BaselineStore from a file path.
// If filePath is empty, an in-memory store is returned.
// Otherwise a BoltDB store is opened (with automatic migration from legacy formats).
func NewBaselineStoreFromPath(filePath string, masterKey []byte) (BaselineStore, error) {
	if filePath == "" {
		logger.Info("Using in-memory baseline store")
		return NewInMemoryBaselineStore(), nil
	}

	store, err := NewBoltDBBaselineStore(filePath, masterKey, "")
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "file exists but is not a valid BoltDB") ||
			strings.Contains(errStr, "BoltDB file exists but has invalid structure") ||
			strings.Contains(errStr, "invalid database") ||
			strings.Contains(errStr, "unrecognized file format") ||
			strings.Contains(errStr, "corrupt") ||
			strings.Contains(errStr, "malformed") {

			logger.Info("Detected old format or invalid BoltDB format in baseline file: %s, initiating migration to BoltDB format", filePath)
			migratedStore, migrationErr := NewBoltDBBaselineStore(filePath, masterKey, filePath)
			if migrationErr != nil {
				return nil, fmt.Errorf("migration from old format failed: %w", migrationErr)
			}
			logger.Info("Successfully migrated baseline file to BoltDB format: %s", filePath)
			return migratedStore, nil
		}

		logger.Error("Failed to open baseline file %s: %v", filePath, err)

		var pathError *os.PathError
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("permission denied accessing baseline file %s: %w", filePath, err)
		} else if errors.As(err, &pathError) {
			return nil, fmt.Errorf("path error accessing baseline file %s: %w", filePath, err)
		}

		if strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "locked") ||
			strings.Contains(errStr, "resource busy") ||
			strings.Contains(errStr, "already in use") ||
			strings.Contains(errStr, "database is locked") {
			return nil, fmt.Errorf("baseline file is locked or timed out %s: %w", filePath, err)
		}

		return nil, fmt.Errorf("failed to create BoltDB baseline store: %w", err)
	}

	logger.Debug("Successfully opened existing BoltDB baseline file: %s", filePath)
	return store, nil
}
