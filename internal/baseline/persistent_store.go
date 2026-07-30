// Package baseline provides the legacy JSON-encrypted baseline store.
//
// PersistentBaselineStore is kept for migration testing only.  It writes baselines
// in the old encrypted-JSON format so that migration tests can create a v0 file
// and verify that BoltDBBaselineStore migrates it correctly.
//
// IMPORTANT: PersistentBaselineStore does NOT implement BaselineStore.
// Production code must use BoltDBBaselineStore or InMemoryBaselineStore.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/pkg/crypto"
	"google.golang.org/protobuf/proto"
)

// PersistentBaselineStore is a legacy JSON-encrypted store used exclusively for
// creating test fixtures that exercise the v0→v2 migration path.
type PersistentBaselineStore struct {
	baselines map[string]*enclave.CredentialBaseline // keyed by target path
	shaIndex  map[string]*enclave.CredentialBaseline // keyed by sha
	storePath string
	masterKey []byte
	mu        sync.RWMutex
}

// NewPersistentBaselineStore creates a new persistent baseline store with encryption.
func NewPersistentBaselineStore(storePath string, masterKey []byte) (*PersistentBaselineStore, error) {
	store := &PersistentBaselineStore{
		baselines: make(map[string]*enclave.CredentialBaseline),
		shaIndex:  make(map[string]*enclave.CredentialBaseline),
		storePath: storePath,
		masterKey: masterKey,
	}
	if err := store.loadFromFile(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load baseline store from file: %w", err)
		}
	}
	return store, nil
}

// Save stores a credential baseline and persists it to the encrypted JSON file.
func (s *PersistentBaselineStore) Save(baseline *enclave.CredentialBaseline) error {
	if baseline == nil {
		return nil
	}
	s.mu.Lock()
	cloned := proto.Clone(baseline).(*enclave.CredentialBaseline)
	if old, exists := s.baselines[baseline.GetTargetPath()]; exists && old.GetSha() != "" {
		delete(s.shaIndex, old.GetSha())
	}
	s.baselines[baseline.GetTargetPath()] = cloned
	if cloned.GetSha() != "" {
		s.shaIndex[cloned.GetSha()] = cloned
	}
	s.mu.Unlock()
	return s.saveToFile()
}

// Delete removes a credential baseline by SHA.
func (s *PersistentBaselineStore) Delete(sha string) error {
	if sha == "" {
		return nil
	}
	s.mu.Lock()
	if bl, exists := s.shaIndex[sha]; exists {
		if bl.GetTargetPath() != "" {
			delete(s.baselines, bl.GetTargetPath())
		}
		delete(s.shaIndex, sha)
	}
	s.mu.Unlock()
	return s.saveToFile()
}

// Get retrieves a credential baseline by target path.
func (s *PersistentBaselineStore) Get(targetPath string) *enclave.CredentialBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if bl, ok := s.baselines[targetPath]; ok {
		return proto.Clone(bl).(*enclave.CredentialBaseline)
	}
	return nil
}

// GetBySha retrieves a credential baseline by SHA.
func (s *PersistentBaselineStore) GetBySha(sha string) *enclave.CredentialBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if bl, ok := s.shaIndex[sha]; ok {
		return proto.Clone(bl).(*enclave.CredentialBaseline)
	}
	return nil
}

// Count returns the number of baselines stored.
func (s *PersistentBaselineStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.baselines)
}

// GetAll returns all stored baselines keyed by target path (deep copies).
func (s *PersistentBaselineStore) GetAll() map[string]*enclave.CredentialBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*enclave.CredentialBaseline)
	for k, v := range s.baselines {
		result[k] = proto.Clone(v).(*enclave.CredentialBaseline)
	}
	return result
}

// ListAll returns all stored baselines as a slice (deep copies).
func (s *PersistentBaselineStore) ListAll() []*enclave.CredentialBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*enclave.CredentialBaseline, 0, len(s.baselines))
	for _, v := range s.baselines {
		result = append(result, proto.Clone(v).(*enclave.CredentialBaseline))
	}
	return result
}

// Set updates an existing credential baseline.
func (s *PersistentBaselineStore) Set(targetPath string, baseline *enclave.CredentialBaseline) error {
	if baseline == nil {
		return nil
	}
	s.mu.Lock()
	cloned := proto.Clone(baseline).(*enclave.CredentialBaseline)
	if old, exists := s.baselines[targetPath]; exists && old.GetSha() != "" {
		delete(s.shaIndex, old.GetSha())
	}
	s.baselines[targetPath] = cloned
	if cloned.GetSha() != "" {
		s.shaIndex[cloned.GetSha()] = cloned
	}
	s.mu.Unlock()
	return s.saveToFile()
}

func (s *PersistentBaselineStore) saveToFile() error {
	s.mu.RLock()
	data := make(map[string]*enclave.CredentialBaseline, len(s.baselines))
	for k, v := range s.baselines {
		data[k] = v
	}
	s.mu.RUnlock()

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal baseline data: %w", err)
	}
	encryptedData, err := crypto.Encrypt(jsonData, s.masterKey)
	crypto.ZeroBytes(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt baseline data: %w", err)
	}
	storeDir := filepath.Dir(s.storePath)
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for baseline store: %w", err)
	}
	return os.WriteFile(s.storePath, encryptedData, 0600)
}

func (s *PersistentBaselineStore) loadFromFile() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	encryptedData, err := os.ReadFile(s.storePath)
	if err != nil {
		return err
	}
	jsonData, err := crypto.Decrypt(encryptedData, s.masterKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt baseline data: %w", err)
	}
	var data map[string]*enclave.CredentialBaseline
	err = json.Unmarshal(jsonData, &data)
	crypto.ZeroBytes(jsonData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal baseline data: %w", err)
	}
	s.baselines = data
	s.shaIndex = make(map[string]*enclave.CredentialBaseline)
	for _, bl := range s.baselines {
		if bl.GetSha() != "" {
			s.shaIndex[bl.GetSha()] = bl
		}
	}
	return nil
}
