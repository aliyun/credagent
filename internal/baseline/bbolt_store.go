package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/pkg/crypto"
	"github.com/aliyun/credagent/pkg/logger"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Sentinel errors for BoltDB store operations.
var (
	ErrInvalidBoltDBFormat    = errors.New("file is not a valid BoltDB format")
	ErrBoltDBStructureInvalid = errors.New("BoltDB file has invalid structure")
	ErrBoltDBLocked           = errors.New("BoltDB file is locked by another process")
)

// Bucket and metadata key constants.
const (
	// fileMetadataBucket stores FileMetadata as unencrypted JSON, keyed by shaIdentifier.
	fileMetadataBucket = "fileMetadata"
	// securityRulesBucket stores AccessRule as encrypted JSON, keyed by shaIdentifier.
	securityRulesBucket = "securityRules"
	// fileContentBucket stores raw file bytes encrypted, keyed by shaIdentifier.
	fileContentBucket = "fileContent"
	// metadataBucket stores store-level metadata (format version, etc.).
	metadataBucket = "metadata"

	// legacyBaselinesBucket is the v1 single-bucket name, kept only for migration.
	legacyBaselinesBucket = "baselines"

	formatVersionKey = "format_version"

	// currentFormatVersion is the current on-disk schema version.
	currentFormatVersion = 2
)

// BoltDBBaselineStore implements BaselineStore using BoltDB with three data buckets.
// All credential data (rule + file content) is encrypted at rest; metadata is plaintext.
type BoltDBBaselineStore struct {
	db        *bolt.DB
	masterKey []byte
}

// NewBoltDBBaselineStore opens or creates a BoltDB baseline store at the given path.
//
// Migration logic:
//   - If the file does not exist: create a new v2 database.
//   - If the file is a valid BoltDB but at format version 1: migrate v1 → v2 in-place.
//   - If the file is not a valid BoltDB (legacy JSON format): migrate JSON → v2.
func NewBoltDBBaselineStore(dbPath string, masterKey []byte, legacyJSONPath string) (*BoltDBBaselineStore, error) {
	targetPath := dbPath
	if targetPath == "" {
		targetPath = legacyJSONPath
	}
	if targetPath == "" {
		return nil, fmt.Errorf("no database path provided")
	}

	store := &BoltDBBaselineStore{masterKey: masterKey}

	db, isBoltDB, err := tryOpenBoltDB(targetPath)
	if err != nil {
		// File exists but is not a valid BoltDB → treat as legacy JSON.
		logger.Info("File %s is not a valid BoltDB, attempting legacy JSON migration: %v", targetPath, err)
		return store.migrateFromLegacyJSON(targetPath, masterKey)
	}

	if isBoltDB {
		store.db = db
		// Check if the existing database needs a v1 → v2 schema migration.
		version := store.readFormatVersion()
		if version < 2 {
			logger.Info("BoltDB at %s is at format version %d, migrating to v2", targetPath, version)
			if err := store.migrateV1toV2(); err != nil {
				db.Close()
				return nil, fmt.Errorf("failed to migrate BoltDB to v2: %w", err)
			}
		}
		// Ensure new buckets exist and run consistency check.
		if err := store.initDB(); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to initialize BoltDB: %w", err)
		}
	} else {
		// File does not exist — create new v2 database.
		logger.Info("Creating new BoltDB file: %s", targetPath)
		options := &bolt.Options{Timeout: 10 * time.Second}
		db, err = bolt.Open(targetPath, 0600, options)
		if err != nil {
			return nil, fmt.Errorf("failed to open BoltDB: %w", err)
		}
		store.db = db
		if err := store.initDB(); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to initialize BoltDB: %w", err)
		}
	}

	return store, nil
}

// readFormatVersion reads the stored format version; returns 0 if unknown.
func (s *BoltDBBaselineStore) readFormatVersion() int {
	var version int
	s.db.View(func(tx *bolt.Tx) error { //nolint:errcheck
		b := tx.Bucket([]byte(metadataBucket))
		if b == nil {
			return nil
		}
		v := b.Get([]byte(formatVersionKey))
		if v == nil {
			return nil
		}
		n, err := strconv.Atoi(string(v))
		if err == nil {
			version = n
		}
		return nil
	})
	return version
}

// initDB creates all required buckets, sets the format version, and performs a
// consistency check to remove any orphaned partial entries.
func (s *BoltDBBaselineStore) initDB() error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{fileMetadataBucket, securityRulesBucket, fileContentBucket, metadataBucket} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		meta := tx.Bucket([]byte(metadataBucket))
		if err := meta.Put([]byte(formatVersionKey), []byte(strconv.Itoa(currentFormatVersion))); err != nil {
			return fmt.Errorf("write format version: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Consistency check: any sha present in some but not all three data buckets is orphaned.
	return s.removeOrphanedEntries()
}

// removeOrphanedEntries deletes shaIdentifier keys that are not present in all three
// data buckets (fileMetadata, securityRules, fileContent).
func (s *BoltDBBaselineStore) removeOrphanedEntries() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		metaBkt := tx.Bucket([]byte(fileMetadataBucket))
		ruleBkt := tx.Bucket([]byte(securityRulesBucket))
		contentBkt := tx.Bucket([]byte(fileContentBucket))
		if metaBkt == nil || ruleBkt == nil || contentBkt == nil {
			return nil
		}

		// Collect all keys from all three buckets.
		allKeys := make(map[string]int) // key → count of buckets that have it
		for _, bkt := range []*bolt.Bucket{metaBkt, ruleBkt, contentBkt} {
			bkt.ForEach(func(k, _ []byte) error { //nolint:errcheck
				allKeys[string(k)]++
				return nil
			})
		}

		// Remove keys that are not present in all three buckets.
		for sha, count := range allKeys {
			if count == 3 {
				continue
			}
			logger.Warn("Consistency check: removing orphaned entry sha=%s (present in %d/3 buckets)", sha, count)
			key := []byte(sha)
			metaBkt.Delete(key)    //nolint:errcheck
			ruleBkt.Delete(key)    //nolint:errcheck
			contentBkt.Delete(key) //nolint:errcheck
		}
		return nil
	})
}

// migrateV1toV2 reads every entry from the legacy single-bucket (v1) format and
// writes them into the three-bucket (v2) structure, then drops the legacy bucket.
func (s *BoltDBBaselineStore) migrateV1toV2() error {
	logger.Info("Starting v1 → v2 migration")

	// Read all v1 entries while the legacy bucket still exists.
	type protoEntry struct {
		sha  string
		data *enclave.CredentialBaseline
	}
	var entries []protoEntry

	err := s.db.View(func(tx *bolt.Tx) error {
		legBkt := tx.Bucket([]byte(legacyBaselinesBucket))
		if legBkt == nil {
			logger.Info("No legacy baselines bucket found; assuming fresh v1 db")
			return nil
		}
		return legBkt.ForEach(func(k, v []byte) error {
			decrypted, err := crypto.Decrypt(v, s.masterKey)
			if err != nil {
				logger.Warn("v1→v2 migration: failed to decrypt entry sha=%s: %v (skipping)", string(k), err)
				return nil
			}
			var pb enclave.CredentialBaseline
			if err := proto.Unmarshal(decrypted, &pb); err != nil {
				crypto.ZeroBytes(decrypted)
				logger.Warn("v1→v2 migration: failed to unmarshal entry sha=%s: %v (skipping)", string(k), err)
				return nil
			}
			crypto.ZeroBytes(decrypted)
			entries = append(entries, protoEntry{sha: string(k), data: &pb})
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("read v1 entries: %w", err)
	}

	// Write entries into the three new buckets and clean up.
	return s.db.Update(func(tx *bolt.Tx) error {
		// Ensure new buckets exist.
		for _, name := range []string{fileMetadataBucket, securityRulesBucket, fileContentBucket, metadataBucket} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}

		metaBkt := tx.Bucket([]byte(fileMetadataBucket))
		ruleBkt := tx.Bucket([]byte(securityRulesBucket))
		contentBkt := tx.Bucket([]byte(fileContentBucket))
		dbMeta := tx.Bucket([]byte(metadataBucket))

		for _, e := range entries {
			pb := e.data
			sha := e.sha

			// Derive FileMetadata from proto fields.
			var perms *FilePerms
			if pb.GetPermissions() != nil {
				perms = &FilePerms{
					UID:  pb.GetPermissions().GetUid(),
					GID:  pb.GetPermissions().GetGid(),
					Mode: pb.GetPermissions().GetMode(),
				}
			}
			meta := FileMetadata{
				TargetPath:  pb.GetTargetPath(),
				Permissions: perms,
				Ctime:       pb.GetCtime(),
				Size:        pb.GetSize(),
			}

			// Derive AccessRule.
			// For v1 data, default Writable=true to preserve old "allow writes" behaviour.
			rule := AccessRule{
				VerificationStrategy:  pb.GetVerificationStrategy(),
				AllowedPrograms:       pb.GetAllowedBinaries(),
				AllowedProgramsSha256: pb.GetAllowedBinariesSha256(),
				MaxOpenCount:          pb.GetMaxOpenCount(),
				Writable:              true,
				Measure:               len(pb.GetAllowedBinariesSha256()) > 0,
			}

			// Marshal and store FileMetadata (unencrypted).
			metaJSON, err := json.Marshal(meta.toJSON())
			if err != nil {
				return fmt.Errorf("marshal metadata for sha=%s: %w", sha, err)
			}
			if err := metaBkt.Put([]byte(sha), metaJSON); err != nil {
				return fmt.Errorf("write metadata for sha=%s: %w", sha, err)
			}

			// Marshal and encrypt AccessRule.
			ruleJSON, err := json.Marshal(rule)
			if err != nil {
				return fmt.Errorf("marshal rule for sha=%s: %w", sha, err)
			}
			encRule, err := crypto.Encrypt(ruleJSON, s.masterKey)
			crypto.ZeroBytes(ruleJSON)
			if err != nil {
				return fmt.Errorf("encrypt rule for sha=%s: %w", sha, err)
			}
			if err := ruleBkt.Put([]byte(sha), encRule); err != nil {
				return fmt.Errorf("write rule for sha=%s: %w", sha, err)
			}

			// Encrypt file content.
			var content []byte = pb.GetEncryptedData()
			encContent, err := crypto.Encrypt(content, s.masterKey)
			if err != nil {
				return fmt.Errorf("encrypt content for sha=%s: %w", sha, err)
			}
			if err := contentBkt.Put([]byte(sha), encContent); err != nil {
				return fmt.Errorf("write content for sha=%s: %w", sha, err)
			}

			logger.Info("v1→v2 migration: migrated sha=%s path=%s", sha, pb.GetTargetPath())
		}

		// Update format version.
		if err := dbMeta.Put([]byte(formatVersionKey), []byte(strconv.Itoa(currentFormatVersion))); err != nil {
			return fmt.Errorf("update format version: %w", err)
		}

		// Drop the legacy bucket.
		if tx.Bucket([]byte(legacyBaselinesBucket)) != nil {
			if err := tx.DeleteBucket([]byte(legacyBaselinesBucket)); err != nil {
				return fmt.Errorf("delete legacy bucket: %w", err)
			}
		}

		logger.Info("v1→v2 migration complete: migrated %d entries", len(entries))
		return nil
	})
}

// ─── BaselineStore interface implementation ───────────────────────────────────

// Save writes all three parts of a CredentialBaseline atomically.
func (s *BoltDBBaselineStore) Save(bl *CredentialBaseline) error {
	if bl == nil {
		return nil
	}
	sha := bl.SHA()
	if sha == "" {
		return fmt.Errorf("baseline SHA is empty, cannot save without valid SHA identifier")
	}

	rule, err := bl.Rule()
	if err != nil {
		return fmt.Errorf("failed to load rule for sha=%s: %w", sha, err)
	}
	if rule == nil {
		rule = &AccessRule{}
	}

	content, err := bl.FileContent()
	if err != nil {
		return fmt.Errorf("failed to load content for sha=%s: %w", sha, err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		return s.writeToBuckets(tx, sha, bl.Metadata(), rule, content)
	})
}

// writeToBuckets writes all three parts of a baseline into the appropriate buckets
// within a single transaction.  The caller is responsible for providing a live tx.
func (s *BoltDBBaselineStore) writeToBuckets(tx *bolt.Tx, sha string, meta FileMetadata, rule *AccessRule, content []byte) error {
	metaBkt := tx.Bucket([]byte(fileMetadataBucket))
	ruleBkt := tx.Bucket([]byte(securityRulesBucket))
	contentBkt := tx.Bucket([]byte(fileContentBucket))
	if metaBkt == nil || ruleBkt == nil || contentBkt == nil {
		return fmt.Errorf("one or more data buckets not found")
	}

	// FileMetadata — stored as plain JSON (no encryption).
	metaJSON, err := json.Marshal(meta.toJSON())
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := metaBkt.Put([]byte(sha), metaJSON); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	// AccessRule — stored as encrypted JSON.
	ruleJSON, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("marshal rule: %w", err)
	}
	encRule, err := crypto.Encrypt(ruleJSON, s.masterKey)
	crypto.ZeroBytes(ruleJSON)
	if err != nil {
		return fmt.Errorf("encrypt rule: %w", err)
	}
	if err := ruleBkt.Put([]byte(sha), encRule); err != nil {
		return fmt.Errorf("write rule: %w", err)
	}

	// File content — stored encrypted.
	encContent, err := crypto.Encrypt(content, s.masterKey)
	if err != nil {
		return fmt.Errorf("encrypt content: %w", err)
	}
	if err := contentBkt.Put([]byte(sha), encContent); err != nil {
		return fmt.Errorf("write content: %w", err)
	}

	return nil
}

// Set is identical to Save (update or insert).
func (s *BoltDBBaselineStore) Set(_ string, bl *CredentialBaseline) error {
	return s.Save(bl)
}

// Delete removes a baseline from all three data buckets atomically.
func (s *BoltDBBaselineStore) Delete(sha string) error {
	if sha == "" {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, bktName := range []string{fileMetadataBucket, securityRulesBucket, fileContentBucket} {
			bkt := tx.Bucket([]byte(bktName))
			if bkt == nil {
				continue
			}
			if err := bkt.Delete([]byte(sha)); err != nil {
				return fmt.Errorf("delete from %s: %w", bktName, err)
			}
		}
		return nil
	})
}

// GetBySha loads the FileMetadata for a baseline and returns a shallow CredentialBaseline
// that will lazily load rule and content on first access.
func (s *BoltDBBaselineStore) GetBySha(sha string) *CredentialBaseline {
	if sha == "" {
		return nil
	}
	var meta FileMetadata
	found := false

	err := s.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(fileMetadataBucket))
		if bkt == nil {
			return nil
		}
		raw := bkt.Get([]byte(sha))
		if raw == nil {
			return nil
		}
		var j fileMetadataJSON
		if err := json.Unmarshal(raw, &j); err != nil {
			return fmt.Errorf("unmarshal metadata: %w", err)
		}
		meta = fileMetadataFromJSON(j)
		found = true
		return nil
	})
	if err != nil || !found {
		return nil
	}
	return shallowCopyMetadata(sha, meta, s)
}

// Get scans the unencrypted fileMetadata bucket to find a baseline by target path.
func (s *BoltDBBaselineStore) Get(targetPath string) *CredentialBaseline {
	var result *CredentialBaseline

	s.db.View(func(tx *bolt.Tx) error { //nolint:errcheck
		bkt := tx.Bucket([]byte(fileMetadataBucket))
		if bkt == nil {
			return nil
		}
		return bkt.ForEach(func(k, v []byte) error {
			var j fileMetadataJSON
			if err := json.Unmarshal(v, &j); err != nil {
				return nil // skip corrupted entries
			}
			if j.TargetPath == targetPath {
				meta := fileMetadataFromJSON(j)
				result = shallowCopyMetadata(string(k), meta, s)
				return fmt.Errorf("stop") // stop iteration
			}
			return nil
		})
	})
	return result
}

// Exists returns true if a baseline with the given SHA exists.
func (s *BoltDBBaselineStore) Exists(sha string) bool {
	if sha == "" {
		return false
	}
	var found bool
	s.db.View(func(tx *bolt.Tx) error { //nolint:errcheck
		bkt := tx.Bucket([]byte(fileMetadataBucket))
		if bkt == nil {
			return nil
		}
		found = bkt.Get([]byte(sha)) != nil
		return nil
	})
	return found
}

// Count returns the number of baselines stored (keyed by the fileMetadata bucket).
func (s *BoltDBBaselineStore) Count() int {
	var count int
	s.db.View(func(tx *bolt.Tx) error { //nolint:errcheck
		bkt := tx.Bucket([]byte(fileMetadataBucket))
		if bkt == nil {
			return nil
		}
		count = bkt.Stats().KeyN
		return nil
	})
	return count
}

// ListAll returns shallow CredentialBaseline objects (metadata only) for all stored baselines.
func (s *BoltDBBaselineStore) ListAll() []*CredentialBaseline {
	var result []*CredentialBaseline

	s.db.View(func(tx *bolt.Tx) error { //nolint:errcheck
		bkt := tx.Bucket([]byte(fileMetadataBucket))
		if bkt == nil {
			return nil
		}
		return bkt.ForEach(func(k, v []byte) error {
			var j fileMetadataJSON
			if err := json.Unmarshal(v, &j); err != nil {
				return nil // skip corrupted entries
			}
			meta := fileMetadataFromJSON(j)
			result = append(result, shallowCopyMetadata(string(k), meta, s))
			return nil
		})
	})
	return result
}

// Close closes the underlying BoltDB file.
func (s *BoltDBBaselineStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// ─── Lazy-load helpers (called by CredentialBaseline) ────────────────────────

// loadRule decrypts and deserialises the AccessRule for the given sha.
func (s *BoltDBBaselineStore) loadRule(sha string) (*AccessRule, error) {
	var rule AccessRule
	err := s.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(securityRulesBucket))
		if bkt == nil {
			return fmt.Errorf("securityRules bucket not found")
		}
		enc := bkt.Get([]byte(sha))
		if enc == nil {
			return fmt.Errorf("rule not found for sha=%s", sha)
		}
		raw, err := crypto.Decrypt(enc, s.masterKey)
		if err != nil {
			return fmt.Errorf("decrypt rule: %w", err)
		}
		err = json.Unmarshal(raw, &rule)
		crypto.ZeroBytes(raw)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

// loadContent decrypts and returns the raw file content for the given sha.
func (s *BoltDBBaselineStore) loadContent(sha string) ([]byte, error) {
	var content []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(fileContentBucket))
		if bkt == nil {
			return fmt.Errorf("fileContent bucket not found")
		}
		enc := bkt.Get([]byte(sha))
		if enc == nil {
			// An empty content entry is valid (truncated file).
			return nil
		}
		raw, err := crypto.Decrypt(enc, s.masterKey)
		if err != nil {
			return fmt.Errorf("decrypt content: %w", err)
		}
		content = raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	return content, nil
}

// ─── Migration helpers ────────────────────────────────────────────────────────

// migrateFromLegacyJSON reads an old encrypted-JSON file (v0), converts each
// proto-based CredentialBaseline to the new three-bucket format, and atomically
// replaces the original file with the new BoltDB database.
func (s *BoltDBBaselineStore) migrateFromLegacyJSON(legacyPath string, masterKey []byte) (*BoltDBBaselineStore, error) {
	logger.Info("Starting migration from legacy JSON format: %s", legacyPath)

	legacyData, err := loadLegacyJSON(legacyPath, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load legacy JSON file: %w", err)
	}

	tempDBPath := legacyPath + ".tmp"
	backupPath := legacyPath + ".bak"

	if err := copyFile(legacyPath, backupPath); err != nil {
		return nil, fmt.Errorf("failed to backup legacy file: %w", err)
	}
	logger.Info("Backed up legacy file to %s", backupPath)

	db, err := bolt.Open(tempDBPath, 0600, nil)
	if err != nil {
		os.Remove(backupPath)
		return nil, fmt.Errorf("failed to open temp BoltDB: %w", err)
	}
	s.db = db

	if err := s.initDB(); err != nil {
		db.Close()
		os.Remove(tempDBPath)
		os.Remove(backupPath)
		return nil, fmt.Errorf("failed to initialize BoltDB: %w", err)
	}

	// Write converted baselines into the three buckets.
	if err := s.writeLegacyProtoBaselines(legacyData); err != nil {
		db.Close()
		os.Remove(tempDBPath)
		os.Remove(backupPath)
		return nil, fmt.Errorf("failed to write baselines: %w", err)
	}

	if err := db.Close(); err != nil {
		os.Remove(tempDBPath)
		os.Remove(backupPath)
		return nil, fmt.Errorf("failed to close temp BoltDB: %w", err)
	}

	if err := os.Rename(tempDBPath, legacyPath); err != nil {
		os.Remove(tempDBPath)
		return nil, fmt.Errorf("failed to atomically replace legacy file: %w", err)
	}

	if err := os.Remove(backupPath); err != nil {
		logger.Warn("Failed to remove backup file %s: %v", backupPath, err)
	}

	db, err = bolt.Open(legacyPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open final BoltDB: %w", err)
	}
	s.db = db

	logger.Info("Successfully migrated legacy JSON file to BoltDB v2 format: %s", legacyPath)
	return s, nil
}

// writeLegacyProtoBaselines converts proto-based legacy baselines and writes them into
// the three new buckets.
func (s *BoltDBBaselineStore) writeLegacyProtoBaselines(data map[string]*enclave.CredentialBaseline) error {
	count := 0
	return s.db.Update(func(tx *bolt.Tx) error {
		metaBkt := tx.Bucket([]byte(fileMetadataBucket))
		ruleBkt := tx.Bucket([]byte(securityRulesBucket))
		contentBkt := tx.Bucket([]byte(fileContentBucket))
		if metaBkt == nil || ruleBkt == nil || contentBkt == nil {
			return fmt.Errorf("one or more data buckets not found")
		}

		for _, pb := range data {
			if pb == nil {
				continue
			}
			sha := pb.GetSha()
			if sha == "" {
				if pb.GetTargetPath() == "" {
					logger.Warn("Skipping baseline with empty SHA and TargetPath during migration")
					continue
				}
				sha = generateShaFromPath(pb.GetTargetPath())
				logger.Info("Generated SHA '%s' for legacy baseline with TargetPath '%s' during migration", sha, pb.GetTargetPath())
			}

			var perms *FilePerms
			if pb.GetPermissions() != nil {
				perms = &FilePerms{
					UID:  pb.GetPermissions().GetUid(),
					GID:  pb.GetPermissions().GetGid(),
					Mode: pb.GetPermissions().GetMode(),
				}
			}
			meta := FileMetadata{
				TargetPath:  pb.GetTargetPath(),
				Permissions: perms,
				Ctime:       pb.GetCtime(),
				Size:        pb.GetSize(),
			}
			rule := AccessRule{
				VerificationStrategy:  pb.GetVerificationStrategy(),
				AllowedPrograms:       pb.GetAllowedBinaries(),
				AllowedProgramsSha256: pb.GetAllowedBinariesSha256(),
				MaxOpenCount:          pb.GetMaxOpenCount(),
				Writable:              true, // default to writable for legacy data
				Measure:               len(pb.GetAllowedBinariesSha256()) > 0,
			}

			metaJSON, err := json.Marshal(meta.toJSON())
			if err != nil {
				return fmt.Errorf("marshal metadata sha=%s: %w", sha, err)
			}
			if err := metaBkt.Put([]byte(sha), metaJSON); err != nil {
				return fmt.Errorf("write metadata sha=%s: %w", sha, err)
			}

			ruleJSON, err := json.Marshal(rule)
			if err != nil {
				return fmt.Errorf("marshal rule sha=%s: %w", sha, err)
			}
			encRule, err := crypto.Encrypt(ruleJSON, s.masterKey)
			crypto.ZeroBytes(ruleJSON)
			if err != nil {
				return fmt.Errorf("encrypt rule sha=%s: %w", sha, err)
			}
			if err := ruleBkt.Put([]byte(sha), encRule); err != nil {
				return fmt.Errorf("write rule sha=%s: %w", sha, err)
			}

			encContent, err := crypto.Encrypt(pb.GetEncryptedData(), s.masterKey)
			if err != nil {
				return fmt.Errorf("encrypt content sha=%s: %w", sha, err)
			}
			if err := contentBkt.Put([]byte(sha), encContent); err != nil {
				return fmt.Errorf("write content sha=%s: %w", sha, err)
			}
			count++
			logger.Info("v0→v2 migration: migrated sha=%s path=%s", sha, pb.GetTargetPath())
		}
		logger.Info("v0→v2 migration complete: migrated %d entries from legacy JSON", count)
		return nil
	})
}

// ─── BoltDB format detection helpers ─────────────────────────────────────────

// tryOpenBoltDB attempts to open a file as BoltDB.
// Returns (db, true, nil)   on success.
// Returns (nil, false, nil) if file does not exist.
// Returns (nil, false, err) if file exists but is not valid BoltDB.
func tryOpenBoltDB(path string) (*bolt.DB, bool, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, false, nil
	}

	options := &bolt.Options{Timeout: 10 * time.Second}
	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		return nil, false, fmt.Errorf("file exists but is not a valid BoltDB: %w", err)
	}

	// Require at least one recognisable bucket to consider the file valid.
	validStructure := false
	viewErr := db.View(func(tx *bolt.Tx) error {
		for _, name := range []string{fileMetadataBucket, legacyBaselinesBucket, metadataBucket} {
			if tx.Bucket([]byte(name)) != nil {
				validStructure = true
				return nil
			}
		}
		return nil
	})
	if viewErr != nil {
		db.Close()
		return nil, false, fmt.Errorf("failed to read BoltDB structure: %w", viewErr)
	}
	if !validStructure {
		db.Close()
		return nil, false, fmt.Errorf("BoltDB file exists but has invalid structure (no recognisable bucket)")
	}
	return db, true, nil
}

// checkBoltDBFormat returns true if the file at path is a valid BoltDB.
func checkBoltDBFormat(path string) (bool, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false, nil
	}
	options := &bolt.Options{Timeout: 5 * time.Second}
	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		return false, nil
	}
	defer db.Close() //nolint:errcheck

	validStructure := false
	err = db.View(func(tx *bolt.Tx) error {
		for _, name := range []string{fileMetadataBucket, legacyBaselinesBucket, metadataBucket} {
			if tx.Bucket([]byte(name)) != nil {
				validStructure = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("failed to read BoltDB structure: %w", err)
	}
	return validStructure, nil
}

// IsMigrated returns true if the file at path is a valid BoltDB database.
func IsMigrated(path string) bool {
	ok, _ := checkBoltDBFormat(path)
	return ok
}

// NeedsMigration returns true if the file exists and is NOT a valid BoltDB database.
func NeedsMigration(path string) bool {
	if path == "" {
		return false
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	ok, _ := checkBoltDBFormat(path)
	return !ok
}

// ─── Legacy JSON loader ───────────────────────────────────────────────────────

// loadLegacyJSON reads and decrypts an old encrypted-JSON baseline file.
func loadLegacyJSON(path string, masterKey []byte) (map[string]*enclave.CredentialBaseline, error) {
	encryptedData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read legacy file: %w", err)
	}
	jsonData, err := crypto.Decrypt(encryptedData, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt legacy data: %w", err)
	}
	var data map[string]*enclave.CredentialBaseline
	err = json.Unmarshal(jsonData, &data)
	crypto.ZeroBytes(jsonData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal legacy JSON: %w", err)
	}
	return data, nil
}

// ─── Utility functions ────────────────────────────────────────────────────────

// generateShaFromPath derives a 12-character hex SHA identifier from a file path.
func generateShaFromPath(targetPath string) string {
	h := sha256.Sum256([]byte(targetPath))
	return hex.EncodeToString(h[:])[:12]
}

// copyFile copies src to dst (used for pre-migration backup).
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read source file: %w", err)
	}
	return os.WriteFile(dst, data, 0600)
}

// protoTimestampFromTimestamppb is a thin alias kept for clarity within this file.
var _ = (*timestamppb.Timestamp)(nil)
