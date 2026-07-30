package baseline

import (
	"sync"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// FilePerms holds Unix file permission information.
type FilePerms struct {
	UID  uint32
	GID  uint32
	Mode uint32
}

// FileMetadata holds unencrypted metadata about a protected file.
// Stored in the fileMetadata bucket without encryption so that
// directory listing operations (ls, stat) can be served quickly.
type FileMetadata struct {
	TargetPath  string
	Permissions *FilePerms
	Ctime       *timestamppb.Timestamp
	Size        int64
}

// fileMetadataJSON is the JSON representation of FileMetadata used for on-disk storage.
// timestamppb.Timestamp is decomposed to plain int64/int32 to avoid proto JSON dependency.
type fileMetadataJSON struct {
	TargetPath  string     `json:"target_path"`
	Permissions *FilePerms `json:"permissions,omitempty"`
	CtimeSec    int64      `json:"ctime_sec"`
	CtimeNanos  int32      `json:"ctime_nanos"`
	Size        int64      `json:"size"`
}

// toJSON converts FileMetadata to its JSON-serializable form.
func (m *FileMetadata) toJSON() fileMetadataJSON {
	j := fileMetadataJSON{
		TargetPath:  m.TargetPath,
		Permissions: m.Permissions,
		Size:        m.Size,
	}
	if m.Ctime != nil {
		j.CtimeSec = m.Ctime.Seconds
		j.CtimeNanos = m.Ctime.Nanos
	}
	return j
}

// fromJSON restores a FileMetadata from its JSON form.
func fileMetadataFromJSON(j fileMetadataJSON) FileMetadata {
	m := FileMetadata{
		TargetPath:  j.TargetPath,
		Permissions: j.Permissions,
		Size:        j.Size,
	}
	if j.CtimeSec != 0 || j.CtimeNanos != 0 {
		m.Ctime = &timestamppb.Timestamp{
			Seconds: j.CtimeSec,
			Nanos:   j.CtimeNanos,
		}
	}
	return m
}

// AccessRule holds the security policy for accessing a credential file.
// Stored encrypted in the securityRules bucket.
type AccessRule struct {
	VerificationStrategy  string
	AllowedPrograms       []string
	AllowedProgramsSha256 []string
	MaxOpenCount          int64
	Writable              bool
	// Measure is true when SHA256 measurement of allowed programs is required.
	// Derived from len(AllowedProgramsSha256) > 0; persisted for fast access.
	Measure bool
}

// CredentialBaseline is the internal domain object for a single protected credential file.
//
// Lazy loading:
//   - metadata is always populated (loaded from fileMetadata bucket on first access).
//   - rule is loaded on demand from the encrypted securityRules bucket.
//   - fileContent is loaded on demand from the encrypted fileContent bucket.
//
// For InMemoryBaselineStore all fields are pre-populated (store == nil).
type CredentialBaseline struct {
	shaIdentifier string
	metadata      FileMetadata

	rule          *AccessRule
	ruleLoaded    bool
	fileContent   []byte
	contentLoaded bool

	mu    sync.Mutex
	store *BoltDBBaselineStore // nil for InMemory
}

// NewCredentialBaseline creates a fully-populated CredentialBaseline (no lazy loading).
// Use this when constructing a new baseline before persisting it.
func NewCredentialBaseline(sha string, meta FileMetadata, rule *AccessRule, content []byte) *CredentialBaseline {
	return &CredentialBaseline{
		shaIdentifier: sha,
		metadata:      meta,
		rule:          rule,
		ruleLoaded:    true,
		fileContent:   content,
		contentLoaded: true,
	}
}

// SHA returns the unique SHA identifier for this baseline.
func (c *CredentialBaseline) SHA() string {
	return c.shaIdentifier
}

// SetSHA sets the SHA identifier.
func (c *CredentialBaseline) SetSHA(sha string) {
	c.shaIdentifier = sha
}

// Metadata returns the file metadata (always populated, no I/O).
func (c *CredentialBaseline) Metadata() FileMetadata {
	return c.metadata
}

// SetMetadata replaces the file metadata.
func (c *CredentialBaseline) SetMetadata(m FileMetadata) {
	c.metadata = m
}

// Rule returns the access rule, loading it lazily from the store if needed.
func (c *CredentialBaseline) Rule() (*AccessRule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ruleLoaded {
		return c.rule, nil
	}

	if c.store == nil {
		// InMemory or pre-populated baseline: rule is already in place.
		c.ruleLoaded = true
		return c.rule, nil
	}

	rule, err := c.store.loadRule(c.shaIdentifier)
	if err != nil {
		return nil, err
	}
	c.rule = rule
	c.ruleLoaded = true
	return c.rule, nil
}

// SetRule replaces the access rule and marks it as loaded.
func (c *CredentialBaseline) SetRule(r *AccessRule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rule = r
	c.ruleLoaded = true
}

// FileContent returns the raw file content, loading it lazily from the store if needed.
func (c *CredentialBaseline) FileContent() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.contentLoaded {
		return c.fileContent, nil
	}

	if c.store == nil {
		c.contentLoaded = true
		return c.fileContent, nil
	}

	content, err := c.store.loadContent(c.shaIdentifier)
	if err != nil {
		return nil, err
	}
	c.fileContent = content
	c.contentLoaded = true
	return c.fileContent, nil
}

// SetFileContent replaces the file content and marks it as loaded.
func (c *CredentialBaseline) SetFileContent(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fileContent = data
	c.contentLoaded = true
}

// shallowCopyMetadata returns a new CredentialBaseline with only metadata populated
// and a reference to the same store for lazy loading of rule and content.
func shallowCopyMetadata(sha string, meta FileMetadata, store *BoltDBBaselineStore) *CredentialBaseline {
	return &CredentialBaseline{
		shaIdentifier: sha,
		metadata:      meta,
		store:         store,
	}
}
