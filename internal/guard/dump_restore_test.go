package guard

import (
	"context"
	"testing"

	"github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/ledger"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func setupDumpRestoreEngine(t *testing.T) (*PolicyEngine, baseline.BaselineStore) {
	t.Helper()
	baselineStore := baseline.NewInMemoryBaselineStore()
	testBaseline := baseline.NewCredentialBaseline(
		"dump123",
		baseline.FileMetadata{
			TargetPath:  "/etc/test/cred.json",
			Permissions: &baseline.FilePerms{UID: 1000, GID: 1000, Mode: 0600},
			Size:        int64(len("secret-content")),
		},
		&baseline.AccessRule{VerificationStrategy: "BASIC"},
		[]byte("secret-content"),
	)
	err := baselineStore.Save(testBaseline)
	assert.NoError(t, err)

	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	assert.NoError(t, err)
	err = adminPasswordStore.SetPassword("correct-password")
	assert.NoError(t, err)

	engine := NewPolicyEngine(
		ledger.NewInMemoryLedger(),
		baselineStore,
		&MockCredAgentClient{},
		[]byte("test-key-32-byte-for-aes-testing"),
		adminPasswordStore,
		nil,
	)
	return engine, baselineStore
}

func TestDumpFileContent(t *testing.T) {
	engine, baselineStore := setupDumpRestoreEngine(t)

	t.Run("success with correct password", func(t *testing.T) {
		resp, err := engine.DumpFileContent(context.Background(), &enclave.DumpFileContentRequest{
			Sha:      "dump123",
			Password: "correct-password",
		})
		assert.NoError(t, err)
		assert.True(t, resp.GetSuccess())
		assert.Equal(t, []byte("secret-content"), resp.GetContent())
		assert.Equal(t, "/etc/test/cred.json", resp.GetTargetPath())

		// Baseline must still exist after dump
		bl := baselineStore.GetBySha("dump123")
		assert.NotNil(t, bl)
	})

	t.Run("fail with wrong password", func(t *testing.T) {
		resp, err := engine.DumpFileContent(context.Background(), &enclave.DumpFileContentRequest{
			Sha:      "dump123",
			Password: "wrong-password",
		})
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, s.Code())
		assert.Nil(t, resp)
	})

	t.Run("fail with empty password", func(t *testing.T) {
		resp, err := engine.DumpFileContent(context.Background(), &enclave.DumpFileContentRequest{
			Sha:      "dump123",
			Password: "",
		})
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, s.Code())
		assert.Nil(t, resp)
	})

	t.Run("fail with non-existent baseline", func(t *testing.T) {
		resp, err := engine.DumpFileContent(context.Background(), &enclave.DumpFileContentRequest{
			Sha:      "nonexistent",
			Password: "correct-password",
		})
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.NotFound, s.Code())
		assert.Nil(t, resp)
	})
}

func TestRestoreFileContent(t *testing.T) {
	engine, baselineStore := setupDumpRestoreEngine(t)

	t.Run("success with correct password", func(t *testing.T) {
		newContent := []byte("updated-secret-content")
		resp, err := engine.RestoreFileContent(context.Background(), &enclave.RestoreFileContentRequest{
			Sha:      "dump123",
			Password: "correct-password",
			Content:  newContent,
		})
		assert.NoError(t, err)
		assert.True(t, resp.GetSuccess())
		assert.Equal(t, int64(len(newContent)), resp.GetNewSize())

		// Verify the content was actually updated in the store
		bl := baselineStore.GetBySha("dump123")
		assert.NotNil(t, bl)
		content, err := bl.FileContent()
		assert.NoError(t, err)
		assert.Equal(t, newContent, content)
		assert.Equal(t, int64(len(newContent)), bl.Metadata().Size)
	})

	t.Run("fail with wrong password", func(t *testing.T) {
		resp, err := engine.RestoreFileContent(context.Background(), &enclave.RestoreFileContentRequest{
			Sha:      "dump123",
			Password: "wrong-password",
			Content:  []byte("data"),
		})
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, s.Code())
		assert.Nil(t, resp)
	})

	t.Run("fail with empty password", func(t *testing.T) {
		resp, err := engine.RestoreFileContent(context.Background(), &enclave.RestoreFileContentRequest{
			Sha:      "dump123",
			Password: "",
			Content:  []byte("data"),
		})
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, s.Code())
		assert.Nil(t, resp)
	})

	t.Run("fail with non-existent baseline", func(t *testing.T) {
		resp, err := engine.RestoreFileContent(context.Background(), &enclave.RestoreFileContentRequest{
			Sha:      "nonexistent",
			Password: "correct-password",
			Content:  []byte("data"),
		})
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.NotFound, s.Code())
		assert.Nil(t, resp)
	})

	t.Run("restore empty content", func(t *testing.T) {
		resp, err := engine.RestoreFileContent(context.Background(), &enclave.RestoreFileContentRequest{
			Sha:      "dump123",
			Password: "correct-password",
			Content:  []byte{},
		})
		assert.NoError(t, err)
		assert.True(t, resp.GetSuccess())
		assert.Equal(t, int64(0), resp.GetNewSize())

		bl := baselineStore.GetBySha("dump123")
		content, err := bl.FileContent()
		assert.NoError(t, err)
		assert.Equal(t, []byte{}, content)
	})
}

func TestDumpThenRestore(t *testing.T) {
	engine, _ := setupDumpRestoreEngine(t)

	// Dump original content
	dumpResp, err := engine.DumpFileContent(context.Background(), &enclave.DumpFileContentRequest{
		Sha:      "dump123",
		Password: "correct-password",
	})
	assert.NoError(t, err)
	originalContent := dumpResp.GetContent()

	// Restore with modified content
	modified := append(originalContent, []byte("-modified")...)
	_, err = engine.RestoreFileContent(context.Background(), &enclave.RestoreFileContentRequest{
		Sha:      "dump123",
		Password: "correct-password",
		Content:  modified,
	})
	assert.NoError(t, err)

	// Dump again and verify
	dumpResp2, err := engine.DumpFileContent(context.Background(), &enclave.DumpFileContentRequest{
		Sha:      "dump123",
		Password: "correct-password",
	})
	assert.NoError(t, err)
	assert.Equal(t, []byte("secret-content-modified"), dumpResp2.GetContent())
}
