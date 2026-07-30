package uds

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/alibaba/CredAgent/api/gen/enclave"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client wraps the gRPC client for communication with the EnclaveDaemon
type Client struct {
	conn   *grpc.ClientConn
	client enclave.EnclaveGuardServiceClient
}

// NewClient creates a new UDS client for connecting to the EnclaveDaemon
func NewClient(socketPath string) (*Client, error) {
	// Create gRPC connection to EnclaveDaemon via Unix Domain Socket
	tlsCreds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	conn, err := grpc.Dial("unix:"+socketPath, grpc.WithTransportCredentials(tlsCreds), grpc.WithTimeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to EnclaveDaemon: %w", err)
	}

	client := enclave.NewEnclaveGuardServiceClient(conn)

	return &Client{
		conn:   conn,
		client: client,
	}, nil
}

// Close closes the underlying connection
func (c *Client) Close() error {
	return c.conn.Close()
}

// RequestPermission requests permission to access a credential file
func (c *Client) RequestPermission(ctx context.Context, intent, cmdline, targetFile string) (*enclave.RequestPermissionResponse, error) {
	req := &enclave.RequestPermissionRequest{
		Intent:     intent,
		Cmdline:    cmdline,
		TargetFile: targetFile,
	}

	resp, err := c.client.RequestPermission(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to request permission: %w", err)
	}

	return resp, nil
}
