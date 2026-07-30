package uds

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// UDSPeerAuthInterceptor is a gRPC unary interceptor for Unix domain socket connections.
// Retained as a pass-through for future per-RPC authorization needs (e.g., audit logging).
func UDSPeerAuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer information")
	}

	if p.Addr.Network() == "unix" {
		_, ok := p.Addr.(*net.UnixAddr)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "not a unix address")
		}
	}

	return handler(ctx, req)
}
