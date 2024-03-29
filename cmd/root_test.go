package cmd

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"istio-ecosystem/hsm-sds-server/pkg/uds"
)

func TestUdsListener(t *testing.T) {
	l, err := uds.NewListener("./tmp/sc/test")
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	defer l.Close()
	conn, err := connect("./tmp/sc/test")
	if err != nil {
		t.Fatalf("failed to connect %v", err)
	}
	conn.Close()
}

func connect(socket string) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption

	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}))

	conn, err := grpc.Dial(socket, opts...)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
