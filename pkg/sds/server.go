package sds

import (
	"context"
	"errors"
	"net"

	"go.uber.org/atomic"
	"google.golang.org/grpc"
	"istio.io/pkg/log"

	sdsv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/uds"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/security"
)

const (
	maxMsgSize    = 20 * 1024 * 1024
	maxStreams    = 10000
	maxRetryTimes = 5
)

// Server is the gPRC server that exposes SDS through UDS.
type Server struct {
	workloadSds          sdsv3.SecretDiscoveryServiceServer
	grpcWorkloadListener net.Listener
	grpcWorkloadServer   *grpc.Server
	stopped              *atomic.Bool
	errChan              chan error
	newSDSv3Server       func() sdsv3.SecretDiscoveryServiceServer
}

// SDSserver bootstrap sequence:
// First step: implement sdsservice as envoy sdsv3.SecretDiscoveryServiceServer interface,
// which cotain request channel as Discovery Request,
// response channel as Discovery response, err channel etc.
// Secret manager for generate CSR, may need an Attestator for stream attestation
// Second step: boot strap grpc server: setup grpc server, create uds listener, and let the server
// serves in this socket path
func NewServer() *Server {
	s := &Server{
		stopped: atomic.NewBool(false),
		errChan: make(chan error),
	}
	s.newSDSv3Server = func() sdsv3.SecretDiscoveryServiceServer {
		return newSDSService()
	}
	s.workloadSds = s.newSDSv3Server()
	return s
}

// Stop closes the gRPC server and debug server.
func (s *Server) Stop() {
	if s == nil {
		return
	}
	s.stopped.Store(true)
	if s.grpcWorkloadServer != nil {
		s.grpcWorkloadServer.Stop()
	}
	if s.grpcWorkloadListener != nil {
		s.grpcWorkloadListener.Close()
	}
}

func (s *Server) StartmTLSSDSService(ctx context.Context) error {
	s.grpcWorkloadServer = grpc.NewServer(s.grpcServerOptions()...)
	sdsv3.RegisterSecretDiscoveryServiceServer(s.grpcWorkloadServer, s.workloadSds)
	var err error
	s.grpcWorkloadListener, err = uds.NewListener(security.WorkloadIdentitySocketPath)
	if err != nil {
		log.Info("mTLS listen generation error ", err)
		return err
	}
	log.Info("Starting mTLS SDS grpc server")
	log.Info("DEBUG 4: Listener addr: ", s.grpcWorkloadListener.Addr())
	if s.grpcWorkloadListener == nil {
		if s.grpcWorkloadListener, err = uds.NewListener(security.WorkloadIdentitySocketPath); err != nil {
			log.Info("mTLS SDS grpc server for workload proxies failed to set up UDS: ", err)
		}
	}
	go func() {
		log.Info("DEBUG: Call go routine")
		s.errChan <- s.grpcWorkloadServer.Serve(s.grpcWorkloadListener)
	}()

	select {
	case err = <-s.errChan:
		log.Warnf("SDS grpc server for workload proxies failed to start: ", err)
	case <-ctx.Done():
		log.Info("Stopping Workload and SDS APIs")
		err = <-s.errChan
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
	}

	if err = <-s.errChan; err != nil {
		log.Infof("DEBUG error:", err)
	}
	log.Info("DEBUG 1: ", s.workloadSds)
	return nil
}

func (s *Server) grpcServerOptions() []grpc.ServerOption {
	grpcOptions := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(uint32(maxStreams)),
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.MaxRecvMsgSize(maxMsgSize),
	}

	return grpcOptions
}
