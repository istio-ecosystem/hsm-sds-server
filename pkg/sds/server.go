package sds

import (
	"context"
	"errors"
	"net"

	"go.uber.org/atomic"
	"google.golang.org/grpc"
	"istio.io/pkg/log"

	sdsv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/uds"
)

const (
	maxMsgSize    = 20 * 1024 * 1024
	maxStreams    = 10000
	maxRetryTimes = 5
)

// Server is the gPRC server that exposes SDS through UDS.
type Server struct {
	workloadSds          sdsv3.SecretDiscoveryServiceServer
	grpcGatewayListener  net.Listener
	grpcWorkloadListener net.Listener
	sdsGrpcServer        *grpc.Server
	stopped              *atomic.Bool
	errGatewayChan       chan error
	errWorkloadChan      chan error
}

// NewServer implements SDS service as envoy sdsv3.SecretDiscoveryServiceServer interface
// SDS service will create Secret manager and generate `default` private key and cert in SGX
// SDS service contains a request channel as Discovery Request,
// a response channel as Discovery response and an err channel.
func NewServer(kubeconfig, configContext string) *Server {
	var s *Server
	sdsService := newSDSService(kubeconfig, configContext)
	if sdsService != nil {
		s = &Server{
			stopped:         atomic.NewBool(false),
			errGatewayChan:  make(chan error),
			errWorkloadChan: make(chan error),
		}
		s.workloadSds = sdsService
	}
	return s
}

// Stop closes the gRPC server and debug server.
func (s *Server) Stop() {
	if s == nil {
		return
	}
	s.stopped.Store(true)
	if s.sdsGrpcServer != nil {
		s.sdsGrpcServer.Stop()
	}
	if s.grpcWorkloadListener != nil {
		s.grpcWorkloadListener.Close()
	}
}

func (s *Server) Start(ctx context.Context) error {
	s.sdsGrpcServer = grpc.NewServer(s.grpcServerOptions()...)
	sdsv3.RegisterSecretDiscoveryServiceServer(s.sdsGrpcServer, s.workloadSds)
	var err error
	s.grpcWorkloadListener, err = uds.NewListener(security.WorkloadIdentitySocketPath)
	if err != nil {
		log.Info("mTLS listen generation error ", err)
		return err
	}
	log.Info("Starting mTLS SDS grpc server")
	log.Infof("mTLS Listener addr: ", s.grpcWorkloadListener.Addr())
	if s.grpcWorkloadListener == nil {
		if s.grpcWorkloadListener, err = uds.NewListener(security.WorkloadIdentitySocketPath); err != nil {
			log.Info("mTLS SDS grpc server for workload proxies failed to set up UDS: ", err)
		}
	}
	go func() {
		s.errWorkloadChan <- s.sdsGrpcServer.Serve(s.grpcWorkloadListener)
	}()

	s.grpcGatewayListener, err = uds.NewListener(security.GatewayIdentitySocketPath)
	if err != nil {
		log.Info("gateway listen generation error ", err)
		return err
	}
	log.Info("Starting gateway SDS grpc server")
	log.Infof("gateway Listener addr: ", s.grpcGatewayListener.Addr())
	if s.grpcGatewayListener == nil {
		if s.grpcGatewayListener, err = uds.NewListener(security.GatewayIdentitySocketPath); err != nil {
			log.Info("gateway SDS grpc server for gateway failed to set up UDS: ", err)
		}
	}
	go func() {
		s.errGatewayChan <- s.sdsGrpcServer.Serve(s.grpcGatewayListener)
	}()

	select {
	case err = <-s.errWorkloadChan:
		log.Warnf("SDS grpc server for workload proxies failed to run: ", err)
	case err = <-s.errWorkloadChan:
		log.Warnf("SDS grpc server for gateway failed to run: ", err)
	case <-ctx.Done():
		log.Info("Stopping Workload and SDS APIs")
		err = <-s.errWorkloadChan
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
		err = <-s.errGatewayChan
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
	}
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
