package sds

import (
	"fmt"
	"net"
	"time"

	"go.uber.org/atomic"
	"google.golang.org/grpc"
	"istio.io/pkg/log"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/uds"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/security"
)

const (
	maxMsgSize    = 20*1024*1024
	maxStreams    = 10000
	maxRetryTimes = 5
)

// Server is the gPRC server that exposes SDS through UDS.
type Server struct {
	workloadSds *sdsservice

	grpcWorkloadListener net.Listener
	// grpcWorkloadConnection net.Conn
	grpcWorkloadServer *grpc.Server
	stopped            *atomic.Bool
}

// SDSserver bootstrap sequence:
// First step: implement sdsservice as envoy interface, which cotain request channel as Discovery Request,
// response channel as Discovery response, err channel etc.
// Secret manager for generate CSR, may need an Attestator for stream attestation
// Second step: boot strap grpc server: setup grpc server, create uds listener, and let the server
// serves in this socket path

func NewServer() *Server {
	s := &Server{stopped: atomic.NewBool(false)}
	s.workloadSds = newSDSService()
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
	if s.workloadSds != nil {
		s.workloadSds.Close()
	}
}

func (s *Server) StartmTLSSDSService() error {
	s.grpcWorkloadServer = grpc.NewServer(s.grpcServerOptions()...)
	s.workloadSds.register(s.grpcWorkloadServer)
	var err error
	s.grpcWorkloadListener, err = uds.NewListener(security.WorkloadIdentitySocketPath)
	if err != nil {
		log.Info("mTLS listen generation error ", err)
		return err
	}
	log.Info("Starting mTLS SDS grpc server")
	waitTime := time.Second
	started := false
	for i := 0; i < maxRetryTimes; i++ {
		serverOk := true
		setUpUdsOK := true
		if s.grpcWorkloadListener == nil {
			if s.grpcWorkloadListener, err = uds.NewListener(security.WorkloadIdentitySocketPath); err != nil {
				log.Info("mTLS SDS grpc server for workload proxies failed to set up UDS: ", err)
				setUpUdsOK = false
			}
		}
		if s.grpcWorkloadListener != nil {
			if err = s.grpcWorkloadServer.Serve(s.grpcWorkloadListener); err != nil {
				log.Info("SDS grpc server for workload proxies failed to start: ", err)
				serverOk = false
			}
		}
		if serverOk && setUpUdsOK {
			log.Info("mTLS SDS server for workload certificates started, listening on ", security.WorkloadIdentitySocketPath)
			started = true
			break
		}
		time.Sleep(waitTime)
		waitTime *= 2
	}
	if !started {
		log.Info("mTLS SDS grpc server could not be started")
		return fmt.Errorf("mTLS SDS grpc server could not be started! Error: %v", err)
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
