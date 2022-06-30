package sds

import (
	"fmt"
	"net"
	"time"

	"go.uber.org/atomic"
	"google.golang.org/grpc"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/uds"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/security"
)

const (
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
	s.initWorkloadgRPC()
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

func (s *Server) initWorkloadgRPC() {
	s.grpcWorkloadServer = grpc.NewServer(s.grpcServerOptions()...)
	s.workloadSds.register(s.grpcWorkloadServer)
	var err error
	s.grpcWorkloadListener, err = uds.NewListener(security.WorkloadIdentitySocketPath)
	if err != nil {
		fmt.Println(err)
		fmt.Println(fmt.Errorf("fail to setup Uds listener in %v", security.WorkloadIdentitySocketPath))
	}
	fmt.Println("Starting SDS grpc server")

	// if s.grpcWorkloadListener != nil {
	// 	defer s.grpcWorkloadListener.Close()
	// 	// TODO: handler receive to DiscoveryRequest
	// 	s.grpcWorkloadConnection, err = s.grpcWorkloadListener.Accept()
	// 	if err != nil {
	// 		fmt.Println("connection init failed %v", err)
	// 	}
	// 	// go{
	// 	// s.grpcWorkloadConnection.onReceive()
	// 	// }
	// }

	// for debug
	// fmt.Println(s.grpcWorkloadServer.GetServiceInfo())
	// fmt.Println(s.grpcWorkloadListener.Addr())
	go func() {
		waitTime := time.Second
		started := false
		for i := 0; i < maxRetryTimes; i++ {
			if s.stopped.Load() {
				return
			}
			serverOk := true
			setUpUdsOK := true
			if s.grpcWorkloadListener == nil {
				if s.grpcWorkloadListener, err = uds.NewListener(security.WorkloadIdentitySocketPath); err != nil {
					// sdsServiceLog.Errorf("SDS grpc server for workload proxies failed to set up UDS: %v", err)
					fmt.Println(fmt.Errorf("SDS grpc server for workload proxies failed to set up UDS: %v", err))
					setUpUdsOK = false
				}
			}
			if s.grpcWorkloadListener != nil {
				if err = s.grpcWorkloadServer.Serve(s.grpcWorkloadListener); err != nil {
					fmt.Println(fmt.Errorf("SDS grpc server failed to start: %v", err))
					serverOk = false
				}
			}
			if serverOk && setUpUdsOK {
				fmt.Printf("SDS server started, listening on %q", security.WorkloadIdentitySocketPath)
				started = true
				break
			}
			time.Sleep(waitTime)
			waitTime *= 2
		}
		if !started {
			fmt.Printf("SDS grpc server could not be started")
		}
	}()
}

func (s *Server) grpcServerOptions() []grpc.ServerOption {
	grpcOptions := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(uint32(maxStreams)),
	}

	return grpcOptions
}

// func onReceive(){

// }
