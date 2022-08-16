package sds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"istio.io/pkg/log"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sdsv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/security"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/security/pki/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

type sdsservice struct {
	st *security.SecretManager

	stop   chan struct{}
	reqch  chan *discovery.DiscoveryRequest
	respch chan *discovery.DiscoveryResponse
}

// newSDSService creates Secret Discovery Service which implements envoy SDS API.
func newSDSService() *sdsservice {
	log.Info("DEBUG 2: starting sdsservice")
	ret := &sdsservice{
		stop:   make(chan struct{}),
		reqch:  make(chan *discovery.DiscoveryRequest, 1),
		respch: make(chan *discovery.DiscoveryResponse, 1),
	}
	options := security.CertOptions{
		Host:       "temp",
		IsCA:       false,
		TTL:        time.Hour * 24,
		NotBefore:  time.Now(),
		RSAKeySize: security.DefaultRSAKeysize,
	}

	ret.st = util.NewSecretManager(&options)
	if _, _, err := ret.st.GenerateK8sCSR(options); err != nil {
		log.Info("DEBUG 3: Generate CSR error: ", err)
	}

	return ret
}

// register adds the SDS handle to the grpc server
// func (s *sdsservice) register(rpcs *grpc.Server) {
// 	sdsv3.RegisterSecretDiscoveryServiceServer(rpcs, s)
// }

func (s *sdsservice) StreamSecrets(stream sdsv3.SecretDiscoveryService_StreamSecretsServer) error {
	// TODO: Authenticate the stream context before handle it
	// identitys, err := s.Authenticate(stream.Context())
	log.Info("DEBUG 6: StreamSecret called")
	errch := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
			log.Info("DEBUG 5 Request: ", req)
			if err != nil {
				if status.Code(err) == codes.Canceled || errors.Is(err, io.EOF) {
					err = nil
				}
				errch <- err
				return
			}
			s.reqch <- req
		}
	}()
	var lastReq *discovery.DiscoveryRequest
	for {
		select {
		case newReq := <-s.reqch:
			lastReq = newReq
		case err := <-errch:
			return err
		}
		resp, err := s.buildResponse(lastReq)
		if err != nil {
			return fmt.Errorf("discovery error %v", err)
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func (s *sdsservice) DeltaSecrets(stream sdsv3.SecretDiscoveryService_DeltaSecretsServer) error {
	return status.Error(codes.Unimplemented, "DeltaSecrets not implemented")
}

func (s *sdsservice) FetchSecrets(ctx context.Context, discReq *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "FetchSecrets not implemented")
}

func (s *sdsservice) Close() {
	close(s.stop)
	close(s.reqch)
	close(s.respch)
}

func (s *sdsservice) buildResponse(req *discovery.DiscoveryRequest) (resp *discovery.DiscoveryResponse, err error) {
	resp = &discovery.DiscoveryResponse{
		TypeUrl:     req.TypeUrl,
		VersionInfo: req.VersionInfo,
	}
	csrBytes, _, err := s.st.GenerateK8sCSR(security.CertOptions{
		Host:       req.TypeUrl,
		IsCA:       false,
		RSAKeySize: security.DefaultRSAKeysize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed generate kubernetes CSR %v", err)
	}
	var keyPEM []byte
	// keyPEM = encodeKey(privkey)
	msg, _ := anypb.New(&tlsv3.Secret{
		Name: req.ResourceNames[0],
		Type: &tlsv3.Secret_TlsCertificate{
			TlsCertificate: &tlsv3.TlsCertificate{
				CertificateChain: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{
						InlineBytes: csrBytes,
					},
				},
				// TODO: privateKey should be sgx private key
				PrivateKey: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{
						InlineBytes: keyPEM,
					},
				},
			},
		},
	})
	resp.Resources = append(resp.Resources, msg)
	return resp, nil
}
