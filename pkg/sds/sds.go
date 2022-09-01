package sds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"istio.io/pkg/log"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sdsv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	sgxv3aplha "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/api/sgx/v3alpha"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/internal/sgx"
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
		// Host:       csrHost.String(),
		IsCA:       false,
		TTL:        time.Hour * 24,
		NotBefore:  time.Now(),
		RSAKeySize: security.DefaultRSAKeysize,
	}

	ret.st = util.NewSecretManager(&options)

	return ret
}

func (s *sdsservice) StreamSecrets(stream sdsv3.SecretDiscoveryService_StreamSecretsServer) error {
	// TODO: Authenticate the stream context before handle it
	log.Info("DEBUG 6: StreamSecret called")
	errch := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
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
			if s.st.SgxContext == nil {
				s.st.SgxContext, _ = sgx.NewContext(sgx.Config{
					HSMTokenLabel: sgx.HSMTokenLabel,
					HSMUserPin:    sgx.HSMUserPin,
					HSMSoPin:      sgx.HSMSoPin,
					HSMConfigPath: sgx.SgxLibrary,
					HSMKeyLabel:   sgx.DefaultKeyLabel,
					HSMKeyType:    sgx.HSMKeyType,
				})
			}
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
	for _, resourceName := range req.ResourceNames {
		// TODO: Encapsulate these functions and do the following steps:
		// Find the certificate in the secretManager cache
		// Generate CSR by resource name (`ROOTCA` or `default`)
		// Get certificate (This should be handle by k8s client)
		// Register the Certificate
		cert, err := s.st.GenerateSecret(resourceName)
		if err != nil {
			return nil, fmt.Errorf("SDS: failed Create Certificate:  %v", err)
		}
		secret := &tlsv3.Secret{
			Name: resourceName,
		}
		if resourceName == security.RootCertName {
			secret.Type = &tlsv3.Secret_ValidationContext{
				ValidationContext: &tlsv3.CertificateValidationContext{
					TrustedCa: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineBytes{
							InlineBytes: cert,
						},
					},
				},
			}
		} else {
			conf := MessageToAny(&sgxv3aplha.SgxPrivateKeyMethodConfig{
				SgxLibrary: s.st.SgxConfigs.HSMConfigPath,
				KeyLabel:   resourceName,
				UsrPin:     s.st.SgxConfigs.HSMUserPin,
				SoPin:      s.st.SgxConfigs.HSMSoPin,
				TokenLabel: s.st.SgxConfigs.HSMTokenLabel,
				KeyType:    s.st.SgxConfigs.HSMKeyType,
			})

			secret.Type = &tlsv3.Secret_TlsCertificate{
				TlsCertificate: &tlsv3.TlsCertificate{
					CertificateChain: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineBytes{
							InlineBytes: cert,
						},
					},
					PrivateKeyProvider: &tlsv3.PrivateKeyProvider{
						ProviderName: "sgx",
						ConfigType: &tlsv3.PrivateKeyProvider_TypedConfig{
							TypedConfig: conf,
						},
					},
					PrivateKey: nil,
				},
			}
		}

		res := MessageToAny(secret)
		resp.Resources = append(resp.Resources, MessageToAny(&discovery.Resource{
			Name:     resourceName,
			Resource: res,
		}))
	}

	log.Info("DEBUG SDS Resp: ", resp)
	return resp, nil
}

// MessageToAny converts from proto message to proto Any
func MessageToAny(msg proto.Message) *anypb.Any {
	out, err := MessageToAnyWithError(msg)
	if err != nil {
		log.Error(fmt.Sprintf("error marshaling Any %s: %v", prototext.Format(msg), err))
		return nil
	}
	return out
}

func MessageToAnyWithError(msg proto.Message) (*anypb.Any, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return &anypb.Any{
		// nolint: staticcheck
		TypeUrl: "type.googleapis.com/" + string(msg.ProtoReflect().Descriptor().FullName()),
		Value:   b,
	}, nil
}
