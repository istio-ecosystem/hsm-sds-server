package sds

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/pkg/log"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sdsv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	// sgxv3alpha "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/private_key_providers/sgx/v3alpha"
	sgxv3alpha "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/api/sgx/v3alpha"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/internal/sgx"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube/csrwatcher"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube/gateway"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube/quoteattestation"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security/pki/util"
)

const (
	configMapKey             = "mesh"
	injectConfigMapKey       = "config"
	valuesConfigMapKey       = "values"
	istioNamespace           = "istio-system"
	defaultMeshConfigMapName = "istio"
	certSignerEnv            = "ISTIO_META_CERT_SIGNER"
)

type sdsservice struct {
	st                  *security.SecretManager
	stop                chan struct{}
	pushch              chan string
	VersionInfoandNonce map[string]VersionInfoandNonce
	sdsClient           kube.Client
	gwWatcher           *gateway.GatewayWatcher
	qaWatcher           *quoteattestation.QuoteAttestationWatcher
	csrWatcher          *csrwatcher.K8sCSRWatcher
}

type VersionInfoandNonce struct {
	VersionInfo string
	Nonce       string
}

var (
	versionCounter int64
	versionInfo    = strconv.FormatInt(versionCounter, 10)
	nonce, _       = nextNonce()
)

// newSDSService creates Secret Discovery Service which implements envoy SDS API.
func newSDSService(kubeconfig, configContext string) *sdsservice {
	log.Info("starting sds service")
	var sdsSvc *sdsservice
	options := security.CertOptions{
		IsCA:                           false,
		TTL:                            time.Hour * 24,
		NotBefore:                      time.Now(),
		RSAKeySize:                     security.DefaultRSAKeysize,
		Org:                            "Intel(R) Corporation",
		SecretRotationGracePeriodRatio: security.SecretRotationGracePeriodRatioEnv,
	}
	st, err := util.NewSecretManager(&options)
	if st != nil && err == nil {
		sdsSvc = &sdsservice{
			stop:                make(chan struct{}),
			pushch:              make(chan string, 1),
			VersionInfoandNonce: make(map[string]VersionInfoandNonce),
		}
		sdsSvc.st = st
	}

	if sdsSvc != nil {
		if err := sdsSvc.initSDSClient(kubeconfig, configContext); err != nil {
			log.Info("DEBUG initSDSClient: init kube SDS client error: ", err)
		}

		// New a GateWayWatcher to watch the credential name of SDS service
		gwWatcher, err := gateway.NewGatewayWatcher(sdsSvc.sdsClient, sdsSvc.st)
		if err != nil {
			log.Errorf("error in NewGateWayWatcher: %v", err)
		}
		sdsSvc.gwWatcher = gwWatcher
		// start GatewayWatcher to watch the gateway credential Name of SDS service
		log.Info("start GatewayWatcher to watch the gateway credential Name of SDS service")
		go sdsSvc.gwWatcher.Run(sdsSvc.stop)

		// New a QuoteAttestationWatcher to watch the QuoteAttestation object of SDS service
		qaWatcher, err := quoteattestation.NewQuoteAttestationWatcher(sdsSvc.sdsClient, sdsSvc.st)
		if err != nil {
			log.Errorf("error in NewQuoteAttestationWatcher: %v", err)
		}
		sdsSvc.qaWatcher = qaWatcher
		go sdsSvc.qaWatcher.Run(sdsSvc.stop)

		// TODO get cert-signer from proxyconfig
		// sds server fetch the certificate from Istio configmap by default
		caCert, err := sdsSvc.getMatchedCertificates("", "", "")
		if err != nil {
			log.Infof("DEBUG Handle CA certificates: %v", err)
		} else {
			sdsSvc.st.Cache.SetRoot([]byte(caCert.GetPem()))
		}
		log.Infof("Get the CA certificate: %v", caCert)

		// csrWatcher, err := csrwatcher.NewK8sCSRWatcher(sdsSvc.sdsClient, sdsSvc.st)
		// if err != nil {
		// 	log.Errorf("error in NewK8sCSRWatcher: %v", err)
		// }
		// sdsSvc.csrWatcher = csrWatcher
		// log.Info("start csrWatcher to watch the Kubernetes CSR object of SDS service")
		// go sdsSvc.csrWatcher.Run(sdsSvc.stop)
	}

	return sdsSvc
}

func (s *sdsservice) StreamSecrets(stream sdsv3.SecretDiscoveryService_StreamSecretsServer) error {
	log.Info("DEBUG: StreamSecret called")
	var err error
	reqch := make(chan *discovery.DiscoveryRequest, 1)
	respch := make(chan *discovery.DiscoveryResponse, 1)
	errch := make(chan error, 1)

	// For receiving
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				if status.Code(err) == codes.Canceled || errors.Is(err, io.EOF) {
					err = nil
					continue
				}
				errch <- err
				return
			}
			if s.shouldResponse(req) {
				reqch <- req
				// versionCounter++
				// nonce, _ = nextNonce()
			}
		}
	}()

	// For building response
	var lastReq *discovery.DiscoveryRequest
	go func() {
		for {
			select {
			case newReq := <-reqch:
				s.st.SgxctxLock.Lock()
				if s.st.SgxContext == nil {
					s.st.SgxContext, _ = sgx.NewContext(sgx.Config{
						HSMTokenLabel: sgx.HSMTokenLabel,
						HSMUserPin:    sgx.HSMUserPin,
						HSMSoPin:      sgx.HSMSoPin,
						HSMConfigPath: sgx.SgxLibrary,
						HSMKeyLabel:   sgx.HSMKeyLabel,
						HSMKeyType:    sgx.HSMKeyType,
					})
				}
				s.st.SgxctxLock.Unlock()
				lastReq = newReq
			case err := <-errch:
				log.Warnf("Got Error: ", err)
				return
			}
			resp, err := s.buildResponse(lastReq)
			if err != nil {
				log.Warnf("Build response failed: ", err)
				return
			}
			respch <- resp
		}
	}()

	// For workload certificate rotation
	go func() {
		for {
			rotateRequest := <-s.pushch
			resp, err := s.buildRotateResponse(rotateRequest)
			if err != nil {
				return
			}
			respch <- resp
		}
	}()

	// For sending response (Both resp and rotation resp)
	for {
		err = stream.Send(<-respch)
		if err != nil {
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
	close(s.pushch)
}

func (s *sdsservice) buildResponse(req *discovery.DiscoveryRequest) (resp *discovery.DiscoveryResponse, err error) {
	log.Info("Build respunse now: ", time.Now())
	log.Info(s.VersionInfoandNonce)
	versionCounter++
	resp = &discovery.DiscoveryResponse{
		TypeUrl: req.TypeUrl,
		// if first request, versionInfo and Nonce is empty
		VersionInfo: versionInfo,
		Nonce:       nonce,
	}
	log.Info("Request ResourceNames: %v", req.ResourceNames)
	for _, resourceName := range req.ResourceNames {
		// TODO: Encapsulate these functions and do the following steps:
		// Find the certificate in the secretManager cache
		// Generate CSR by resource name (`ROOTCA` or `default`)
		// Get certificate (This should be handle by k8s client)
		// Register the Certificate

		// Get cert from SecretManager Cache first
		var cert []byte
		// This rootCA is of gateway's mTLS rootCA from client
		var gwRootCA []byte
		// is a Gateway request from envoy or not
		var isGateway bool = strings.HasPrefix(resourceName, security.SDSCredNamePrefix)

		ns, isCA := s.st.GetCachedSecret(resourceName)
		if isCA {
			cert = ns.RootCert
		} else if isGateway {
			var myCred *security.GatewayCred
			credMap := s.st.GetCredMap()
			log.Info("Cred Map lenght: ", len(credMap))
			resName := resourceName
			for port, cred := range credMap {
				lableKey := s.st.GetLableKeyWithPortForGateway(port)
				sdsPrefixLableKey := security.HandleCredNameForEnvoy(resourceName)
				sdsSuffixLableKey := strings.TrimSuffix(sdsPrefixLableKey, security.SDSCredNameSuffix)
				log.Info("lableKey: ", lableKey)
				if lableKey == sdsPrefixLableKey || lableKey == sdsSuffixLableKey {
					myCred = cred
					resName = lableKey
					break
				}
			}
			if myCred == nil {
				myCred = &security.GatewayCred{}
				myCred.SetSGXKeyLable(resName)
			}

			if !strings.HasSuffix(resourceName, security.SDSCredNameSuffix) {
				log.Info("wait for certificate data")
				<-myCred.CertSync
				log.Info("certificate data arrive")
				cert = myCred.GetCertData()
				log.Info("certificate data: ", cert)
				if cert == nil {
					return nil, fmt.Errorf("no available certificate for resource [%s]", resName)
				}
			} else {
				log.Info("wait for rootCA data")
				<-myCred.RootSync
				log.Info("rootCA data arrive")
				gwRootCA = myCred.GetRootData()
				log.Info("root CA data: ", gwRootCA)
				if len(gwRootCA) == 0 {
					return nil, fmt.Errorf("no available rootCA for resource [%s]", resName)
				}
			}
		} else if ns == nil {
			log.Infof("DEBUG: cache secret is nil, generate new certificate")
			// cert, err = s.st.GenerateSecret(resourceName)
			cert, err = s.GenCSRandGetCert(resourceName)
			if err != nil {
				return nil, fmt.Errorf("failed Create Certificate %v", err)
			}
			secretItem := security.SecretItem{
				ResourceName:     resourceName,
				CertificateChain: cert,
				RootCert:         s.st.Cache.GetRoot(),
				CreatedTime:      time.Now(),
				ExpireTime:       time.Now().Add(time.Hour * 24),
			}
			// register the new generated secret
			s.registerSecret(secretItem, resourceName)
		} else {
			cert = ns.CertificateChain
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
		} else if isGateway && strings.HasSuffix(resourceName, security.SDSCredNameSuffix) && len(gwRootCA) > 0 {
			secret.Type = &tlsv3.Secret_ValidationContext{
				ValidationContext: &tlsv3.CertificateValidationContext{
					TrustedCa: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineBytes{
							InlineBytes: gwRootCA,
						},
					},
				},
			}
		} else {
			s.toEnvoySecret(secret, cert, isGateway)
		}

		res := MessageToAny(secret)
		resp.Resources = append(resp.Resources, MessageToAny(&discovery.Resource{
			Name:     resourceName,
			Resource: res,
		}))
		resp.Nonce = nonce
		if V, ok := s.VersionInfoandNonce[resourceName]; ok {
			V.VersionInfo = versionInfo
			V.Nonce = nonce
			s.VersionInfoandNonce[resourceName] = V
		} else {
			s.VersionInfoandNonce[resourceName] = VersionInfoandNonce{
				VersionInfo: versionInfo,
				Nonce:       nonce,
			}
		}
	}

	log.Info("DEBUG SDS Resp: ", resp)
	return resp, nil
}

// registerSecret will set the new secret to cache and call delay func
func (s *sdsservice) registerSecret(item security.SecretItem, resourceName string) {
	delay := s.st.RotateTime(item)
	security.CertExpirySeconds.ValueFrom(func() float64 { return time.Until(item.ExpireTime).Seconds() }, item.ResourceName)
	item.ResourceName = resourceName
	if s.st.Cache.GetWorkload() != nil {
		log.Info("%v skip scheduling certificate rotation, already scheduled", resourceName)
		return
	}
	s.st.Cache.SetWorkload(&item)
	log.Info(resourceName, ": scheduled certificate for rotation in ", delay)

	s.st.DelayQueue.PushDelayed(func() error {
		// Clear the cache so the next call generates a fresh certificate
		s.st.Cache.SetWorkload(nil)
		s.pushch <- item.ResourceName
		log.Infof("DEBUG: Time to delay, set workload as nil")
		return nil
	}, delay)
}

// buildRotateResponse build the rotateResponse from rotateRequest in push channel
func (s *sdsservice) buildRotateResponse(resourceName string) (*discovery.DiscoveryResponse, error) {
	log.Infof("DEBUG: Build certificate rotation response now")
	secret := &tlsv3.Secret{
		Name: resourceName,
	}
	resp := &discovery.DiscoveryResponse{
		VersionInfo: versionInfo,
		Nonce:       nonce,
	}
	cert, err := s.GenCSRandGetCert(resourceName)
	if err != nil {
		return nil, fmt.Errorf("failed Create Certificate %v", err)
	}
	secretItem := security.SecretItem{
		ResourceName:     resourceName,
		CertificateChain: cert,
		RootCert:         s.st.Cache.GetRoot(),
		CreatedTime:      time.Now(),
		ExpireTime:       time.Now().Add(time.Hour * 24),
	}
	// register the new generated secret
	s.registerSecret(secretItem, resourceName)
	s.toEnvoySecret(secret, cert, false)
	res := MessageToAny(secret)
	resp.Resources = append(resp.Resources, MessageToAny(&discovery.Resource{
		Name:     resourceName,
		Resource: res,
	}))
	if V, ok := s.VersionInfoandNonce[resourceName]; ok {
		V.VersionInfo = versionInfo
		V.Nonce = nonce
		s.VersionInfoandNonce[resourceName] = V
	} else {
		s.VersionInfoandNonce[resourceName] = VersionInfoandNonce{
			VersionInfo: versionInfo,
			Nonce:       nonce,
		}
	}
	log.Infof("DEBUG: workload certificate updated successfully.")
	log.Info("DEBUG Rotate resp: ", resp)
	return resp, nil
}

func (s *sdsservice) GenCSRandGetCert(resourceName string) ([]byte, error) {
	isCA := false
	log.Info(resourceName)
	var cert []byte
	var err error
	if resourceName == security.RootCertName {
		isCA = true
	}
	if isCA {
		if cert = s.st.Cache.GetRoot(); cert != nil {
			log.Info("Find root cert in secret cache")
			return cert, err
		} else {
			return nil, fmt.Errorf("%v cert not found", resourceName)
		}
	} else {
		csrBytes, err := s.st.GenerateCSR(*s.st.ConfigOptions, security.NeedQuoteExtension)
		if err != nil {
			return nil, fmt.Errorf("failed generate kubernetes CSR %v", err)
		}
		// SetcsrBytes and wait for third part CA signed certificate
		s.st.Cache.SetcsrBytes(csrBytes)
		s.st.SgxctxLock.Lock()
		cert, err = s.SignCSRK8s(csrBytes, resourceName)
		if cert == nil {
			log.Warnf("Can't read signed certificate")
		}
		s.st.SgxctxLock.Unlock()
		if err != nil {
			log.Warnf("Can't get certificate: ", err)
		}
		if cert != nil {
			log.Infof("workload certificate generated successfully.")
			return cert, nil
		}

		// Else self-sign a cert
		// signerCert, err := security.ParsePemEncodedCertificate(s.st.Cache.GetRoot())
		// if err != nil {
		// 	return nil, fmt.Errorf("failed get signer cert from cache %v", err)
		// }
		// if signerCert != nil {
		// 	s.st.ConfigOptions.SignerCert = signerCert
		// }
		// s.st.SgxctxLock.Lock()
		// cert, err = s.st.CreateNewCertificate(csrBytes, s.st.ConfigOptions.SignerCert, time.Hour*24, isCA, x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature,
		// 	[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
		// if err != nil {
		// 	return nil, fmt.Errorf("failed Create New Certificate: %v", err)
		// }
		// s.st.SgxctxLock.Unlock()

		// x509cert, _ := security.ParsePemEncodedCertificate(cert)
		// secretItem := &security.SecretItem{
		// 	ResourceName:     resourceName,
		// 	CertificateChain: cert,
		// 	RootCert:         s.st.Cache.GetRoot(),
		// 	CreatedTime:      x509cert.NotBefore,
		// 	ExpireTime:       x509cert.NotAfter,
		// }
		// log.Infof("workload certificate generated successfully.")
		// s.st.Cache.SetWorkload(secretItem)
		// return cert, nil
		// TODO: approve this csr manually
		// patch := client.MergeFrom(k8scsr.DeepCopy())

		// k8scsr.Status.Conditions = append(k8scsr.Status.Conditions, certv1.CertificateSigningRequestCondition{
		// 	Type:           certv1.CertificateApproved,
		// 	Reason:         "User activation",
		// 	Message:        "This CSR was approved",
		// 	LastUpdateTime: metav1.Now(),
		// 	Status:         v1.ConditionTrue,
		// })
		// k8scsr, err = s.sdsClient.Kube().CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), resourceName, k8scsr, metav1.UpdateOptions{})
		// if err != nil {
		// 	log.Info("Can't Update csr approval")
		// 	log.Info(err)
		// 	return nil, nil
		// }

		// k8scsr.Status.Certificate = append(k8scsr.Status.Certificate, cert...)
		// k8scsr, err = s.sdsClient.Kube().CertificatesV1().CertificateSigningRequests().UpdateStatus(context.TODO(), k8scsr, metav1.UpdateOptions{})
		// if err != nil {
		// 	log.Info("Can't update csr status")
		// 	log.Info(err)
		// 	return nil, nil
		// }
		// for i := 0; i < security.MAXRetryTime; i++ {
		// 	// Waiting for signed CSR object and get cert from spec
		// 	if k8scsr.Status.Certificate != nil {
		// 		log.Info("Get signed certificate from CSR object")
		// 		return k8scsr.Status.Certificate, nil
		// 	}
		// 	// 500ms
		// 	time.Sleep(time.Millisecond * 500)
		// }
		// return cert, nil

	}
	// log.Info("Can't get Certificate from CSR object")
	// return nil, nil
	return nil, nil
}

// shouldResponse determines if the sds server will build response,
// Only the first request will build response, and ACK/NACK will not return response
func (s *sdsservice) shouldResponse(req *discovery.DiscoveryRequest) bool {
	if len(req.ResourceNames) == 0 {
		log.Warnf("No resource name request, unnecessary to response")
		return false
	}
	if req.GetResponseNonce() == "" {
		log.Info("DEBUG Envoy Request nonce is none, need response")
		return true
	} else if (req.GetErrorDetail() != nil) || (req.VersionInfo != s.VersionInfoandNonce[req.ResourceNames[0]].VersionInfo) {
		log.Warnf("Get NACK from Envoy: ", req.GetErrorDetail().GetMessage())
		nonce, _ = nextNonce()
		versionCounter++
		return false
	} else {
		log.Info("Get ACK from Envoy successfully , no response")
		return false
	}

}

// toEnvoySecret add generated cert and sgx configs to tls.Secret
func (s *sdsservice) toEnvoySecret(secret *tlsv3.Secret, cert []byte, isGateway bool) {
	sgxPKMC := &sgxv3alpha.SgxPrivateKeyMethodConfig{
		SgxLibrary: s.st.SgxConfigs.HSMConfigPath,
		KeyLabel:   s.st.SgxConfigs.HSMKeyLabel,
		UsrPin:     s.st.SgxConfigs.HSMUserPin,
		SoPin:      s.st.SgxConfigs.HSMSoPin,
		TokenLabel: s.st.SgxConfigs.HSMTokenLabel,
		KeyType:    s.st.SgxConfigs.HSMKeyType,
	}
	if isGateway {
		sgxPKMC.KeyLabel = security.HandleCredNameForEnvoy(secret.Name)
	}
	conf := MessageToAny(sgxPKMC)
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

// initSDSClient create a default sds kube-istio client
func (s *sdsservice) initSDSClient(kubeconfig, configContext string) error {
	kubeRestConfig, err := kube.DefaultRestConfig(kubeconfig, configContext, func(config *rest.Config) {
		config.QPS = 50
		config.Burst = 100
	})
	if err != nil {
		return fmt.Errorf("failed creating kube config: %v", err)
	}
	s.sdsClient, err = kube.NewSDSClient(kube.NewClientConfigForRestConfig(kubeRestConfig))
	if err != nil {
		return fmt.Errorf("failed creating kube client: %v", err)
	}
	return nil
}

// GetMatchedCertificates will return the matched certificate data defined in mesh configmap
func (s *sdsservice) getMatchedCertificates(meshConfigMapName, revision string, certSigner string) (*meshconfig.MeshConfig_CertificateData, error) {
	// if there is no specified certificates signer, will fetch it from Istio configmap
	if certSigner == "" {
		meshConf, err := s.getMeshConfigFromConfigMap(meshConfigMapName, revision)
		if err != nil {
			return nil, err
		}
		// Fetch the cert signer from Istio configmap
		var certSigner string
		if meshConf != nil {
			defaultConf := meshConf.GetDefaultConfig()
			if defaultConf != nil {
				certSigner = defaultConf.GetProxyMetadata()[certSignerEnv]
			}
		}
		// Set the cert signer as istio namespace
		if certSigner == "" {
			certSigner = istioNamespace
		}
		if meshConf != nil && len(meshConf.CaCertificates) > 0 {
			for _, caCert := range meshConf.CaCertificates {
				for _, signerName := range caCert.CertSigners {
					signers := strings.Split(signerName, "/")
					signer := signers[len(signers)-1]
					if certSigner == signer {
						return caCert, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("cannot get the matched CA certificate with specified ISTIO_META_CERT_SIGNER: %v", certSignerEnv)
}

// getMeshConfigFromConfigMap will return the istio mesh configmap via kube client
func (s *sdsservice) getMeshConfigFromConfigMap(meshConfigMapName, revision string) (*meshconfig.MeshConfig, error) {
	if meshConfigMapName == "" {
		meshConfigMapName = defaultMeshConfigMapName
	}
	if meshConfigMapName == defaultMeshConfigMapName && revision != "" {
		meshConfigMapName = fmt.Sprintf("%s-%s", defaultMeshConfigMapName, revision)
	}

	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	log.Infof("getMeshConfigFromConfigMap KUBERNETES_SERVICE_HOST: %v, KUBERNETES_SERVICE_PORT: %v", host, port)

	meshConfigMap, err := s.sdsClient.Kube().CoreV1().ConfigMaps(istioNamespace).Get(context.TODO(), meshConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not read valid configmap %q from namespace %q: %v - "+
			"please ensure valid MeshConfig exists!",
			meshConfigMapName, istioNamespace, err)
	}

	configYaml, exists := meshConfigMap.Data[configMapKey]
	if !exists {
		return nil, fmt.Errorf("missing configuration map key %q", configMapKey)
	}
	cfg, err := mesh.ApplyMeshConfigDefaults(configYaml)
	if err != nil {
		return nil, fmt.Errorf("cannot parse mesh config based on yaml [%v]", configYaml)
	}

	return cfg, nil
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

func nextNonce() (string, error) {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		return "", errs.Wrap(err)
	}
	return hex.EncodeToString(b), nil
}
