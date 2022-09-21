package security

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	istioapi "istio.io/api/networking/v1alpha3"
	"istio.io/pkg/env"
	"istio.io/pkg/log"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/internal/sgx"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/queue"
)

const (
	WorkloadIdentitySocketPath = "/var/run/secrets/workload-spiffe-uds/socket"
	DefaultRSAKeysize          = 2048
	RootCertName               = "ROOTCA"
	WorkloadCertName           = "default"
)

type SecretManager struct {
	Name string
	// configOptions includes all configurable params for the cache.
	ConfigOptions *CertOptions
	SgxConfigs    *sgx.Config
	SgxContext    *sgx.SgxContext
	SgxctxLock    sync.Mutex
	Cache         SecretCache
	// queue maintains all certificate rotation events that need to be triggered when they are about to expire
	DelayQueue queue.Delayed
	Stop       chan struct{}
	// callback function to invoke when detecting secret change.
	secretHandler func(resourceName string)
}

type SecretCache struct {
	mu          sync.RWMutex
	workload    *SecretItem
	rootCert    []byte
	csrBytes    []byte
	credNameMap map[*istioapi.Port]string
}

type SecretItem struct {
	CertificateChain []byte
	PrivateKeyLabel  []byte

	RootCert []byte

	// ResourceName passed from envoy SDS discovery request.
	// "ROOTCA" for root cert request, "default" for key/cert request.
	ResourceName string

	CreatedTime time.Time

	ExpireTime time.Time
}

// SupportedECSignatureAlgorithms are the types of EC Signature Algorithms
// to be used in key generation (e.g. ECDSA or ED2551)
type SupportedECSignatureAlgorithms string

const (
	// only ECDSA using P256 is currently supported
	EcdsaSigAlg SupportedECSignatureAlgorithms = "ECDSA"
	RsaSignAlg  SupportedECSignatureAlgorithms = "RSA"
)

func (alg SupportedECSignatureAlgorithms) String() string {
	return string(alg)
}

const (
	Scheme = "spiffe"

	URIPrefix    = Scheme + "://"
	URIPrefixLen = len(URIPrefix)

	// The default SPIFFE URL value for trust domain
	defaultTrustDomain    = "cluster.local"
	ServiceAccountSegment = "sa"
	NamespaceSegment      = "ns"
)

// SPIFFE Identity type define
type SPIFFEIdentity struct {
	TrustDomain    string
	Namespace      string
	ServiceAccount string
}

func (i SPIFFEIdentity) String() string {
	return URIPrefix + i.TrustDomain + "/ns/" + i.Namespace + "/sa/" + i.ServiceAccount
}

type CertOptions struct {
	// Comma-separated hostnames and IPs to generate a certificate for.
	// This can also be set to the identity running the workload,
	// like kubernetes service account.
	Host string

	// The NotBefore field of the issued certificate.
	NotBefore time.Time

	// TTL of the certificate. NotAfter - NotBefore.
	TTL time.Duration

	// Signer certificate.
	SignerCert *x509.Certificate

	// Signer private key.
	SignerPriv crypto.PrivateKey

	// Signer private key (PEM encoded).
	SignerPrivPem []byte

	// Organization for this certificate.
	Org string

	// The size of RSA private key to be generated.
	RSAKeySize int

	// Whether this certificate is used as signing cert for CA.
	IsCA bool

	// Whether this certificate is self-signed.
	IsSelfSigned bool

	// Whether this certificate is for a client.
	IsClient bool

	// Whether this certificate is for a server.
	IsServer bool

	// Whether this certificate is for dual-use clients (SAN+CN).
	IsDualUse bool

	// If true, the private key is encoded with PKCS#8.
	PKCS8Key bool

	// The type of Elliptical Signature algorithm to use
	// when generating private keys. Currently only ECDSA is supported.
	// If empty, RSA is used, otherwise ECC is used.
	ECSigAlg SupportedECSignatureAlgorithms

	// Subjective Alternative Name values.
	DNSNames string

	// The ratio of cert lifetime to refresh a cert. For example, at 0.10 and 1 hour TTL,
	// we would refresh 6 minutes before expiration.
	SecretRotationGracePeriodRatio float64
}

var (
	TrustDomain = env.RegisterStringVar("TRUST_DOMAIN", "cluster.local",
		"The trust domain for spiffe certificates").Get()
	WorkloadNamespace = env.RegisterStringVar("POD_NAMESPACE", "", "").Get()
	ServiceAccount    = env.RegisterStringVar("SERVICE_ACCOUNT", "", "Name of service account").Get()

	secretRotationGracePeriodRatioEnv = env.Register("SECRET_GRACE_PERIOD_RATIO", 0.5,
		"The grace period ratio for the cert rotation, by default 0.5.").Get()
)

func (sc *SecretManager) GenerateSecret(resourceName string) ([]byte, error) {
	isCA := false
	log.Info(resourceName)
	var cert []byte
	var err error
	if resourceName == RootCertName {
		isCA = true
	}

	if isCA {
		if cert = sc.Cache.GetRoot(); cert != nil {
			log.Info("Find root cert in secret cache")
			return cert, err
		} else {
			return nil, fmt.Errorf("%v cert not found", resourceName)
		}
	} else {
		csrBytes, err := sc.GenerateK8sCSR(*sc.ConfigOptions)
		if err != nil {
			return nil, fmt.Errorf("failed generate kubernetes CSR %v", err)
		}
		signerCert, err := ParsePemEncodedCertificate(sc.Cache.GetRoot())
		if err != nil {
			return nil, fmt.Errorf("failed get signer cert from cache %v", err)
		}
		if signerCert != nil {
			sc.ConfigOptions.SignerCert = signerCert
		}
		cert, err = sc.CreateNewCertificate(csrBytes, sc.ConfigOptions.SignerCert, time.Hour*24, isCA, x509.KeyUsageCRLSign|x509.KeyUsageCertSign|x509.KeyUsageContentCommitment,
			[]x509.ExtKeyUsage{})
		if err != nil {
			return nil, fmt.Errorf("failed Create New Certificate: %v", err)
		}
	}
	return cert, nil
}

func (sc *SecretManager) GenerateK8sCSR(options CertOptions) ([]byte, error) {

	csrHostName := &SPIFFEIdentity{
		TrustDomain:    TrustDomain,
		Namespace:      WorkloadNamespace,
		ServiceAccount: ServiceAccount,
	}

	options.Host = csrHostName.String()

	template, err := GenCSRTemplate(options)
	if err != nil {
		return nil, fmt.Errorf("CSR template creation failed (%v)", err)
	}
	log.Info("DEBUG Template:", template)
	var privKey crypto.Signer

	cryptoctx, err := sc.SgxContext.GetCryptoContext()
	if err != nil {
		return nil, fmt.Errorf("failed find crypto11 context: %v", err)
	}
	privKey, err = cryptoctx.FindKeyPair(nil, []byte(sc.SgxConfigs.HSMKeyLabel))
	if err != nil {
		return nil, fmt.Errorf("GenerateK8sCSR: failed find crypto11 private key: %v", err)
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, fmt.Errorf("CSR creation failed (%v)", err)
	}
	csrPem, err := encodePem(true, csrBytes)
	return csrPem, err
}

func (sc *SecretManager) CreateNewCertificate(csrPEM []byte, signerCert *x509.Certificate, duration time.Duration, isCA bool, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) ([]byte, error) {
	var cert []byte
	var err error
	certTemplate, err := GenCertTemplate(csrPEM, duration, isCA, keyUsage, extKeyUsage)
	if err != nil {
		return nil, fmt.Errorf("Generate cert template error: (%v)", err)
	}
	var privKey crypto.Signer

	cryptoctx, err := sc.SgxContext.GetCryptoContext()
	if err != nil {
		return nil, fmt.Errorf("failed find crypto11 context: %v", err)
	}
	privKey, err = cryptoctx.FindKeyPair(nil, []byte(sc.SgxConfigs.HSMKeyLabel))
	if err != nil {
		return nil, fmt.Errorf("CreateNewCertificate: failed find crypto11 private key: %v", err)
	}
	if signerCert == nil {
		signerCert = certTemplate
	}
	certPem, err := x509.CreateCertificate(rand.Reader, signerCert, certTemplate, privKey.Public(), privKey)
	if err != nil {
		return nil, fmt.Errorf("Create Certificate failed (%v)", err)
	}
	cert, err = encodePem(false, certPem)
	return cert, err
}

// getCachedSecret: retrieve cached cert (workload-certificate/workload-root) from secretManager
func (sc *SecretManager) GetCachedSecret(resourceName string) (*SecretItem, bool) {
	isCA := false
	if resourceName == RootCertName {
		isCA = true
	}
	if isCA {
		return &SecretItem{
			ResourceName: resourceName,
			RootCert:     sc.Cache.GetRoot(),
		}, isCA
	} else {
		return sc.Cache.GetWorkload(), isCA
	}
}

// GetRoot returns cached root cert and cert expiration time. This method is thread safe.
func (s *SecretCache) GetRoot() (rootCert []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rootCert
}

// SetRoot sets root cert into cache. This method is thread safe.
func (s *SecretCache) SetRoot(rootCert []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rootCert = rootCert
}

func (s *SecretCache) GetWorkload() *SecretItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.workload == nil {
		return nil
	}
	return s.workload
}

func (s *SecretCache) SetWorkload(value *SecretItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workload = value
}

func (sc *SecretManager) GetCredNameMap() map[*istioapi.Port]string {
	if sc.Cache.credNameMap == nil {
		sc.Cache.credNameMap = make(map[*istioapi.Port]string)
	}
	return sc.Cache.credNameMap
}

func (sc *SecretManager) GetCredNameMapWithPort(port *istioapi.Port) string {
	if sc.Cache.credNameMap != nil {
		return sc.Cache.credNameMap[port]
	}
	return ""
}

func (sc *SecretManager) SetCredNameMap(port *istioapi.Port, credName string) {
	sc.Cache.mu.RLock()
	defer sc.Cache.mu.RUnlock()
	if sc.Cache.credNameMap == nil {
		sc.Cache.credNameMap = make(map[*istioapi.Port]string)
	}
	sc.Cache.credNameMap[port] = credName
}

func (sc *SecretManager) RegisterSecretHandler(h func(resourceName string)) {
	sc.SgxctxLock.Lock()
	defer sc.SgxctxLock.Unlock()
	sc.secretHandler = h
}

// GenCSRTemplate generates a certificateRequest template with the given options.
func GenCSRTemplate(options CertOptions) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{options.Org},
		},
	}

	// Build spiffe extension here
	if h := options.Host; len(h) > 0 {
		s, err := BuildSubjectAltNameExtension(h)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = []pkix.Extension{*s}
	}

	// TODO: Add Quote Extension

	return template, nil
}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func GenCertTemplate(csrPEM []byte, duration time.Duration, isCA bool, keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage) (*x509.Certificate, error) {

	csr, err := ParsePemEncodedCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err.Error())
	}

	return &x509.Certificate{
		Version:               csr.Version,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		IsCA:                  isCA,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage:       keyUsage,
		ExtKeyUsage:    extKeyUsage,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}, nil
}

func encodePem(isCSR bool, csrOrCert []byte) (
	csrOrCertPem []byte, err error) {
	encodeMsg := "CERTIFICATE"
	if isCSR {
		encodeMsg = "CERTIFICATE REQUEST"
	}
	csrOrCertPem = pem.EncodeToMemory(&pem.Block{Type: encodeMsg, Bytes: csrOrCert})
	err = nil
	return
}

func ParsePemEncodedCertificate(certBytes []byte) (*x509.Certificate, error) {
	cb, _ := pem.Decode(certBytes)
	if cb == nil {
		return nil, fmt.Errorf("invalid PEM encoded certificate")
	}

	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate")
	}

	return cert, nil
}

// ParsePemEncodedCSR constructs a `x509.CertificateRequest` object using the
// given PEM-encoded certificate signing request.
func ParsePemEncodedCSR(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrBytes)
	if block == nil {
		return nil, fmt.Errorf("certificate signing request is not properly encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate signing request")
	}
	return csr, nil
}

// newCACertificate returns a self-signed certificate used as certificate authority
func newCACertificate(key crypto.Signer) ([]byte, error) {
	max := new(big.Int).SetInt64(math.MaxInt64)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Version:               tls.VersionTLS12,
		SerialNumber:          serial,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		Subject: pkix.Name{
			CommonName:   "SGX self-signed root certificate authority",
			Organization: []string{"Intel(R) Corporation"},
		},
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)

	return certBytes, nil
}
