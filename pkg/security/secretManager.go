package security

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"strings"
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
	GatewayIdentitySocketPath  = "/var/run/secrets/credential-uds/socket"
	DefaultRSAKeysize          = 2048
	RootCertName               = "ROOTCA"
	WorkloadCertName           = "default"
	PendingSelfSignerName      = "clusterissuers.tcs.intel.com/istio-system"
	SDSCredNamePrefix          = "sds://"
	// Max retry time to get signed certificate in kubernetes csr
	MAXRetryTime = 5
	// PendingSelfSignerName      = "kubernetes.io/kube-apiserver-client"
)

// Default cert expire seconds: one day
var DefaultExpirationSeconds int32 = 86400

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

type GatewayCred struct {
	sgxKeyLable string
	certData    []byte
	rootData    []byte
	DataSync    chan struct{}
}

type SecretCache struct {
	mu       sync.RWMutex
	workload *SecretItem
	rootCert []byte
	csrBytes []byte
	credMap  map[*istioapi.Port]*GatewayCred
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
	WorkloadNamespace = env.RegisterStringVar("POD_NAMESPACE", "default", "").Get()
	ServiceAccount    = env.RegisterStringVar("SERVICE_ACCOUNT", "default", "Name of service account").Get()

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
		csrBytes, err := sc.GenerateCSR(*sc.ConfigOptions, true)
		if err != nil {
			return nil, fmt.Errorf("failed generate kubernetes CSR %v", err)
		}
		// SetcsrBytes and wait for third part CA signed certificate
		sc.Cache.SetcsrBytes(csrBytes)
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

func (sc *SecretManager) GenerateCSR(options CertOptions, needQuoteExtension bool) ([]byte, error) {

	var template *x509.CertificateRequest
	var err error
	csrHostName := &SPIFFEIdentity{
		TrustDomain:    TrustDomain,
		Namespace:      WorkloadNamespace,
		ServiceAccount: ServiceAccount,
	}

	log.Info("DEBUG SPIFFE ID: ", csrHostName)
	options.Host = csrHostName.String()
	if needQuoteExtension {
		if err = sc.SgxContext.GenerateQuoteAndPublicKey(false); err != nil {
			return nil, fmt.Errorf("failed to generate sgx quote and public key %s", err)
		}
		quote, err := sc.SgxContext.Quote(false)
		if err != nil {
			return nil, fmt.Errorf("get sgx quote error %s", err)
		}

		quotePubKey, err := sc.SgxContext.QuotePublicKey(false)
		if err != nil {
			return nil, fmt.Errorf("get quote public key error %s", err)
		}
		template, err = GenCSRTemplate(options, quote, quotePubKey, true)
		if err != nil {
			return nil, fmt.Errorf("CSR template creation failed (%v)", err)
		}
	} else {
		template, err = GenCSRTemplate(options, nil, nil, false)
		if err != nil {
			return nil, fmt.Errorf("CSR template creation failed (%v)", err)
		}
	}

	log.Info("CSR template generated")
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
	signerKey, err := ParsePemEncodedKey(CAKey)
	if err != nil {
		log.Warn(err)
		return nil, fmt.Errorf("ParsePemEncodedKey failed (%v)", err)
	}
	certPem, err := x509.CreateCertificate(rand.Reader, certTemplate, signerCert, privKey.Public(), signerKey)

	if err != nil {
		log.Warn(err)
		return nil, fmt.Errorf("Create Certificate failed (%v)", err)
	}
	cert, err = encodePem(false, certPem)
	return cert, err
}

const (
	blockTypeECPrivateKey    = "EC PRIVATE KEY"
	blockTypeRSAPrivateKey   = "RSA PRIVATE KEY" // PKCS#1 private key
	blockTypePKCS8PrivateKey = "PRIVATE KEY"     // PKCS#8 plain private key
)

func ParsePemEncodedKey(keyBytes []byte) (crypto.PrivateKey, error) {
	kb, _ := pem.Decode(keyBytes)
	if kb == nil {
		return nil, fmt.Errorf("invalid PEM-encoded key")
	}

	switch kb.Type {
	case blockTypeECPrivateKey:
		key, err := x509.ParseECPrivateKey(kb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the ECDSA private key")
		}
		return key, nil
	case blockTypeRSAPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the RSA private key")
		}
		return key, nil
	case blockTypePKCS8PrivateKey:
		key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the PKCS8 private key")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type for a private key: %s", kb.Type)
	}
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

// GetRoot returns cached root cert. This method is thread safe.
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

// GetRoot returns cached workload SecretItem. This method is thread safe.
func (s *SecretCache) GetWorkload() *SecretItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.workload == nil {
		return nil
	}
	return s.workload
}

// SetWorkload sets workload SecretItem into cache. This method is thread safe.
func (s *SecretCache) SetWorkload(value *SecretItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workload = value
}

// SetcsrBytes sets csrBytes into cache. This method is thread safe.
func (s *SecretCache) SetcsrBytes(csrBytes []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.csrBytes = csrBytes
}

// SetcsrBytes sets csrBytes into cache. This method is thread safe.
func (s *SecretCache) GetcsrBytes() (csrBytes []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.csrBytes
}

func (sc *SecretManager) GetCredMap() map[*istioapi.Port]*GatewayCred {
	if sc.Cache.credMap == nil {
		sc.Cache.credMap = make(map[*istioapi.Port]*GatewayCred)
	}
	return sc.Cache.credMap
}

func (sc *SecretManager) GetCredWithPort(port *istioapi.Port) *GatewayCred {
	if sc.Cache.credMap != nil {
		return sc.Cache.credMap[port]
	}
	return nil
}

func (sc *SecretManager) GetLableKeyWithPortForGateway(port *istioapi.Port) string {
	if sc.Cache.credMap != nil {
		return sc.Cache.credMap[port].sgxKeyLable
	}
	return ""
}

func (sc *SecretManager) GetCertWithPortForGateway(port *istioapi.Port) []byte {
	if sc.Cache.credMap != nil {
		return sc.Cache.credMap[port].certData
	}
	return nil
}

func (sc *SecretManager) GetCAWithPortForGateway(port *istioapi.Port) []byte {
	if sc.Cache.credMap != nil {
		return sc.Cache.credMap[port].rootData
	}
	return nil
}

func (sc *SecretManager) SetCredMap(port *istioapi.Port, cred *GatewayCred) {
	sc.Cache.mu.RLock()
	defer sc.Cache.mu.RUnlock()
	if sc.Cache.credMap == nil {
		sc.Cache.credMap = make(map[*istioapi.Port]*GatewayCred)
	}
	sc.Cache.credMap[port] = cred
}

func (sc *SecretManager) RegisterSecretHandler(h func(resourceName string)) {
	sc.SgxctxLock.Lock()
	defer sc.SgxctxLock.Unlock()
	sc.secretHandler = h
}

func (gwC *GatewayCred) GetSGXKeyLable() string {
	return gwC.sgxKeyLable
}

func (gwC *GatewayCred) SetSGXKeyLable(keyLable string) {
	gwC.sgxKeyLable = keyLable
}

func (gwC *GatewayCred) GetCertData() []byte {
	return gwC.certData
}

func (gwC *GatewayCred) SetCertData(certData []byte) {
	gwC.certData = certData
}

// GenCSRTemplate generates a certificateRequest template with the given options.
func GenCSRTemplate(options CertOptions, quote []byte, quotePubKey []byte, needQuoteExtension bool) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "SGX based workload",
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

	// Build sgx quote extension here
	if needQuoteExtension {
		s, _ := BuildQuoteExtension(quote)
		template.ExtraExtensions = append(template.ExtraExtensions, *s)
		p, _ := BuildPubkeyExtension(quotePubKey)
		template.ExtraExtensions = append(template.ExtraExtensions, *p)
	}

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

// NewCACertificate returns a self-signed certificate used as certificate authority
func (sc *SecretManager) NewCACertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	max := new(big.Int).SetInt64(math.MaxInt64)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		Version:               tls.VersionTLS12,
		SerialNumber:          serial,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		Subject: pkix.Name{
			CommonName:   "SGX self-signed root certificate authority",
			Organization: []string{"Intel(R) Corporation"},
		},
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caPrivKey.Public(), caPrivKey)
	*tmpl = x509.Certificate{}
	if err != nil {
		return nil, nil, err
	}
	// certPem, _ := encodePem(false, certBytes)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, caPrivKey, nil
}

func HandleCredNameForEnvoy(credName string) string {
	if credName == "" {
		return credName
	}
	// remove the 'sds://' prefix
	delPrefix := strings.TrimPrefix(credName, SDSCredNamePrefix)
	// replace the '.' by '-'
	newCredName := strings.ReplaceAll(delPrefix, ".", "-")
	return newCredName
}

