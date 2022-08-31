package security

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/internal/sgx"
	// "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/security/pki/util"
	"istio.io/pkg/env"
	"istio.io/pkg/log"
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
	cache         *secretCache
}

type secretCache struct {
	mu       sync.RWMutex
	workload *SecretItem
	rootCert []byte
	csrBytes []byte
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
}

var (
	TrustDomain = env.RegisterStringVar("TRUST_DOMAIN", "cluster.local",
		"The trust domain for spiffe certificates").Get()
	WorkloadNamespace = env.RegisterStringVar("POD_NAMESPACE", "", "").Get()
	ServiceAccount    = env.RegisterStringVar("SERVICE_ACCOUNT", "", "Name of service account").Get()
)

func (sc *SecretManager) GenerateSecret(resourceName string) ([]byte, error) {
	isCA := false
	log.Info(resourceName)
	var cert []byte
	// var err error
	if resourceName == RootCertName {
		isCA = true
	}
	if isCA {
		// if cert = sc.GetRoot(); cert != nil {
		// 	log.Info("Find root cert in secret cache")
		// 	return cert, err
		// }
		cryptoctx, err := sc.SgxContext.GetCryptoContext()
		if err != nil {
			return nil, fmt.Errorf("failed find crypto11 context: %v", err)
		}
		privKey, err := cryptoctx.FindKeyPair(nil, []byte(sc.SgxConfigs.HSMKeyLabel))
		if err != nil {
			return nil, fmt.Errorf("failed find crypto11 private key: %v", err)
		}
		certByte, err := newCACertificate(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed generate root cert: %v", err)
		}
		// sc.SetRoot(certByte)
		cert, _ = encodePem(false, certByte)
	} else {
		csrBytes, err := sc.GenerateK8sCSR(CertOptions{
			IsCA:       isCA,
			TTL:        time.Hour * 240,
			NotBefore:  time.Now(),
			RSAKeySize: DefaultRSAKeysize,
		})
		if err != nil {
			return nil, fmt.Errorf("failed generate kubernetes CSR %v", err)
		}
		cert, err = sc.CreateNewCertificate(csrBytes, time.Hour*240, isCA, x509.KeyUsageCRLSign|x509.KeyUsageCertSign|x509.KeyUsageContentCommitment,
			[]x509.ExtKeyUsage{})
		if err != nil {
			return nil, fmt.Errorf("failed Create Certificate %v", err)
		}
	}
	// sc.registerSecret(isCA, cert)
	return cert, nil
}

func (sc *SecretManager) GenerateK8sCSR(options CertOptions) ([]byte, error) {
	// if options.IsCA {
	// 	// TODO: find RootCert
	// 	if rootcert, err := sc.getCacheRootCert(); rootcert != nil {
	// 		log.Info("Find root cert in secret cache")
	// 		return rootcert, err
	// 	}
	// }

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
		return nil, fmt.Errorf("failed find crypto11 private key: %v", err)
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, fmt.Errorf("CSR creation failed (%v)", err)
	}
	// log.Info("DEBUG csrBytes:", csrBytes)
	// certTemplate, _ := GenCertTemplate(csrBytes, time.Hour*24, false, x509.KeyUsageCRLSign|x509.KeyUsageCertSign|x509.KeyUsageContentCommitment,
	// 	[]x509.ExtKeyUsage{})
	// cert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, privKey.Public(), privKey)
	// if err != nil {
	// 	return nil, fmt.Errorf("Create Certificate failed (%v)", err)
	// }
	csrPem, err := encodePem(true, csrBytes)
	return csrPem, err
}

func (sc *SecretManager) CreateNewCertificate(csrPEM []byte, duration time.Duration, isCA bool, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) ([]byte, error) {
	var cert []byte
	var err error
	// FIXME
	// if cert, err = sc.getCacheWorkloadCert(); cert != nil {
	// 	log.Info("Find cert in secret cache")
	// 	return cert, err
	// }
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
		return nil, fmt.Errorf("failed find crypto11 private key: %v", err)
	}
	// parent, err := x509.ParseCertificate(sc.cache.rootCert)
	certPem, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, privKey.Public(), privKey)
	if err != nil {
		return nil, fmt.Errorf("Create Certificate failed (%v)", err)
	}
	cert, err = encodePem(false, certPem)
	// log.Info("DEBUG: Cert generated: ", cert)
	return cert, err
}

// GetRoot returns cached root cert and cert expiration time. This method is thread safe.
func (sc *SecretManager) GetRoot() (rootCert []byte) {
	sc.cache.mu.RLock()
	defer sc.cache.mu.RUnlock()
	return sc.cache.rootCert
}

// SetRoot sets root cert into cache. This method is thread safe.
func (sc *SecretManager) SetRoot(rootCert []byte) {
	sc.cache.mu.Lock()
	defer sc.cache.mu.Unlock()
	sc.cache.rootCert = rootCert
}

func (sc *SecretManager) GetWorkload() *SecretItem {
	sc.cache.mu.RLock()
	defer sc.cache.mu.RUnlock()
	if sc.cache.workload == nil {
		return nil
	}
	return sc.cache.workload
}

func (sc *SecretManager) SetWorkload(value *SecretItem) {
	sc.cache.mu.Lock()
	defer sc.cache.mu.Unlock()
	sc.cache.workload = value
}

func (sc *SecretManager) registerSecret(item SecretItem) {

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

func GenCertTemplate(csrPEM []byte, duration time.Duration, isCA bool, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) (*x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("failed to decode csr")
		// log.Info(err)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
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
		NotAfter:              time.Now().Add(time.Hour * 24 * 365).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		Subject: pkix.Name{
			CommonName:   "SGX self-signed root certificate authority",
			Organization: []string{"Intel(R) Corporation"},
		},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	// *tmpl = x509.Certificate{}
	// if err != nil {
	// 	return nil, err
	// }

	// cert, err := x509.ParseCertificate(certBytes)
	// if err != nil {
	// 	return nil, err
	// }

	// runtime.SetFinalizer(cert, func(c *x509.Certificate) {
	// 	*c = x509.Certificate{}
	// })

	return certBytes, nil
}
