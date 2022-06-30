package security

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

const (
	WorkloadIdentitySocketPath = "/var/run/secrets/workload-spiffe-uds/socket.sock"
	DefaultRSAKeysize          = 2048
	BlockTypeECPrivateKey      = "EC PRIVATE KEY"
	BlockTypeRSAPrivateKey     = "RSA PRIVATE KEY" // PKCS#1 private key
	BlockTypePKCS8PrivateKey   = "PRIVATE KEY"     // PKCS#8 plain private key
)

// type SecretManager interface {
// 	GenerateK8sCSR(options CertOptions) ([]byte, error)
// }

type SecretManager struct {
	Name string
	// configOptions includes all configurable params for the cache.
	ConfigOptions *CertOptions
}

// SupportedECSignatureAlgorithms are the types of EC Signature Algorithms
// to be used in key generation (e.g. ECDSA or ED2551)
type SupportedECSignatureAlgorithms string

const (
	// only ECDSA using P256 is currently supported
	EcdsaSigAlg SupportedECSignatureAlgorithms = "ECDSA"
)

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

func (sc *SecretManager) GenerateK8sCSR(options CertOptions) ([]byte, *rsa.PrivateKey, error) {
	// sgx.NewContext()
	priv, err := rsa.GenerateKey(rand.Reader, options.RSAKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA key generation failed (%v)", err)
	}
	template, err := GenCSRTemplate(options)
	if err != nil {
		return nil, nil, fmt.Errorf("CSR template creation failed (%v)", err)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, crypto.PrivateKey(priv))
	if err != nil {
		return nil, nil, fmt.Errorf("CSR creation failed (%v)", err)
	}

	// csr, privKey, err := encodePem(true, csrBytes, priv, options.PKCS8Key)
	return csrBytes, priv, err
}

// GenCSRTemplate generates a certificateRequest template with the given options.
func GenCSRTemplate(options CertOptions) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{options.Org},
		},
	}

	// TODO: build SAN extension
	// if h := options.Host; len(h) > 0 {
	// 	s, err := BuildSubjectAltNameExtension(h)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if options.IsDualUse {
	// 		cn, err := DualUseCommonName(h)
	// 		if err != nil {
	// 			// log and continue
	// 			log.Errorf("dual-use failed for CSR template - omitting CN (%v)", err)
	// 		} else {
	// 			template.Subject.CommonName = cn
	// 		}
	// 	}
	// 	template.ExtraExtensions = []pkix.Extension{*s}
	// }

	return template, nil
}
