package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/security"
)

// "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/sds"

func NewSecretManager(options *security.CertOptions) *security.SecretManager {
	st := &security.SecretManager{
		Name:          "test",
		ConfigOptions: options,
	}
	return st
}

func encodePem(isCSR bool, csrOrCert []byte, priv interface{}, pkcs8 bool) (
	csrOrCertPem []byte, privPem []byte, err error,
) {
	encodeMsg := "CERTIFICATE"
	if isCSR {
		encodeMsg = "CERTIFICATE REQUEST"
	}
	csrOrCertPem = pem.EncodeToMemory(&pem.Block{Type: encodeMsg, Bytes: csrOrCert})

	var encodedKey []byte
	if pkcs8 {
		if encodedKey, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
			return nil, nil, err
		}
		privPem = pem.EncodeToMemory(&pem.Block{Type: security.BlockTypePKCS8PrivateKey, Bytes: encodedKey})
	} else {
		switch k := priv.(type) {
		case *rsa.PrivateKey:
			encodedKey = x509.MarshalPKCS1PrivateKey(k)
			privPem = pem.EncodeToMemory(&pem.Block{Type: security.BlockTypeRSAPrivateKey, Bytes: encodedKey})
		case *ecdsa.PrivateKey:
			encodedKey, err = x509.MarshalECPrivateKey(k)
			if err != nil {
				return nil, nil, err
			}
			privPem = pem.EncodeToMemory(&pem.Block{Type: security.BlockTypeECPrivateKey, Bytes: encodedKey})
		}
	}
	err = nil
	return
}
