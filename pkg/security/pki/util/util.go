package util

import (
	"crypto/x509"
	"istio.io/pkg/log"
	"time"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/internal/sgx"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
)

// NewSecretManager will create a secretManager for SDS server leveraging SGX as backend
// Pre-generate 'default' private key and cert before getting SDS request from envoy to improve startup latency.
func NewSecretManager(options *security.CertOptions) (*security.SecretManager, error) {
	st := &security.SecretManager{
		Name:          "SecretManager for SDS Server",
		ConfigOptions: options,
		SgxConfigs: &sgx.Config{
			HSMTokenLabel: sgx.HSMTokenLabel,
			HSMUserPin:    sgx.HSMUserPin,
			HSMSoPin:      sgx.HSMSoPin,
			HSMConfigPath: sgx.SgxLibrary,
			HSMKeyLabel:   sgx.HSMKeyLabel,
			HSMKeyType:    sgx.HSMKeyType,
		},
	}

	var err error
	if err = st.SgxConfigs.Validate(); err != nil {
		log.Warnf("invalid SGX Config")
		return nil, err
	}
	st.SgxctxLock.Lock()
	st.SgxContext, err = sgx.NewContext(*st.SgxConfigs)
	if err != nil {
		log.Warnf("Can't init sgx Context: ", err)
		return nil, err
	}
	st.SgxctxLock.Unlock()
	if err = st.SgxContext.InitializeKey(st.SgxConfigs.HSMKeyLabel, st.SgxConfigs.HSMKeyType, security.DefaultRSAKeysize); err != nil {
		log.Warnf("failed to create default private key via sgx: ", err)
		return nil, err
	}
	csrPem, err := st.GenerateK8sCSR(*options)
	if err != nil {
		log.Info("failed to generate Kubernetes CSR: ", err)
		return nil, err
	}
	// todo: replace it via reading from CSR
	if _, err := st.CreateNewCertificate(csrPem, time.Hour*24, false, x509.KeyUsageCRLSign|x509.KeyUsageCertSign|x509.KeyUsageContentCommitment,
		[]x509.ExtKeyUsage{}); err != nil {
		log.Info("failed to create Certificate: ", err)
	}
	return st, nil
}
