package util

import (
	"crypto/x509"
	"time"

	"istio.io/pkg/log"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/internal/sgx"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/security"
)

func NewSecretManager(options *security.CertOptions) *security.SecretManager {
	st := &security.SecretManager{
		Name:          "SecretManager for SDS Server",
		ConfigOptions: options,
		SgxConfigs: &sgx.Config{
			HSMTokenLabel: sgx.HSMTokenLabel,
			HSMUserPin:    sgx.HSMUserPin,
			HSMSoPin:      sgx.HSMSoPin,
			HSMConfigPath: sgx.SgxLibrary,
			HSMKeyLabel:   sgx.DefaultKeyLabel,
			HSMKeyType:    sgx.HSMKeyType,
		},
	}

	var err error
	if err = st.SgxConfigs.Validate(); err != nil {
		log.Warnf("In valid SGX Config")
	}
	st.SgxContext, err = sgx.NewContext(*st.SgxConfigs)
	if err != nil {
		log.Warnf("Can't init sgx Context: ", err)
	}
	if err = st.SgxContext.InitializeKey(st.SgxConfigs.HSMKeyLabel, st.SgxConfigs.HSMKeyType, security.DefaultRSAKeysize); err != nil {
		log.Warnf("Can't init sgx Key Pair: ", err)
	}
	csrPem, err := st.GenerateK8sCSR(*options)
	if err != nil {
		log.Info("DEBUG 3: Generate CSR Warmup error: ", err)
	}

	if _, err := st.CreateNewCertificate(csrPem, time.Hour*24, false, x509.KeyUsageCRLSign|x509.KeyUsageCertSign|x509.KeyUsageContentCommitment,
		[]x509.ExtKeyUsage{}); err != nil {
		log.Info("DEBUG: Create Certificate Warmup error: ", err)
	}
	return st
}
