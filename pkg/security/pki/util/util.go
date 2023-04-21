package util

import (
	"crypto/x509"
	"sync"
	"time"

	"istio.io/pkg/log"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/internal/sgx"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/queue"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
)

// NewSecretManager will create a secretManager for SDS server leveraging SGX as backend
// Pre-generate 'default' private key and cert before getting SDS request from envoy to improve startup latency.
func NewSecretManager(options *security.CertOptions) (*security.SecretManager, error) {
	st := &security.SecretManager{
		Name:          "SecretManager for SDS Server",
		DelayQueue:    queue.NewDelayed(queue.DelayQueueBuffer(0)),
		ConfigOptions: options,
		SgxConfigs: &sgx.Config{
			HSMTokenLabel:  sgx.HSMTokenLabel,
			HSMUserPin:     sgx.HSMUserPin,
			HSMSoPin:       sgx.HSMSoPin,
			HSMConfigPath:  sgx.SgxLibrary,
			HSMKeyLabel:    sgx.HSMKeyLabel,
			HSMKeyType:     sgx.HSMKeyType,
			UseRandonNonce: sgx.UseRandonNonce,
		},
		SgxctxLock: sync.Mutex{},
		Stop:       make(chan struct{}),
	}

	// init the SecretCache
	st.Cache = security.SecretCache{}
	st.GetCredMap()

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
	if err = st.SgxContext.InitializeKey(st.SgxConfigs.HSMKeyLabel, st.SgxConfigs.HSMKeyType, security.DefaultRSAKeysize); err != nil {
		log.Warnf("failed to create default private key via sgx: ", err)
		return nil, err
	}
	st.SgxctxLock.Unlock()

	csrPem, err := st.GenerateCSR(*options, security.NeedQuoteExtension)
	if err != nil {
		log.Info("failed to generate Kubernetes CSR: ", err)
		return nil, err
	}
	// todo: replace it via reading from CSR
	if _, err := st.CreateNewCertificate(csrPem, nil, time.Hour*24, false, x509.KeyUsageCRLSign|x509.KeyUsageCertSign|x509.KeyUsageContentCommitment,
		[]x509.ExtKeyUsage{}); err != nil {
		log.Warnf("failed to create Certificate: %v", err)
	}

	go st.DelayQueue.Run(st.Stop)
	return st, nil
}
