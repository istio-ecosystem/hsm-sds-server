package sgx

import (
	"fmt"
)

type Config struct {
	MetricsAddress     string
	HealthProbeAddress string
	LeaderElection     bool
	CertManagerIssuer  bool
	CSRFullCertChain   bool

	HSMTokenLabel string
	HSMUserPin    string
	HSMSoPin      string
	HSMConfigPath string
}

func (cfg Config) Validate() error {
	if cfg.HSMSoPin == "" || cfg.HSMUserPin == "" {
		return fmt.Errorf("invalid HSM config: missing user/so pin")
	}

	return nil
}
