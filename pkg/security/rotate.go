package security

import (
	"time"

	"istio.io/pkg/monitoring"
)

var CertExpirySeconds = monitoring.NewDerivedGauge(
	"cert_expiry_seconds",
	"The time remaining, in seconds, before the certificate chain will expire. "+
		"A negative value indicates the cert is expired.",
	monitoring.WithLabelKeys("resource_name"))

// RotateTime return the rotatetime for delay queue run push task
func (sc *SecretManager) RotateTime(secret SecretItem) time.Duration {
	secretLifeTime := secret.ExpireTime.Sub(secret.CreatedTime)
	gracePeriod := time.Duration((sc.ConfigOptions.SecretRotationGracePeriodRatio) * float64(secretLifeTime))
	delay := time.Until(secret.ExpireTime.Add(-gracePeriod))
	if delay < 0 {
		delay = 0
	}
	return delay
}
