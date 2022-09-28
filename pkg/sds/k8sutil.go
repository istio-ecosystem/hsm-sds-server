package sds

import (
	"context"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
	certv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *sdsservice) CreateK8sCSR(csr []byte, resourceName string) (*certv1.CertificateSigningRequest, error) {
	var k8scsr *certv1.CertificateSigningRequest
	k8scsr, err := s.sdsClient.Kube().CertificatesV1().CertificateSigningRequests().Get(context.TODO(), resourceName, metav1.GetOptions{})

	if err != nil && errors.IsNotFound(err) {
		k8scsr = newK8sCSR(resourceName, "", csr, nil)
		k8scsr, _ = s.sdsClient.Kube().CertificatesV1().CertificateSigningRequests().Create(context.TODO(), k8scsr, metav1.CreateOptions{})
		// k8scsr.DeepCopy()
		// r.client.Kube().CertificatesV1().CertificateSigningRequests().Patch(context.Background(),&k8scsr,)
	}
	if k8scsr.Spec.Request == nil {
		k8scsr.Spec.Request = csr
		s.sdsClient.Kube().CertificatesV1().CertificateSigningRequests().Update(context.TODO(), k8scsr, metav1.UpdateOptions{})
	}
	return k8scsr, err
}

func newK8sCSR(name, signerName string, request []byte, usages []certv1.KeyUsage) *certv1.CertificateSigningRequest {
	if usages == nil {
		usages = []certv1.KeyUsage{
			certv1.UsageDigitalSignature,
			certv1.UsageKeyEncipherment,
			certv1.UsageClientAuth,
			// certv1.UsageServerAuth,
		}
	}
	if signerName == "" {
		signerName = security.PendingSelfSignerName
	}
	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:           request,
			SignerName:        signerName,
			Usages:            usages,
			ExpirationSeconds: &security.DefaultExpirationSeconds,
		},
	}

	return csr
}
