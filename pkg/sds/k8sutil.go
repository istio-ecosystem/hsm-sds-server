package sds

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/internal/sgx"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
	"istio.io/pkg/log"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// SignCSRK8s generates a certificate from CSR using the K8s CA (e.g. TCS)
// 1. Ceate a CSR
// 2. Approve a CSR
// 3. Read the signed certificate
// 4. Clean up the artifacts (e.g., delete CSR)
func (s *sdsservice) SignCSRK8s(csr []byte, resourceName string) ([]byte, error) {

	log.Info("Start signing Kubernetes certificatesigningrequest")
	// 1. Ceate a CSR
	csrName := "csr-" + resourceName + "-" + security.PodName
	k8scsr, err := s.CreateK8sCSR(csr, csrName)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	defer func() {
		_ = cleanUpCertGen(s.sdsClient.Kube(), csrName)
	}()

	// 2. Approve a CSR
	csrMsg := fmt.Sprintf("CSR (%s) is approved", csrName)
	err = approveCSR(csrName, csrMsg, s.sdsClient.Kube(), k8scsr)
	if err != nil {
		return nil, fmt.Errorf("unable to approve CSR request. Error: %v", err)
	}
	log.Infof("certificatesigningrequest (%v) is approved", csrName)

	// 3. Read the signed certificate
	cert := readSignedCsr(s.sdsClient.Kube(), csrName, security.CertWatchTimeout, security.CertReadInterval, security.MAXRetryTime)
	if err != nil {
		return nil, nil
	}
	log.Info("Sign kubernetes certificatesigningrequest finished")
	return cert, nil
}

func (s *sdsservice) CreateK8sCSR(csrPem []byte, csrName string) (*certv1.CertificateSigningRequest, error) {
	// s.st.SgxctxLock.Lock()
	// defer s.st.SgxctxLock.Unlock()
	log.Info("Start creating kubernetes certificatesigningrequest")
	var k8scsr *certv1.CertificateSigningRequest
	var lastErr error
	usages := []certv1.KeyUsage{
		certv1.UsageDigitalSignature,
		certv1.UsageKeyEncipherment,
		certv1.UsageServerAuth,
		certv1.UsageClientAuth,
	}

	signerName := security.PendingSelfSignerName

	for i := 0; i < security.MAXRetryTime; i++ {
		k8scsr = &certv1.CertificateSigningRequest{
			TypeMeta: metav1.TypeMeta{Kind: "CertificateSigningRequest"},
			ObjectMeta: metav1.ObjectMeta{
				Name: csrName,
			},
			Spec: certv1.CertificateSigningRequestSpec{
				Request:           csrPem,
				SignerName:        signerName,
				Usages:            usages,
				ExpirationSeconds: &security.DefaultExpirationSeconds,
			},
		}
		v1req, err := s.sdsClient.Kube().CertificatesV1().CertificateSigningRequests().Create(context.TODO(), k8scsr, metav1.CreateOptions{})
		if err == nil {
			return v1req, nil
		}
		lastErr = err
	}
	return k8scsr, lastErr
}

func approveCSR(csrName string, csrMsg string, client kubernetes.Interface, v1CsrReq *certv1.CertificateSigningRequest) error {
	var err error

	v1CsrReq.Status.Conditions = append(v1CsrReq.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:    certv1.CertificateApproved,
		Reason:  csrMsg,
		Message: csrMsg,
		Status:  corev1.ConditionTrue,
	})
	_, err = client.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), csrName, v1CsrReq, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("failed to approve CSR (%v): %v", csrName, err)
		return err
	}
	return err
}

// Return signed CSR through a watcher. If no CSR is read, return nil.
func readSignedCsr(client kubernetes.Interface, csrName string, watchTimeout time.Duration, readInterval time.Duration,
	maxNumRead int) []byte {

	log.Info("Reading signed certificatesigningrequest")
	var watcher watch.Interface
	var err error
	selector := fields.OneTermEqualSelector("metadata.name", csrName).String()
	// Setup a List+Watch, like informers do
	// A simple Watch will fail if the cert is signed too quickly
	l, _ := client.CertificatesV1().CertificateSigningRequests().List(context.TODO(), metav1.ListOptions{
		FieldSelector: selector,
	})
	if l != nil && len(l.Items) > 0 {
		reqSigned := l.Items[0]
		if reqSigned.Status.Certificate != nil {
			return reqSigned.Status.Certificate
		}
	}
	var rv string
	if l != nil {
		rv = l.ResourceVersion
	}
	watcher, err = client.CertificatesV1().CertificateSigningRequests().Watch(context.TODO(), metav1.ListOptions{
		ResourceVersion: rv,
		FieldSelector:   selector,
	})

	if err == nil {
		timeout := false
		// Set a timeout
		timer := time.After(watchTimeout)
		for {
			select {
			case r := <-watcher.ResultChan():
				reqSigned := r.Object.(*certv1.CertificateSigningRequest)
				if reqSigned.Status.Certificate != nil {
					return reqSigned.Status.Certificate
				}
			case <-timer:
				log.Debugf("timeout when watching CSR %v", csrName)
				timeout = true
			}
			if timeout {
				break
			}
		}
	}
	log.Info("DEBUG readSignedCsr finished")
	return getSignedCsr(client, csrName, readInterval, maxNumRead)
}

func getSignedCsr(client kubernetes.Interface, csrName string, readInterval time.Duration, maxNumRead int) []byte {
	log.Info("DEBUG getSignedCsr called")
	var err error
	var r *certv1.CertificateSigningRequest
	for i := 0; i < maxNumRead; i++ {
		log.Info("DEBUG run into for{maxNumRead} to get cert")
		r, err = client.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), csrName, metav1.GetOptions{})
		if err == nil && r.Status.Certificate != nil {
			// Certificate is ready
			return r.Status.Certificate
		}
		log.Info(csrName, " ERROR: ", err, " times: ", i)
		time.Sleep(readInterval)
	}
	if err != nil || r.Status.Certificate == nil {
		if err != nil {
			log.Errorf("failed to read the CSR (%v): %v", csrName, err)
		} else if r.Status.Certificate == nil {
			for _, c := range r.Status.Conditions {
				if c.Type == certv1.CertificateDenied {
					log.Errorf("CertificateDenied, name: %v, uid: %v, cond-type: %v, cond: %s",
						r.Name, r.UID, c.Type, c.String())
					break
				}
			}
		}
		return []byte{}
	}
	log.Info("DEBUG getSignedCsr finished")
	return []byte{}
}

// Clean up the CSR
func cleanUpCertGen(client kubernetes.Interface, csrName string) error {

	err := client.CertificatesV1().CertificateSigningRequests().Delete(context.TODO(), csrName, metav1.DeleteOptions{})

	if err != nil {
		log.Errorf("failed to delete CSR (%v): %v", csrName, err)
	} else {
		log.Debugf("deleted CSR: %v", csrName)
	}
	log.Info("Cleaning up certificatsigingrequest")
	return err
}

// DecodeCert return the decoded csr of given encodedCertRequest
func DecodeCertRequest(encodedCertRequest []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(encodedCertRequest)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block is not a CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

func getQuoteAndPublicKeyFromCSR(extensions []pkix.Extension) ([]byte, *rsa.PublicKey, error) {
	decodeExtensionValue := func(value []byte) ([]byte, error) {
		strValue := ""
		if _, err := asn1.Unmarshal(value, &strValue); err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(strValue)
	}
	var encPublickey, quote []byte
	var err error
	var publickey *rsa.PublicKey
	for _, ext := range extensions {
		if ext.Id.Equal(security.OidSubjectQuoteExtensionName) {
			quote, err = decodeExtensionValue(ext.Value)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to unmarshal SGX quote extension value: %v", err)
			}
		} else if ext.Id.Equal(security.OidSubjectPubkeyExtensionName) {
			encPublickey, err = decodeExtensionValue(ext.Value)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to unmarshal SGX quote extension value: %v", err)
			}
			publickey, err = sgx.ParseQuotePublickey(encPublickey)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse SGX quote publickey value: %v", err)
			}
		}
	}
	if quote == nil {
		return nil, nil, fmt.Errorf("missing quote extension")
	}
	if publickey == nil {
		return nil, nil, fmt.Errorf("missing quote public key extension")
	}
	return quote, publickey, nil
}
