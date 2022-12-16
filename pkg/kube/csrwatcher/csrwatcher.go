package csrwatcher

import (
	"context"

	certv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube/queue"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
	_ "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/util/labels"

	_ "istio.io/client-go/pkg/listers/networking/v1alpha3"
	"istio.io/pkg/log"
)

type K8sCSRWatcher struct {
	csrInformer cache.SharedIndexInformer
	// csrLister     v1alpha3.WorkloadEntryLister
	queue         queue.Queue
	secretManager *security.SecretManager
	client        kube.Client
}

func (r *K8sCSRWatcher) Reconcile(req types.NamespacedName) error {
	// get, watch, update CSR here
	log.Infof("K8sCSRWatcher Reconcile Called.")
	var csr *certv1.CertificateSigningRequest
	var err error
	csr = r.CreateK8sCSR(r.secretManager.Cache.GetcsrBytes(), req)
	if isCSRApproved(&csr.Status) {
		cert := csr.Status.Certificate
		x509cert, _ := security.ParsePemEncodedCertificate(cert)
		secretItem := &security.SecretItem{
			ResourceName:     req.Name,
			CertificateChain: cert,
			RootCert:         r.secretManager.Cache.GetRoot(),
			CreatedTime:      x509cert.NotBefore,
			ExpireTime:       x509cert.NotAfter,
		}
		r.secretManager.Cache.SetWorkload(secretItem)
	}
	return err
}

func (r *K8sCSRWatcher) Run(stopCh chan struct{}) {
	log.Info("Start to run K8sCSRWatcher")
	// Starts all the shared informers that have been created by the factory so far
	go r.csrInformer.Run(stopCh)
	// wait for the initial synchronization of the local cache.
	if !cache.WaitForCacheSync(stopCh, r.csrInformer.HasSynced) {
		log.Error("failed to wait for cache sync")
	}
	go r.queue.Run(stopCh)
}

func NewK8sCSRWatcher(client kube.Client, sm *security.SecretManager) (*K8sCSRWatcher, error) {
	log.Info("New CSRWatcher in SDS server")
	csrInf := client.KubeInformer().Certificates().V1().CertificateSigningRequests().Informer()

	r := &K8sCSRWatcher{
		csrInformer: csrInf,
		// gwLister:   gatewaylister.NewGatewayLister(iform.GetIndexer()),
		secretManager: sm,
		client:        client,
	}
	r.queue = queue.NewQueue("SDS Kubernetes CSR Watcher",
		queue.WithReconciler(r.Reconcile),
		queue.WithMaxAttempts(5))
	_ = r.csrInformer.SetTransform(kube.StripUnusedFields)

	r.csrInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {},
		},
	)

	return r, nil
}

// isCSRApproved checks if the given Kubernetes certificate signing request
// has been approved by the cluster admin
func isCSRApproved(csrStatus *certv1.CertificateSigningRequestStatus) bool {
	approved := false
	for _, c := range csrStatus.Conditions {
		if c.Type == certv1.CertificateApproved {
			approved = true
		}
		if c.Type == certv1.CertificateDenied {
			return false
		}
	}

	return approved
}

func (r *K8sCSRWatcher) CreateK8sCSR(csr []byte, req types.NamespacedName) *certv1.CertificateSigningRequest {
	var k8scsr *certv1.CertificateSigningRequest
	k8scsr, err := r.client.Kube().CertificatesV1().CertificateSigningRequests().Get(context.TODO(), req.Name, metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		k8scsr = newK8sCSR(req.Name, "", csr, nil)
		k8scsr, _ = r.client.Kube().CertificatesV1().CertificateSigningRequests().Create(context.TODO(), k8scsr, metav1.CreateOptions{})
	}
	if k8scsr.Spec.Request == nil {
		k8scsr.Spec.Request = csr
		r.client.Kube().CertificatesV1().CertificateSigningRequests().Update(context.TODO(), k8scsr, metav1.UpdateOptions{})
	}
	return k8scsr
}

func newK8sCSR(name, signerName string, request []byte, usages []certv1.KeyUsage) *certv1.CertificateSigningRequest {
	if usages == nil {
		usages = []certv1.KeyUsage{
			certv1.UsageDigitalSignature,
			certv1.UsageKeyEncipherment,
			certv1.UsageServerAuth,
			certv1.UsageClientAuth,
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
