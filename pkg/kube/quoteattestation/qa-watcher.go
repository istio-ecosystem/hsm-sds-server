package quoteattestation

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	quoteapi "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/apis/tcs/v1alpha1"
	v1alpha1 "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/client/clientset/versioned/typed/tcs/v1alpha1"
	qalister "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/client/listers/tcs/v1alpha1"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/constants"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube/queue"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/util/cmutil"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/util/k8sutil"

	"istio.io/pkg/log"
)

const (
	// one quoteattestation custom resource(cr) will be generated for one Quote Attestation cr
	// instance name is using quoteAttestationPrefix + corresponding Quote Attestation cr name + "- " + Quote Attestation cr namespace
	quoteAttestationPrefix     = "sgxquoteattestation-"
	DefaultQuoteVersion        = "ECDSA Quote 3"
	KMRABased                  = "KMRA"
	asRootCA                   = true
	defaultCertPrefix          = "init-cert."
	EnclaveQuoteKeyObjectLabel = "Enclave Quote"
)

type QuoteAttestationWatcher struct {
	qaInformer cache.SharedIndexInformer
	qaLister   qalister.QuoteAttestationLister
	queue      queue.Queue
	qaSM       *security.SecretManager
	tcsClient  v1alpha1.TCSV1alpha1Interface
	kubeClient kubernetes.Interface
}

// Run starts shared informers and waits for the shared informer cache to synchronize
func (qa *QuoteAttestationWatcher) Run(stopCh chan struct{}) {
	log.Info("Start to run QuoteAttestationWatcher")
	// Starts all the shared informers that have been created by the factory so far
	go qa.qaInformer.Run(stopCh)
	// wait for the initial synchronization of the local cache.
	if !cache.WaitForCacheSync(stopCh, qa.qaInformer.HasSynced) {
		 log.Error("failed to wait for cache sync")
	}
	go qa.queue.Run(stopCh)
}

// onQuoteAttestationAdd is the add event for Istio Quote Attestation
func (qa *QuoteAttestationWatcher) onQuoteAttestationAdd(obj any) {
	qaCR := obj.(*quoteapi.QuoteAttestation)
	qa.queue.Add(types.NamespacedName{Namespace: qaCR.Namespace, Name: qaCR.Name})

	return
}

func (qa *QuoteAttestationWatcher) Reconcile(req types.NamespacedName) error {
	log.Info("Start to run QuoteAttestationWatcher Reconcile")
	log := log.WithLabels("istio Quote Attestation", req)
	qaObj, err := qa.qaLister.QuoteAttestations(req.Namespace).Get(req.Name)
	if err != nil {
		log.Errorf("Reconcile: unable to fetch Quote Attestation CR %s under the namespace %s : %v", req.Name, req.Namespace, err)
		return err
	}
	return nil
	var statusErr error
	if qaObj.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("checking quoteattestation status")
		var attesReady bool
		var cMessage string
		for _, c := range qaObj.Status.Conditions {
			if c.Type == quoteapi.ConditionReady {
				attesReady = true
				break
			} else {
				cMessage += "\n c.Message"
			}
		}
		if !attesReady {
			message := "quote attestation verification failure"
			log.Error(fmt.Errorf(message), "message", cMessage)
			return fmt.Errorf(message)
		}
		// attestation passed. Quote get verified
		log.Info("quoteattestation verification success")
		signer := qaObj.Spec.SignerName
		secretName := qaObj.Spec.SecretName
		var caSecretName string

		log.Info("using KMRA based secret.")
		if caSecretName, err = qa.loadKMRASecret(qa.kubeClient, secretName, signer, req.Namespace); err != nil {
			log.Error(err, "failed to load private key for signer ", signer)
			statusErr = multierror.Append(statusErr, err)
			return statusErr
		}

		log.Info("Need to fetch the secret [%s]", caSecretName)
	} else {
		err := qa.qaSM.SgxContext.RemoveKeyForSigner(EnclaveQuoteKeyObjectLabel)
		statusErr = multierror.Append(statusErr, err)
	}

	if statusErr != nil {
		return fmt.Errorf("some error occurs when load keys into sgx enclave")
	}
	return nil
}

func (qa *QuoteAttestationWatcher) loadKMRASecret(kubeClient kubernetes.Interface, secretName, signerName string, ns string) (string, error) {
	secret, err := kubeClient.CoreV1().Secrets(ns).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	wrappedData := secret.Data[corev1.TLSPrivateKeyKey]
	cmCert := secret.Data[corev1.TLSCertKey]

	sgxctx := qa.qaSM.SgxContext
	//try to clean up old key
	err = sgxctx.RemoveKeyForSigner(signerName)
	if err != nil {
		return "", err
	}
	err = sgxctx.ProvisionKey(signerName, wrappedData)
	if err != nil {
		// log.Error(err, "Failed to provision key to enclave")
		return "", err
	}

	ref, _ := k8sutil.SignerIssuerRefFromSignerName(signerName)
	if t, _ := k8sutil.IssuerKindFromType(ref.Type); t == constants.ClusterIssuerKind {
		ns = ""
	}

	cmSecretName := cmutil.GenerateSecretName(signerName)
	cmSecretExist := false
	cmSecret, err := kubeClient.CoreV1().Secrets(ns).Get(context.Background(), cmSecretName, metav1.GetOptions{})
	if err == nil {
		cmSecretExist = true
	} else if k8sErrors.IsNotFound(err) {
		cmSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmSecretName,
				Namespace: ns,
			},
			Type: corev1.SecretTypeTLS,
		}
	} else {
		return "", err
	}

	if cmSecret.Data == nil {
		cmSecret.Data = make(map[string][]byte)
	}
	cmSecret.Data[corev1.TLSPrivateKeyKey] = []byte(signerName)
	cmSecret.Data[corev1.TLSCertKey] = cmCert

	if cmSecretExist {
		_, err = kubeClient.CoreV1().Secrets(ns).Update(context.Background(), cmSecret, metav1.UpdateOptions{})
	} else {
		_, err = kubeClient.CoreV1().Secrets(ns).Create(context.Background(), cmSecret, metav1.CreateOptions{})
	}
	if err != nil {
		return "", err
	}

	return cmSecretName, nil
}

// NewQuoteAttestationWatcher creates a QuoteAttestationWatcher instance 
func NewQuoteAttestationWatcher(client kube.Client, sm *security.SecretManager) (*QuoteAttestationWatcher, error) {
	log.Info("New QuoteAttestationWatcher in SDS server")
	qaInf := client.QaAPIInformer().TCS().V1alpha1().QuoteAttestations().Informer()
	if qaInf == nil {
		return nil, fmt.Errorf("error: no Quote Attestation Informer can be found by kube/istio client.")
	}

	qa := &QuoteAttestationWatcher{
		qaInformer: qaInf,
		qaLister:   qalister.NewQuoteAttestationLister(qaInf.GetIndexer()),
		qaSM:       sm,
		kubeClient: client.Kube(),
	}

	tcsClient, err := v1alpha1.NewForConfig(client.RESTConfig())
	if err != nil {
		return nil, fmt.Errorf("error: no tcs client can be found by kube/istio client.")
	}
	qa.tcsClient = tcsClient

	qa.queue = queue.NewQueue("SDS service QuoteAttestation",
		queue.WithReconciler(qa.Reconcile),
		queue.WithMaxAttempts(5))
	_ = qa.qaInformer.SetTransform(kube.StripUnusedFields)

	qa.qaInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) { qa.onQuoteAttestationAdd(obj) },
		},
	)
	return qa, nil
}
