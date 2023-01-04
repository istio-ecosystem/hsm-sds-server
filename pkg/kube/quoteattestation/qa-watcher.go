package quoteattestation

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/go-multierror"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	quoteapi "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/apis/tcs/v1alpha1"
	v1alpha1 "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/client/clientset/versioned/typed/tcs/v1alpha1"
	qalister "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/client/listers/tcs/v1alpha1"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube/queue"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"

	"istio.io/pkg/log"
)

const (
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
	tcsClient  v1alpha1.TcsV1alpha1Interface
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
	credMap := qa.qaSM.GetCredMap()
	if len(credMap) == 0 {
		return
	}
	log.Info("Call onQuoteAttestationAdd")
	qaCR := obj.(*quoteapi.QuoteAttestation)
	qa.queue.Add(types.NamespacedName{Namespace: qaCR.Namespace, Name: qaCR.Name})

	return
}

// onQuoteAttestationUpdate is the update event for Istio Quote Attestation
func (qa *QuoteAttestationWatcher) onQuoteAttestationUpdate(obj any) {
	credMap := qa.qaSM.GetCredMap()
	if len(credMap) == 0 {
		return
	}
	log.Info("Call onQuoteAttestationUpdate")
	qaCR := obj.(*quoteapi.QuoteAttestation)
	qa.queue.Add(types.NamespacedName{Namespace: qaCR.Namespace, Name: qaCR.Name})
	return
}

func (qa *QuoteAttestationWatcher) Reconcile(req types.NamespacedName) error {
	log.Info("Start to run QuoteAttestationWatcher Reconcile")
	log.Info("Namespace: ", req.Namespace, " Name: ", req.Name)
	qaObj, err := qa.qaLister.QuoteAttestations(req.Namespace).Get(req.Name)
	if err != nil {
		log.Errorf("Reconcile: unable to fetch Quote Attestation CR %s under the namespace %s : %v", req.Name, req.Namespace, err)
		return err
	}
	var statusErr error
	log.Info("need to check: ", qaObj.ObjectMeta.DeletionTimestamp.IsZero())
	if qaObj.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("checking quoteattestation status")
		log.Info("QA Status: ", qaObj.Status)
		log.Info("QA SecretName: ", qaObj.Spec.SecretName)
		// var attesReady bool
		// var cMessage string
		if qaObj.Spec.SecretName == "" {
			return nil
		}

		/*if len(qaObj.Status.Conditions) == 0 {
			log.Info("QA Conditions lenght is: ", 0)
			return nil
		}
		for _, c := range qaObj.Status.Conditions {
			log.Info("QuoteAttestationWatcher Reconcile QA status: ", c.Type)
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
		}*/
		// attestation passed. Quote get verified
		log.Info("quoteattestation verification success")
		signer := qaObj.Spec.SignerName
		secretName := qaObj.Spec.SecretName

		log.Info("using KMRA based secret.")
		if err = qa.loadKMRASecret(qa.kubeClient, secretName, signer, req.Namespace); err != nil {
			log.Error(err, "failed to load private key for signer ", signer)
			statusErr = multierror.Append(statusErr, err)
			return statusErr
		}
		instanceName := security.QuoteAttestationPrefix + security.PodName + "-" + signer
		ctx := context.Background()
		err = qa.tcsClient.QuoteAttestations(req.Namespace).Delete(ctx, instanceName, metav1.DeleteOptions{})
		if err != nil {
			log.Error(err, "failed to delete the quoteattestation cr ", instanceName)
		}
		err = qa.kubeClient.CoreV1().Secrets(req.Namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		if err != nil {
			log.Error(err, "failed to delete the secret ", secretName)
		}
	} else {
		err := qa.qaSM.SgxContext.RemoveKeyForSigner(EnclaveQuoteKeyObjectLabel)
		statusErr = multierror.Append(statusErr, err)
	}

	if statusErr != nil {
		return fmt.Errorf("some error occurs when load keys into sgx enclave")
	}
	return nil
}

func (qa *QuoteAttestationWatcher) loadKMRASecret(kubeClient kubernetes.Interface, secretName, signerName string, ns string) error {
	secret, err := kubeClient.CoreV1().Secrets(ns).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	rootCABase64 := secret.Data[corev1.ServiceAccountRootCAKey]
	rootCAData, err := base64.StdEncoding.DecodeString(string(rootCABase64))
	if err != nil {
		return err
	}
	certBase64 := secret.Data[corev1.TLSCertKey]
	certData, err := base64.StdEncoding.DecodeString(string(certBase64))
	if err != nil {
		return err
	}
	wrappedData := secret.Data[corev1.TLSPrivateKeyKey]
	sgxctx := qa.qaSM.SgxContext
	//try to clean up old key
	err = sgxctx.RemoveKeyForSigner(signerName)
	if err != nil {
		return err
	}
	err = sgxctx.RemoveKey(signerName)
	if err != nil {
		return err
	}
	err = sgxctx.ProvisionKey(signerName, wrappedData, true)
	if err != nil {
		// log.Error(err, "Failed to provision key to enclave")
		return err
	}

	log.Info("Begin to add certificate/rootCA data to credMap")
	credMap := qa.qaSM.GetCredMap()
	for credKey, cred := range credMap {
		credName := cred.GetSGXKeyLable()
		log.Info("CredName: ", credName)
		if credName == signerName {
			if len(certData) > 0 {
				log.Info("certData is not empty")
				log.Info(certData)
				cred.SetCertData(certData)
			}
			if len(rootCAData) > 0 {
				log.Info("rootCAData is not empty")
				log.Info(rootCAData)
				cred.SetRootData(rootCAData)
			}
			qa.qaSM.SetCredMap(credKey, cred)

			if len(certData) > 0 {
				cred.CertSync <- struct{}{}
			}

			if len(rootCAData) > 0 {
				cred.RootSync <- struct{}{}
			}
			break
		}
	}

	return nil
}

// NewQuoteAttestationWatcher creates a QuoteAttestationWatcher instance
func NewQuoteAttestationWatcher(client kube.Client, sm *security.SecretManager) (*QuoteAttestationWatcher, error) {
	log.Info("New QuoteAttestationWatcher in SDS server")
	qaInf := client.QaAPIInformer().Tcs().V1alpha1().QuoteAttestations().Informer()
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
			AddFunc:    func(obj any) { qa.onQuoteAttestationAdd(obj) },
			UpdateFunc: func(oldObj any, newObj any) { qa.onQuoteAttestationUpdate(newObj) },
		},
	)
	return qa, nil
}
