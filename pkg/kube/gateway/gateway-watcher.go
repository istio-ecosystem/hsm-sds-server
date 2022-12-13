package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	quoteapi "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/apis/tcs/v1alpha1"
	v1alpha1 "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/client/clientset/versioned/typed/tcs/v1alpha1"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/constants"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube/queue"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
	downward "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/util/downwardAPI"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/util/labels"

	istioapi "istio.io/api/networking/v1alpha3"
	gateway "istio.io/client-go/pkg/apis/networking/v1alpha3"
	gatewaylister "istio.io/client-go/pkg/listers/networking/v1alpha3"

	"istio.io/pkg/env"
	"istio.io/pkg/log"
)

const (
	// one quoteattestation custom resource(cr) will be generated for one gateway cr
	// instance name is using quoteAttestationPrefix + corresponding gateway cr name + "- " + gateway cr namespace
	quoteAttestationPrefix = "sgxquoteattestation-"
	DefaultQuoteVersion    = "ECDSA Quote 3"
	KMRABased              = "KMRA"
	asRootCA               = true
	defaultCertPrefix      = "init-cert."
)

type GatewayWatcher struct {
	gwInformer cache.SharedIndexInformer
	gwLister   gatewaylister.GatewayLister
	queue      queue.Queue
	gwPodLabel labels.Instance
	gwSM       *security.SecretManager
	tcsClient  v1alpha1.TcsV1alpha1Interface
}

var (
	PodName = env.RegisterStringVar("POD_NAME", "istio-ingressgateway", "Name of istio ingressgateway pod").Get()
)

// Run starts shared informers and waits for the shared informer cache to synchronize
func (gw *GatewayWatcher) Run(stopCh chan struct{}) {
	log.Info("Start to run GatewayWatcher")
	// Starts all the shared informers that have been created by the factory so far
	go gw.gwInformer.Run(stopCh)
	// wait for the initial synchronization of the local cache.
	if !cache.WaitForCacheSync(stopCh, gw.gwInformer.HasSynced) {
		log.Error("failed to wait for cache sync")
	}
	go gw.queue.Run(stopCh)
}

// onGatewayAdd is the add event for Istio gateway
func (gw *GatewayWatcher) onGatewayAdd(obj any) {
	gatewayCR := obj.(*gateway.Gateway)
	gwAPICR := istioapi.Gateway(gatewayCR.Spec)
	gwSeletor := gwAPICR.GetSelector()
	if gwSeletor == nil {
		log.Errorf("error: istio gateway %s has not selector.", gatewayCR.Name)
		return
	}
	var credNames []string
	// fetch the credential name for gateway CR
	gatewaySelector := labels.Instance(gwSeletor)
	log.Infof("This sds server gatewaySelector: %v", gatewaySelector)
	log.Infof("This sds server gwPodLabel: %v", gw.gwPodLabel)
	if gatewaySelector.SubsetOf(gw.gwPodLabel) {
		log.Infof("This sds server pod is the selected sds server pod with selector: %v", gatewaySelector)
		gwServers := gwAPICR.GetServers()
		for _, gwServer := range gwServers {
			if gwTLS := gwServer.GetTls(); gwTLS != nil {
				credName := gwTLS.GetCredentialName()
				if credName != "" && strings.HasPrefix(credName, security.SDSCredNamePrefix) {
					log.Infof("Credential Name of the gatway is [%s]", credName)
					newCredName := security.HandleCredNameForEnvoy(credName)
					credNames = append(credNames, newCredName)
					var gatewayCred security.GatewayCred
					gatewayCred.SetSGXKeyLable(newCredName)
					gatewayCred.DataSync = make(chan struct{})
					gw.gwSM.SetCredMap(gwServer.Port, &gatewayCred)
				} else {
					log.Errorf("error: no required gateway %s CredentialName for the sds server", gatewayCR.Name)
					return
				}
			}
		}
	}

	if len(credNames) == 0 {
		return
	}

	ctx := context.Background()
	for _, credName := range credNames {
		// create quoteAttestation CR for gateway CR
		instanceName := quoteAttestationPrefix + PodName + "-" + credName
		if credName != "" {
			if err := gw.QuoteAttestationDeliver(ctx, credName, instanceName, gatewayCR.Namespace); err != nil {
				log.Errorf("failed to created or updated quoteAttestation CR %s", err)
				return
			}
			log.Info("QuoteAttestation CR created or updated ", "name", instanceName)
		} else {
			gw.tcsClient.QuoteAttestations(gatewayCR.Namespace).Delete(ctx, instanceName, metav1.DeleteOptions{})
		}
	}
	gw.queue.Add(types.NamespacedName{Namespace: gatewayCR.Namespace, Name: gatewayCR.Name})

	return
}

// onGatewayDelete is the delete event for Istio gateway
func (gw *GatewayWatcher) onGatewayDelete(obj any) {
	gatewayCR := obj.(*gateway.Gateway)
	gwAPICR := istioapi.Gateway(gatewayCR.Spec)
	gwSeletor := gwAPICR.GetSelector()
	if gwSeletor == nil {
		log.Errorf("error: istio gateway %s has not selector.", gatewayCR.Name)
		return
	}

	sgxctx := gw.gwSM.SgxContext
	if sgxctx == nil {
		log.Errorf("sgx context for this hsm custom resource has not been initialized")
		return
	}

	// fetch the credential name for gateway CR
	gatewaySelector := labels.Instance(gwSeletor)
	if gatewaySelector.SubsetOf(gw.gwPodLabel) {
		gwServers := gwAPICR.GetServers()
		for _, gwServer := range gwServers {
			if gwTLS := gwServer.GetTls(); gwTLS != nil {
				credName := gwTLS.GetCredentialName()
				if credName != "" && strings.HasPrefix(credName, security.SDSCredNamePrefix) {
					log.Infof("Credential Name of the gatway is [%s]", credName)
					signerName := security.HandleCredNameForEnvoy(credName)
					//delete the given key from signer and SGX enclave
					err := sgxctx.RemoveKeyForSigner(signerName)
					if err != nil {
						log.Errorf("Remove Key %s for signer error: %v", signerName, err)
					}
					err = sgxctx.RemoveKey(signerName)
					if err != nil {
						log.Errorf("Remove Key %s from SGX enclave error: %v", signerName, err)
					}
				}
			}
		}
	}

}

func (gw *GatewayWatcher) Reconcile(req types.NamespacedName) error {
	log.Info("Start to run GatewayWatcher Reconcile")
	log := log.WithLabels("istio gateway", req)
	_, err := gw.gwLister.Gateways(req.Namespace).Get(req.Name)
	if err != nil {
		log.Errorf("Reconcile: unable to fetch Gateway CR %s under the namespace %s : %v", req.Name, req.Namespace, err)
		return err
	}
	return nil
}

// NewGatewayWatcher creates a GatewayWatcher instance
func NewGatewayWatcher(client kube.Client, sm *security.SecretManager) (*GatewayWatcher, error) {
	log.Info("New GatewayWatcher in SDS server")
	gwInf := client.IstioInformer().Networking().V1alpha3().Gateways().Informer()
	if gwInf == nil {
		return nil, fmt.Errorf("error: no gateway Informer can be found by kube/istio client.")
	}

	gw := &GatewayWatcher{
		gwInformer: gwInf,
		gwLister:   gatewaylister.NewGatewayLister(gwInf.GetIndexer()),
		gwSM:       sm,
	}

	tcsClient, err := v1alpha1.NewForConfig(client.RESTConfig())
	if err != nil {
		return nil, fmt.Errorf("error: no tcs client can be found by kube/istio client.")
	}
	gw.tcsClient = tcsClient

	gw.queue = queue.NewQueue("Istio gateway",
		queue.WithReconciler(gw.Reconcile),
		queue.WithMaxAttempts(5))
	_ = gw.gwInformer.SetTransform(kube.StripUnusedFields)

	gw.gwInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) { gw.onGatewayAdd(obj) },
			DeleteFunc: func(obj any) { gw.onGatewayDelete(obj) },
		},
	)

	var reErr error
	lbls, err := downward.ReadPodLabels()
	if err == nil {
		podLable := map[string]string{}
		for k, v := range lbls {
			// ignore `pod-template-hash` label
			if k == constants.DefaultDeploymentUniqueLabelKey {
				continue
			}
			podLable[k] = v
		}
		if len(podLable) > 0 {
			gw.gwPodLabel = labels.Instance(podLable)
		}
	} else {
		if os.IsNotExist(err) {
			log.Debugf("failed to read pod labels: %v", err)
			reErr = fmt.Errorf("failed to read pod labels: %v", err)
		} else {
			log.Warnf("failed to read pod labels: %v", err)
			reErr = fmt.Errorf("failed to read pod labels: %v", err)
		}
	}

	return gw, reErr
}

func (gw *GatewayWatcher) QuoteAttestationDeliver(ctx context.Context, signerName, instanceName, ns string) error {
	sgxctx := gw.gwSM.SgxContext
	if sgxctx == nil {
		log.Errorf("sgx context for this hsm custom resource has not been initialized")
		return fmt.Errorf("sgx context for this hsm custom resource has not been initialized")
	}
	if err := sgxctx.GenerateQuoteAndPublicKey(true, signerName); err != nil {
		return fmt.Errorf("failed to generate sgx quote and public key %s", err)
	}
	quote, err := sgxctx.Quote(true, signerName)
	if err != nil {
		return fmt.Errorf("get sgx quote error %s", err)
	}

	publicKey, err := sgxctx.QuotePublicKey(true, signerName)
	if err != nil {
		return fmt.Errorf("get public key error %s", err)
	}
	tokenLabel, err := sgxctx.TokenLabel()
	if err != nil {
		return fmt.Errorf("get service id error %s", err)
	}

	quoteAttestation := &quoteapi.QuoteAttestation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instanceName,
			Namespace: ns,
		},
		Spec: quoteapi.QuoteAttestationSpec{
			Type:         quoteapi.QuoteAttestationRequestType(quoteapi.RequestTypeKeyProvisioning),
			Quote:        quote,
			QuoteVersion: DefaultQuoteVersion,
			SignerName:   signerName,
			ServiceID:    tokenLabel,
			PublicKey:    publicKey,
		},
	}

	//If not found object, create a new one
	cr, err := gw.tcsClient.QuoteAttestations(ns).Get(ctx, instanceName, metav1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err := gw.tcsClient.QuoteAttestations(ns).Create(ctx, quoteAttestation, metav1.CreateOptions{})
		if err != nil {
			log.Error(err, "Failed to create QuoteAttestation CR")
		}
		return err
	}

	//else create a patch from this object retired and merge to current object
	if err == nil {
		quoteAttestation := cr.DeepCopy()
		quoteAttestation.Spec = quoteapi.QuoteAttestationSpec{
			Type:         quoteapi.QuoteAttestationRequestType(quoteapi.RequestTypeKeyProvisioning),
			Quote:        quote,
			QuoteVersion: DefaultQuoteVersion,
			SignerName:   signerName,
			ServiceID:    tokenLabel,
			PublicKey:    publicKey,
		}
		_, err := gw.tcsClient.QuoteAttestations(ns).Update(ctx, quoteAttestation, metav1.UpdateOptions{})
		if err != nil {
			log.Error(err, "Failed to update QuoteAttestation CR")
		}
		return err
	}

	return fmt.Errorf("create or update SGX attestation instance error: %v", err)
}
