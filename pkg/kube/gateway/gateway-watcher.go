package gateway

import (
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/constants"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/kube/queue"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/security"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/util/downwardAPI"
	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/util/labels"

	istioapi "istio.io/api/networking/v1alpha3"
	gateway "istio.io/client-go/pkg/apis/networking/v1alpha3"
	gatewaylister "istio.io/client-go/pkg/listers/networking/v1alpha3"
	"istio.io/pkg/log"
)

type GatewayWatcher struct {
	gwInformer cache.SharedIndexInformer
	gwLister   gatewaylister.GatewayLister
	queue      queue.Queue
	gwPodLabel labels.Instance
	gwSM       *security.SecretManager
}

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
	gw.queue.Add(types.NamespacedName{Namespace: gatewayCR.Namespace, Name: gatewayCR.Name})
}

func (gw *GatewayWatcher) Reconcile(req types.NamespacedName) error {
	log.Info("Start to run GatewayWatcher Reconcile")
	log := log.WithLabels("istio gateway", req)
	gwClientCR, err := gw.gwLister.Gateways(req.Namespace).Get(req.Name)
	if err != nil {
		return err
	}
	gwAPICR := istioapi.Gateway(gwClientCR.Spec)
	gwSeletor := gwAPICR.GetSelector()
	if gwSeletor == nil {
		return fmt.Errorf("error: istio gateway %s has not selector.", req.Name)
	}
	gatewaySelector := labels.Instance(gwSeletor)
	log.Infof("This sds server gatewaySelector: %v", gatewaySelector)
	log.Infof("This sds server gwPodLabel: %v", gw.gwPodLabel)
	if gw.gwPodLabel.SubsetOf(gatewaySelector) {
		log.Infof("This sds server pod is the selected sds server pod with selector: %v", gatewaySelector)
		gwServers := gwAPICR.GetServers()
		for _, gwServer := range gwServers {
			if gwTLS := gwServer.GetTls(); gwTLS != nil {
				credName := gwTLS.GetCredentialName()
				if credName != "" {
					log.Infof("Credential Name of the gatway is [%s]", credName)
					gw.gwSM.SetCredNameMap(gwServer.Port, credName)
				} else {
					log.Errorf("error: no required gateway %s CredentialName for the sds server", req.Name)
					return fmt.Errorf("error: no required gateway %s CredentialName for the sds server", req.Name)
				}
			}
		}
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
	gw.queue = queue.NewQueue("Istio gateway",
		queue.WithReconciler(gw.Reconcile),
		queue.WithMaxAttempts(5))
	_ = gw.gwInformer.SetTransform(kube.StripUnusedFields)

	gw.gwInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) { gw.onGatewayAdd(obj) },
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
