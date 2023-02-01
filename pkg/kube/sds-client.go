package kube

import (
	"fmt"
	"reflect"
	"time"

	"go.uber.org/atomic"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	kubeExtClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	kubeExtInformers "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	gatewayapi "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayapibeta "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayapiinformer "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"

	clientextensions "istio.io/client-go/pkg/apis/extensions/v1alpha1"
	clientnetworkingalpha "istio.io/client-go/pkg/apis/networking/v1alpha3"
	clientnetworkingbeta "istio.io/client-go/pkg/apis/networking/v1beta1"
	clientsecurity "istio.io/client-go/pkg/apis/security/v1beta1"
	clienttelemetry "istio.io/client-go/pkg/apis/telemetry/v1alpha1"
	istioclient "istio.io/client-go/pkg/clientset/versioned"
	istioinformer "istio.io/client-go/pkg/informers/externalversions"
	"istio.io/istio/operator/pkg/apis"
	"istio.io/istio/pkg/kube/mcs"

	tcsapi "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/apis/tcs/v1alpha2"
	tcsv1alpha2 "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/client/clientset/versioned"
	qaapiinformer "github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/client/informers/externalversions"
)

type Client interface {
	// RESTConfig returns the Kubernetes rest.Config used to configure the clients.
	RESTConfig() *rest.Config

	// Ext returns the API extensions client.
	Ext() kubeExtClient.Interface

	// Kube returns the core kube client
	Kube() kubernetes.Interface

	// Istio returns the Istio kube client.
	Istio() istioclient.Interface

	// GatewayAPI returns the gateway-api kube client.
	GatewayAPI() gatewayapiclient.Interface

	// KubeInformer returns an informer for core kube client
	KubeInformer() informers.SharedInformerFactory

	// IstioInformer returns an informer for the istio client
	IstioInformer() istioinformer.SharedInformerFactory

	// GatewayAPIInformer returns an informer for the gateway-api client
	GatewayAPIInformer() gatewayapiinformer.SharedInformerFactory

	// ExtInformer returns an informer for the extension client
	ExtInformer() kubeExtInformers.SharedInformerFactory

	// QaAPIInformer returns an informer for the quote attestation client
	QaAPIInformer() qaapiinformer.SharedInformerFactory

	// QaAPI returns the quote attestation kube client
	QaAPI() tcsv1alpha2.Interface

	// RunAndWait starts all informers and waits for their caches to sync.
	// Warning: this must be called AFTER .Informer() is called, which will register the informer.
	RunAndWait(stop <-chan struct{})
}

var (
	_ Client = &SdsClient{}
)

const resyncInterval = 0

type SdsClient struct {
	config     *rest.Config
	restClient *rest.RESTClient

	extSet      kubeExtClient.Interface
	extInformer kubeExtInformers.SharedInformerFactory

	kube         kubernetes.Interface
	kubeInformer informers.SharedInformerFactory

	istio         istioclient.Interface
	istioInformer istioinformer.SharedInformerFactory

	gatewayapi         gatewayapiclient.Interface
	gatewayapiInformer gatewayapiinformer.SharedInformerFactory

	// If enable, will wait for cache syncs with extremely short delay. This should be used only for tests
	fastSync               bool
	informerWatchesPending *atomic.Int32

	qaapi            tcsv1alpha2.Interface
	qaInformer       qaapiinformer.SharedInformerFactory
}

// NewSDSClient creates a Kubernetes client from the given rest config.
func NewSDSClient(clientConfig clientcmd.ClientConfig) (Client, error) {
	return newSDSClientInternal(newSDSClientFactory(clientConfig, false), "")
}

// newSDSClientInternal creates a Kubernetes client from the given factory.
func newSDSClientInternal(clientFactory *clientFactory, revision string) (*SdsClient, error) {
	var c SdsClient
	var err error

	c.config, err = clientFactory.ToRESTConfig()
	if err != nil {
		return nil, err
	}

	c.restClient, err = clientFactory.RESTClient()
	if err != nil {
		return nil, err
	}

	c.kube, err = kubernetes.NewForConfig(c.config)
	if err != nil {
		return nil, err
	}
	c.kubeInformer = informers.NewSharedInformerFactory(c.kube, resyncInterval)

	c.istio, err = istioclient.NewForConfig(c.config)
	if err != nil {
		return nil, err
	}
	c.istioInformer = istioinformer.NewSharedInformerFactory(c.istio, resyncInterval)

	c.gatewayapi, err = gatewayapiclient.NewForConfig(c.config)
	if err != nil {
		return nil, err
	}
	c.gatewayapiInformer = gatewayapiinformer.NewSharedInformerFactory(c.gatewayapi, resyncInterval)

	c.extSet, err = kubeExtClient.NewForConfig(c.config)
	if err != nil {
		return nil, err
	}
	c.extInformer = kubeExtInformers.NewSharedInformerFactory(c.extSet, resyncInterval)

	c.qaapi , err = tcsv1alpha2.NewForConfig(c.config)
	if err != nil {
		return nil, err
	}
	c.qaInformer = qaapiinformer.NewSharedInformerFactory(c.qaapi, resyncInterval)


	return &c, nil
}

// NewDefaultClient returns a default client, using standard Kubernetes config resolution to determine
// the cluster to access.
func NewDefaultClient() (Client, error) {
	return NewSDSClient(BuildClientCmd("", ""))
}

func (c *SdsClient) RESTConfig() *rest.Config {
	if c.config == nil {
		return nil
	}
	cpy := *c.config
	return &cpy
}

func (c *SdsClient) Ext() kubeExtClient.Interface {
	return c.extSet
}

func (c *SdsClient) Kube() kubernetes.Interface {
	return c.kube
}

func (c *SdsClient) Istio() istioclient.Interface {
	return c.istio
}

func (c *SdsClient) IstioInformer() istioinformer.SharedInformerFactory {
	return c.istioInformer
}

func (c *SdsClient) GatewayAPI() gatewayapiclient.Interface {
	return c.gatewayapi
}

func (c *SdsClient) KubeInformer() informers.SharedInformerFactory {
	return c.kubeInformer
}

func (c *SdsClient) GatewayAPIInformer() gatewayapiinformer.SharedInformerFactory {
	return c.gatewayapiInformer
}

func (c *SdsClient) ExtInformer() kubeExtInformers.SharedInformerFactory {
	return c.extInformer
}

func (c *SdsClient) QaAPIInformer() qaapiinformer.SharedInformerFactory {
	return c.qaInformer
}
func (c *SdsClient) QaAPI() tcsv1alpha2.Interface{
	return c.qaapi
}

// RunAndWait starts all informers and waits for their caches to sync.
// Warning: this must be called AFTER .Informer() is called, which will register the informer.
func (c *SdsClient) RunAndWait(stop <-chan struct{}) {
	c.kubeInformer.Start(stop)
	c.istioInformer.Start(stop)
	c.gatewayapiInformer.Start(stop)
	c.extInformer.Start(stop)
	c.qaInformer.Start(stop)
	if c.fastSync {
		// WaitForCacheSync will virtually never be synced on the first call, as its called immediately after Start()
		// This triggers a 100ms delay per call, which is often called 2-3 times in a test, delaying tests.
		// Instead, we add an aggressive sync polling
		fastWaitForCacheSync(stop, c.kubeInformer)
		fastWaitForCacheSync(stop, c.istioInformer)
		fastWaitForCacheSync(stop, c.gatewayapiInformer)
		fastWaitForCacheSync(stop, c.extInformer)
		fastWaitForCacheSync(stop, c.qaInformer)
		_ = wait.PollImmediate(time.Microsecond*100, wait.ForeverTestTimeout, func() (bool, error) {
			select {
			case <-stop:
				return false, fmt.Errorf("channel closed")
			default:
			}
			if c.informerWatchesPending.Load() == 0 {
				return true, nil
			}
			return false, nil
		})
	} else {
		c.kubeInformer.WaitForCacheSync(stop)
		c.istioInformer.WaitForCacheSync(stop)
		c.gatewayapiInformer.WaitForCacheSync(stop)
		c.extInformer.WaitForCacheSync(stop)
		c.qaInformer.WaitForCacheSync(stop)
	}
}

type reflectInformerSync interface {
	WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool
}

// Wait for cache sync immediately, rather than with 100ms delay which slows tests
// See https://github.com/kubernetes/kubernetes/issues/95262#issuecomment-703141573
func fastWaitForCacheSync(stop <-chan struct{}, informerFactory reflectInformerSync) {
	returnImmediately := make(chan struct{})
	close(returnImmediately)
	_ = wait.PollImmediate(time.Microsecond*100, wait.ForeverTestTimeout, func() (bool, error) {
		select {
		case <-stop:
			return false, fmt.Errorf("channel closed")
		default:
		}
		for _, synced := range informerFactory.WaitForCacheSync(returnImmediately) {
			if !synced {
				return false, nil
			}
		}
		return true, nil
	})
}

// IstioScheme returns a scheme will all known Istio-related types added
var IstioScheme = istioScheme()

func istioScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(kubescheme.AddToScheme(scheme))
	utilruntime.Must(mcs.AddToScheme(scheme))
	utilruntime.Must(clientnetworkingalpha.AddToScheme(scheme))
	utilruntime.Must(clientnetworkingbeta.AddToScheme(scheme))
	utilruntime.Must(clientsecurity.AddToScheme(scheme))
	utilruntime.Must(clienttelemetry.AddToScheme(scheme))
	utilruntime.Must(clientextensions.AddToScheme(scheme))
	utilruntime.Must(gatewayapi.AddToScheme(scheme))
	utilruntime.Must(gatewayapibeta.AddToScheme(scheme))
	utilruntime.Must(apis.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
	utilruntime.Must(tcsapi.AddToScheme(scheme))
	return scheme
}
