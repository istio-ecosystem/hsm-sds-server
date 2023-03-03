# Build Istio

HUB='istio' TAG='sds' DOCKER_TARGETS='docker.pilot docker.proxyv2' make docker

# Build sds server

make docker

# Workload Test


docker save -o ${BINARY}.tar ${HUB}/${BINARY}:${TAG}
	ctr -n k8s.io image import ${BINARY}.tar
### Build sds server
make docker

### Install TCS Signer

Refer to https://github.com/intel/trusted-certificate-issuer/blob/main/docs/istio-custom-ca-with-csr.md

export CA_SIGNER_NAME=sgx-signer
cat << EOF | kubectl create -f -
apiVersion: tcs.intel.com/v1alpha1
kind: TCSClusterIssuer
metadata:
    name: $CA_SIGNER_NAME
spec:
    secretName: ${CA_SIGNER_NAME}-secret
    # If using quoteattestaion, set selfSign as false
    # selfSign: false
EOF

### Get CA Cert and replace it in deployment/istio-configs/istio-hsm-config.yaml
kubectl get secret -n tcs-issuer ${CA_SIGNER_NAME}-secret -o jsonpath='{.data.tls\.crt}' |base64 -d | sed -e 's;\(.*\);        \1;g'


## Install

```
istioctl install -f deployment/istio-configs/istio-hsm-config.yaml -y --set values.global.proxy.logLevel=debug --set values.global.logging.level=all:debug

kubectl apply -f <(istioctl kube-inject -f deployment/istio-configs/sleep-hsm.yaml)

kubectl apply -f deployment/istio-configs/sleep-gateway.yaml

kubectl apply -f <(istioctl kube-inject -f deployment/istio-configs/httpbin-hsm.yaml)
```

## dump config

```
ps -ef | grep envoy

sudo nsenter -t {envoy pid } -n

curl localhost:15000/config_dump > .json

kubectl exec "$(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name})" -c istio-proxy -- curl -v -s http://httpbin.default:8000/headers

kubectl exec "$(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name})" -c sleep -- curl -v -s http://httpbin.default:8000/headers

kubectl exec $(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name}) -c istio-proxy -- curl -s http://httpbin.default:8000/headers -o /dev/null -s -w '%{http_code}\n'

kubectl exec $(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name}) -c sleep -- curl -s http://httpbin.default:8000/headers -o /dev/null -s -w '%{http_code}\n'
```

## Clean up

```
istioctl x uninstall --purge -y

kubectl delete -f deployment/istio-configs/sleep-hsm.yaml

kubectl delete -f deployment/istio-configs/httpbin-hsm.yaml

kubectl delete -f deployment/istio-configs/sleep-gateway.yaml
```

## Binary test

```
LIBRARY_PATH=/usr/local/lib go build main.go

sudo ./main -c /etc/kubernetes/admin.conf

sudo ./envoy -c test/boot.yaml -l debug --service-node 'local-envoy' --service-cluster 'local-envoy'

sudo ./envoy -c test/boot.yaml -l debug --log-path out.txt  --service-node 'local-envoy' --service-cluster 'local-envoy'

curl localhost:12346/config_dump > envoy_config.json

kubectl certificate approve default

cmctl approve -n istio-system mesh-ca --reason "pki-team" --message "this certificate is valid"
# Approved CertificateRequest 'istio-system/mesh-ca'

kubectl get csr/default -o yaml
```

# Gateway Test

## Install Istio and application
```
cd applications.services.cloud.hsm-sds-server

istioctl install -f deployment/istio-configs/gateway-istio-hsm.yaml -y --set values.global.proxy.logLevel=debug --set values.global.logging.level=all:debug

kubectl apply -f <(istioctl kube-inject -f deployment/istio-configs/httpbin-hsm.yaml)

kubectl apply -f deployment/istio-configs/httpbin-gateway.yaml
```

Note: please execute `kubectl apply -f deployment/istio-configs/gateway-clusterrole.yaml` to make sure that the ingress gateway has enough privilege.

## Get the credential information

### We use command line tools to read and write the QuoteAttestation manually. You get the tools, `km-attest` and `km-wrap`, provided by the [Intel® KMRA project](https://www.intel.com/content/www/us/en/developer/topic-technology/open/key-management-reference-application/overview.html).

Note: use release version 2.2.1

```
mkdir -p $HOME/sgx/gateway
export CREDENTIAL=$HOME/sgx/gateway

kubectl get quoteattestations.tcs.intel.com 
# Manually get the quoteattestation name via previous command
export QA_NAME=<YOUR QUOTEATTESTATION NAME>

kubectl get quoteattestations.tcs.intel.com -n default $QA_NAME -o jsonpath='{.spec.publicKey}' | base64 -d > $CREDENTIAL/public.key
kubectl get quoteattestations.tcs.intel.com -n default $QA_NAME -o jsonpath='{.spec.quote}' | base64 -d > $CREDENTIAL/quote.data
km-attest --pubkey $CREDENTIAL/public.key --quote $CREDENTIAL/quote.data

openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -subj '/O=example Inc./CN=example.com' -keyout $CREDENTIAL/example.com.key -out $CREDENTIAL/example.com.crt
openssl req -out $CREDENTIAL/httpbin.csr -newkey rsa:2048 -nodes -keyout $CREDENTIAL/httpbin.key -subj "/CN=httpbin.example.com/O=httpbin organization"
openssl x509 -req -sha256 -days 365 -CA $CREDENTIAL/example.com.crt -CAkey $CREDENTIAL/example.com.key -set_serial 0 -in $CREDENTIAL/httpbin.csr -out $CREDENTIAL/httpbin.crt
```

## Configurate `/opt/intel/km-wrap/km-wrap.conf` according to below content:
```
{
    "keys": [
        {
            "signer": "tcsclusterissuer.tcs.intel.com/sgx-signer",
            "key_path": "$CREDENTIAL/httpbin.key",
            "cert": "$CREDENTIAL/httpbin.crt"
        }
    ]
}
```

## Update credential quote attestation CR with secret contained wrapped key
```
WRAPPED_KEY=$(km-wrap --signer tcsclusterissuer.tcs.intel.com/sgx-signer --pubkey $CREDENTIAL/public.key --pin "HSMUserPin" --token "HSMSDSServer" --module /usr/local/lib/softhsm/libsofthsm2.so)
kubectl create secret generic -n default wrapped-key --from-literal=tls.key=${WRAPPED_KEY} --from-literal=tls.crt=$(base64 -w 0 < $CREDENTIAL/httpbin.crt)
```
kubectl edit quoteattestations.tcs.intel.com $QA_NAME -n default with `secretName: wrapped-key`

## Verify the service accessibility
```
export INGRESS_NAME=istio-ingressgateway
export INGRESS_NS=istio-system
export SECURE_INGRESS_PORT=$(kubectl -n "${INGRESS_NS}" get service "${INGRESS_NAME}" -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
export INGRESS_HOST=$(kubectl get po -l istio=ingressgateway -n "${INGRESS_NS}" -o jsonpath='{.items[0].status.hostIP}')

curl -v -HHost:httpbin.example.com --resolve "httpbin.example.com:$SECURE_INGRESS_PORT:$INGRESS_HOST" \
  --cacert $CREDENTIAL/example.com.crt "https://httpbin.example.com:$SECURE_INGRESS_PORT/status/418"
```
It will be okay if got below response:
[Response](./gateway-test.png)

## Clean up

```
istioctl x uninstall --purge -y

kubectl delete -f deployment/istio-configs/httpbin-gateway.yaml

kubectl delete -f deployment/istio-configs/httpbin-hsm.yaml
```
