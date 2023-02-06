```sh

# Install TCS Signer
export CA_SIGNER_NAME=sgx-signer
cat << EOF | kubectl create -f -
apiVersion: tcs.intel.com/v1alpha1
kind: TCSClusterIssuer
metadata:
    name: $CA_SIGNER_NAME
spec:
    secretName: ${CA_SIGNER_NAME}-secret
    selfSign: false
EOF

# Get the CA Cert, then export the CA Cert in CACERT and replace it in istio-hsm-config.yaml caCertificates field
$(kubectl get secret -n tcs-issuer ${CA_SIGNER_NAME}-secret -o jsonpath='{.data.tls\.crt}' |base64 -d | sed -e 's;\(.*\);        \1;g')

# Create the CA certificate file
echo $CACERT > cacert.crt

# Install Istio, if set `NEED_QUOTE` as true, sds-server will add quote/publickey extension to the csr 
istioctl install -f istio-gateway-sgx-tcs-config.yaml -y

# Deploy workload and its gateway
kubectl apply -f <(istioctl kube-inject -f httpbin-hsm.yaml )
kubectl apply -f httpbin-gateway.yaml

# Check the quoteattestations CR for gateway
kubectl get quoteattestations.tcs.intel.com
export QA_NAME=<The Name of The quoteattestations CR>

# Verify the result 
export INGRESS_NAME=istio-ingressgateway
export INGRESS_NS=istio-system
export SECURE_INGRESS_PORT=$(kubectl -n "${INGRESS_NS}" get service "${INGRESS_NAME}" -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
export INGRESS_HOST=$(kubectl get po -l istio=ingressgateway -n "${INGRESS_NS}" -o jsonpath='{.items[0].status.hostIP}') 

curl -v -HHost:httpbin.example.com --resolve "httpbin.example.com:$SECURE_INGRESS_PORT:$INGRESS_HOST" \
  --cacert cacert.crt "https://httpbin.example.com:$SECURE_INGRESS_PORT/status/418"

It will be okay if got below response:
[Response](../gateway-test.png)

# Clean up
istioctl uninstall --purge -y
kubectl delete -f httpbin-hsm.yaml
kubectl delete -f httpbin-gateway.yaml
```
