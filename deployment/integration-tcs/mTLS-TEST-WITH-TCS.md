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

# Get the CA Cert and replace it in istio-hsm-config.yaml caCertificates field
$(kubectl get secret -n tcs-issuer ${CA_SIGNER_NAME}-secret -o jsonpath='{.data.tls\.crt}' |base64 -d | sed -e 's;\(.*\);        \1;g')

# Install Istio, if set `NEED_QUOTE` as true, sds-server will add quote/publickey extension to the csr 
istioctl install -f istio-sgx-tcs-config.yaml -y

# Install workloads
kubectl apply -f <(istioctl kube-inject -f sleep-hsm.yaml )
kubectl apply -f <(istioctl kube-inject -f httpbin-hsm.yaml )

# Test workloads mTLS
kubectl exec "$(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name})" -c sleep -- curl -v -s http://httpbin.default:8000/headers

# Should be 200
kubectl exec $(kubectl get pod -l app=sleep -o jsonpath={.items..metadata.name}) -c sleep -- curl -s http://httpbin.default:8000/headers -o /dev/null -s -w '%{http_code}\n'

# Clean up
istioctl uninstall --purge -y
kubectl delete -f sleep-hsm.yaml
kubectl delete -f httpbin-hsm.yaml
```
