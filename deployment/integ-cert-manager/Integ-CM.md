> Note: please ensure installed cert manager with flag  `--feature-gates=ExperimentalCertificateSigningRequestControllers=true`. You can use `--set featureGates="ExperimentalCertificateSigningRequestControllers=true"` when helm install cert-manager

```sh

# Create cert manager issuer
$ cat <<EOF > ./istio-cm-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-istio-issuer
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: istio-ca
  namespace: cert-manager
spec:
  isCA: true
  commonName: istio-system
  secretName: istio-ca-selfsigned
  issuerRef:
    name: selfsigned-istio-issuer
    kind: ClusterIssuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: istio-system
spec:
  ca:
    secretName: istio-ca-selfsigned
EOF
$ kubectl apply -f ./istio-cm-issuer.yaml

# Get the issuer certificate and replace it in the caCertificates.pem field of the yaml file
$ kubectl get clusterissuers istio-system -o jsonpath='{.spec.ca.secretName}' | xargs kubectl get secret -n cert-manager -o jsonpath='{.data.ca\.crt}' | base64 -d

# install with mTLS chart
$ istioctl install -f integ-cert-manager-mTLS.yaml -y

# Or install with gateway chart
$ istioctl install -f integ-cert-manager-gateway.yaml -y

# install workload
$ kubectl apply -f ../istio-configs/sleep-hsm.yaml
$ kubectl apply -f ../istio-configs/httpbin-hsm.yaml
```
