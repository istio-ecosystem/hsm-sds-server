```sh
make docker

kubectl delete -f deployment/istio-configs/sleep-hsm.yaml

istioctl x uninstall --purge -y

istioctl install -f deployment/istio-configs/istio-hsm-config.yaml -y

kubectl apply -f <(istioctl kube-inject -f deployment/istio-configs/sleep-hsm.yaml )

kubectl apply -f <(istioctl kube-inject -f deployment/istio-configs/sleep-gateway.yaml )

kubectl delete -f deployment/istio-configs/sleep-hsm.yaml

kubectl delete -f deployment/istio-configs/sleep-gateway.yaml

kubectl get po

kubectl logs -l app=sleep -c testsds

istioctl pc all sleep-854bcf566d-vd2cp.debugsds -o json > config_dump.json

sudo ./main -c /etc/kubernetes/admin.conf

sudo ./envoy -c test/boot.yaml -l debug --service-node 'local-envoy' --service-cluster 'local-envoy'

sudo ./envoy -c test/boot.yaml -l debug --log-path out.txt  --service-node 'local-envoy' --service-cluster 'local-envoy'

curl localhost:12346/config_dump > envoy_config.json

kubectl certificate approve default

cmctl approve -n istio-system mesh-ca --reason "pki-team" --message "this certificate is valid"
# Approved CertificateRequest 'istio-system/mesh-ca'

kubectl get csr/default -o yaml
```