module sample-scheduler-framework

go 1.13

require (
	k8s.io/api v0.0.0
	k8s.io/apimachinery v0.0.0
	k8s.io/component-base v0.0.0
	k8s.io/klog v1.0.0
	k8s.io/kubernetes v0.0.0-00010101000000-000000000000
)

replace (
	k8s.io/api => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/api
	k8s.io/apiextensions-apiserver => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver
	k8s.io/apimachinery => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/apimachinery
	k8s.io/apiserver => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/apiserver
	k8s.io/cli-runtime => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/cli-runtime
	k8s.io/client-go => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/client-go
	k8s.io/cloud-provider => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/cloud-provider
	k8s.io/cluster-bootstrap => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/cluster-bootstrap
	k8s.io/code-generator => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/code-generator
	k8s.io/component-base => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/component-base
	k8s.io/cri-api => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/cri-api
	k8s.io/csi-translation-lib => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/csi-translation-lib
	k8s.io/kube-aggregator => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator
	k8s.io/kube-controller-manager => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/kube-controller-manager
	k8s.io/kube-proxy => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/kube-proxy
	k8s.io/kube-scheduler => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/kube-scheduler
	k8s.io/kubectl => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/kubectl
	k8s.io/kubelet => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/kubelet
	k8s.io/kubernetes => /home/k8s-develop/goproject/src/k8s.io/kubernetes
	k8s.io/legacy-cloud-providers => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/legacy-cloud-providers
	k8s.io/metrics => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/metrics
	k8s.io/sample-apiserver => /home/k8s-develop/goproject/src/k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver
)
