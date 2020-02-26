# 调度框架 Scheduling Framework

## 架构设计

工作流程图可以查看 ![工作流程图](image/scheduling-framework-extensions.png)

相关文档参见[sig-scheduling](https://github.com/kubernetes/enhancements/tree/master/keps/sig-scheduling)

## 前提

调度框架定义了一组扩展点，用户可以实现扩展点定义的接口来定义自己的调度逻辑，并将扩展注册到扩展点上，调度框架在执行调度工作流时，遇到对应的扩展点时，将调用用户注册的扩展。

调度 Pod 时一般会有两个步骤：调度过程和绑定过程。

将调度过程和绑定过程合在一起，称之为调度上下文（scheduling context）。调度是同步的，绑定过程是异步运行的。
调度过程和绑定过程遇到如下情况时会中途退出，调度程序认为当前没有该 Pod 的可选节点或者产生内部错误，该 Pod 将被放回到待调度队列，并等待下次重试。

*Pod Scheduling Context*

*Scheduling Cycle*

QueueSort   Pre-filter    Filter    Post-filter   Scoring    Normalize scoring    Reserve

QueueSort 扩展用于对 Pod 的待调度队列进行排序，以决定先调度哪个 Pod，QueueSort 扩展本质上只需要实现一个方法 Less(Pod1, Pod2) 用于比较两个 Pod 谁更优先获得调度即可，同一时间点只能有一个 QueueSort 插件生效。

Pre-filter 扩展用于对 Pod 的信息进行预处理，检查一些集群或 Pod 必须满足的前提条件，如果 pre-filter 返回了 error，则调度过程终止。

Filter 扩展用于排除那些不能运行该 Pod 的节点，对于每一个节点，调度器将按顺序执行 filter 扩展；如果任何一个 filter 将节点标记为不可选，则余下的 filter 扩展将不会被执行。调度器可以同时对多个节点执行 filter 扩展。

Post-filter 是一个通知类型的扩展点，调用该扩展的参数是 filter 阶段结束后被筛选为可选节点的节点列表，可以在扩展中使用这些信息更新内部状态，或者产生日志或 metrics 信息。

Scoring 扩展用于为所有可选节点进行打分，调度器将针对每一个节点调用 Scoring 扩展，评分结果是一个范围内的整数。在 normalize scoring 阶段，调度器将会把每个 scoring 扩展对具体某个节点的评分结果和该扩展的权重合并起来，作为最终评分结果。

Normalize scoring 扩展在调度器对节点进行最终排序之前修改每个节点的评分结果，注册到该扩展点的扩展在被调用时，将获得同一个插件中的 scoring 扩展的评分结果作为参数，调度框架每执行一次调度，都将调用所有插件中的一个 normalize scoring 扩展一次。

Reserve 是一个通知性质的扩展点，有状态的插件可以使用该扩展点来获得节点上为 Pod 预留的资源，该事件发生在调度器将 Pod 绑定到节点之前，目的是避免调度器在等待 Pod 与节点绑定的过程中调度新的 Pod 到节点上时，发生实际使用资源超出可用资源的情况。（因为绑定 Pod 到节点上是异步发生的）。这是调度过程的最后一个步骤，Pod 进入 reserved 状态以后，要么在绑定失败时触发 Unreserve 扩展，要么在绑定成功时，由 Post-bind 扩展结束绑定过程。

Permit 扩展用于阻止或者延迟 Pod 与节点的绑定。Permit 扩展可以做下面三件事中的一项：

    approve（批准）：当所有的 permit 扩展都 approve 了 Pod 与节点的绑定，调度器将继续执行绑定过程
    deny（拒绝）：如果任何一个 permit 扩展 deny 了 Pod 与节点的绑定，Pod 将被放回到待调度队列，此时将触发 Unreserve 扩展
    wait（等待）：如果一个 permit 扩展返回了 wait，则 Pod 将保持在 permit 阶段，直到被其他扩展 approve，如果超时事件发生，wait 状态变成 deny，Pod 将被放回到待调度队列，此时将触发 Unreserve 扩展。

*Binding Cycle*

Pre-bind    Bind      Post-bind    Unreserve

Pre-bind 扩展用于在 Pod 绑定之前执行某些逻辑。例如，pre-bind 扩展可以将一个基于网络的数据卷挂载到节点上，以便 Pod 可以使用。如果任何一个 pre-bind 扩展返回错误，Pod 将被放回到待调度队列，此时将触发 Unreserve 扩展。

Bind 扩展用于将 Pod 绑定到节点上。

    只有所有的 pre-bind 扩展都成功执行了，bind 扩展才会执行
    调度框架按照 bind 扩展注册的顺序逐个调用 bind 扩展
    具体某个 bind 扩展可以选择处理或者不处理该 Pod
    如果某个 bind 扩展处理了该 Pod 与节点的绑定，余下的 bind 扩展将被忽略

Post-bind 是一个通知性质的扩展。

    Post-bind 扩展在 Pod 成功绑定到节点上之后被动调用
    Post-bind 扩展是绑定过程的最后一个步骤，可以用来执行资源清理的动作

Unreserve 是一个通知性质的扩展，如果为 Pod 预留了资源，Pod 又在被绑定过程中被拒绝绑定，
则 unreserve 扩展将被调用。Unreserve 扩展应该释放已经为 Pod 预留的节点上的计算资源。
在一个插件中，reserve 扩展和 unreserve 扩展应该成对出现。

对应的拓展点接口可见于 pkg/scheduler/framework/v1alpha1/interface.go

源码简单示例可参见 pkg/scheduler/framework/plugins/examples

## 示例

实现对应的扩展点，然后将插件注册到调度器中即可，下面是默认调度器在初始化的时候注册的插件。

    func NewRegistry() Registry {
    	return Registry{
    		// FactoryMap:
    		// New plugins are registered here.
    		// example:
    		// {
    		//  stateful_plugin.Name: stateful.NewStatefulMultipointExample,
    		//  fooplugin.Name: fooplugin.New,
    		// }
    	}
    }

可以看到默认中并没有注册一些插件，所以要想让调度器能够识别我们的插件代码，
就需要自己来实现一个调度器了，当然这个调度器我们完全没必要自己实现，
直接调用默认的调度器，然后在上面的 NewRegistry() 函数中将我们的插件注册进去即可。
在 kube-scheduler 的源码文件 `kubernetes/cmd/kube-scheduler/app/server.go` 
中有一个 NewSchedulerCommand 入口函数，其中的参数是一个类型为 Option 的列表，
而这个 Option 恰好就是一个插件配置的定义。

    // Option configures a framework.Registry.
    type Option func(framework.Registry) error
    
    // NewSchedulerCommand creates a *cobra.Command object with default parameters and registryOptions
    func NewSchedulerCommand(registryOptions ...Option) *cobra.Command {
      ......
    }

我们完全就可以直接调用这个函数来作为我们的函数入口，并且传入我们自己实现的插件作为参数即可，
而且该文件下面还有一个名为 WithPlugin 的函数可以来创建一个 Option 实例。

    // WithPlugin creates an Option based on plugin name and factory.
    func WithPlugin(name string, factory framework.PluginFactory) Option {
    	return func(registry framework.Registry) error {
    		return registry.Register(name, factory)
    	}
    }

    type PluginFactory = func(configuration *runtime.Unknown, f FrameworkHandle) (Plugin, error)

sample.New 实际上就是上面的这个函数，在这个函数中我们可以获取到插件中的一些数据然后进行逻辑处理即可，
插件实现如下所示，我们这里只是简单获取下数据打印日志，如果你有实际需求的可以根据获取的数据就行处理即可，
我们这里只是实现了 PreFilter、Filter、PreBind 三个扩展点，其它的可以用同样的方式来扩展即可。

## 最后

在项目根目录编译镜像
docker build -t tanjunchen/sample-scheduler:1.0 .

集群不在本地
docker save  -o  sample-scheduler.tar tanjunchen/sample-scheduler
scp
docker load < sample-scheduler.tar

配置文件介绍

```
# ClusterRole 集群角色
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: sample-scheduler-clusterrole
rules:
  - apiGroups:
      - ""
    resources:
      - endpoints
      - events
    verbs:
      - create
      - get
      - update
  - apiGroups:
      - ""
    resources:
      - nodes
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - pods
    verbs:
      - delete
      - get
      - list
      - watch
      - update
  - apiGroups:
      - ""
    resources:
      - bindings
      - pods/binding
    verbs:
      - create
  - apiGroups:
      - ""
    resources:
      - pods/status
    verbs:
      - patch
      - update
  - apiGroups:
      - ""
    resources:
      - replicationcontrollers
      - services
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - apps
      - extensions
    resources:
      - replicasets
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - apps
    resources:
      - statefulsets
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - policy
    resources:
      - poddisruptionbudgets
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - persistentvolumeclaims
      - persistentvolumes
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - configmaps
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - "storage.k8s.io"
    resources:
      - storageclasses
      - csinodes
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - "coordination.k8s.io"
    resources:
      - leases
    verbs:
      - create
      - get
      - list
      - update
  - apiGroups:
      - "events.k8s.io"
    resources:
      - events
    verbs:
      - create
      - patch
      - update
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sample-scheduler-sa
  namespace: kube-system
---
# 角色绑定 即这个角色拥有的资源权限
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: sample-scheduler-clusterrolebinding
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: sample-scheduler-clusterrole
subjects:
- kind: ServiceAccount
  name: sample-scheduler-sa
  namespace: kube-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: scheduler-config
  namespace: kube-system
data:
  scheduler-config.yaml: |
    apiVersion: kubescheduler.config.k8s.io/v1alpha1
    kind: KubeSchedulerConfiguration
    schedulerName: sample-scheduler
    leaderElection:
      leaderElect: true
      lockObjectName: sample-scheduler
      lockObjectNamespace: kube-system
    plugins:
      preFilter:
        enabled:
        - name: "sample-plugin"
      filter:
        enabled:
        - name: "sample-plugin"
      preBind:
        enabled:
        - name: "sample-plugin"
    pluginConfig:
    - name: "sample-plugin"
      args:
        favorite_color: "#326CE5"
        favorite_number: 7
        thanks_to: "tanjunchen"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sample-scheduler
  namespace: kube-system
  labels:
    component: sample-scheduler
spec:
  replicas: 1
  selector:
    matchLabels:
      component: sample-scheduler
  template:
    metadata:
      labels:
        component: sample-scheduler
    spec:
      serviceAccount: sample-scheduler-sa
      priorityClassName: system-cluster-critical
      volumes:
        - name: scheduler-config
          configMap:
            name: scheduler-config
      containers:
        - name: scheduler-ctrl
          image: tanjunchen/sample-scheduler:1.0
          imagePullPolicy: IfNotPresent
          args:
            - sample-scheduler-framework
            - --config=/etc/kubernetes/scheduler-config.yaml
            - --v=3
          resources:
            requests:
              cpu: "50m"
          volumeMounts:
            - name: scheduler-config
              mountPath: /etc/kubernetes
```

直接部署 `kubectl -f apply  *.yaml ` 上面的资源对象即可，这样我们就部署了一个名为 `sample-scheduler` 的调度器。

应用 yaml 文件。

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-scheduler
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-scheduler
  template:
    metadata:
      labels:
        app: test-scheduler
    spec:
      # schedulerName 对应于自身定义的调度器的名称
      schedulerName: sample-scheduler
      containers:
      - image: nginx
        imagePullPolicy: IfNotPresent
        name: nginx
        ports:
        - containerPort: 80
```

kubectl get pods -n kube-system -l component=sample-scheduler

kubectl logs -f pod名称 -n kube-system

```
I0226 13:22:06.585043       1 reflector.go:158] Listing and watching *v1beta1.PodDisruptionBudget from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.585414       1 reflector.go:158] Listing and watching *v1.Service from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.585694       1 reflector.go:158] Listing and watching *v1.ReplicaSet from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.585949       1 reflector.go:158] Listing and watching *v1.StorageClass from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.594623       1 reflector.go:158] Listing and watching *v1.Node from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.594836       1 reflector.go:158] Listing and watching *v1.StatefulSet from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.594961       1 reflector.go:158] Listing and watching *v1beta1.CSINode from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.595078       1 reflector.go:158] Listing and watching *v1.ReplicationController from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.600079       1 reflector.go:158] Listing and watching *v1.PersistentVolumeClaim from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.600360       1 reflector.go:158] Listing and watching *v1.PersistentVolume from k8s.io/client-go/informers/factory.go:134
I0226 13:22:06.600510       1 reflector.go:158] Listing and watching *v1.Pod from k8s.io/kubernetes/cmd/kube-scheduler/app/server.go:250
I0226 13:22:12.610045       1 node_tree.go:93] Added node "k8s-master" in group "" to NodeTree
I0226 13:22:12.610118       1 node_tree.go:93] Added node "node01" in group "" to NodeTree
I0226 13:22:12.610161       1 node_tree.go:93] Added node "node02" in group "" to NodeTree
I0226 13:22:12.649440       1 leaderelection.go:241] attempting to acquire leader lease  kube-system/sample-scheduler...
I0226 13:22:30.229500       1 leaderelection.go:251] successfully acquired lease kube-system/sample-scheduler
I0226 13:37:59.770417       1 scheduler.go:530] Attempting to schedule pod: default/test-scheduler-6d779d9465-vsvxh
I0226 13:37:59.771224       1 plugins.go:30] prefilter pod: test-scheduler-6d779d9465-vsvxh
I0226 13:37:59.774870       1 plugins.go:35] filter pod: test-scheduler-6d779d9465-vsvxh, node: k8s-master
I0226 13:37:59.775419       1 plugins.go:35] filter pod: test-scheduler-6d779d9465-vsvxh, node: node01
I0226 13:37:59.775436       1 plugins.go:35] filter pod: test-scheduler-6d779d9465-vsvxh, node: node02
I0226 13:37:59.782129       1 plugins.go:43] prebind node info: &Node{ObjectMeta:{node02   /api/v1/nodes/node02 ccf12cec-5234-4eb7-820f-a420ffbf1a2f 49340 0 2020-02-25 10:00:02 +0000 UTC <nil> <nil> map[beta.kubernetes.io/arch:amd64 beta.kubernetes.io/os:linux kubernetes.io/arch:amd64 kubernetes.io/hostname:node02 kubernetes.io/os:linux] map[kubeadm.alpha.kubernetes.io/cri-socket:/var/run/dockershim.sock node.alpha.kubernetes.io/ttl:0 projectcalico.org/IPv4Address:192.168.17.132/24 projectcalico.org/IPv4IPIPTunnelAddr:192.168.140.64 volumes.kubernetes.io/controller-managed-attach-detach:true] [] []  []},Spec:NodeSpec{PodCIDR:10.244.2.0/24,DoNotUse_ExternalID:,ProviderID:,Unschedulable:false,Taints:[]Taint{},ConfigSource:nil,PodCIDRs:[10.244.2.0/24],},Status:NodeStatus{Capacity:ResourceList{cpu: {{1 0} {<nil>} 1 DecimalSI},ephemeral-storage: {{40465752064 0} {<nil>}  BinarySI},hugepages-1Gi: {{0 0} {<nil>} 0 DecimalSI},hugepages-2Mi: {{0 0} {<nil>} 0 DecimalSI},memory: {{3953999872 0} {<nil>}  BinarySI},pods: {{110 0} {<nil>} 110 DecimalSI},},Allocatable:ResourceList{cpu: {{1 0} {<nil>} 1 DecimalSI},ephemeral-storage: {{36419176798 0} {<nil>} 36419176798 DecimalSI},hugepages-1Gi: {{0 0} {<nil>} 0 DecimalSI},hugepages-2Mi: {{0 0} {<nil>} 0 DecimalSI},memory: {{3849142272 0} {<nil>}  BinarySI},pods: {{110 0} {<nil>} 110 DecimalSI},},Phase:,Conditions:[]NodeCondition{NodeCondition{Type:NetworkUnavailable,Status:False,LastHeartbeatTime:2020-02-25 10:00:06 +0000 UTC,LastTransitionTime:2020-02-25 10:00:06 +0000 UTC,Reason:CalicoIsUp,Message:Calico is running on this node,},NodeCondition{Type:MemoryPressure,Status:False,LastHeartbeatTime:2020-02-26 13:37:17 +0000 UTC,LastTransitionTime:2020-02-25 10:00:02 +0000 UTC,Reason:KubeletHasSufficientMemory,Message:kubelet has sufficient memory available,},NodeCondition{Type:DiskPressure,Status:False,LastHeartbeatTime:2020-02-26 13:37:17 +0000 UTC,LastTransitionTime:2020-02-25 10:00:02 +0000 UTC,Reason:KubeletHasNoDiskPressure,Message:kubelet has no disk pressure,},NodeCondition{Type:PIDPressure,Status:False,LastHeartbeatTime:2020-02-26 13:37:17 +0000 UTC,LastTransitionTime:2020-02-25 10:00:02 +0000 UTC,Reason:KubeletHasSufficientPID,Message:kubelet has sufficient PID available,},NodeCondition{Type:Ready,Status:True,LastHeartbeatTime:2020-02-26 13:37:17 +0000 UTC,LastTransitionTime:2020-02-25 10:00:12 +0000 UTC,Reason:KubeletReady,Message:kubelet is posting ready status,},},Addresses:[]NodeAddress{NodeAddress{Type:InternalIP,Address:192.168.17.132,},NodeAddress{Type:Hostname,Address:node02,},},DaemonEndpoints:NodeDaemonEndpoints{KubeletEndpoint:DaemonEndpoint{Port:10250,},},NodeInfo:NodeSystemInfo{MachineID:d492c6ab0e5c4a32a5a2407fd619f919,SystemUUID:A6D24D56-387E-EE32-06D3-50E47141E69C,BootID:e8c01186-8897-4812-93cc-cd27fde17fa3,KernelVersion:3.10.0-1062.4.3.el7.x86_64,OSImage:CentOS Linux 7 (Core),ContainerRuntimeVersion:docker://19.3.5,KubeletVersion:v1.16.3,KubeProxyVersion:v1.16.3,OperatingSystem:linux,Architecture:amd64,},Images:[]ContainerImage{ContainerImage{Names:[perl@sha256:89b9d23c03a95d4f7995e4fbcc4811cf0286f93338aca9407ec1ff525e325b73 perl:latest],SizeBytes:857108231,},ContainerImage{Names:[mysql@sha256:6d0741319b6a2ae22c384a97f4bbee411b01e75f6284af0cce339fee83d7e314 mysql:latest],SizeBytes:465244873,},ContainerImage{Names:[kubeguide/tomcat-app@sha256:7a9193c2e5c6c74b4ad49a8abbf75373d4ab76c8f8db87672dc526b96ac69ac4 kubeguide/tomcat-app:v1],SizeBytes:358241257,},ContainerImage{Names:[tomcat@sha256:8ecb10948deb32c34aeadf7bf95d12a93fbd3527911fa629c1a3e7823b89ce6f tomcat:8.0],SizeBytes:356245923,},ContainerImage{Names:[mysql@sha256:bef096aee20d73cbfd87b02856321040ab1127e94b707b41927804776dca02fc mysql:5.6],SizeBytes:302490673,},ContainerImage{Names:[allingeek/ch6_ipc@sha256:eeeb7255a341751d31fbcfbeef0b27a9f02e61819ac6ab4b95bcdbd223b5f250 allingeek/ch6_ipc:latest],SizeBytes:279090357,},ContainerImage{Names:[calico/node@sha256:887bcd551668cccae1fbfd6d2eb0f635ec37bb4cf599e1169989aa49dfac5b57 calico/node:v3.11.2],SizeBytes:255343962,},ContainerImage{Names:[calico/node@sha256:8ee677fa0969bf233deb9d9e12b5f2840a0e64b7d6acaaa8ac526672896b8e3c calico/node:v3.11.1],SizeBytes:225848439,},ContainerImage{Names:[calico/cni@sha256:f5808401a96ba93010b9693019496d88070dde80dda6976d10bc4328f1f18f4e calico/cni:v3.11.2],SizeBytes:204185753,},ContainerImage{Names:[calico/cni@sha256:e493af94c8385fdfbce859dd15e52d35e9bf34a0446fec26514bb1306e323c17 calico/cni:v3.11.1],SizeBytes:197763545,},ContainerImage{Names:[calico/node@sha256:441abbaeaa2a03d529687f8da49dab892d91ca59f30c000dfb5a0d6a7c2ede24 calico/node:v3.10.1],SizeBytes:192029475,},ContainerImage{Names:[nginx@sha256:f2d384a6ca8ada733df555be3edc427f2e5f285ebf468aae940843de8cf74645 nginx:1.11.9],SizeBytes:181819831,},ContainerImage{Names:[nginx@sha256:35779791c05d119df4fe476db8f47c0bee5943c83eba5656a15fc046db48178b nginx:1.10.1],SizeBytes:180708613,},ContainerImage{Names:[httpd@sha256:ac6594daaa934c4c6ba66c562e96f2fb12f871415a9b7117724c52687080d35d httpd:latest],SizeBytes:165254767,},ContainerImage{Names:[calico/cni@sha256:dad425d218fd33b23a3929b7e6a31629796942e9e34b13710d7be69cea35cb22 calico/cni:v3.10.1],SizeBytes:163333600,},ContainerImage{Names:[nginx@sha256:50cf965a6e08ec5784009d0fccb380fc479826b6e0e65684d9879170a9df8566 nginx:latest],SizeBytes:126323486,},ContainerImage{Names:[debian@sha256:79f0b1682af1a6a29ff63182c8103027f4de98b22d8fb50040e9c4bb13e3de78 debian:latest],SizeBytes:114052312,},ContainerImage{Names:[calico/pod2daemon-flexvol@sha256:93c64d6e3e0a0dc75d1b21974db05d28ef2162bd916b00ce62a39fd23594f810 calico/pod2daemon-flexvol:v3.11.2],SizeBytes:111122324,},ContainerImage{Names:[calico/pod2daemon-flexvol@sha256:4757a518c0cd54d3cad9481c943716ae86f31cdd57008afc7e8820b1821a74b9 calico/pod2daemon-flexvol:v3.11.1],SizeBytes:111122324,},ContainerImage{Names:[nginx@sha256:23b4dcdf0d34d4a129755fc6f52e1c6e23bb34ea011b315d87e193033bcd1b68 nginx:1.15],SizeBytes:109331233,},ContainerImage{Names:[nginx@sha256:f7988fb6c02e0ce69257d9bd9cf37ae20a60f1df7563c3a2a6abe24160306b8d nginx:1.14],SizeBytes:109129446,},ContainerImage{Names:[registry.cn-beijing.aliyuncs.com/mrvolleyball/nginx@sha256:d9b43ba0db2f6a02ce843d9c2d68558e514864dec66d34b9dd82ab9a44f16671 registry.cn-beijing.aliyuncs.com/mrvolleyball/nginx:v1],SizeBytes:109057403,},ContainerImage{Names:[registry.cn-beijing.aliyuncs.com/mrvolleyball/nginx@sha256:31da21eb24615dacdd8d219e1d43dcbaea6d78f6f8548ce50c3f56699312496b registry.cn-beijing.aliyuncs.com/mrvolleyball/nginx:v2],SizeBytes:109057403,},ContainerImage{Names:[nginx@sha256:e3456c851a152494c3e4ff5fcc26f240206abac0c9d794affb40e0714846c451 nginx:1.7.9],SizeBytes:91664166,},ContainerImage{Names:[registry.aliyuncs.com/google_containers/kube-proxy@sha256:1a1b21354e31190c0a1c6b0e16485ec095e7a4d423620e4381c3982ebfa24b3a registry.aliyuncs.com/google_containers/kube-proxy:v1.16.3],SizeBytes:86065116,},ContainerImage{Names:[quay.io/coreos/flannel@sha256:3fa662e491a5e797c789afbd6d5694bdd186111beb7b5c9d66655448a7d3ae37 quay.io/coreos/flannel:v0.11.0],SizeBytes:52567296,},ContainerImage{Names:[calico/kube-controllers@sha256:46951fa7f713dfb0acc6be5edb82597df6f31ddc4e25c4bc9db889e894d02dd7 calico/kube-controllers:v3.11.1],SizeBytes:52477980,},ContainerImage{Names:[calico/kube-controllers@sha256:1169cca40b489271714cb1e97fed9b6b198aabdca1a1cc61698dd73ee6703d60 calico/kube-controllers:v3.11.2],SizeBytes:52477980,},ContainerImage{Names:[registry.aliyuncs.com/google_containers/coredns@sha256:4dd4d0e5bcc9bd0e8189f6fa4d4965ffa81207d8d99d29391f28cbd1a70a0163 registry.aliyuncs.com/google_containers/coredns:1.6.2],SizeBytes:44100963,},ContainerImage{Names:[quay.io/coreos/etcd@sha256:4e51857931144bc6974ecd0e6f07b90da54d678e56d2166d5323a48afbc6eed7 quay.io/coreos/etcd:v3.1.5],SizeBytes:33649054,},ContainerImage{Names:[redis@sha256:e9083e10f5f81d350a3f687d582aefd06e114890b03e7f08a447fa1a1f66d967 redis:3.2-alpine],SizeBytes:22894256,},ContainerImage{Names:[nginx@sha256:db5acc22920799fe387a903437eb89387607e5b3f63cf0f4472ac182d7bad644 nginx:1.12-alpine],SizeBytes:15502679,},ContainerImage{Names:[calico/pod2daemon-flexvol@sha256:42ca53c5e4184ac859f744048e6c3d50b0404b9a73a9c61176428be5026844fe calico/pod2daemon-flexvol:v3.10.1],SizeBytes:9780495,},ContainerImage{Names:[busybox@sha256:1828edd60c5efd34b2bf5dd3282ec0cc04d47b2ff9caa0b6d4f07a21d1c08084 busybox:latest],SizeBytes:1219782,},ContainerImage{Names:[gcr.azk8s.cn/google_containers/pause@sha256:f78411e19d84a252e53bff71a4407a5686c46983a2c2eeed83929b888179acea registry.aliyuncs.com/google_containers/pause@sha256:759c3f0f6493093a9043cc813092290af69029699ade0e3dbe024e968fcb7cca gcr.azk8s.cn/google_containers/pause:3.1 registry.aliyuncs.com/google_containers/pause:3.1],SizeBytes:742472,},},VolumesInUse:[],VolumesAttached:[]AttachedVolume{},Config:nil,},}
I0226 13:37:59.784266       1 factory.go:610] Attempting to bind test-scheduler-6d779d9465-vsvxh to node02
I0226 13:37:59.788509       1 scheduler.go:667] pod default/test-scheduler-6d779d9465-vsvxh is bound successfully on node "node02", 3 nodes evaluated, 2 nodes were found feasible. Bound node resource: "Capacity: CPU<1>|Memory<3861328Ki>|Pods<110>|StorageEphemeral<39517336Ki>; Allocatable: CPU<1>|Memory<3758928Ki>|Pods<110>|StorageEphemeral<36419176798>.".
```

从日志中我们得知 Pod 是调用自定义调度器的。

kubectl get pods

kubectl get pod pod名称 -o yaml

apiVersion: v1
kind: Pod
metadata:
  annotations:
    cni.projectcalico.org/podIP: 192.168.140.65/32
    cni.projectcalico.org/podIPs: 192.168.140.65/32
  creationTimestamp: "2020-02-26T13:37:59Z"
  generateName: test-scheduler-6d779d9465-
  labels:
    app: test-scheduler
    pod-template-hash: 6d779d9465
  name: test-scheduler-6d779d9465-vsvxh
  namespace: default
  ownerReferences:
  - apiVersion: apps/v1
    blockOwnerDeletion: true
    controller: true
    kind: ReplicaSet
    name: test-scheduler-6d779d9465
    uid: 0b57ec49-c02e-4f49-903e-d4063a9f4a45
  resourceVersion: "49454"
  selfLink: /api/v1/namespaces/default/pods/test-scheduler-6d779d9465-vsvxh
  uid: 7f511c47-cae3-4520-a1d8-91215da60527
spec:
  containers:
  - image: nginx
    imagePullPolicy: IfNotPresent
    name: nginx
    ports:
    - containerPort: 80
      protocol: TCP
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: default-token-hmmcv
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  nodeName: node02
  priority: 0
  restartPolicy: Always
  schedulerName: sample-scheduler
  securityContext: {}
  serviceAccount: default
  serviceAccountName: default
  terminationGracePeriodSeconds: 30
  tolerations:
  - effect: NoExecute
    key: node.kubernetes.io/not-ready
    operator: Exists
    tolerationSeconds: 300
  - effect: NoExecute
    key: node.kubernetes.io/unreachable
    operator: Exists
    tolerationSeconds: 300
  volumes:
  - name: default-token-hmmcv
    secret:
      defaultMode: 420
      secretName: default-token-hmmcv
status:
  conditions:
  - lastProbeTime: null
    lastTransitionTime: "2020-02-26T13:37:59Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2020-02-26T13:38:02Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2020-02-26T13:38:02Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2020-02-26T13:37:59Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: docker://86e5078b5ede4d6c08803e880061dcb72050b6cbf895615d8eca42f0d064f8a8
    image: nginx:latest
    imageID: docker-pullable://nginx@sha256:50cf965a6e08ec5784009d0fccb380fc479826b6e0e65684d9879170a9df8566
    lastState: {}
    name: nginx
    ready: true
    restartCount: 0
    started: true
    state:
      running:
        startedAt: "2020-02-26T13:38:02Z"
  hostIP: 192.168.17.132
  phase: Running
  podIP: 192.168.140.65
  podIPs:
  - ip: 192.168.140.65
  qosClass: BestEffort
  startTime: "2020-02-26T13:37:59Z"

在 Kubernetes v1.17 版本中，Scheduler Framework 内置的预选和优选函数已经全部插件化，所以我们应该掌握并理解这种扩展调度器。

# Scheduler 预选策略与优选函数

## 介绍



## 节点选择过程



## 调度器



## 高级调度设置机制



# 注意事项

go.mod 中的包要替换成自己的路径 replace  注意下

# 参考

https://www.qikqiak.com/post/custom-kube-scheduler/
