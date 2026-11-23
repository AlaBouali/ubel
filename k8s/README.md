# ubel-k8s — Kubernetes security audit

`ubel-k8s` audits a **live cluster** or a set of **manifest files** and writes a JSON and an HTML report with **diffs against the
previous scan, compliance mapping (Pod Security Standards, NIST, PCI DSS, ISO 27001 …) and detailed stats** —
the same report model as `ubel-cloud` and `ubel-vm`.

- **Zero third-party dependencies, no subprocesses.** Node.js built-ins only: the API is spoken with `node:https`, kubeconfig and
  manifests are parsed in-process, and `kubectl` or any other program is never started.
- **Read-only.** Only `GET` requests are sent. **Secret values are never fetched or stored**: Secrets are requested as *metadata only*
  (`PartialObjectMetadataList`) and any `data` that a server returns anyway is discarded on arrival.
- **Honest coverage.** Every check ends as **passed**, **failed**, **not applicable** or **not assessed**. If your credentials may not list
  a resource, the checks that need it are *not assessed* (never a pass) and the run exits `3` unless you pass `--allow-partial`.

```bash
ubel-k8s                                       # current kubeconfig context (or the in-cluster service account)
ubel-k8s --kubeconfig ./kc.yaml --context prod --exclude-namespace kube-system
ubel-k8s --namespace payments,checkout         # namespace-scoped access is enough (lists per namespace)
ubel-k8s --token-file ./sa.token --kubelet-configz --allowed-registries registry.example.com,ghcr.io
ubel-k8s --manifests ./deploy,./charts-rendered/app.yaml   # offline: YAML / JSON files or directories
ubel-k8s --list-checks
```

## Connecting

Order: `--kubeconfig`, `$KUBECONFIG`, `~/.kube/config`, then the in-cluster service account. Supported credentials: client certificate +
key, bearer token (inline, `tokenFile`, `--token-file`, `$KUBE_TOKEN`) and the OIDC token a kubeconfig already contains.

### EKS, GKE and AKS — without running their CLIs

Kubeconfigs of managed clusters usually hold no credential: they name a helper program that prints a short-lived token. `ubel-k8s` starts **no**
other program, so it does what those helpers do itself, in-process, and refreshes the token when it expires (or after a `401`):

| Cluster | Helper in the kubeconfig | What `ubel-k8s` does instead | Credentials it reads |
|---|---|---|---|
| **EKS** | `aws eks get-token`, `aws-iam-authenticator token` | builds the same presigned STS `GetCallerIdentity` token (`k8s-aws-v1.…`; byte-identical to botocore's for the same inputs), optionally after assuming `--role-arn` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`, or a static `~/.aws` profile (including `role_arn` + `source_profile`); the `--region`, `--cluster-name`, `--profile`, `--role-arn` of the helper are honoured |
| **GKE** | `gke-gcloud-auth-plugin` (and the legacy `gcp` auth-provider) | obtains an OAuth2 access token from Application Default Credentials | `GOOGLE_APPLICATION_CREDENTIALS` (service-account key), the ADC file written by `gcloud auth application-default login`, or the metadata server on GCE/GKE |
| **AKS** | `kubelogin get-token --login spn\|msi\|workloadidentity` (and the legacy `azure` auth-provider) | requests an Entra ID token for the AKS server application | `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`, a managed identity, or workload identity (`AZURE_FEDERATED_TOKEN_FILE`) |

Helpers that need a browser, a prompt or a cloud CLI — AWS IAM Identity Center (SSO) profiles, `gcloud` itself, `kubelogin --login devicecode|interactive|azurecli`, or any
other exec plugin — **cannot** be reproduced without a subprocess and are refused with an explanation; hand the scanner a bearer token instead (`--token-file`, `$KUBE_TOKEN`) or export temporary credentials as environment variables.

### Managed control planes

On a managed cluster there is no kube-apiserver / etcd static pod to inspect, so those checks are *not applicable* — and instead the **provider's own description of the cluster** is read through its REST API with the same credentials
(`eks:DescribeCluster`, `container.clusters.get`, `Microsoft.ContainerService/managedClusters/read`) and assessed: endpoint exposure and authorized networks, audit logging, secrets encryption, legacy authentication (GKE ABAC / basic auth / client certificates),
network-policy enforcement, Workload Identity, RBAC and Entra ID integration (AKS). The cluster is identified from the kubeconfig (EKS ARN / endpoint, `gke_<project>_<location>_<cluster>`, AKS cluster name + `AZURE_SUBSCRIPTION_ID`); pass `--managed-cluster`
(`<region>/<name>`, `<project>/<location>/<name>`, `<subscription>/<resourceGroup>/<name>`) when it cannot be derived, or `--no-managed-api` to skip the provider calls. If the credentials may not describe the cluster, those checks are reported as *not assessed* with the reason.

Minimal read-only access (the built-in `view` role does not include nodes, RBAC objects or secret metadata):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: ubel-k8s-audit}
rules:
- apiGroups: [""]
  resources: [namespaces, nodes, pods, services, serviceaccounts, secrets, resourcequotas, limitranges, replicationcontrollers]
  verbs: [get, list]
- apiGroups: [apps, batch, networking.k8s.io, rbac.authorization.k8s.io]
  resources: [deployments, daemonsets, statefulsets, replicasets, jobs, cronjobs, ingresses, networkpolicies, roles, rolebindings, clusterroles, clusterrolebindings]
  verbs: [get, list]
```

`secrets: list` is needed only to see Secret *metadata* (used to find legacy long-lived service-account tokens); the scanner never reads their values.
`--kubelet-configz` additionally needs `nodes/proxy` (`get`), which is itself a powerful permission — it is opt-in.

## Options

| Option | Meaning |
|---|---|
| `--kubeconfig <file>` / `--context <name>` | Which kubeconfig and context to use |
| `--token-file <file>` | Bearer token file (overrides the kubeconfig credentials; `$KUBE_TOKEN` also works) |
| `--managed-cluster <id>` | Cluster identity for the provider API when it cannot be derived (EKS `<region>/<name>`, GKE `<project>/<location>/<name>`, AKS `<subscription>/<resourceGroup>/<name>`) |
| `--no-managed-api` | Do not call the cloud provider's API (the managed control-plane checks become not applicable) |
| `--insecure-skip-tls-verify` | Do not verify the API server certificate (recorded as a coverage note) |
| `--namespace <a,b>` / `--exclude-namespace <a,b>` | Restrict / exclude namespaces (named namespaces are read one by one, so no cluster-wide list permission is needed) |
| `--manifests <paths>` | Audit YAML / JSON files or directories instead of a cluster (Helm templates must be rendered first: `helm template … > out.yaml`) |
| `--kubelet-configz` | Read each kubelet's configuration through the API (anonymous auth, authorization mode, read-only port) |
| `--allowed-registries <a,b>` | Flag images that do not come from these registries |
| `--timeout <seconds>` | Per-request timeout (default 30) |
| `--only` / `--skip` / `--min-severity` / `--fail-on` / `--allow-partial` / `--working-dir` / `--verbose` / `--quiet` / `--list-checks` | As in `ubel-vm` |

Exit codes: `0` ok · `2` a `--fail-on` finding exists or bad arguments · `3` incomplete assessment · `1` fatal error.

## Reports

Written like every UBEL scan (`report.k8s.json` / `report.k8s.html` in the history zip, `latest.k8s.*` in `.ubel/reports/`). Tabs:
Dashboard, Executive Summary, Findings, Compliance (findings per control + check posture per framework), **Diffs**, **Stats** and Scan Info
(target, options, coverage caveats, full check catalogue). Findings are grouped by **area** and by **namespace** (the report's *scope*).

**Diffs** compare with the previous report **of the same cluster** (reports of other clusters sharing the asset folder are ignored). Findings are
matched on area + check + resource + namespace; checks that were not evaluated both times and namespaces that were not scanned both times are
left out so they never read as "fixed", and a note says so.

Workloads are audited once: a Pod owned by a ReplicaSet / StatefulSet / DaemonSet / Job is covered through its controller's pod template, and
container settings are merged with pod-level settings the way Kubernetes does. Finding resources look like `Deployment/web[nginx]` with the namespace as scope.

## Compliance mapping

Category-based controls (OWASP, PCI DSS, NIST SP 800-53, ISO 27001, SOC 2, CIS Controls v8) plus, where a check has one, the matching
**Kubernetes Pod Security Standards** control (baseline / restricted profile). Benchmark-specific control numbers (the CIS Kubernetes Benchmark) are
deliberately not mapped: their numbering differs between benchmark versions. Best-effort guidance, not a compliance assessment.

## What it checks

### Workloads (`workload`)

How pods and containers are configured: privileges, host access, capabilities, images, secrets and resource limits.

| Check | Severity | What it detects |
|---|---|---|
| `k8s-workload-privileged` | critical | Privileged container |
| `k8s-workload-host-pid` | high | Workload shares the host PID namespace |
| `k8s-workload-host-ipc` | high | Workload shares the host IPC namespace |
| `k8s-workload-host-network` | high | Workload uses the host network |
| `k8s-workload-host-path` | medium | Workload mounts a host path |
| `k8s-workload-host-port` | medium | Container uses a host port |
| `k8s-workload-privilege-escalation` | low | Container allows privilege escalation |
| `k8s-workload-run-as-root` | low | Container runs, or may run, as root |
| `k8s-workload-capabilities` | medium | Container adds Linux capabilities beyond the baseline |
| `k8s-workload-net-raw` | low | Container keeps the NET_RAW capability |
| `k8s-workload-readonly-rootfs` | low | Container root filesystem is writable |
| `k8s-workload-seccomp` | low | Container has no seccomp profile |
| `k8s-workload-baseline-settings` | medium | Workload uses a setting forbidden by the Pod Security baseline |
| `k8s-workload-resource-limits` | low | Container has no CPU / memory limits |
| `k8s-workload-image-tag` | medium | Container image uses a mutable tag |
| `k8s-workload-image-registry` | medium | Container image comes from a registry outside the allow-list |
| `k8s-workload-secret-in-env` | high | Secret value written in plain text in the pod spec |
| `k8s-workload-secret-env-ref` | info | Secret exposed to the container as an environment variable |
| `k8s-workload-default-service-account` | low | Workload runs as the default service account with its token mounted |
| `k8s-workload-default-namespace` | low | Workload is deployed in the default namespace |

### RBAC & service accounts (`rbac`)

Who is allowed to do what in the cluster, including powerful roles and service-account tokens.

| Check | Severity | What it detects |
|---|---|---|
| `k8s-rbac-cluster-admin-binding` | high | cluster-admin granted to a user, group or service account |
| `k8s-rbac-anonymous-binding` | high | Role granted to anonymous or all authenticated users |
| `k8s-rbac-system-masters` | critical | Binding references the system:masters group |
| `k8s-rbac-wildcard-role` | medium | Role uses wildcards for verbs or resources |
| `k8s-rbac-secrets-access` | medium | Role can read Secrets |
| `k8s-rbac-escalation-verbs` | high | Role can escalate, bind or impersonate |
| `k8s-rbac-pod-access` | medium | Role can create pods or run commands in pods |
| `k8s-rbac-dangerous-permissions` | high | Role grants a permission that leads to privilege escalation |
| `k8s-sa-default-bound` | medium | A role is bound to a namespace's default service account |
| `k8s-sa-default-automount` | low | Default service account token is auto-mounted |
| `k8s-sa-legacy-token-secret` | medium | Long-lived service-account token Secret exists |

### Network exposure (`network`)

How workloads are exposed (load balancers, node ports, ingress) and isolated from each other.

| Check | Severity | What it detects |
|---|---|---|
| `k8s-net-no-networkpolicy` | medium | Namespace with workloads has no NetworkPolicy |
| `k8s-net-no-default-deny` | low | Namespace has NetworkPolicies but no default-deny ingress policy |
| `k8s-net-allow-all-policy` | medium | NetworkPolicy allows all ingress to every pod in the namespace |
| `k8s-svc-loadbalancer-exposed` | medium | LoadBalancer service is open to the internet |
| `k8s-svc-nodeport` | low | NodePort service exposes a port on every node |
| `k8s-svc-external-ips` | medium | Service sets externalIPs |
| `k8s-ingress-no-tls` | medium | Ingress does not terminate TLS |
| `k8s-ingress-snippet-annotations` | medium | Ingress injects raw configuration snippets |

### Namespaces (`namespace`)

Guardrails per namespace: Pod Security enforcement, quotas and limits.

| Check | Severity | What it detects |
|---|---|---|
| `k8s-ns-no-pod-security` | medium | Namespace has no Pod Security Admission enforcement |
| `k8s-ns-psa-privileged` | low | Namespace enforces the privileged Pod Security level |
| `k8s-ns-no-quota` | low | Namespace has no ResourceQuota or LimitRange |

### Cluster & control plane (`cluster`)

API server, etcd and cluster-wide settings and version support.

| Check | Severity | What it detects |
|---|---|---|
| `k8s-api-anonymous-access` | critical | The API server answers unauthenticated requests |
| `k8s-apiserver-flags` | high | API server is started with an insecure option |
| `k8s-etcd-flags` | high | etcd is started with an insecure option |
| `k8s-controlplane-flags` | low | Controller manager or scheduler is started with a weak option |
| `k8s-eks-endpoint-exposure` | high | EKS API endpoint is reachable from the internet |
| `k8s-eks-audit-logging` | medium | EKS control-plane audit logging is not enabled |
| `k8s-eks-secrets-encryption` | medium | EKS does not envelope-encrypt Kubernetes Secrets |
| `k8s-gke-endpoint-exposure` | high | GKE control plane is reachable from the internet without authorized networks |
| `k8s-gke-legacy-auth` | high | GKE legacy authentication is enabled |
| `k8s-gke-network-policy` | medium | GKE does not enforce NetworkPolicy |
| `k8s-gke-workload-identity` | low | GKE Workload Identity is not enabled |
| `k8s-gke-logging` | medium | GKE cluster logging is disabled |
| `k8s-gke-shielded-nodes` | low | GKE shielded nodes are not enabled |
| `k8s-aks-endpoint-exposure` | high | AKS API server is reachable from the internet |
| `k8s-aks-rbac` | critical | AKS Kubernetes RBAC is disabled |
| `k8s-aks-identity` | medium | AKS is not integrated with Entra ID, or local accounts are enabled |
| `k8s-aks-network-policy` | medium | AKS has no network policy engine |
| `k8s-aks-monitoring` | low | AKS monitoring is not enabled |

### Nodes (`node`)

The machines that run workloads: kubelet settings, versions and operating-system support.

| Check | Severity | What it detects |
|---|---|---|
| `k8s-kubelet-config` | high | Kubelet is configured insecurely |
| `k8s-node-version-skew` | medium | Kubelet version is outside the supported skew |
| `k8s-node-external-ip` | low | Node has a public IP address |

**What is not applicable to a cluster scan.** `ubel-k8s` talks to the API server and never runs another program, so it cannot pull an image or open a node's disk, and it does not look up packages or component versions in any vulnerability database: the packages *inside* images are scanned with `ubel-docker`.

## Limits worth knowing

- **API objects, not runtime.** It does not scan images or the packages inside them, does not look up component versions or packages in any vulnerability database, and cannot see what happens inside containers.
- **Policy engines are not evaluated.** Kyverno, OPA Gatekeeper, ValidatingAdmissionPolicy and CNI-level policies (Cilium, Calico) may compensate for a missing
  Kubernetes object; the *Pod Security Admission* and *NetworkPolicy* findings say so.
- **Manifest mode is a partial view.** Checks that conclude from the *absence* of objects (no NetworkPolicy, no quota, API server version, anonymous access) are *not applicable*.
- **Control-plane flag checks need static pods** in `kube-system` (kubeadm-style). Managed services (EKS, GKE, AKS) do not expose them, so those checks are *not applicable*; their control plane is assessed through the provider API instead (needs read permission on the cluster resource).
- **Node-level checks** (file permissions, etcd data directory, kubelet configuration files) cannot be seen through the API: run `ubel-vm` on the nodes — its *Kubernetes node* area covers the node-level hardening checks.
- **Embedded dates age.** The Kubernetes minor-version support table and the node-OS table are part of the tool version; a version that is not listed is not judged.
- The report engine is shared with `ubel-vm` and lives in `vm/lib/`.
