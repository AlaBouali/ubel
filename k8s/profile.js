'use strict';
// profile.js — labels and area descriptions of ubel-k8s, embedded in every report (see ../vm/lib/html_report.js).

export const K8S_PROFILE = {
  key: 'k8s',
  tool: 'k8s-scanner',
  title: 'Kubernetes Security Report',
  exec_title: 'Kubernetes Security Posture — Executive Summary',
  logo: 'K',
  subject_noun: 'cluster',
  scope_label: 'Namespace',
  scopes_label: 'Namespaces',
  statement: 'Produced by a read-only review of Kubernetes API objects (or of manifest files). Secret values are never requested or stored. It reflects the configuration at the time of the scan.',
  scope_description: 'ubel-k8s audits a Kubernetes cluster, or a set of manifest files, against a hardening baseline: pod and container security settings (Pod Security Standards), RBAC, network exposure and isolation, namespace guardrails, control-plane and node configuration; on EKS, GKE and AKS it also reads the provider\'s description of the managed control plane. It only issues read (GET) requests and never changes the cluster.',
  discovery: 'In live mode the tool lists the cluster\'s objects through the API server with the credentials of the kubeconfig (or the in-cluster service account; the EKS / GKE / AKS login helpers are reproduced in-process); where a list is forbidden the checks that depend on it are reported as not assessed. In manifest mode it reads YAML / JSON files; checks that need a view of the whole cluster are not applicable.',
  method_steps: [
    { step: 'Collect the objects', detail: 'Namespaces, nodes, workloads (Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs), Services, Ingresses, NetworkPolicies, RBAC objects and ServiceAccounts are listed read-only. Secrets are requested as metadata only; their values are never fetched or stored.' },
    { step: 'Audit each workload once', detail: 'Pods owned by a controller are audited through the controller\'s pod template, so one workload produces one set of findings. Container settings are merged with pod-level settings the way Kubernetes does.' },
    { step: 'Evaluate each check', detail: 'Every check reports passed, failed, not applicable (for example control-plane checks on a managed cluster) or not assessed (for example list permission denied); a check that could not run is never counted as a pass.' },
    { step: 'Check the component versions (live cluster)', detail: 'The versions the cluster reports — API server, kubelets, container runtimes and the official kube-system images — are looked up by the SCA engine (OSV.dev). Findings are SCA vulnerabilities (sc_vuln / sc_infection) and open in the SCA vulnerability view. A lookup that cannot be completed is reported as not assessed.' },
    { step: 'Map to compliance frameworks', detail: 'Findings carry controls of the Kubernetes Pod Security Standards, NIST SP 800-53, PCI DSS, ISO/IEC 27001, SOC 2 and others.' },
    { step: 'Compare with the previous scan', detail: 'The Diffs tab lists findings that are new, still present or fixed since the previous report of the same cluster, in the namespaces scanned both times.' },
  ],
  limitations: [
    'The tool sees API objects, not what runs inside containers: it does not scan images or the packages inside them (use ubel-docker) nor the operating-system packages of the nodes (use ubel-vm --root <mount> --host-proc as a DaemonSet), and it does not inspect application behaviour. It does check the component versions the cluster reports (API server, kubelet, container runtime, kube-system add-ons) against OSV.dev through the SCA engine.',
    'Policy engines (Kyverno, OPA Gatekeeper, ValidatingAdmissionPolicy) and CNI-level policies (Cilium, Calico) are not evaluated; a missing Kubernetes object may be compensated by them.',
    'Control-plane flag checks only work on clusters whose control plane runs as static pods in kube-system (for example kubeadm). Managed services (EKS, GKE, AKS) do not expose them; their control plane is assessed through the provider API instead (needs read permission on the cluster resource).',
    'No external program is ever executed. The EKS, GKE and AKS login helpers are reproduced in-process; helpers that need a browser, a prompt or a cloud CLI (aws sso, gcloud, kubelogin devicecode / azurecli) are not supported: use a token or client certificate.',
  ],
  glossary: [
    { term: 'RBAC', meaning: 'Role-based access control: which identities may perform which actions on which Kubernetes objects.' },
    { term: 'Pod Security Standards', meaning: 'The Kubernetes definition of privileged, baseline and restricted pod settings, enforced by Pod Security Admission.' },
    { term: 'NetworkPolicy', meaning: 'A Kubernetes object that limits which pods may talk to each other; without one, all pod traffic is allowed.' },
    { term: 'Namespace', meaning: 'A logical partition of a cluster used to separate teams, applications and permissions.' },
  ],
  areas: {
    workload: { label: 'Workloads', plain: 'How pods and containers are configured: privileges, host access, capabilities, images, secrets and resource limits.', owner: 'Application / platform engineering' },
    rbac: { label: 'RBAC & service accounts', plain: 'Who is allowed to do what in the cluster, including powerful roles and service-account tokens.', owner: 'Platform / security team' },
    network: { label: 'Network exposure', plain: 'How workloads are exposed (load balancers, node ports, ingress) and isolated from each other.', owner: 'Platform / network team' },
    namespace: { label: 'Namespaces', plain: 'Guardrails per namespace: Pod Security enforcement, quotas and limits.', owner: 'Platform engineering' },
    cluster: { label: 'Cluster & control plane', plain: 'API server, etcd and cluster-wide settings and version support.', owner: 'Platform / cluster operators' },
    components: { label: 'Cluster components', plain: 'The versions of the Kubernetes components the cluster reports (API server, kubelets, container runtime, kube-system add-ons), checked against known vulnerabilities by the SCA engine.', owner: 'Platform / cluster operators' },
    node: { label: 'Nodes', plain: 'The machines that run workloads: kubelet settings, versions and operating-system support.', owner: 'Platform / infrastructure team' },
  },
};
