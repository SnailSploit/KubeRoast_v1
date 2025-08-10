from typing import List, Dict, Set, Tuple, DefaultDict
from collections import defaultdict
from ..utils.findings import Finding

def _principal_id(kind: str, name: str, namespace: str = None) -> str:
    if kind == "ServiceAccount" and namespace:
        return f"sa:{namespace}:{name}"
    return f"{kind.lower()}:{name}"

def analyze_attack_paths(roles, croles, rbs, crbs, pods) -> List[Finding]:
    """
    Minimal viable 'attack graph' for RBAC-based privilege escalation:
      - For each principal bound via (C)RBs to (Cluster)Roles, aggregate verbs/resources
      - Flag principals that can:
          * bind or escalate or impersonate
          * create rolebindings/clusterrolebindings
          * create clusterroles/roles
          * create pods and exec into them
          * read secrets
      - Link ServiceAccounts to pods that use them
    """
    findings: List[Finding] = []

    # Build role -> rule set
    role_rules: Dict[str, List] = {}
    for r in roles:
        role_rules[f"Role/{r.metadata.namespace}/{r.metadata.name}"] = list(r.rules or [])
    for cr in croles:
        role_rules[f"ClusterRole/{cr.metadata.name}"] = list(cr.rules or [])

    # Subject -> roles mapping via bindings
    principal_roles: DefaultDict[str, Set[str]] = defaultdict(set)

    def add_binding(b, is_crb=False):
        role_ref = b.role_ref
        if is_crb:
            role_key = f"ClusterRole/{role_ref.name}" if role_ref.kind == "ClusterRole" else f"Role/{b.metadata.namespace}/{role_ref.name}"
        else:
            # RoleBinding can also reference a ClusterRole
            role_key = f"{role_ref.kind}/{b.metadata.namespace}/{role_ref.name}" if role_ref.kind == "Role" else f"ClusterRole/{role_ref.name}"
        for s in (b.subjects or []):
            ns = getattr(s, "namespace", None)
            pid = _principal_id(s.kind, s.name, ns)
            principal_roles[pid].add(role_key)

    for b in rbs:
        add_binding(b, is_crb=False)
    for b in crbs:
        add_binding(b, is_crb=True)

    # Aggregate permissions per principal
    principal_perms: Dict[str, Set[Tuple[str,str]]] = defaultdict(set)
    for p, rset in principal_roles.items():
        for rk in rset:
            for rule in role_rules.get(rk, []):
                verbs = set(rule.verbs or [])
                resources = set(rule.resources or [])
                for v in verbs:
                    for res in resources:
                        principal_perms[p].add((v, res))

    # Map pods -> service accounts
    sa_to_pods: DefaultDict[str, Set[str]] = defaultdict(set)
    for pod in pods:
        ns = pod.metadata.namespace
        pname = pod.metadata.name
        sa = (pod.spec.service_account_name or "default") if pod.spec else "default"
        sa_to_pods[f"sa:{ns}:{sa}"].add(f"{ns}/{pname}")

    # Heuristics for escalation potential
    def has_perm(p: str, verb: str, resource: str) -> bool:
        perms = principal_perms.get(p, set())
        return (verb, resource) in perms or (verb, "*") in perms or ("*", resource) in perms or ("*", "*") in perms

    for principal in principal_perms:
        risky = []
        if has_perm(principal, "bind", "clusterrolebindings") or has_perm(principal, "bind", "rolebindings"):
            risky.append("can bind new rolebindings")
        if has_perm(principal, "escalate", "clusterroles") or has_perm(principal, "escalate", "roles"):
            risky.append("can escalate roles")
        if has_perm(principal, "impersonate", "users") or has_perm(principal, "impersonate", "serviceaccounts") or has_perm(principal, "impersonate", "groups"):
            risky.append("can impersonate identities")
        if has_perm(principal, "create", "pods") and (has_perm(principal, "create", "secrets") or has_perm(principal, "get", "secrets") or has_perm(principal, "list", "secrets")):
            risky.append("can create pods and read/modify secrets")
        if has_perm(principal, "create", "clusterrolebindings") or has_perm(principal, "create", "rolebindings"):
            risky.append("can create role bindings")
        if has_perm(principal, "create", "clusterroles") or has_perm(principal, "create", "roles"):
            risky.append("can create roles")
        if has_perm(principal, "create", "pods/exec") or has_perm(principal, "create", "pods/attach") or has_perm(principal, "get", "pods/exec"):
            risky.append("can exec/attach to pods")

        if risky:
            pods_using = sorted(sa_to_pods.get(principal, []))
            findings.append(Finding(
                id="AP-RBAC-ESC",
                title="RBAC permissions enable potential privilege escalation",
                description=f"Principal '{principal}' has risky permissions: {', '.join(risky)}.",
                severity="critical", category="AttackPath",
                resource="; ".join(pods_using) if pods_using else None,
                remediation="Remove escalate/bind/impersonate, split duties, and restrict create on RBAC and pods.",
                references=[
                    "https://raesene.github.io/blog/2021/01/16/Getting-Into-A-Bind-with-Kubernetes/",
                    "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
                ]
            ))

    return findings
