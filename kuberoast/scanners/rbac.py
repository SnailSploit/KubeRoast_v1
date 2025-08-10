from typing import List, Dict, Set, Tuple, DefaultDict
from collections import defaultdict
from ..utils.findings import Finding

SUS_VERBS_ESCALATE = {"escalate", "bind", "impersonate"}
SUS_RESOURCES = {"clusterroles", "clusterrolebindings", "roles", "rolebindings", "secrets", "pods", "pods/exec", "pods/attach"}

def _rule_sets(rule) -> Tuple[Set[str], Set[str]]:
    verbs = set(rule.verbs or [])
    resources = set(rule.resources or [])
    # include subresources via resourceNames? handled elsewhere; we focus on wildcards and sensitive
    return verbs, resources

def scan_rbac(roles, croles, rbs, crbs) -> List[Finding]:
    findings: List[Finding] = []

    # 1) Wildcards and cluster-admin grants in bindings
    def bind_check(binding, is_cluster=False):
        role_ref = binding.role_ref
        role_name = f"{role_ref.kind}/{role_ref.name}"
        bname = f"{'CRB' if is_cluster else 'RB'}/{binding.metadata.name}"
        for s in (binding.subjects or []):
            subj = f"{s.kind}:{s.namespace+'/'+s.name if getattr(s,'namespace',None) else s.name}"
            if s.kind == "Group" and s.name in {"system:unauthenticated","system:authenticated","*"}:
                findings.append(Finding(
                    id="RBAC-BROAD-GROUP",
                    title="Broad group subject in binding",
                    description=f"{bname} binds broad group '{s.name}' to {role_name}.",
                    severity="high", category="RBAC",
                    remediation="Avoid broad groups; bind narrow groups or specific service accounts.",
                    references=[
                        "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
                    ]
                ))
            if s.kind == "User" and s.name in {"*","system:anonymous"}:
                findings.append(Finding(
                    id="RBAC-ANON",
                    title="Anonymous or wildcard user bound",
                    description=f"{bname} binds '{s.name}' to {role_name}.",
                    severity="critical", category="RBAC",
                    remediation="Remove wildcard/anonymous subjects from bindings.",
                    references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"]
                ))
        if role_ref.name == "cluster-admin":
            findings.append(Finding(
                id="RBAC-CLUSTER-ADMIN",
                title="cluster-admin granted via binding",
                description=f"{bname} grants cluster-admin.",
                severity="critical", category="RBAC",
                remediation="Replace cluster-admin with least privilege and scoped roles.",
                references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"]
            ))

    for b in rbs:
        bind_check(b, is_cluster=False)
    for b in crbs:
        bind_check(b, is_cluster=True)

    # 2) Wildcards in role rules; escalate/bind/impersonate verbs etc.
    def role_check(role, scope="Role"):
        for rule in (role.rules or []):
            verbs, resources = _rule_sets(rule)
            if "*" in verbs or "*" in resources:
                findings.append(Finding(
                    id="RBAC-WILDCARD",
                    title="Wildcard in RBAC rule",
                    description=f"{scope}/{role.metadata.name} contains wildcard verbs/resources.",
                    severity="high", category="RBAC",
                    remediation="Avoid '*' in verbs/resources; specify only what is needed.",
                    references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"]
                ))
            if SUS_VERBS_ESCALATE & verbs or (SUS_RESOURCES & resources):
                findings.append(Finding(
                    id="RBAC-SENSITIVE-VERB-RES",
                    title="Sensitive RBAC verbs/resources present",
                    description=f"{scope}/{role.metadata.name} has verbs {sorted(verbs & SUS_VERBS_ESCALATE)} or resources {sorted(resources & SUS_RESOURCES)}.",
                    severity="high", category="RBAC",
                    remediation="Audit principals bound to this role; split privileges and remove escalation paths.",
                    references=[
                        "https://raesene.github.io/blog/2021/01/16/Getting-Into-A-Bind-with-Kubernetes/"
                    ]
                ))

    for r in roles:
        role_check(r, "Role")
    for cr in croles:
        role_check(cr, "ClusterRole")

    return findings
