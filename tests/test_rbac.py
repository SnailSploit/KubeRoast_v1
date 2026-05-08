from kuberoast.scanners.rbac import scan_rbac
from tests.conftest import make_binding, make_role, make_rule, make_subject


def test_wildcard_verbs_flagged():
    role = make_role(rules=[make_rule(verbs=["*"], resources=["pods"])])
    findings = scan_rbac([role], [], [], [])
    ids = {f.id for f in findings}
    assert "RBAC-WILDCARD" in ids


def test_escalation_verb_flagged():
    role = make_role(rules=[make_rule(verbs=["escalate"], resources=["clusterroles"])])
    findings = scan_rbac([role], [], [], [])
    ids = {f.id for f in findings}
    assert "RBAC-ESCALATION-VERB" in ids


def test_read_only_sensitive_resources_not_flagged():
    """Reading secrets should not trigger the sensitive-write finding."""
    role = make_role(rules=[make_rule(verbs=["get", "list"], resources=["secrets"])])
    findings = scan_rbac([role], [], [], [])
    ids = {f.id for f in findings}
    assert "RBAC-SENSITIVE-WRITE" not in ids


def test_write_sensitive_resources_flagged():
    role = make_role(rules=[make_rule(verbs=["create", "delete"], resources=["secrets"])])
    findings = scan_rbac([role], [], [], [])
    ids = {f.id for f in findings}
    assert "RBAC-SENSITIVE-WRITE" in ids


def test_cluster_admin_binding_flagged():
    binding = make_binding(
        role_kind="ClusterRole", role_name="cluster-admin",
        subjects=[make_subject(kind="User", name="admin")]
    )
    findings = scan_rbac([], [], [], [binding])
    ids = {f.id for f in findings}
    assert "RBAC-CLUSTER-ADMIN" in ids


def test_anonymous_user_flagged():
    binding = make_binding(
        role_kind="ClusterRole", role_name="view",
        subjects=[make_subject(kind="User", name="system:anonymous")]
    )
    findings = scan_rbac([], [], [], [binding])
    ids = {f.id for f in findings}
    assert "RBAC-ANON" in ids


def test_broad_group_flagged():
    binding = make_binding(
        role_kind="ClusterRole", role_name="view",
        subjects=[make_subject(kind="Group", name="system:unauthenticated")]
    )
    findings = scan_rbac([], [], [], [binding])
    ids = {f.id for f in findings}
    assert "RBAC-BROAD-GROUP" in ids
