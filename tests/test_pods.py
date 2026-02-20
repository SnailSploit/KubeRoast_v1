from kuberoast.scanners.pods import scan_pod_security
from tests.conftest import make_pod, make_container


def test_privileged_container_flagged():
    pod = make_pod(containers=[make_container(privileged=True)])
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-PRIV" in ids


def test_non_privileged_container_not_flagged():
    pod = make_pod(containers=[make_container(privileged=False)])
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-PRIV" not in ids


def test_root_user_flagged():
    pod = make_pod(containers=[make_container(run_as_user=0)])
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-ROOT" in ids


def test_allow_privilege_escalation_not_set_flagged():
    """When allow_privilege_escalation is None (unset), it defaults to true so should be flagged."""
    pod = make_pod(containers=[make_container(allow_privilege_escalation=None)])
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-PE" in ids


def test_allow_privilege_escalation_false_not_flagged():
    pod = make_pod(containers=[make_container(allow_privilege_escalation=False)])
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-PE" not in ids


def test_writable_rootfs_not_set_flagged():
    """When read_only_root_filesystem is None (unset), default is writable so should be flagged."""
    pod = make_pod(containers=[make_container(read_only_root_filesystem=None)])
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-RWFS" in ids


def test_readonly_rootfs_not_flagged():
    pod = make_pod(containers=[make_container(read_only_root_filesystem=True)])
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-RWFS" not in ids


def test_host_network_flagged():
    pod = make_pod(host_network=True)
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-HOSTNS" in ids


def test_dangerous_caps_flagged():
    pod = make_pod(containers=[make_container(caps_add=["SYS_ADMIN"])])
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-CAPS" in ids


def test_automount_token_disabled_not_flagged():
    pod = make_pod(automount_service_account_token=False)
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-SATOKEN" not in ids


def test_automount_token_default_flagged():
    pod = make_pod(automount_service_account_token=None)
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-SATOKEN" in ids
