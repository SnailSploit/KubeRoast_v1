from kuberoast.scanners.pss import scan_namespace_pss
from tests.conftest import make_namespace


def test_unlabeled_namespace_flagged():
    ns = make_namespace(name="production")
    findings = scan_namespace_pss([ns])
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_system_namespace_info_severity():
    ns = make_namespace(name="kube-system")
    findings = scan_namespace_pss([ns])
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_labeled_namespace_not_flagged():
    ns = make_namespace(
        name="secure",
        labels={"pod-security.kubernetes.io/enforce": "restricted"},
    )
    findings = scan_namespace_pss([ns])
    assert len(findings) == 0
