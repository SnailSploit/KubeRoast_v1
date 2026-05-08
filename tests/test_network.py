from types import SimpleNamespace

from kuberoast.scanners.network import scan_ingresses, scan_services
from tests.conftest import make_ingress, make_service


def test_nodeport_flagged():
    svc = make_service(svc_type="NodePort")
    findings = scan_services([svc])
    ids = {f.id for f in findings}
    assert "NET-NODEPORT" in ids


def test_clusterip_not_flagged():
    svc = make_service(svc_type="ClusterIP")
    findings = scan_services([svc])
    ids = {f.id for f in findings}
    assert "NET-NODEPORT" not in ids
    assert "NET-LB-OPEN" not in ids


def test_loadbalancer_without_source_ranges_flagged():
    svc = make_service(svc_type="LoadBalancer")
    findings = scan_services([svc])
    ids = {f.id for f in findings}
    assert "NET-LB-OPEN" in ids


def test_loadbalancer_with_source_ranges_not_flagged():
    svc = make_service(svc_type="LoadBalancer", load_balancer_source_ranges=["10.0.0.0/8"])
    findings = scan_services([svc])
    ids = {f.id for f in findings}
    assert "NET-LB-OPEN" not in ids


def test_ingress_without_tls_flagged():
    ing = make_ingress()
    findings = scan_ingresses([ing])
    ids = {f.id for f in findings}
    assert "NET-INGRESS-NO-TLS" in ids


def test_ingress_with_tls_not_flagged():
    ing = make_ingress(tls=[SimpleNamespace(hosts=["example.com"], secret_name="tls-secret")])
    findings = scan_ingresses([ing])
    ids = {f.id for f in findings}
    assert "NET-INGRESS-NO-TLS" not in ids


def test_wildcard_host_flagged():
    rule = SimpleNamespace(host="*.example.com", http=None)
    ing = make_ingress(rules=[rule])
    findings = scan_ingresses([ing])
    ids = {f.id for f in findings}
    assert "NET-INGRESS-WILDCARD" in ids
