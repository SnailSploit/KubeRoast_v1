"""Property-based tests using Hypothesis.

These generate randomized manifests and verify scanner invariants:
  - The parser never crashes on well-formed but oddly-shaped manifests.
  - Scanners always return List[Finding] (or compatible) without raising.
  - Findings always carry stable ID, severity, and category fields.
  - Severity is always one of the allowed values.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from kuberoast.scanners.network import scan_ingresses, scan_services
from kuberoast.scanners.pods import scan_pod_security
from kuberoast.scanners.rbac import scan_rbac
from kuberoast.scanners.secrets import scan_secrets
from kuberoast.utils.findings import Finding
from kuberoast.utils.manifests import load_manifests

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

# A safe alphabet for K8s names: lowercase letters, digits, dashes
NAME = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=20).filter(
    lambda s: not s.startswith("-") and not s.endswith("-") and "--" not in s
)


def _container_strategy():
    return st.fixed_dictionaries(
        {
            "name": NAME,
            "image": st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789:./-", min_size=1, max_size=30),
        },
        optional={
            "securityContext": st.fixed_dictionaries(
                {},
                optional={
                    "privileged": st.booleans(),
                    "runAsUser": st.integers(min_value=0, max_value=65535),
                    "runAsNonRoot": st.booleans(),
                    "allowPrivilegeEscalation": st.booleans(),
                    "readOnlyRootFilesystem": st.booleans(),
                    "capabilities": st.fixed_dictionaries(
                        {},
                        optional={
                            "add": st.lists(
                                st.sampled_from([
                                    "SYS_ADMIN", "NET_ADMIN", "NET_BIND_SERVICE",
                                    "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH",
                                ]),
                                max_size=4,
                            ),
                            "drop": st.lists(
                                st.sampled_from(["ALL", "NET_RAW"]), max_size=2
                            ),
                        },
                    ),
                },
            ),
        },
    )


def _pod_strategy():
    return st.fixed_dictionaries(
        {
            "apiVersion": st.just("v1"),
            "kind": st.just("Pod"),
            "metadata": st.fixed_dictionaries(
                {"name": NAME},
                optional={"namespace": NAME, "labels": st.dictionaries(NAME, NAME, max_size=3)},
            ),
            "spec": st.fixed_dictionaries(
                {"containers": st.lists(_container_strategy(), min_size=1, max_size=3)},
                optional={
                    "hostNetwork": st.booleans(),
                    "hostPID": st.booleans(),
                    "hostIPC": st.booleans(),
                    "automountServiceAccountToken": st.booleans(),
                    "serviceAccountName": NAME,
                },
            ),
        }
    )


@given(_pod_strategy())
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_pod_scanner_never_crashes_on_random_pods(tmp_path_factory, pod):
    """The pod scanner should handle any well-formed pod without raising."""
    tmp_path = tmp_path_factory.mktemp("pods")
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(pod), encoding="utf-8")
    objects = load_manifests(str(tmp_path))
    findings = scan_pod_security(objects["pods"][0])
    for f in findings:
        assert isinstance(f, Finding)
        assert f.id
        assert f.severity in VALID_SEVERITIES
        assert f.category


@given(
    svc_type=st.sampled_from(["ClusterIP", "NodePort", "LoadBalancer", "ExternalName"]),
    name=NAME,
    has_source_ranges=st.booleans(),
    has_external_ips=st.booleans(),
)
@settings(max_examples=30)
def test_service_scanner_never_crashes(tmp_path_factory, svc_type, name, has_source_ranges, has_external_ips):
    tmp_path = tmp_path_factory.mktemp("svc")
    spec = {"type": svc_type, "ports": [{"port": 80}]}
    if has_source_ranges:
        spec["loadBalancerSourceRanges"] = ["10.0.0.0/8"]
    if has_external_ips:
        spec["externalIPs"] = ["1.2.3.4"]
    doc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }
    (tmp_path / "s.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    objects = load_manifests(str(tmp_path))
    findings = scan_services(objects["services"])
    for f in findings:
        assert f.severity in VALID_SEVERITIES


@given(
    name=NAME,
    has_tls=st.booleans(),
    host=st.one_of(NAME, st.just("*"), st.just("*.example.com")),
)
@settings(max_examples=30)
def test_ingress_scanner_never_crashes(tmp_path_factory, name, has_tls, host):
    tmp_path = tmp_path_factory.mktemp("ing")
    spec = {"rules": [{"host": host, "http": {"paths": [{"path": "/", "pathType": "Prefix"}]}}]}
    if has_tls:
        spec["tls"] = [{"hosts": [host], "secretName": "x"}]
    doc = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }
    (tmp_path / "i.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    objects = load_manifests(str(tmp_path))
    findings = scan_ingresses(objects["ingresses"])
    for f in findings:
        assert f.severity in VALID_SEVERITIES


@given(
    verbs=st.lists(
        st.sampled_from(["get", "list", "watch", "create", "update", "patch", "delete", "*", "escalate", "bind"]),
        min_size=1,
        max_size=5,
        unique=True,
    ),
    resources=st.lists(
        st.sampled_from(["pods", "secrets", "services", "configmaps", "*", "clusterroles", "rolebindings"]),
        min_size=1,
        max_size=5,
        unique=True,
    ),
    name=NAME,
)
@settings(max_examples=30)
def test_rbac_scanner_never_crashes_on_random_rules(tmp_path_factory, verbs, resources, name):
    tmp_path = tmp_path_factory.mktemp("rbac")
    doc = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": name},
        "rules": [{"apiGroups": [""], "resources": resources, "verbs": verbs}],
    }
    (tmp_path / "r.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    objects = load_manifests(str(tmp_path))
    findings = scan_rbac([], objects["cluster_roles"], [], [])
    for f in findings:
        assert f.severity in VALID_SEVERITIES
        assert f.category == "RBAC"


def test_parser_handles_garbage_yaml(tmp_path: Path):
    """Truly malformed YAML should warn-and-skip, not crash."""
    (tmp_path / "broken.yaml").write_text(":\n  - [\nthis is not yaml]: : :", encoding="utf-8")
    objects = load_manifests(str(tmp_path))
    assert objects["pods"] == []


def test_parser_skips_empty_files(tmp_path: Path):
    (tmp_path / "empty.yaml").write_text("", encoding="utf-8")
    (tmp_path / "comment.yaml").write_text("# just a comment\n", encoding="utf-8")
    objects = load_manifests(str(tmp_path))
    assert all(v == [] for v in objects.values())


def test_parser_handles_deeply_nested_pod(tmp_path: Path):
    """An ephemeralContainers + initContainers + containers manifest must work."""
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "complex"},
        "spec": {
            "initContainers": [{"name": "init", "image": "x"}],
            "containers": [{"name": "main", "image": "x", "securityContext": {"privileged": True}}],
            "ephemeralContainers": [{"name": "debug", "image": "x"}],
        },
    }
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    objects = load_manifests(str(tmp_path))
    findings = scan_pod_security(objects["pods"][0])
    assert any(f.id == "POD-PRIV" for f in findings)


@given(st.lists(_pod_strategy(), min_size=0, max_size=10))
@settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
def test_secrets_scanner_handles_arbitrary_pod_count(tmp_path_factory, pods):
    """Even with arbitrary numbers of unrelated pods, secret scanner returns []."""
    tmp_path = tmp_path_factory.mktemp("secrets")
    if pods:
        (tmp_path / "pods.yaml").write_text(
            "\n---\n".join(yaml.safe_dump(p) for p in pods), encoding="utf-8"
        )
    objects = load_manifests(str(tmp_path))
    findings = scan_secrets(objects["secrets"])
    assert findings == []
