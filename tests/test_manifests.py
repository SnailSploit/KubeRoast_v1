import textwrap
from pathlib import Path

import pytest

from kuberoast.scanners.network import scan_ingresses, scan_services
from kuberoast.scanners.pods import scan_pod_security
from kuberoast.scanners.rbac import scan_rbac
from kuberoast.utils.manifests import ManifestObject, load_manifests


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


def test_load_pod_yaml(tmp_path: Path):
    _write(
        tmp_path,
        "pod.yaml",
        """
        apiVersion: v1
        kind: Pod
        metadata:
          name: insecure-pod
          namespace: default
        spec:
          hostNetwork: true
          containers:
            - name: app
              image: nginx
              securityContext:
                privileged: true
                runAsUser: 0
        """,
    )
    objects = load_manifests(str(tmp_path))
    assert len(objects["pods"]) == 1
    pod = objects["pods"][0]
    assert pod.metadata.name == "insecure-pod"
    assert pod.spec.host_network is True
    assert pod.spec.containers[0].security_context.privileged is True


def test_pod_scanner_works_against_manifest_object(tmp_path: Path):
    _write(
        tmp_path,
        "pod.yaml",
        """
        apiVersion: v1
        kind: Pod
        metadata:
          name: bad
          namespace: default
        spec:
          hostNetwork: true
          containers:
            - name: c
              image: nginx
              securityContext:
                privileged: true
                runAsUser: 0
                allowPrivilegeEscalation: true
                capabilities:
                  add: [SYS_ADMIN]
        """,
    )
    objects = load_manifests(str(tmp_path))
    pod = objects["pods"][0]
    findings = scan_pod_security(pod)
    ids = {f.id for f in findings}
    assert "POD-PRIV" in ids
    assert "POD-ROOT" in ids
    assert "POD-PE" in ids
    assert "POD-HOSTNS" in ids
    assert "POD-CAPS" in ids


def test_load_deployment_extracts_pod_template(tmp_path: Path):
    _write(
        tmp_path,
        "deploy.yaml",
        """
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: web
          namespace: default
        spec:
          replicas: 1
          selector: {matchLabels: {app: web}}
          template:
            metadata:
              labels: {app: web}
            spec:
              containers:
                - name: web
                  image: nginx
                  securityContext:
                    privileged: true
        """,
    )
    objects = load_manifests(str(tmp_path))
    assert len(objects["pods"]) == 1
    findings = scan_pod_security(objects["pods"][0])
    assert any(f.id == "POD-PRIV" for f in findings)


def test_load_cronjob_extracts_pod_template(tmp_path: Path):
    _write(
        tmp_path,
        "cron.yaml",
        """
        apiVersion: batch/v1
        kind: CronJob
        metadata: {name: backup, namespace: default}
        spec:
          schedule: "0 0 * * *"
          jobTemplate:
            spec:
              template:
                spec:
                  containers:
                    - name: c
                      image: busybox
                      securityContext:
                        runAsUser: 0
                  restartPolicy: OnFailure
        """,
    )
    objects = load_manifests(str(tmp_path))
    assert len(objects["pods"]) == 1
    ids = {f.id for f in scan_pod_security(objects["pods"][0])}
    assert "POD-ROOT" in ids


def test_load_rbac_resources(tmp_path: Path):
    _write(
        tmp_path,
        "rbac.yaml",
        """
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        metadata: {name: too-broad}
        rules:
          - apiGroups: ["*"]
            resources: ["*"]
            verbs: ["*"]
        ---
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRoleBinding
        metadata: {name: anon-admin}
        subjects:
          - kind: User
            name: system:anonymous
            apiGroup: rbac.authorization.k8s.io
        roleRef:
          kind: ClusterRole
          name: cluster-admin
          apiGroup: rbac.authorization.k8s.io
        """,
    )
    objects = load_manifests(str(tmp_path))
    findings = scan_rbac(
        objects["roles"],
        objects["cluster_roles"],
        objects["role_bindings"],
        objects["cluster_role_bindings"],
    )
    ids = {f.id for f in findings}
    assert "RBAC-WILDCARD" in ids
    assert "RBAC-ANON" in ids
    assert "RBAC-CLUSTER-ADMIN" in ids


def test_load_service_loadbalancer(tmp_path: Path):
    _write(
        tmp_path,
        "svc.yaml",
        """
        apiVersion: v1
        kind: Service
        metadata: {name: web, namespace: default}
        spec:
          type: LoadBalancer
          ports: [{port: 80}]
        """,
    )
    objects = load_manifests(str(tmp_path))
    findings = scan_services(objects["services"])
    assert any(f.id == "NET-LB-OPEN" for f in findings)


def test_load_ingress_no_tls(tmp_path: Path):
    _write(
        tmp_path,
        "ing.yaml",
        """
        apiVersion: networking.k8s.io/v1
        kind: Ingress
        metadata: {name: app, namespace: default}
        spec:
          rules:
            - host: app.example.com
              http:
                paths:
                  - path: /
                    pathType: Prefix
                    backend: {service: {name: web, port: {number: 80}}}
        """,
    )
    objects = load_manifests(str(tmp_path))
    findings = scan_ingresses(objects["ingresses"])
    assert any(f.id == "NET-INGRESS-NO-TLS" for f in findings)


def test_load_json_manifest(tmp_path: Path):
    _write(
        tmp_path,
        "pod.json",
        """
        {
          "apiVersion": "v1",
          "kind": "Pod",
          "metadata": {"name": "j", "namespace": "default"},
          "spec": {
            "containers": [{"name": "c", "image": "x", "securityContext": {"privileged": true}}]
          }
        }
        """,
    )
    objects = load_manifests(str(tmp_path))
    assert len(objects["pods"]) == 1


def test_missing_path_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_manifests(str(tmp_path / "does-not-exist"))


def test_skips_non_kube_kinds(tmp_path: Path):
    _write(
        tmp_path,
        "kustomize.yaml",
        """
        apiVersion: kustomize.config.k8s.io/v1beta1
        kind: Kustomization
        resources:
          - pod.yaml
        """,
    )
    objects = load_manifests(str(tmp_path))
    assert objects["pods"] == []


def test_manifest_object_falls_back_to_none():
    obj = ManifestObject({"name": "x"})
    assert obj.name == "x"
    assert obj.missing is None
