"""Offline manifest scanning — load YAML/JSON Kubernetes manifests from disk.

Wraps raw dict manifests in attribute-style objects compatible with the
existing scanners (which expect Kubernetes Python client model objects).
"""
from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kuberoast")

try:
    import yaml  # PyYAML
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class ManifestObject:
    """Recursive attribute-style wrapper around a manifest dict.

    Translates kebab/camelCase keys to snake_case attribute access so that
    code written against kubernetes.client models works against raw YAML.
    """

    __slots__ = ("_data",)

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        self._data = data or {}

    def _wrap(self, value: Any) -> Any:
        if isinstance(value, dict):
            return ManifestObject(value)
        if isinstance(value, list):
            return [self._wrap(v) for v in value]
        return value

    def __getattr__(self, item: str) -> Any:
        if item.startswith("_"):
            raise AttributeError(item)
        # Direct match
        if item in self._data:
            return self._wrap(self._data[item])
        # Special-cased acronyms (K8s API doesn't use simple camelCase consistently)
        alias = _SPECIAL_ALIASES.get(item)
        if alias and alias in self._data:
            return self._wrap(self._data[alias])
        # snake_case -> camelCase mapping
        camel = _snake_to_camel(item)
        if camel in self._data:
            return self._wrap(self._data[camel])
        # Return None for missing attributes — matches kubernetes.client model
        # behavior where unset fields are exposed as None rather than raising.
        # Note: this means getattr(obj, "x", default) returns None, not default,
        # but the existing scanners normalize via `or default` patterns.
        return None

    def __getitem__(self, item: str) -> Any:
        return self._wrap(self._data.get(item))

    def get(self, item: str, default: Any = None) -> Any:
        return self._wrap(self._data.get(item, default))

    def __bool__(self) -> bool:
        return bool(self._data)

    def __repr__(self) -> str:
        kind = self._data.get("kind", "Manifest")
        name = self._data.get("metadata", {}).get("name", "?")
        return f"<{kind} {name}>"


_SPECIAL_ALIASES: Dict[str, str] = {
    "host_pid": "hostPID",
    "host_ipc": "hostIPC",
    "external_i_ps": "externalIPs",
    "external_ips": "externalIPs",
    "load_balancer_source_ranges": "loadBalancerSourceRanges",
    "automount_service_account_token": "automountServiceAccountToken",
    "service_account_name": "serviceAccountName",
    "host_network": "hostNetwork",
    "init_containers": "initContainers",
    "ephemeral_containers": "ephemeralContainers",
    "security_context": "securityContext",
    "run_as_user": "runAsUser",
    "run_as_non_root": "runAsNonRoot",
    "allow_privilege_escalation": "allowPrivilegeEscalation",
    "read_only_root_filesystem": "readOnlyRootFilesystem",
    "seccomp_profile": "seccompProfile",
    "host_path": "hostPath",
    "role_ref": "roleRef",
    "role_kind": "roleKind",
    "role_name": "roleName",
    "api_groups": "apiGroups",
    "api_group": "apiGroup",
    "secret_name": "secretName",
    "subjects": "subjects",
}


def _snake_to_camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def _wrap_pod(doc: dict) -> ManifestObject:
    """Pod-shaped wrapper: ensures spec.containers/init_containers/ephemeral_containers exist as lists."""
    spec = doc.get("spec", {}) or {}
    spec.setdefault("containers", [])
    spec.setdefault("initContainers", [])
    spec.setdefault("ephemeralContainers", [])
    spec.setdefault("volumes", [])
    doc["spec"] = spec
    return ManifestObject(doc)


def _wrap_workload_template(doc: dict) -> Optional[ManifestObject]:
    """Extract pod template from Deployment/StatefulSet/DaemonSet/Job/CronJob/ReplicaSet."""
    kind = doc.get("kind", "")
    spec = doc.get("spec", {}) or {}
    template: Optional[Dict[str, Any]] = None

    if kind == "CronJob":
        template = (
            spec.get("jobTemplate", {})
            .get("spec", {})
            .get("template")
        )
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet", "ReplicationController"}:
        template = spec.get("template")

    if not template:
        return None

    pod_doc = {
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {
            "name": (template.get("metadata", {}).get("name")
                     or f"{doc.get('metadata', {}).get('name', 'unknown')}-template"),
            "namespace": doc.get("metadata", {}).get("namespace", "default"),
            "labels": template.get("metadata", {}).get("labels", {}),
            "annotations": template.get("metadata", {}).get("annotations", {}),
        },
        "spec": template.get("spec", {}) or {},
    }
    return _wrap_pod(pod_doc)


def _iter_manifest_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return
    for root, _, files in os.walk(path):
        for fn in files:
            if fn.lower().endswith((".yaml", ".yml", ".json")):
                yield Path(root) / fn


def _parse_file(path: Path) -> List[dict]:
    """Parse a YAML or JSON manifest file. Returns list of documents."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse %s: %s", path, e)
            return []
        return [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])

    if not HAS_YAML:
        logger.warning("PyYAML not installed; skipping %s. Install with `pip install pyyaml`.", path)
        return []
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as e:
        logger.warning("Failed to parse %s: %s", path, e)
        return []
    return [d for d in docs if isinstance(d, dict)]


def load_manifests(path: str) -> Dict[str, list]:
    """Load Kubernetes manifests from a file or directory.

    Returns a dict mapping resource type to list of wrapped objects:
        {
          "pods": [...],
          "namespaces": [...],
          "roles": [...],
          ...
        }
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Manifest path not found: {path}")

    out: Dict[str, list] = {
        "pods": [],
        "namespaces": [],
        "roles": [],
        "cluster_roles": [],
        "role_bindings": [],
        "cluster_role_bindings": [],
        "secrets": [],
        "services": [],
        "ingresses": [],
        "crds": [],
    }

    workload_kinds = {
        "Deployment", "StatefulSet", "DaemonSet", "Job",
        "CronJob", "ReplicaSet", "ReplicationController",
    }

    for fp in _iter_manifest_files(p):
        for doc in _parse_file(fp):
            kind = doc.get("kind")
            if not kind:
                continue
            if kind == "Pod":
                out["pods"].append(_wrap_pod(doc))
            elif kind in workload_kinds:
                wrapped = _wrap_workload_template(doc)
                if wrapped:
                    out["pods"].append(wrapped)
            elif kind == "Namespace":
                out["namespaces"].append(ManifestObject(doc))
            elif kind == "Role":
                out["roles"].append(ManifestObject(_normalize_rbac(doc)))
            elif kind == "ClusterRole":
                out["cluster_roles"].append(ManifestObject(_normalize_rbac(doc)))
            elif kind == "RoleBinding":
                out["role_bindings"].append(ManifestObject(_normalize_binding(doc)))
            elif kind == "ClusterRoleBinding":
                out["cluster_role_bindings"].append(ManifestObject(_normalize_binding(doc)))
            elif kind == "Secret":
                out["secrets"].append(ManifestObject(doc))
            elif kind == "Service":
                out["services"].append(ManifestObject(doc))
            elif kind == "Ingress":
                out["ingresses"].append(ManifestObject(doc))
            elif kind == "CustomResourceDefinition":
                out["crds"].append(ManifestObject(doc))

    return out


def _normalize_rbac(doc: dict) -> dict:
    """Ensure RBAC role rules use snake_case-friendly keys."""
    rules = doc.get("rules") or []
    for r in rules:
        if "apiGroups" in r and "api_groups" not in r:
            r["api_groups"] = r["apiGroups"]
    doc["rules"] = rules
    return doc


def _normalize_binding(doc: dict) -> dict:
    """Map roleRef -> role_ref attribute access for bindings."""
    role_ref = doc.get("roleRef") or doc.get("role_ref") or {}
    doc["roleRef"] = role_ref
    doc["role_ref"] = role_ref
    return doc
