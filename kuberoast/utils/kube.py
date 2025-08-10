from typing import Dict, Any, Optional, List
from kubernetes import client, config
from kubernetes.client import ApiException

def load_clients() -> Dict[str, Any]:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return {
        "core": client.CoreV1Api(),
        "apps": client.AppsV1Api(),
        "rbac": client.RbacAuthorizationV1Api(),
        "version": client.VersionApi(),
    }

def list_all_pods(core) -> List:
    pods = []
    cont = None
    while True:
        resp = core.list_pod_for_all_namespaces(limit=200, _continue=cont)
        pods.extend(resp.items or [])
        cont = resp.metadata._continue
        if not cont:
            break
    return pods

def list_all_namespaces(core) -> List:
    return (core.list_namespace().items or [])

def list_all_nodes(core) -> List:
    try:
        return core.list_node().items or []
    except ApiException as e:
        if e.status in (401,403):
            return []
        raise

def list_rbac(rbac):
    roles = rbac.list_role_for_all_namespaces().items or []
    croles = rbac.list_cluster_role().items or []
    rbs = rbac.list_role_binding_for_all_namespaces().items or []
    crbs = rbac.list_cluster_role_binding().items or []
    return roles, croles, rbs, crbs

def list_all_secrets(core) -> List:
    try:
        return core.list_secret_for_all_namespaces().items or []
    except ApiException as e:
        if e.status in (401,403):
            return []
        raise
