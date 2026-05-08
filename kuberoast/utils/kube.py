import logging
from typing import Any, Dict, List, Optional

from kubernetes import client, config
from kubernetes.client import ApiException

logger = logging.getLogger("kuberoast")


def load_clients(kubeconfig: Optional[str] = None) -> Dict[str, Any]:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config(config_file=kubeconfig)
    return {
        "core": client.CoreV1Api(),
        "apps": client.AppsV1Api(),
        "rbac": client.RbacAuthorizationV1Api(),
        "networking": client.NetworkingV1Api(),
        "apiextensions": client.ApiextensionsV1Api(),
        "version": client.VersionApi(),
    }


def _paginate(api_call, **kwargs) -> List:
    """Generic paginated list helper for large clusters."""
    items = []
    cont = None
    while True:
        resp = api_call(limit=200, _continue=cont, **kwargs)
        items.extend(resp.items or [])
        cont = resp.metadata._continue
        if not cont:
            break
    return items


def list_all_pods(core, namespace: Optional[str] = None) -> List:
    if namespace:
        return _paginate(core.list_namespaced_pod, namespace=namespace)
    return _paginate(core.list_pod_for_all_namespaces)


def list_all_namespaces(core) -> List:
    return core.list_namespace().items or []


def list_all_nodes(core) -> List:
    try:
        return core.list_node().items or []
    except ApiException as e:
        if e.status in (401, 403):
            logger.warning("Insufficient permissions to list nodes (HTTP %d) — skipping node scan", e.status)
            return []
        raise


def list_rbac(rbac, namespace: Optional[str] = None):
    if namespace:
        roles = rbac.list_namespaced_role(namespace).items or []
        rbs = rbac.list_namespaced_role_binding(namespace).items or []
    else:
        roles = rbac.list_role_for_all_namespaces().items or []
        rbs = rbac.list_role_binding_for_all_namespaces().items or []
    croles = rbac.list_cluster_role().items or []
    crbs = rbac.list_cluster_role_binding().items or []
    return roles, croles, rbs, crbs


def list_all_secrets(core, namespace: Optional[str] = None) -> List:
    try:
        if namespace:
            return _paginate(core.list_namespaced_secret, namespace=namespace)
        return _paginate(core.list_secret_for_all_namespaces)
    except ApiException as e:
        if e.status in (401, 403):
            logger.warning("Insufficient permissions to list secrets (HTTP %d) — skipping secret scan", e.status)
            return []
        raise


def list_all_services(core, namespace: Optional[str] = None) -> List:
    try:
        if namespace:
            return _paginate(core.list_namespaced_service, namespace=namespace)
        return _paginate(core.list_service_for_all_namespaces)
    except ApiException as e:
        if e.status in (401, 403):
            logger.warning("Insufficient permissions to list services (HTTP %d) — skipping service scan", e.status)
            return []
        raise


def list_all_ingresses(networking, namespace: Optional[str] = None) -> List:
    try:
        if namespace:
            return _paginate(networking.list_namespaced_ingress, namespace=namespace)
        return _paginate(networking.list_ingress_for_all_namespaces)
    except ApiException as e:
        if e.status in (401, 403):
            logger.warning("Insufficient permissions to list ingresses (HTTP %d) — skipping ingress scan", e.status)
            return []
        raise


def list_all_crds(apiext) -> List:
    try:
        return apiext.list_custom_resource_definition().items or []
    except ApiException as e:
        if e.status in (401, 403):
            logger.warning("Insufficient permissions to list CRDs (HTTP %d) — skipping policy engine scan", e.status)
            return []
        raise
