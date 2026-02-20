"""Shared test fixtures providing mock Kubernetes objects."""
import pytest
from types import SimpleNamespace


def make_metadata(name="test", namespace="default", labels=None, annotations=None):
    return SimpleNamespace(
        name=name,
        namespace=namespace,
        labels=labels or {},
        annotations=annotations or {},
    )


def make_container(name="app", privileged=False, run_as_user=None,
                   allow_privilege_escalation=None, read_only_root_filesystem=None,
                   caps_add=None, seccomp_profile=None, limits=None):
    capabilities = SimpleNamespace(add=caps_add or [], drop=[]) if caps_add else SimpleNamespace(add=[], drop=[])
    resources = SimpleNamespace(limits=limits, requests=None) if limits else SimpleNamespace(limits=None, requests=None)
    sc = SimpleNamespace(
        privileged=privileged,
        run_as_user=run_as_user,
        allow_privilege_escalation=allow_privilege_escalation,
        read_only_root_filesystem=read_only_root_filesystem,
        capabilities=capabilities,
        seccomp_profile=seccomp_profile,
    )
    return SimpleNamespace(name=name, security_context=sc, resources=resources)


def make_pod(name="test-pod", namespace="default", containers=None,
             host_network=False, host_pid=False, host_ipc=False,
             automount_service_account_token=None, volumes=None,
             service_account_name="default", annotations=None,
             pod_seccomp=None):
    if containers is None:
        containers = [make_container()]
    pod_sc = SimpleNamespace(seccomp_profile=pod_seccomp) if pod_seccomp else SimpleNamespace(seccomp_profile=None)
    spec = SimpleNamespace(
        containers=containers,
        init_containers=[],
        ephemeral_containers=[],
        host_network=host_network,
        host_pid=host_pid,
        host_ipc=host_ipc,
        automount_service_account_token=automount_service_account_token,
        volumes=volumes or [],
        service_account_name=service_account_name,
        security_context=pod_sc,
    )
    return SimpleNamespace(
        metadata=make_metadata(name=name, namespace=namespace, annotations=annotations),
        spec=spec,
    )


def make_namespace(name="default", labels=None):
    return SimpleNamespace(metadata=make_metadata(name=name, labels=labels))


def make_role(name="test-role", namespace="default", rules=None, kind="Role"):
    return SimpleNamespace(
        metadata=make_metadata(name=name, namespace=namespace),
        rules=rules or [],
    )


def make_rule(verbs=None, resources=None, api_groups=None):
    return SimpleNamespace(
        verbs=verbs or [],
        resources=resources or [],
        api_groups=api_groups or [""],
    )


def make_binding(name="test-binding", role_kind="Role", role_name="test-role",
                 subjects=None, namespace="default"):
    return SimpleNamespace(
        metadata=make_metadata(name=name, namespace=namespace),
        role_ref=SimpleNamespace(kind=role_kind, name=role_name, api_group="rbac.authorization.k8s.io"),
        subjects=subjects or [],
    )


def make_subject(kind="ServiceAccount", name="default", namespace="default"):
    return SimpleNamespace(kind=kind, name=name, namespace=namespace)


def make_secret(name="my-secret", namespace="default", secret_type="Opaque",
                data=None, annotations=None):
    return SimpleNamespace(
        metadata=make_metadata(name=name, namespace=namespace, annotations=annotations),
        type=secret_type,
        data=data or {},
    )


def make_service(name="my-svc", namespace="default", svc_type="ClusterIP",
                 load_balancer_source_ranges=None, external_ips=None):
    return SimpleNamespace(
        metadata=make_metadata(name=name, namespace=namespace),
        spec=SimpleNamespace(
            type=svc_type,
            load_balancer_source_ranges=load_balancer_source_ranges,
            external_i_ps=external_ips,
            external_ips=external_ips,
        ),
    )


def make_ingress(name="my-ing", namespace="default", tls=None, rules=None):
    return SimpleNamespace(
        metadata=make_metadata(name=name, namespace=namespace),
        spec=SimpleNamespace(tls=tls, rules=rules or []),
    )


def make_node(name="node-1", addresses=None):
    if addresses is None:
        addresses = [SimpleNamespace(type="InternalIP", address="10.0.0.1")]
    return SimpleNamespace(
        metadata=make_metadata(name=name),
        status=SimpleNamespace(addresses=addresses),
    )
