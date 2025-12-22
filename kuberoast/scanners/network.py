from typing import List
from ..utils.findings import Finding

def scan_services(services) -> List[Finding]:
    """Scan Kubernetes Services for network exposure risks."""
    findings: List[Finding] = []

    for svc in services:
        ns = svc.metadata.namespace
        name = svc.metadata.name
        spec = svc.spec

        if not spec:
            continue

        svc_type = getattr(spec, "type", "ClusterIP")

        # NodePort exposes service on all nodes
        if svc_type == "NodePort":
            findings.append(Finding(
                id="NET-NODEPORT",
                title="Service exposed via NodePort",
                description=f"Service {name} is exposed via NodePort, accessible on all cluster nodes.",
                severity="medium",
                category="Network",
                namespace=ns,
                resource=f"service/{name}",
                remediation="Use LoadBalancer with source ranges or Ingress instead. If NodePort is required, restrict access via NetworkPolicies and firewall rules.",
                references=["https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport"]
            ))

        # LoadBalancer without source ranges
        if svc_type == "LoadBalancer":
            source_ranges = getattr(spec, "load_balancer_source_ranges", None)
            if not source_ranges or len(source_ranges) == 0:
                findings.append(Finding(
                    id="NET-LB-OPEN",
                    title="LoadBalancer without source IP restrictions",
                    description=f"Service {name} is a LoadBalancer without loadBalancerSourceRanges, exposing it to the internet.",
                    severity="high",
                    category="Network",
                    namespace=ns,
                    resource=f"service/{name}",
                    remediation="Specify loadBalancerSourceRanges to restrict access to known IP ranges.",
                    references=["https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer"]
                ))

        # External IPs
        external_ips = getattr(spec, "external_i_ps", None) or getattr(spec, "external_ips", None)
        if external_ips and len(external_ips) > 0:
            findings.append(Finding(
                id="NET-EXTERNAL-IP",
                title="Service with externalIPs",
                description=f"Service {name} uses externalIPs {external_ips}, which can bypass firewalls and expose services.",
                severity="high",
                category="Network",
                namespace=ns,
                resource=f"service/{name}",
                remediation="Remove externalIPs and use LoadBalancer or Ingress with proper controls instead.",
                references=["https://kubernetes.io/docs/concepts/services-networking/service/#external-ips"]
            ))

    return findings


def scan_ingresses(ingresses) -> List[Finding]:
    """Scan Kubernetes Ingresses for security issues."""
    findings: List[Finding] = []

    for ing in ingresses:
        ns = ing.metadata.namespace
        name = ing.metadata.name
        spec = ing.spec

        if not spec:
            continue

        # Check for TLS configuration
        tls_configs = getattr(spec, "tls", None)
        has_tls = bool(tls_configs and len(tls_configs) > 0)

        if not has_tls:
            findings.append(Finding(
                id="NET-INGRESS-NO-TLS",
                title="Ingress without TLS",
                description=f"Ingress {name} is not configured with TLS, exposing traffic in plaintext.",
                severity="high",
                category="Network",
                namespace=ns,
                resource=f"ingress/{name}",
                remediation="Configure TLS for the Ingress with valid certificates. Use cert-manager for automated certificate management.",
                references=["https://kubernetes.io/docs/concepts/services-networking/ingress/#tls"]
            ))

        # Check for wildcard hosts
        rules = getattr(spec, "rules", []) or []
        for rule in rules:
            host = getattr(rule, "host", None)
            if host and host.startswith("*"):
                findings.append(Finding(
                    id="NET-INGRESS-WILDCARD",
                    title="Ingress with wildcard host",
                    description=f"Ingress {name} uses wildcard host '{host}', which may expose unintended subdomains.",
                    severity="medium",
                    category="Network",
                    namespace=ns,
                    resource=f"ingress/{name}",
                    remediation="Use specific hostnames instead of wildcards where possible. If wildcards are needed, ensure proper authentication.",
                    references=["https://kubernetes.io/docs/concepts/services-networking/ingress/"]
                ))

    return findings
