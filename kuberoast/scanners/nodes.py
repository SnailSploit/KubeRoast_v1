import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional
from ..utils.findings import Finding

logger = logging.getLogger("kuberoast")


def _is_open(ip: str, port: int, timeout: float = 1.5) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def _probe_node(node_name: str, ip: str) -> List[Finding]:
    """Probe a single node IP for kubelet ports."""
    findings: List[Finding] = []
    if _is_open(ip, 10255):
        findings.append(Finding(
            id="NODE-KUBELET-RO",
            title="Kubelet read-only port 10255 reachable",
            description=f"Node {node_name} at {ip} exposes kubelet read-only/insecure endpoint.",
            severity="critical", category="Node",
            resource=f"node/{node_name}",
            remediation="Disable read-only port and secure kubelet authentication and authorization.",
            references=["https://www.cisa.gov/news-events/alerts/2022/03/15/updated-kubernetes-hardening-guide"]
        ))
    if _is_open(ip, 10250):
        findings.append(Finding(
            id="NODE-KUBELET-API",
            title="Kubelet API port 10250 reachable",
            description=f"Node {node_name} at {ip} exposes kubelet API; ensure TLS and authz are enforced.",
            severity="medium", category="Node",
            resource=f"node/{node_name}",
            remediation="Require client cert authN and webhook/ABAC/RBAC authZ for kubelet; restrict network access.",
            references=["https://www.cisa.gov/news-events/alerts/2022/03/15/updated-kubernetes-hardening-guide"]
        ))
    return findings


def scan_nodes(nodes, max_workers: int = 10) -> List[Finding]:
    findings: List[Finding] = []
    tasks: List[Tuple[str, str]] = []

    for n in nodes:
        addrs = getattr(n.status, "addresses", []) or []
        ips = [a.address for a in addrs if a.type in ("InternalIP", "ExternalIP")]
        for ip in ips:
            tasks.append((n.metadata.name, ip))

    if not tasks:
        return findings

    with ThreadPoolExecutor(max_workers=min(max_workers, len(tasks))) as pool:
        futures = {pool.submit(_probe_node, name, ip): (name, ip) for name, ip in tasks}
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
            except Exception as e:
                name, ip = futures[future]
                logger.warning("Failed to probe node %s at %s: %s", name, ip, e)

    return findings
