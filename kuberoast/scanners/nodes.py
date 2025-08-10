import socket
from typing import List
from ..utils.findings import Finding

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

def scan_nodes(nodes) -> List[Finding]:
    findings: List[Finding] = []
    for n in nodes:
        addrs = getattr(n.status, "addresses", []) or []
        ips = [a.address for a in addrs if a.type in ("InternalIP","ExternalIP")]
        for ip in ips:
            if _is_open(ip, 10255):
                findings.append(Finding(
                    id="NODE-KUBELET-RO",
                    title="Kubelet read-only port 10255 reachable",
                    description=f"Node {n.metadata.name} at {ip} exposes kubelet read-only/insecure endpoint.",
                    severity="critical", category="Node",
                    remediation="Disable read-only port and secure kubelet authentication and authorization.",
                    references=["https://www.cisa.gov/news-events/alerts/2022/03/15/updated-kubernetes-hardening-guide"]
                ))
            if _is_open(ip, 10250):
                findings.append(Finding(
                    id="NODE-KUBELET-API",
                    title="Kubelet API port 10250 reachable",
                    description=f"Node {n.metadata.name} at {ip} exposes kubelet API; ensure TLS and authz are enforced.",
                    severity="medium", category="Node",
                    remediation="Require client cert authN and webhook/ABAC/RBAC authZ for kubelet; restrict network access.",
                    references=["https://www.cisa.gov/news-events/alerts/2022/03/15/updated-kubernetes-hardening-guide"]
                ))
    return findings
