import base64, re
from typing import List
from ..utils.findings import Finding

SUSPICIOUS_SECRET_KEYS = re.compile(r"""
(password|passwd|pwd|token|apikey|api_key|secret|aws_?access|aws_?secret|ssh-?key|oauth|bearer)
""", re.I)

def scan_secrets(secrets) -> List[Finding]:
    findings: List[Finding] = []
    for s in secrets:
        data = getattr(s, "data", {}) or {}
        for key, val in data.items():
            try:
                decoded = base64.b64decode(val + "==").decode(errors="ignore")
            except Exception:
                decoded = ""
            if SUSPICIOUS_SECRET_KEYS.search(key) or SUSPICIOUS_SECRET_KEYS.search(decoded):
                findings.append(Finding(
                    id="SECRET-LEAKY",
                    title="Suspicious secret key/content",
                    description=f"Secret {s.metadata.name} key '{key}' resembles sensitive credentials.",
                    severity="medium", category="Secrets",
                    namespace=s.metadata.namespace, resource=f"secret/{s.metadata.name}",
                    remediation="Rotate this secret; avoid storing high-value long-lived credentials in Secrets (use external vaults).",
                    references=["https://kubernetes.io/docs/concepts/configuration/secret/"]
                ))
    return findings
