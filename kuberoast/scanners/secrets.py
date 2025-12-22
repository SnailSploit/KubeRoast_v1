import base64, re, json
from typing import List
from ..utils.findings import Finding

SUSPICIOUS_SECRET_KEYS = re.compile(r"""
(password|passwd|pwd|token|apikey|api_key|secret|aws_?access|aws_?secret|ssh-?key|oauth|bearer|private.*key|credentials?)
""", re.I | re.X)

# Kubernetes service account tokens are expected, skip them
SYSTEM_SECRET_TYPES = {"kubernetes.io/service-account-token"}

def scan_secrets(secrets) -> List[Finding]:
    findings: List[Finding] = []

    for s in secrets:
        secret_type = getattr(s, "type", None)
        name = s.metadata.name
        ns = s.metadata.namespace

        # Skip service account tokens (expected system secrets)
        if secret_type in SYSTEM_SECRET_TYPES:
            continue

        # Check dockerconfigjson secrets for overly permissive access
        if secret_type == "kubernetes.io/dockerconfigjson":
            data = getattr(s, "data", {}) or {}
            dockerconfig_data = data.get(".dockerconfigjson", "")
            if dockerconfig_data:
                try:
                    decoded = base64.b64decode(dockerconfig_data).decode()
                    config = json.loads(decoded)
                    auths = config.get("auths", {})
                    # Check for registry credentials
                    for registry in auths:
                        if "docker.io" in registry or "index.docker.io" in registry:
                            findings.append(Finding(
                                id="SECRET-DOCKER-HUB",
                                title="Docker Hub credentials in secret",
                                description=f"Secret {name} contains Docker Hub credentials which may be overly permissive.",
                                severity="medium",
                                category="Secrets",
                                namespace=ns,
                                resource=f"secret/{name}",
                                remediation="Use imagePullSecrets scoped to specific namespaces. Consider using workload identity instead.",
                                references=["https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/"]
                            ))
                except Exception:
                    pass

        # Check for sensitive keys in Opaque secrets (most common)
        if secret_type == "Opaque" or not secret_type:
            data = getattr(s, "data", {}) or {}
            suspicious_keys = []

            for key, val in data.items():
                # Skip very short values (likely not real credentials)
                if not val or len(val) < 8:
                    continue

                try:
                    decoded = base64.b64decode(val + "==").decode(errors="ignore")
                except Exception:
                    decoded = ""

                # Only flag if key name matches (reduce false positives from content search)
                if SUSPICIOUS_SECRET_KEYS.search(key):
                    suspicious_keys.append(key)

            if suspicious_keys:
                findings.append(Finding(
                    id="SECRET-SENSITIVE",
                    title="Secret contains sensitive credential keys",
                    description=f"Secret {name} has suspicious keys: {', '.join(suspicious_keys)}.",
                    severity="medium",
                    category="Secrets",
                    namespace=ns,
                    resource=f"secret/{name}",
                    remediation="Rotate this secret regularly; consider external secret management (Vault, AWS Secrets Manager, etc.).",
                    references=["https://kubernetes.io/docs/concepts/configuration/secret/"]
                ))

        # Check for TLS secrets without proper annotations
        if secret_type == "kubernetes.io/tls":
            annotations = getattr(s.metadata, "annotations", {}) or {}
            if not any("cert-manager" in k for k in annotations.keys()):
                findings.append(Finding(
                    id="SECRET-TLS-MANUAL",
                    title="Manually managed TLS secret",
                    description=f"TLS secret {name} is not managed by cert-manager, requiring manual rotation.",
                    severity="low",
                    category="Secrets",
                    namespace=ns,
                    resource=f"secret/{name}",
                    remediation="Use cert-manager for automated certificate lifecycle management.",
                    references=["https://cert-manager.io/"]
                ))

    return findings
