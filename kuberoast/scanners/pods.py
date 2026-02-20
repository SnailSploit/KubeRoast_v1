from typing import List, Set
from .shared import iter_containers
from ..utils.findings import Finding

DANGEROUS_CAPS: Set[str] = {
    "SYS_ADMIN","SYS_MODULE","SYS_PTRACE","NET_ADMIN","DAC_READ_SEARCH","SYS_RAWIO"
}

def scan_pod_security(pod) -> List[Finding]:
    findings: List[Finding] = []
    spec = pod.spec
    ns = pod.metadata.namespace
    pname = pod.metadata.name

    # host namespaces
    if getattr(spec, "host_network", False) or getattr(spec, "host_pid", False) or getattr(spec, "host_ipc", False):
        findings.append(Finding(
            id="POD-HOSTNS",
            title="Pod uses host namespaces",
            description="Pod has hostNetwork/hostPID/hostIPC enabled which can allow container-to-node or cross-pod attacks.",
            severity="high",
            category="Pod Security",
            namespace=ns,
            resource=f"pod/{pname}",
            remediation="Disable host namespaces unless strictly required. Prefer network policies and sidecars.",
            references=[
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
            ]
        ))

    # containers + initContainers
    for c, name in iter_containers(pod):
        sc = getattr(c, "security_context", None)
        privileged = bool(getattr(sc, "privileged", False)) if sc else False
        run_as_user = getattr(sc, "run_as_user", None) if sc else None
        allow_pe = getattr(sc, "allow_privilege_escalation", None) if sc else None
        read_only_rootfs = getattr(sc, "read_only_root_filesystem", None) if sc else None
        caps_add = set(getattr(getattr(sc, "capabilities", None), "add", []) or []) if sc else set()

        # Check seccomp profile
        seccomp_profile = getattr(sc, "seccomp_profile", None) if sc else None
        # Also check pod-level seccomp
        pod_sc = getattr(spec, "security_context", None)
        pod_seccomp = getattr(pod_sc, "seccomp_profile", None) if pod_sc else None

        # Check AppArmor annotations
        annotations = getattr(pod.metadata, "annotations", {}) or {}
        apparmor_key = f"container.apparmor.security.beta.kubernetes.io/{c.name}"
        apparmor_profile = annotations.get(apparmor_key, None)

        # Check resource limits
        resources = getattr(c, "resources", None)
        limits = getattr(resources, "limits", None) if resources else None

        if privileged:
            findings.append(Finding(
                id="POD-PRIV",
                title="Privileged container",
                description="Container runs in privileged mode, granting broad access to the host kernel.",
                severity="critical",
                category="Pod Security",
                namespace=ns,
                resource=f"pod/{pname}::{name}",
                remediation="Remove privileged=true. Grant narrow capabilities only if needed.",
                references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
            ))

        if run_as_user == 0:
            findings.append(Finding(
                id="POD-ROOT",
                title="Container runs as root (runAsUser=0)",
                description="Running as root increases blast radius if the container is compromised.",
                severity="high",
                category="Pod Security",
                namespace=ns,
                resource=f"pod/{pname}::{name}",
                remediation="Set runAsNonRoot=true and runAsUser to a non-zero UID.",
                references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
            ))

        # allowPrivilegeEscalation defaults to true when not set, so flag both
        # explicit True and unset (None) — only silence when explicitly False
        if allow_pe is not False:
            findings.append(Finding(
                id="POD-PE",
                title="allowPrivilegeEscalation not disabled",
                description="allowPrivilegeEscalation is not set to false; process may gain more privileges via setuid/setgid binaries.",
                severity="high" if allow_pe is True else "medium",
                category="Pod Security",
                namespace=ns,
                resource=f"pod/{pname}::{name}",
                remediation="Set allowPrivilegeEscalation=false.",
                references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
            ))

        # readOnlyRootFilesystem defaults to false when not set, so flag both
        # explicit False and unset (None) — only silence when explicitly True
        if read_only_rootfs is not True:
            findings.append(Finding(
                id="POD-RWFS",
                title="Writable root filesystem",
                description="readOnlyRootFilesystem is not enabled; writable root filesystems enable persistence and tampering inside containers.",
                severity="medium",
                category="Pod Security",
                namespace=ns,
                resource=f"pod/{pname}::{name}",
                remediation="Set readOnlyRootFilesystem=true and mount a writable volume only where needed.",
                references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
            ))

        bad_caps = list(caps_add & DANGEROUS_CAPS)
        if bad_caps:
            findings.append(Finding(
                id="POD-CAPS",
                title="Dangerous Linux capabilities added",
                description=f"Container adds dangerous capabilities: {bad_caps}.",
                severity="high",
                category="Pod Security",
                namespace=ns,
                resource=f"pod/{pname}::{name}",
                remediation="Drop ALL by default; add back only minimal capabilities (e.g., NET_BIND_SERVICE if needed).",
                references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
            ))

        # Check for seccomp profile
        if not seccomp_profile and not pod_seccomp:
            findings.append(Finding(
                id="POD-NO-SECCOMP",
                title="No seccomp profile configured",
                description="Container lacks seccomp profile, allowing all syscalls which increases attack surface.",
                severity="medium",
                category="Pod Security",
                namespace=ns,
                resource=f"pod/{pname}::{name}",
                remediation="Set seccompProfile to RuntimeDefault or Localhost with a custom profile.",
                references=["https://kubernetes.io/docs/tutorials/security/seccomp/"]
            ))

        # Check for AppArmor profile
        if not apparmor_profile:
            findings.append(Finding(
                id="POD-NO-APPARMOR",
                title="No AppArmor profile configured",
                description="Container lacks AppArmor profile for mandatory access control.",
                severity="low",
                category="Pod Security",
                namespace=ns,
                resource=f"pod/{pname}::{name}",
                remediation="Add AppArmor annotation: container.apparmor.security.beta.kubernetes.io/<container>: runtime/default",
                references=["https://kubernetes.io/docs/tutorials/security/apparmor/"]
            ))

        # Check for resource limits
        if not limits:
            findings.append(Finding(
                id="POD-NO-LIMITS",
                title="No resource limits configured",
                description="Container lacks CPU/memory limits, risking resource exhaustion and DoS.",
                severity="medium",
                category="Pod Security",
                namespace=ns,
                resource=f"pod/{pname}::{name}",
                remediation="Set resources.limits.cpu and resources.limits.memory to prevent resource exhaustion.",
                references=["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"]
            ))

    # hostPath volumes
    for v in (spec.volumes or []):
        if getattr(v, "host_path", None):
            findings.append(Finding(
                id="POD-HOSTPATH",
                title="hostPath volume mounted",
                description=f"Pod mounts hostPath {v.host_path.path}, exposing node filesystem into the container.",
                severity="high",
                category="Pod Security",
                namespace=ns,
                resource=f"pod/{pname}",
                remediation="Avoid hostPath; use PVCs or projected volumes. If unavoidable, mount readOnly and very narrow paths.",
                references=["https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"]
            ))

    # Check if SA token automounting is NOT explicitly disabled (default is True)
    automount_token = getattr(spec, "automount_service_account_token", None)
    if automount_token is not False:
        findings.append(Finding(
            id="POD-SATOKEN",
            title="Service account token automounting not disabled",
            description="Pod does not explicitly disable automountServiceAccountToken (default is true), increasing credential theft risk.",
            severity="low",
            category="Pod Security",
            namespace=ns,
            resource=f"pod/{pname}",
            remediation="Set automountServiceAccountToken=false unless the pod needs to access the Kubernetes API. Use projected tokens when needed.",
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
        ))

    return findings
