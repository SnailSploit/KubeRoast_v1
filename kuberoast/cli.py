import argparse, logging, sys
from typing import List
from .utils.kube import load_clients, list_all_pods, list_all_nodes, list_rbac, list_all_secrets, list_all_namespaces, list_all_services, list_all_ingresses, list_all_crds
from .scanners.pods import scan_pod_security
from .scanners.nodes import scan_nodes
from .scanners.rbac import scan_rbac
from .scanners.secrets import scan_secrets
from .scanners.pss import scan_namespace_pss
from .scanners.network import scan_services, scan_ingresses
from .scanners.policy import scan_policy_engines
from .attackpaths.rbac_escalation import analyze_attack_paths
from .reporting import json as json_report, text as text_report, html as html_report
from .utils.findings import Finding

logger = logging.getLogger("kuberoast")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def run_cluster_scan(args) -> List[Finding]:
    ns = getattr(args, "namespace", None)
    clients = load_clients(kubeconfig=getattr(args, "kubeconfig", None))
    core, rbac_api, networking, apiext = clients["core"], clients["rbac"], clients["networking"], clients["apiextensions"]
    findings: List[Finding] = []

    logger.info("Scanning pods...")
    pods = list_all_pods(core, namespace=ns)
    for p in pods:
        findings.extend(scan_pod_security(p))

    logger.info("Scanning namespace PSS labels...")
    nslist = list_all_namespaces(core)
    findings.extend(scan_namespace_pss(nslist))

    logger.info("Scanning RBAC...")
    roles, croles, rbs, crbs = list_rbac(rbac_api, namespace=ns)
    findings.extend(scan_rbac(roles, croles, rbs, crbs))

    if not args.skip_nodes:
        logger.info("Scanning nodes...")
        nodes = list_all_nodes(core)
        findings.extend(scan_nodes(nodes))

    if not args.skip_secrets:
        logger.info("Scanning secrets...")
        secrets = list_all_secrets(core, namespace=ns)
        findings.extend(scan_secrets(secrets))

    if not args.skip_attack_paths:
        logger.info("Analyzing RBAC attack paths...")
        findings.extend(analyze_attack_paths(roles, croles, rbs, crbs, pods))

    logger.info("Scanning services...")
    services = list_all_services(core, namespace=ns)
    findings.extend(scan_services(services))

    logger.info("Scanning ingresses...")
    ingresses = list_all_ingresses(networking, namespace=ns)
    findings.extend(scan_ingresses(ingresses))

    logger.info("Detecting policy engines...")
    crds = list_all_crds(apiext)
    findings.extend(scan_policy_engines(crds))

    return findings


def _max_severity(findings: List[Finding]) -> int:
    if not findings:
        return 0
    return max(SEVERITY_ORDER.get(f.severity, 0) for f in findings)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="kuberoast - offensive K8s misconfig & attack-path scanner")
    ap.add_argument("--report", choices=["json", "text", "html"], default="json", help="Output format")
    ap.add_argument("--out", help="Write report to file (required for HTML)")
    ap.add_argument("--skip-nodes", action="store_true", help="Skip node/kubelet probes")
    ap.add_argument("--skip-secrets", action="store_true", help="Skip secret heuristics")
    ap.add_argument("--skip-attack-paths", action="store_true", help="Skip RBAC attack-path analysis")
    ap.add_argument("--manifests", help="Directory of YAML/JSON manifests to scan (MVP)")
    ap.add_argument("--provider", choices=["generic", "eks", "aks", "gke"], default="generic",
                    help="Cloud provider for context-aware remediation advice")
    ap.add_argument("--kubeconfig", help="Path to kubeconfig file (defaults to ~/.kube/config)")
    ap.add_argument("--namespace", "-n", help="Limit scan to a specific namespace")
    ap.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"],
                    default="info", help="Only include findings at or above this severity")
    ap.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"],
                    default=None, help="Exit with code 1 if any finding meets or exceeds this severity")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    if args.manifests:
        logger.error("Manifest mode not yet implemented. Use cluster mode.")
        return 2

    if args.report == "html" and not args.out:
        logger.error("--report html requires --out FILE")
        return 2

    try:
        findings = run_cluster_scan(args)
    except Exception as e:
        logger.error("Scan failed: %s", e)
        return 2

    # Filter by minimum severity
    min_sev = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_sev]

    # Pass provider to reporters for context-aware remediation
    if args.report == "json":
        output = json_report.emit(findings)
    elif args.report == "html":
        output = html_report.emit(findings)
    else:
        output = text_report.emit(findings)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"Report written to {args.out}", file=sys.stderr)
    else:
        print(output)

    # Exit code based on --fail-on threshold
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if _max_severity(findings) >= threshold:
            return 1

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
