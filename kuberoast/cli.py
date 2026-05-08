import argparse
import logging
import sys
from typing import List, Optional

from . import __version__
from .attackpaths.rbac_escalation import analyze_attack_paths
from .reporting import csv_report
from .reporting import html as html_report
from .reporting import json as json_report
from .reporting import junit as junit_report
from .reporting import sarif as sarif_report
from .reporting import text as text_report
from .scanners.network import scan_ingresses, scan_services
from .scanners.nodes import scan_nodes
from .scanners.pods import scan_pod_security
from .scanners.policy import scan_policy_engines
from .scanners.pss import scan_namespace_pss
from .scanners.rbac import scan_rbac
from .scanners.secrets import scan_secrets
from .utils.compliance import enrich_findings
from .utils.findings import Finding
from .utils.kube import (
    list_all_crds,
    list_all_ingresses,
    list_all_namespaces,
    list_all_nodes,
    list_all_pods,
    list_all_secrets,
    list_all_services,
    list_rbac,
    load_clients,
)
from .utils.manifests import load_manifests
from .utils.style import print_banner

logger = logging.getLogger("kuberoast")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

REPORT_FORMATS = {
    "json": json_report.emit,
    "text": text_report.emit,
    "html": html_report.emit,
    "sarif": sarif_report.emit,
    "junit": junit_report.emit,
    "csv": csv_report.emit,
}


def run_cluster_scan(args) -> List[Finding]:
    ns = getattr(args, "namespace", None)
    clients = load_clients(kubeconfig=getattr(args, "kubeconfig", None))
    core, rbac_api = clients["core"], clients["rbac"]
    networking, apiext = clients["networking"], clients["apiextensions"]
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


def run_manifest_scan(path: str, args) -> List[Finding]:
    logger.info("Loading manifests from %s...", path)
    objects = load_manifests(path)
    findings: List[Finding] = []

    for pod in objects["pods"]:
        findings.extend(scan_pod_security(pod))

    if objects["namespaces"]:
        findings.extend(scan_namespace_pss(objects["namespaces"]))

    findings.extend(
        scan_rbac(
            objects["roles"],
            objects["cluster_roles"],
            objects["role_bindings"],
            objects["cluster_role_bindings"],
        )
    )

    if not args.skip_secrets and objects["secrets"]:
        findings.extend(scan_secrets(objects["secrets"]))

    if not args.skip_attack_paths:
        findings.extend(
            analyze_attack_paths(
                objects["roles"],
                objects["cluster_roles"],
                objects["role_bindings"],
                objects["cluster_role_bindings"],
                objects["pods"],
            )
        )

    findings.extend(scan_services(objects["services"]))
    findings.extend(scan_ingresses(objects["ingresses"]))

    if objects["crds"]:
        findings.extend(scan_policy_engines(objects["crds"]))

    return findings


def _max_severity(findings: List[Finding]) -> int:
    if not findings:
        return 0
    return max(SEVERITY_ORDER.get(f.severity, 0) for f in findings)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="kuberoast",
        description="KubeRoast — offensive Kubernetes misconfiguration & attack-path scanner",
        epilog="Run safely. Read-only by design. Ethical use only.",
    )
    ap.add_argument("--version", action="version", version=f"kuberoast {__version__}")
    ap.add_argument("--no-banner", action="store_true",
                    help="Suppress the startup banner")
    ap.add_argument("--report", choices=sorted(REPORT_FORMATS.keys()), default="json",
                    help="Output format")
    ap.add_argument("--out", help="Write report to file (required for HTML/SARIF/JUnit/CSV)")
    ap.add_argument("--skip-nodes", action="store_true", help="Skip node/kubelet probes")
    ap.add_argument("--skip-secrets", action="store_true", help="Skip secret heuristics")
    ap.add_argument("--skip-attack-paths", action="store_true", help="Skip RBAC attack-path analysis")
    ap.add_argument("--manifests",
                    help="Scan a directory or file of YAML/JSON Kubernetes manifests instead of a live cluster")
    ap.add_argument("--provider", choices=["generic", "eks", "aks", "gke"], default="generic",
                    help="Cloud provider for context-aware remediation advice")
    ap.add_argument("--kubeconfig", help="Path to kubeconfig file (defaults to ~/.kube/config)")
    ap.add_argument("--namespace", "-n", help="Limit scan to a specific namespace")
    ap.add_argument("--min-severity", choices=list(SEVERITY_ORDER.keys()), default="info",
                    help="Only include findings at or above this severity")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER.keys()), default=None,
                    help="Exit with code 1 if any finding meets or exceeds this severity")
    ap.add_argument("--no-compliance", action="store_true",
                    help="Skip CIS / MITRE ATT&CK / CWE enrichment")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    ap.add_argument("-q", "--quiet", action="store_true", help="Suppress non-error logging")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stderr,
    )

    # Banner: only when running interactively to text/html, never when piping
    # machine-readable output, and never under --quiet or --no-banner.
    if (
        not args.no_banner
        and not args.quiet
        and args.report in {"text", "html"}
        and sys.stderr.isatty()
    ):
        print_banner()

    if args.report in {"html", "sarif", "junit", "csv"} and not args.out:
        logger.error("--report %s requires --out FILE", args.report)
        return 2

    try:
        if args.manifests:
            findings = run_manifest_scan(args.manifests, args)
        else:
            findings = run_cluster_scan(args)
    except FileNotFoundError as e:
        logger.error("%s", e)
        return 2
    except Exception as e:
        logger.error("Scan failed: %s", e)
        if args.verbose:
            logger.exception("Traceback:")
        return 2

    if not args.no_compliance:
        enrich_findings(findings)

    min_sev = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_sev]

    emit = REPORT_FORMATS[args.report]
    output = emit(findings)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fp:
            fp.write(output)
        logger.warning("Report written to %s (%d findings)", args.out, len(findings))
    else:
        print(output)

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if _max_severity(findings) >= threshold:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
