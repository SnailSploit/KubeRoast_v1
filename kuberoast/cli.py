import argparse, sys
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

def run_cluster_scan(args) -> List[Finding]:
    clients = load_clients()
    core, rbac, networking, apiext = clients["core"], clients["rbac"], clients["networking"], clients["apiextensions"]
    findings: List[Finding] = []

    pods = list_all_pods(core)
    for p in pods:
        findings.extend(scan_pod_security(p))

    nslist = list_all_namespaces(core)
    findings.extend(scan_namespace_pss(nslist))

    roles, croles, rbs, crbs = list_rbac(rbac)
    findings.extend(scan_rbac(roles, croles, rbs, crbs))

    if not args.skip_nodes:
        nodes = list_all_nodes(core)
        findings.extend(scan_nodes(nodes))

    if not args.skip_secrets:
        secrets = list_all_secrets(core)
        findings.extend(scan_secrets(secrets))

    if not args.skip_attack_paths:
        findings.extend(analyze_attack_paths(roles, croles, rbs, crbs, pods))

    # Network scanning
    services = list_all_services(core)
    findings.extend(scan_services(services))

    ingresses = list_all_ingresses(networking)
    findings.extend(scan_ingresses(ingresses))

    # Policy engine detection
    crds = list_all_crds(apiext)
    findings.extend(scan_policy_engines(crds))

    return findings

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="kuberoast2 - offensive K8s misconfig & attack-path scanner")
    ap.add_argument("--report", choices=["json","text","html"], default="json", help="Output format")
    ap.add_argument("--out", help="Write report to file (required for HTML)")
    ap.add_argument("--skip-nodes", action="store_true", help="Skip node/kubelet probes")
    ap.add_argument("--skip-secrets", action="store_true", help="Skip secret heuristics")
    ap.add_argument("--skip-attack-paths", action="store_true", help="Skip RBAC attack-path analysis")
    ap.add_argument("--manifests", help="Directory of YAML/JSON manifests to scan (MVP)")
    ap.add_argument("--provider", choices=["generic","eks","aks","gke"], default="generic",
                    help="Cloud provider for context-aware remediation advice")
    args = ap.parse_args(argv)

    if args.manifests:
        print("Manifest mode MVP not yet implemented in this drop. Use cluster mode.", file=sys.stderr)
        return 2

    if args.report == "html" and not args.out:
        print("Error: --report html requires --out FILE", file=sys.stderr)
        return 2

    findings = run_cluster_scan(args)

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

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
