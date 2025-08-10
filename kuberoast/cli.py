import argparse, sys
from typing import List
from .utils.kube import load_clients, list_all_pods, list_all_nodes, list_rbac, list_all_secrets, list_all_namespaces
from .scanners.pods import scan_pod_security
from .scanners.nodes import scan_nodes
from .scanners.rbac import scan_rbac
from .scanners.secrets import scan_secrets
from .scanners.pss import scan_namespace_pss
from .attackpaths.rbac_escalation import analyze_attack_paths
from .reporting import json as json_report, text as text_report
from .utils.findings import Finding

def run_cluster_scan(args) -> List[Finding]:
    clients = load_clients()
    core, rbac = clients["core"], clients["rbac"]
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

    return findings

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="kuberoast2 - offensive K8s misconfig & attack-path scanner")
    ap.add_argument("--report", choices=["json","text"], default="json")
    ap.add_argument("--skip-nodes", action="store_true", help="Skip node/kubelet probes")
    ap.add_argument("--skip-secrets", action="store_true", help="Skip secret heuristics")
    ap.add_argument("--skip-attack-paths", action="store_true", help="Skip RBAC attack-path analysis")
    ap.add_argument("--manifests", help="Directory of YAML/JSON manifests to scan (MVP)")
    args = ap.parse_args(argv)

    if args.manifests:
        print("Manifest mode MVP not yet implemented in this drop. Use cluster mode.", file=sys.stderr)
        return 2

    findings = run_cluster_scan(args)

    if args.report == "json":
        print(json_report.emit(findings))
    else:
        print(text_report.emit(findings))

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
