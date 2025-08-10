# Kuberoast

From-scratch rebuild of a pentest-focused Kubernetes misconfiguration & attack-path scanner.

## Quick start

```bash
python -m pip install -e .
kuberoast --report text
# or
kuberoast --report json > results.json
```

## Modes

- **Cluster mode** (default): connects to the Kubernetes API using in-cluster credentials or KUBECONFIG.
- **Manifest mode** (`--manifests <dir>`): static scan of YAML/JSON manifests (MVP parses obvious pod spec security fields).

## Safety

By default, `kuberoast2` is **read-only**. Add `--danger-exec` to try non-destructive exec-based probes.
