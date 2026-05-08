import json
import textwrap
from pathlib import Path

import pytest

from kuberoast import __version__
from kuberoast.cli import build_parser, main


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")


def test_parser_version_flag(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert __version__ in captured.out


def test_parser_defaults():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.report == "json"
    assert args.min_severity == "info"
    assert args.fail_on is None
    assert args.no_compliance is False


def test_parser_supports_new_formats():
    parser = build_parser()
    for fmt in ("json", "text", "html", "sarif", "junit", "csv"):
        args = parser.parse_args(["--report", fmt])
        assert args.report == fmt


def test_html_requires_out():
    rc = main(["--report", "html"])
    assert rc == 2


def test_sarif_requires_out():
    rc = main(["--report", "sarif"])
    assert rc == 2


def test_manifest_scan_via_cli(tmp_path: Path, capsys):
    pod_path = tmp_path / "pod.yaml"
    _write(
        pod_path,
        """
        apiVersion: v1
        kind: Pod
        metadata:
          name: bad
          namespace: default
        spec:
          containers:
            - name: c
              image: nginx
              securityContext:
                privileged: true
        """,
    )
    rc = main(["--manifests", str(tmp_path), "--report", "json", "--no-compliance"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    ids = {f["id"] for f in data}
    assert "POD-PRIV" in ids


def test_manifest_scan_with_compliance(tmp_path: Path, capsys):
    pod_path = tmp_path / "pod.yaml"
    _write(
        pod_path,
        """
        apiVersion: v1
        kind: Pod
        metadata:
          name: bad
          namespace: default
        spec:
          containers:
            - name: c
              image: nginx
              securityContext:
                privileged: true
        """,
    )
    rc = main(["--manifests", str(tmp_path), "--report", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    priv = next(f for f in data if f["id"] == "POD-PRIV")
    assert priv["cis_controls"]
    assert priv["mitre_attack"]
    assert priv["cwe"]


def test_manifest_scan_fail_on_threshold(tmp_path: Path):
    pod_path = tmp_path / "pod.yaml"
    _write(
        pod_path,
        """
        apiVersion: v1
        kind: Pod
        metadata:
          name: bad
          namespace: default
        spec:
          containers:
            - name: c
              image: nginx
              securityContext:
                privileged: true
        """,
    )
    rc = main([
        "--manifests", str(tmp_path),
        "--report", "json",
        "--fail-on", "critical",
    ])
    assert rc == 1


def test_manifest_scan_min_severity_filter(tmp_path: Path, capsys):
    pod_path = tmp_path / "pod.yaml"
    _write(
        pod_path,
        """
        apiVersion: v1
        kind: Pod
        metadata:
          name: bad
          namespace: default
        spec:
          containers:
            - name: c
              image: nginx
              securityContext:
                privileged: true
        """,
    )
    rc = main([
        "--manifests", str(tmp_path),
        "--report", "json",
        "--min-severity", "critical",
    ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert all(f["severity"] == "critical" for f in data)


def test_manifest_scan_sarif_to_file(tmp_path: Path):
    pod_path = tmp_path / "pod.yaml"
    out_path = tmp_path / "out.sarif"
    _write(
        pod_path,
        """
        apiVersion: v1
        kind: Pod
        metadata:
          name: bad
          namespace: default
        spec:
          containers:
            - name: c
              image: nginx
              securityContext:
                privileged: true
        """,
    )
    rc = main([
        "--manifests", str(tmp_path),
        "--report", "sarif",
        "--out", str(out_path),
    ])
    assert rc == 0
    assert out_path.exists()
    sarif = json.loads(out_path.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "KubeRoast"


def test_missing_manifest_path_returns_2(tmp_path: Path):
    rc = main(["--manifests", str(tmp_path / "nope")])
    assert rc == 2
