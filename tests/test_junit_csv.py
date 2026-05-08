import csv
import io
from xml.etree import ElementTree as ET

from kuberoast.reporting import csv_report, junit
from kuberoast.utils.findings import Finding


def _findings():
    return [
        Finding(
            id="POD-PRIV",
            title="Privileged container",
            description="Bad",
            severity="critical",
            category="Pod Security",
            resource="pod/web::nginx",
            namespace="default",
            remediation="Don't be privileged",
            cis_controls=["CIS-K8s-5.2.1"],
            mitre_attack=["T1611"],
        ),
        Finding(
            id="NET-LB-OPEN",
            title="LB open",
            description="Open to internet",
            severity="high",
            category="Network",
            resource="service/web",
        ),
    ]


def test_junit_emits_valid_xml():
    out = junit.emit(_findings())
    root = ET.fromstring(out)
    assert root.tag == "testsuites"
    assert root.attrib["tests"] == "2"
    assert int(root.attrib["failures"]) >= 1


def test_junit_groups_by_category():
    out = junit.emit(_findings())
    root = ET.fromstring(out)
    suites = {s.attrib["name"] for s in root.findall("testsuite")}
    assert "Pod Security" in suites
    assert "Network" in suites


def test_junit_critical_emits_error_tag():
    out = junit.emit(_findings())
    root = ET.fromstring(out)
    pod_suite = next(s for s in root.findall("testsuite") if s.attrib["name"] == "Pod Security")
    case = pod_suite.find("testcase")
    assert case.find("error") is not None


def test_csv_header_and_rows():
    out = csv_report.emit(_findings())
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    assert rows[0][0] == "id"
    assert "POD-PRIV" in [r[0] for r in rows[1:]]
    assert "NET-LB-OPEN" in [r[0] for r in rows[1:]]


def test_csv_includes_compliance_columns():
    out = csv_report.emit(_findings())
    reader = csv.DictReader(io.StringIO(out))
    rows = list(reader)
    pod = next(r for r in rows if r["id"] == "POD-PRIV")
    assert "CIS-K8s-5.2.1" in pod["cis_controls"]
    assert "T1611" in pod["mitre_attack"]


def test_csv_handles_empty():
    out = csv_report.emit([])
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0][0] == "id"
