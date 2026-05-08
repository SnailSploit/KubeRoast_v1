from kuberoast.reporting import html as html_report
from kuberoast.reporting import json as json_report
from kuberoast.reporting import text as text_report
from kuberoast.utils.findings import Finding


def _sample_findings():
    return [
        Finding(id="TEST-1", title="Critical issue", description="Bad", severity="critical", category="Test"),
        Finding(id="TEST-2", title="Low issue", description="Minor", severity="low", category="Test"),
        Finding(id="TEST-3", title="High issue", description="Moderate", severity="high", category="Test"),
    ]


def test_json_output_valid():
    import json
    output = json_report.emit(_sample_findings())
    data = json.loads(output)
    assert len(data) == 3
    assert data[0]["id"] == "TEST-1"


def test_text_output_grouped_by_severity():
    output = text_report.emit(_sample_findings())
    # Critical should appear before high, high before low
    crit_pos = output.index("CRITICAL")
    high_pos = output.index("HIGH")
    low_pos = output.index("LOW")
    assert crit_pos < high_pos < low_pos


def test_text_output_summary():
    output = text_report.emit(_sample_findings())
    assert "3 findings" in output
    assert "1 critical" in output


def test_text_empty_findings():
    output = text_report.emit([])
    assert "No findings" in output


def test_html_output_contains_table():
    output = html_report.emit(_sample_findings())
    assert "<table" in output
    assert "CRITICAL" in output
