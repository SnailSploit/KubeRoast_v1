import base64
from kuberoast.scanners.secrets import scan_secrets
from tests.conftest import make_secret


def test_sa_token_skipped():
    secret = make_secret(secret_type="kubernetes.io/service-account-token")
    findings = scan_secrets([secret])
    assert len(findings) == 0


def test_suspicious_key_flagged():
    val = base64.b64encode(b"supersecretpassword123").decode()
    secret = make_secret(data={"password": val})
    findings = scan_secrets([secret])
    ids = {f.id for f in findings}
    assert "SECRET-SENSITIVE" in ids


def test_short_value_not_flagged():
    secret = make_secret(data={"password": "eHh4"})  # "xxx" — 4 chars, below the 8-char threshold
    findings = scan_secrets([secret])
    ids = {f.id for f in findings}
    assert "SECRET-SENSITIVE" not in ids


def test_tls_without_cert_manager_flagged():
    secret = make_secret(secret_type="kubernetes.io/tls")
    findings = scan_secrets([secret])
    ids = {f.id for f in findings}
    assert "SECRET-TLS-MANUAL" in ids


def test_tls_with_cert_manager_not_flagged():
    secret = make_secret(
        secret_type="kubernetes.io/tls",
        annotations={"cert-manager.io/certificate-name": "my-cert"},
    )
    findings = scan_secrets([secret])
    ids = {f.id for f in findings}
    assert "SECRET-TLS-MANUAL" not in ids
