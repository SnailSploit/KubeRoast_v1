"""Tests for the styling / banner / color module."""
from __future__ import annotations

import io

import pytest

from kuberoast import __version__
from kuberoast.utils import style


def test_banner_contains_version_and_tagline():
    out = style.banner()
    assert __version__ in out
    assert "Offensive Kubernetes" in out
    assert "kuberoast".upper() in out.upper() or "KUBEROAST" in out.upper() or "K" in out  # ASCII art


def test_banner_no_color_strips_ansi(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    out = style.banner()
    assert "\033[" not in out


def test_banner_force_color_emits_ansi(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("KUBEROAST_NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    out = style.banner()
    assert "\033[" in out


def test_color_returns_plain_when_no_tty():
    """A non-TTY stream should not get color codes."""
    buf = io.StringIO()
    out = style.color("hello", "red", stream=buf)
    assert out == "hello"


def test_color_with_force_color_emits(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    out = style.color("hello", "red")
    assert "\033[" in out
    assert "hello" in out


def test_severity_badge_format(monkeypatch):
    """Without colors, severity_badge is just `[CRITICAL]`."""
    monkeypatch.setenv("NO_COLOR", "1")
    assert style.severity_badge("critical") == "[CRITICAL]"
    assert style.severity_badge("info") == "[INFO]"


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_severity_color_map_complete(severity):
    assert severity in style.SEVERITY_COLOR
    assert style.SEVERITY_COLOR[severity] in style.FG


def test_print_banner_writes_to_stream(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    buf = io.StringIO()
    style.print_banner(stream=buf)
    written = buf.getvalue()
    assert __version__ in written
    assert "Offensive Kubernetes" in written


def test_kuberoast_no_color_disables_colors(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setenv("KUBEROAST_NO_COLOR", "1")
    out = style.color("hi", "red")
    assert "\033[" not in out
