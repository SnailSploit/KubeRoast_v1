"""Terminal styling: ASCII banner, ANSI colors, severity badges.

Respects NO_COLOR (https://no-color.org) and KUBEROAST_NO_COLOR. Auto-detects
TTY on the target stream — never emits escape codes when piping to a file.
"""
from __future__ import annotations

import os
import sys
from typing import IO, Optional

from .. import __version__

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Foreground colors
FG = {
    "red": "\033[38;5;203m",
    "orange": "\033[38;5;209m",
    "yellow": "\033[38;5;221m",
    "blue": "\033[38;5;75m",
    "cyan": "\033[38;5;87m",
    "green": "\033[38;5;120m",
    "magenta": "\033[38;5;213m",
    "gray": "\033[38;5;245m",
    "white": "\033[38;5;255m",
}

# Severity → color
SEVERITY_COLOR = {
    "critical": "red",
    "high": "orange",
    "medium": "yellow",
    "low": "blue",
    "info": "gray",
}


def _colors_enabled(stream: Optional[IO] = None) -> bool:
    """Decide whether to emit ANSI colors on `stream` (default: stdout)."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("KUBEROAST_NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    s = stream if stream is not None else sys.stdout
    return bool(getattr(s, "isatty", lambda: False)())


def color(text: str, name: str, *, bold: bool = False, stream: Optional[IO] = None) -> str:
    """Wrap text in ANSI color codes when the stream is a TTY."""
    if not _colors_enabled(stream):
        return text
    code = FG.get(name, "")
    prefix = (BOLD if bold else "") + code
    return f"{prefix}{text}{RESET}" if prefix else text


def severity_badge(severity: str, *, stream: Optional[IO] = None) -> str:
    """Render an inline `[CRITICAL]`-style badge with severity color."""
    label = f"[{severity.upper()}]"
    return color(label, SEVERITY_COLOR.get(severity, "gray"), bold=True, stream=stream)


_BANNER_ART = r"""
 ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗  █████╗ ███████╗████████╗
 ██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝
 █████╔╝ ██║   ██║██████╔╝█████╗  ██████╔╝██║   ██║███████║███████╗   ██║
 ██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗██║   ██║██╔══██║╚════██║   ██║
 ██║  ██╗╚██████╔╝██████╔╝███████╗██║  ██║╚██████╔╝██║  ██║███████║   ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝
"""

_TAGLINE = "Offensive Kubernetes misconfig & attack-path scanner"


def banner(*, stream: Optional[IO] = None) -> str:
    """Return the ASCII banner with version + tagline.

    Coloured on TTYs, plain text otherwise.
    """
    art = _BANNER_ART.rstrip("\n")
    if _colors_enabled(stream):
        art = color(art, "magenta", bold=True, stream=stream)
        version_line = (
            f" {color('v' + __version__, 'cyan', bold=True, stream=stream)}"
            f"  {color('•', 'gray', stream=stream)}  "
            f"{color(_TAGLINE, 'white', stream=stream)}"
        )
    else:
        version_line = f" v{__version__}  •  {_TAGLINE}"
    return f"{art}\n{version_line}\n"


def print_banner(stream: Optional[IO] = None) -> None:
    """Emit the banner to stderr (default), so JSON/SARIF output stays clean."""
    target = stream if stream is not None else sys.stderr
    target.write(banner(stream=target))
    target.flush()
