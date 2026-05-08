# Security Policy

## Supported versions

The latest minor release of KubeRoast receives security fixes. Older versions are best-effort.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a vulnerability

Please report security issues privately. Do **not** open a public GitHub issue.

- Use [GitHub Security Advisories](https://github.com/SnailSploit/KubeRoast_v1/security/advisories/new) (preferred), or
- Email the maintainer at the address listed in the repository profile.

Please include:
- A clear description of the issue and impact
- Steps to reproduce, ideally a minimal proof-of-concept
- Affected versions

We aim to acknowledge reports within 5 business days and to ship a fix within 30 days for high/critical issues.

## Scope

KubeRoast is a read-only scanner. It does not modify cluster state. If you find a code path that issues writes, parses untrusted input unsafely, or leaks credentials, that is in scope.
