# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

Security fixes land on the latest 1.x release. Upgrade before reporting an issue that only reproduces on an older release.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/pysqlcage/security/advisories/new). Do not open a public issue with exploit details for an unpatched vulnerability.

Include:

- The affected pysqlcage version or commit.
- The Python version, operating system and SQL dialect.
- A minimal reproduction using synthetic schema, identifiers and values.
- The public API used, expected security property and observed result.
- A short assessment of impact and any preconditions.

Do not include real credentials, connection strings, production data, secrets or personal data in a report.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix or documented mitigation within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed state and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

## Scope

In scope:

- Untrusted data becoming executable SQL through the builder.
- Bypasses in identifier, schema, ordering, `IN`, `VALUES`, `SET` or `LIKE` validation.
- Fragment forgery or mutation.
- Compiler behavior that exceeds documented caps or crashes on hostile input.
- Auditor lexer bypasses for documented PostgreSQL, MySQL or SQLite syntax.
- CLI file-handling vulnerabilities.

Out of scope:

- Handwritten SQL that bypasses the library.
- Database server vulnerabilities.
- Driver vulnerabilities outside pysqlcage.
- Applications passing attacker-controlled strings as trusted SQL template text.
- Denial of service caused by inputs already trusted by the application operator.

## Security design notes

pysqlcage builds parameterized SQL without concatenating untrusted values into SQL text. It combines strict schema allowlists, safe SQL helpers, immutable fragments and a lexical auditor. The auditor is a defense-in-depth control and does not replace parameterized queries or database permissions.
