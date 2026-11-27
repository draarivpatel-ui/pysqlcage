# Security policy

`pysqlcage` is a security library. Please report suspected vulnerabilities privately rather than opening a public issue with exploit details.

## Reporting

Open a GitHub Security Advisory on the repository if private reporting is enabled. If it is not enabled, open a minimal public issue asking for a private contact path and do not include a proof of concept, exploit payload, affected production system, or secret data.

## Scope

In scope:

- Untrusted data becoming executable SQL through the builder
- Bypasses in identifier, schema, ordering, `IN`, `VALUES`, `SET`, or `LIKE` validation
- Fragment forgery or mutation
- Compiler behavior that exceeds documented caps or crashes on hostile input
- Auditor lexer bypasses for documented PostgreSQL, MySQL, or SQLite syntax
- CLI file handling vulnerabilities

Out of scope:

- Handwritten SQL that bypasses the library
- Database server vulnerabilities
- Driver vulnerabilities outside `pysqlcage`
- Applications passing attacker-controlled strings as trusted SQL template text
- Denial of service caused by inputs already trusted by the application operator

## Response expectations

This is a small open source project. Reports will be triaged as quickly as practical, coordinated disclosure is preferred, and credit will be given when requested.
