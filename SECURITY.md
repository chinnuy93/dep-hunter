# Security Policy

## Supported versions

Security fixes are provided for the current `1.0.x` release line.

## Reporting a vulnerability in Dep-Hunter

Report vulnerabilities in the tool itself through GitHub's private vulnerability
reporting:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Include the affected version, operating system, Python version, impact, and a
   minimal reproduction.

Do not open a public issue for an exploitable vulnerability, and do not include real
target data, authorization files, access tokens, or generated scan reports in a report
or issue. Use synthetic examples.

Reports about third-party targets, registry services, or bug-bounty programs are out of
scope for this policy; contact the relevant program or service directly.

## Scope

In scope for this policy:

- Scope or SSRF bypasses
- Unauthorized state-changing requests
- Credential or token disclosure by the tool
- Parser denial of service or code execution
- Report injection or unsafe report rendering
- Evidence or database integrity failures

Out of scope:

- Vulnerabilities in scanned third-party targets
- Findings produced by a scan
- Rate limiting imposed by a target or registry
- Missing optional ecosystem CLIs
- Social engineering or physical attacks

This project does not operate a bug-bounty program and does not offer payment for
reports. Good-faith reports are appreciated.
