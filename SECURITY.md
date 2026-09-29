# Security Policy

## Scope

This repository contains a security testing dashboard and supporting scanners. Use it only against systems you own or are explicitly authorized to test. The DDoS module is for controlled, rate-limited load testing in an isolated environment; it is not intended for public targets.

## Supported versions

Only the latest commit on the default branch is supported. Please update before reporting an issue.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's Security Advisories feature for this repository. Include:

- A clear description and impact assessment
- The affected file, endpoint, or configuration
- Reproduction steps or a minimal proof of concept
- Any required environment variables and versions
- A suggested mitigation, if known

Do not include live credentials, personal data, or unauthorized target information in a report. Do not publicly disclose a vulnerability until a fix and disclosure timeline have been agreed.

## Credential handling

- Never commit `.env`, API keys, database passwords, session secrets, private keys, or target credentials.
- Copy `.env.example` to `.env` for local configuration.
- Generate unique secrets for every environment and set `REQUIRE_API_KEY=true` when the API is exposed beyond a trusted local machine.
- Rotate any secret that may have been exposed, even if it was later removed from the working tree.

## Safe testing

Test only with explicit authorization and use non-production targets whenever possible. Keep load-test concurrency and request limits low, record the authorization and test window, and stop immediately if the target becomes unstable.
