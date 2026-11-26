# VPN Benchmark — public disposable lab

PREPARED / NOT RUN. Public CI adaptation of the v1.4 candidate, not a production deployment package. Only test templates and the integration harness are published. No personal infrastructure documentation, production addresses, credentials, or deployment lifecycle script.

Run manually via Actions on the main branch with lab_confirmed. Standard GitHub-hosted Ubuntu 24.04 only, 20-minute timeout, no automatic triggers, no repository secrets, no artifact uploads. Synthetic 198.18.254.0/29 addresses, temporary network namespace, throwaway credentials generated at runtime. No real ACME issuance; use a local test certificate for startup. Do not use this harness on a real server.

Scope: native sing-box and nftables validation, Mita build/startup, non-root container startup, permitted/denied TCP source checks and listener closure after stopping. Record upstream commit and image IDs. Not yet covered: authenticated protocol traffic, real DNS path, IPv6 packet tests, full internal-service isolation, actual ACME issuance/renewal, failure injection, production rollback, and Russian networks. TCP connectivity is not protocol authentication. Runtime success must be established by the actual job.
