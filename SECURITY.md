# Security Policy

## The safety contract

Keyring Audit handles credentials. The contract is non-negotiable:

1. **Never store a secret.** The scanner keeps a salted hash
   (`sha256("keyring-audit-v1" + value)`) and the first/last 4 characters.
   The full value exists only in memory for the duration of one validity
   check, and is wiped after. No secret ever touches disk, a log, a
   report file, or a network call except the provider's own validity
   endpoint.
2. **Read-only checks, minimal scope.** Validity = one identity call per
   credential (`GET /user`, `sts:GetCallerIdentity`). Permissions =
   metadata reads and policy simulation only. No data reads, ever. Every
   check is logged with the exact API call made.
3. **Only scan what you authorised.** The CLI scans the repos and
   accounts you point it at. Testing a credential you do not own is
   unauthorised access in most jurisdictions — this tool refuses to
   validate a credential it was not given by its owner.

## Reporting a vulnerability

If you find a flaw in Keyring Audit itself — especially anything that
could leak a secret into a log, a report, or a network call — please
report it privately: open a GitHub issue titled "SECURITY" with no
secret material in it, or email samirshirjan890@gmail.com. Do not include
a real credential in any report.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |
