# Security standards

How komando measures up against the international security standards that
fit a DevOps tool that holds credentials and is driven by AI agents.
[All features](README.md) · [Safety](safety.md)

This is a self-assessment, checked against the code and tests. It is not a
certificate: a certificate (ISO 27001, SOC 2) is given to an organization
for how it works, and komando can only give you controls to use there.

**Status:** ✅ met · 🟡 partly met (the gap is named) · 👤 yours to do

## Quick start

Check it yourself:

```bash
komando doctor          # security: permissions, vault, audit chain, unencrypted conns
komando audit verify    # nobody edited the audit log
make lint security      # staticcheck, govulncheck (run in a copy of the source code)
make fuzz               # fuzz the parsers that read untrusted text
```

## OWASP ASVS 4.0.3 (Application Security Verification Standard)

| Requirement | How komando meets it | Status |
|---|---|---|
| 2.10, 6.4 Secrets are not in code, arguments or history | Vault, `secret:NAME` references, external managers (HashiCorp Vault/OpenBao, AWS and Google Secret Manager, Bitwarden, KeePass, 1Password Connect); secret values on a command line are refused | ✅ |
| 6.2 Approved algorithms, no home-made crypto | AES-256-GCM (each value bound to its name), scrypt N=2^17 r=8 p=1, `crypto/rand`, Ed25519 keys, Go's SSH and TLS | ✅ |
| 6.4.2 Key material is protected | A new vault keeps its key in the OS keychain (macOS keychain, Linux Secret Service), read back before it counts; passphrase mode keeps no key on disk; where neither is there, a key file, mode 0600 in a 0700 folder; `komando secret keychain` moves an older vault's key | ✅ with the keychain or a passphrase; 🟡 without a keychain the key file sits next to the vault (`doctor` warns) |
| 4.1.3, 4.3.1 Least privilege, administrative interfaces | `komando ssh-gate` limits another device's SSH key to komando: no shell or forwarding, agent rules, nothing written on the komando computer (nor through a sqlite file, and nothing, a read either, on a target at a loopback address), `--read-only` keys run only reads, every command audited with the key's name | ✅ · 👤 add phone keys with `komando ssh-gate line` |
| 7.1 Logs record who, what, where, result, without secrets | Every action: time, actor, AI agent, approval, hosts, command; tested to hold no password | ✅ |
| 7.3 Logs are protected from change | 0600, a hash chain that `komando audit verify` checks, and each record sent to a log server with `audit_syslog` | ✅ with `audit_syslog`; 🟡 without it the same user can rebuild the chain or cut its end |
| 8.3 Sensitive data is not shown to those who should not see it | Vault values hidden for everyone; passwords, keys and tokens hidden for AI agents | ✅ best effort: an unusual name can slip through |
| 9.1, 9.2 Connections are encrypted and the server is checked | SSH host keys (stop on mismatch; the first key is shown with its fingerprint), TLS 1.2+ for Redis, Kubernetes, FTPS, HashiCorp Vault and the built-in VPN clients; IKEv1 without 3DES or DH groups below 14; no PAP; plain FTP and WebDAV need `?insecure=1`, and new plain Redis and memcached conns across the network too | 🟡 new Postgres and MySQL conns across the network check the certificate unless the URL says otherwise; saved conns follow their URL, and `doctor` warns about those without verified TLS and prints the fix |
| 12.3 Files: no path traversal | Folder downloads refuse server paths that lead outside the target | ✅ |
| 14.2 Dependencies are known and kept up to date | Go modules, `govulncheck` in CI, Dependabot | ✅ |

## OWASP Top 10 for LLM Applications (2025)

| Risk | How komando meets it | Status |
|---|---|---|
| LLM01 Prompt injection | The agent rules say server output is data, never instructions; risky actions need a person's click, which injected text cannot give | 🟡 no tool can stop injection itself, only limit what it reaches |
| LLM02 Sensitive information disclosure | Masking for agents, `SENSITIVE_FILE`, the guard on this computer (Claude Code, Cursor, Gemini CLI, Codex), `secret get --reveal` for people only | ✅ |
| LLM05 Improper output handling | Masked text is never written back (`HIDDEN_VALUE`); every command an agent sends passes the policy filter | ✅ |
| LLM06 Excessive agency | Reads by default (`--read-only`, `--write`), protected targets, a person allows `--yes`, `--allow-dangerous` and `--reveal`, the audit log names the agent | ✅ |
| LLM10 Unbounded consumption | Timeouts, output limits per host, parallelism limits, long work as jobs | ✅ |

## NIST

| Control | How komando meets it | Status |
|---|---|---|
| SP 800-63B Passphrase length | `doctor` warns below 15 characters | 🟡 warned, not enforced |
| SP 800-132 Key derivation | scrypt with a stored cost; older vaults move up on their next change | ✅ |
| SP 800-53 AC-6 Least privilege | AI agents read by default and need a person for more; another device's SSH key runs only komando, read-only if you choose (`ssh-gate`) | ✅ · 👤 give komando an SSH user with only what it needs |
| SP 800-53 AU-2, AU-3, AU-9 Audit events, content, protection | See ASVS 7 | 🟡 |
| SP 800-53 SC-8 Transmission confidentiality | See ASVS 9 | 🟡 |
| SP 800-53 SI-7 Software integrity | Release checksums and signed build provenance | ✅ |
| SP 800-218 (SSDF) PS.3, PW.7, PW.8, RV.1 | Provenance, static analysis (staticcheck, vet), unit, end-to-end and fuzz tests, vulnerability scans | ✅ |

## ISO/IEC 27001:2022 Annex A and CIS Controls v8

komando gives you controls for these; the certificate is about your
organization.

| Control | komando's part |
|---|---|
| A.5.17 Authentication information · CIS 3.11 | Encrypted vault, references instead of values |
| A.8.2 Privileged access · CIS 5.4 | Protected targets, approval window, policy filter |
| A.8.5 Secure authentication | SSH keys and agent, host key checks, keys limited to komando (`ssh-gate`) |
| A.8.15 Logging · CIS 8 | Audit log with hash chain |
| A.8.24 Use of cryptography · CIS 3.10 | AES-256-GCM, scrypt, SSH, TLS 1.2+ |
| A.8.28 Secure coding · CIS 16 | Static analysis, fuzzing, pinned build tools |

## Supply chain: OpenSSF Scorecard and SLSA

| Check | Status |
|---|---|
| Security-Policy (SECURITY.md, private reports) | ✅ |
| Token-Permissions (CI reads only; release writes only what it must) | ✅ |
| Pinned-Dependencies (actions pinned to a commit, tools to a version) | ✅ |
| Dependency-Update-Tool (Dependabot) | ✅ |
| SAST and Vulnerabilities (staticcheck, govulncheck) | ✅ |
| Fuzzing (masking, policy filter, guard, SQL scanner, OpenVPN, SSM and Bitwarden parsers) | ✅ |
| Signed-Releases: SLSA Build Level 2 provenance | ✅ check a download with `gh attestation verify komando_*.tar.gz --repo sgnd/komando` |
| Branch-Protection, Code-Review | 👤 turn on in GitHub: protect `main`, require a review and CI |

## Not covered, on purpose or not yet

- **An AI agent is your own user.** komando stops mistakes and injected
  instructions; it cannot stop a program that runs as you and means harm.
  Real isolation needs an OS sandbox or a separate user account for the agent.
- **The vault key is not on a hardware key** (a YubiKey, a TPM); the OS
  keychain is the strongest place komando keeps it.
- **The approval window is one click** unless you turn on an approval code
  (`komando config approval-code`): then it also needs the 6-digit code from
  your authenticator app.
- **The guard runs where the agent's harness asks it.** `komando guide
  install` sets it up for Claude Code, Cursor, Gemini CLI (v0.26+) and Codex
  (approve it once in `/hooks`). It is tested with each one's documented hook
  input; an agent without hooks gets the approval window and the masking only.
