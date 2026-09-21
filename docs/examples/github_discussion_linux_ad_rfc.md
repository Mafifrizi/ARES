# [RFC] Cross-Platform Linux Active Directory Post-Exploitation & Credential Harvesting Architecture

> **Notice**: This is a ready-to-post template for a GitHub Discussion (under "Ideas" or "RFCs") or a GitHub Issue (labeled `rfc`, `research`, `help wanted`) on the ARES repository.

---

### Title:
`[RFC 001] Cross-Platform Linux Active Directory Post-Exploitation & Credential Harvesting Architecture`

### Body:

```markdown
### Summary

Modern enterprise hybrid networks increasingly deploy Linux hosts (CI/CD build nodes, container hosts, database clusters, identity proxies) as domain members integrated with Active Directory via **SSSD (`realmd`)** and **Winbind/Samba**. While Windows AD attack vectors (Pass-the-Hash, DPAPI, LSASS injection) have mature offensive tooling, Linux domain members remain an under-researched, high-value blindspot.

We have published a formal technical specification: **[RFC 001: Linux Active Directory Tradecraft](docs/research/linux-active-directory-tradecraft.md)**, establishing an open architecture for native, high-performance, non-destructive post-exploitation modules in ARES.

We are opening this RFC to gather technical feedback, coordinate module implementations, and invite researchers and practitioners specializing in Linux offensive tradecraft and Active Directory internals to collaborate.

---

### Motivation & Research Scope

When an operator or red team establishes a foothold on a domain-joined Linux machine, that endpoint often holds:
1. **SSSD Cached Credentials**: `/var/lib/sss/db/cache_*.ldb` storing salted offline password hashes, group memberships, and cached PAC records.
2. **Kerberos Ticket Caches (`ccache`)**: In-memory and on-disk Kerberos tickets (`/tmp/krb5cc_*`, Linux Kernel Keyrings `KEYRING:persistent:%{uid}`, or KCM sockets) containing valid Domain Admin TGTs.
3. **Machine Account Keytabs**: `/etc/krb5.keytab` containing symmetric keys (`AES256-CTS-HMAC`, `RC4-HMAC`) that permit forging Silver Tickets or performing cross-realm delegation abuse.
4. **Samba/Winbind Secrets**: `/var/lib/samba/private/secrets.tdb` containing machine passwords and schannel credentials.

ARES provides an asynchronous, type-safe execution engine (`BaseModule`), fail-closed scope governance (`ScopeGuard`), and an AES-256-GCM AEAD encrypted credential vault (`AresVault`). Integrating native Linux AD modules enables continuous, deterministic validation of hybrid attack paths.

---

### Prioritized Module Wishlist (MITRE ATT&CK Mapped)

We are seeking collaboration and PRs for the following prioritized module contracts:

| Module Identifier | Target Subsystem | MITRE ATT&CK | OPSEC Profile |
| :--- | :--- | :--- | :--- |
| `linux.sssd_harvest` | SSSD LDB databases (`/var/lib/sss/db/`) | T1003.008, T1558 | `OpsecLevel.SILENT` |
| `linux.ccache_hunt` | Kerberos ccache files & Kernel Keyring | T1558, T1550.003 | `OpsecLevel.SILENT` |
| `linux.keytab_abuse` | Machine keytab parsing & ticket forging | T1558.003, T1078 | `OpsecLevel.LOW` |
| `linux.samba_secrets` | Winbind/Samba secrets (`secrets.tdb`) | T1003, T1550.002 | `OpsecLevel.SILENT` |
| `credential.ticket_converter` | In-memory bi-directional ccache <-> kirbi | T1558 | `OpsecLevel.SILENT` |

---

### Architectural Standards & OPSEC Constraints

To ensure safety, stability, and detection-minimization:
- **No Uncontrolled Subprocess Spawning**: Modules must prioritize direct binary structure parsing (e.g. standard library `struct.unpack`) over shell execution (`bash -c`, `klist`, `cat`) to prevent `auditd` `execve` tripwires.
- **Fail-Closed Governance**: Any out-of-scope network connection attempts abort immediately via `ScopeGuard`.
- **Encrypted Evidence Vault**: Extracted tickets, keys, and hashes are committed to `AresVault` using PBKDF2-HMAC-SHA256 authenticated AES-256-GCM encryption.

---

### How to Get Involved

1. Read the full technical specification: [`docs/research/linux-active-directory-tradecraft.md`](docs/research/linux-active-directory-tradecraft.md).
2. Review our developer guide: [`docs/module-development.md`](docs/module-development.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md).
3. Drop a comment below with:
   - Module you're interested in building or reviewing
   - Edge cases or exotic configurations in your lab/enterprise experience
   - Detection heuristics or EDR telemetry considerations

---

### Acknowledgments

This research track draws inspiration from foundational cross-platform tradecraft, notably the pioneering work of **Tim Brown (`@timb-machine`)** on `linikatz`, **Benjamin Delpy (`@gentilkiwi`)** on `mimikatz`, **Alberto Solino (`@asolino`)** on `Impacket`, and the broader open-source offensive security research community.
```
