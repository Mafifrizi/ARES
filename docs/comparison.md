# Market Comparison Matrix

How ARES compares to traditional manual penetration testing and legacy vulnerability scanners for continuous enterprise red-team engagements.

| Operational Capability | Traditional Manual Pentest | Legacy Vulnerability Scanners | ARES Orchestration Platform |
| :--- | :---: | :---: | :---: |
| **Testing Frequency** | Annual / Semi-Annual | Scheduled Daily / Weekly | **Continuous / On-Demand** |
| **Exploitability Validation** | Manual & Labor Intensive | Theoretical CVE Matching (no validation) | **Deterministic Multi-Stage Proof** |
| **Multi-Hop Attack Paths** | Manual Drawing | None | **Real-Time Interactive DAG** |
| **Scope Enclave & Egress Guard** | Operator Discipline Only | Network Firewalls Only | **Fail-Closed Dual-Layer ScopeGuard & OS/Transport Firewall** |
| **Active Directory Lateral Paths** | Slow Script Execution | No Active Paths | **Native BloodHound, Kerberos Suite & Linux AD RFC Track** |
| **Credential Security & Storage** | Loose Flat Files / Cleartext | Vulnerability Logs | **AES-256-GCM Authenticated Vault** |
| **OPSEC & Telemetry Throttling** | Manual Jitter Scripts | High Network Noise | **Adaptive Noise Profiles & Governor** |
| **Delivery Time for Reports** | 1–2 Weeks Post-Engagement | Raw Data Dumps | **Instant Multi-Format Artifacts** |
| **Deployment Footprint** | External Consultants | Bulky Cloud Agents | **Air-Gapped Local / Self-Hosted** |

## Why those columns matter

- **Testing frequency**: Point-in-time pentests leave gaps every time configuration, identity or infrastructure drifts. ARES is designed to be re-run on every merge or every day.
- **Exploitability validation**: A scanner that says a CVE "might" apply is noise. ARES only reports what it actually proved on the live target.
- **Multi-hop attack paths**: Real breaches chain weak links. The interactive DAG surfaces the shortest path to Tier-0 Crown Jewels, not just a flat vulnerability list.
- **Scope enclave & egress guard**: Fail-closed means a mis-typed CIDR cannot leak offensive packets out-of-scope. This is the single hardest thing to get right without platform support.
- **OPSEC & telemetry throttling**: Noise profiles (`stealth` / `evasive` / `noisy`) let the same module run in a red-team engagement without lighting up the SOC on day one.

## Deeper reading

- [Enterprise Security & Threat Model](security-model.md)
- [Scope enclave, execution policy & isolation](execution-policy.md)
- [Attack Graph engine design](engine_design.md)
- [Module catalog (66 active, 60+ MITRE techniques)](modules.md)
