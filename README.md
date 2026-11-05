<div align="center">

<img src="frontend/public/brand/ares-logo-v2.png" alt="ARES Logo" width="360">

### Operator-directed red team orchestration & continuous security validation

Prove exploitability. Compute shortest paths to Crown Jewels. Ship audit-ready evidence.
Built for enterprise red teams, MSSPs and security operations centers that need to validate defensive posture continuously, not once a year.

<br>

[![Release](https://img.shields.io/badge/release-v6.0--enterprise-DC2626?style=flat-square)](releases/)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/frontend-React%2018%20%7C%20Vite-61DAFB?style=flat-square&logo=react&logoColor=111111)](https://react.dev)
[![MITRE ATT&amp;CK](https://img.shields.io/badge/coverage-MITRE%20ATT%26CK-FF6F00?style=flat-square)](docs/modules.md)
[![License](https://img.shields.io/badge/license-MIT-3B82F6?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-5%2C074-22C55E?style=flat-square)](tests/)

[**Quickstart**](#quickstart) · [**Screens**](#screens) · [**Features**](#features) · [**Docs**](docs/) · [**Security**](docs/security-model.md) · [**Sponsor**](#support)

</div>

---

## What ARES is

A self-hosted platform that runs **real** offensive validation modules inside a fail-closed scope enclave, maps attack paths on an interactive DAG, and produces branded reports — so your SOC sees exactly what an attacker could reach today, not what a scanner thinks might be a problem.

**Not just a scanner.** ARES only reports what it actually proved on a live target, including the multi-stage chain used to prove it.

> **Why not a traditional pentest or a vulnerability scanner?** See the [market comparison matrix](docs/comparison.md).

---

## Screens

<div align="center">

<img src="docs/assets/screens/login-hd.png" alt="ARES login — dragon mascot" width="840"><br>
*Sign-in with the ARES mascot and the SSO fallback. Memory-only JWT access tokens, HttpOnly rotating refresh.*

<br>

<img src="docs/assets/screens/overview-hd.png" alt="Operator overview" width="840"><br>
*Operator overview — active engagements, validated findings, attack surface, engine health, telemetry pulse.*

<br>

<img src="docs/assets/screens/modules-catalog-hd.png" alt="Module catalog" width="840"><br>
*Catalog — 66 active modules across 13 categories, each annotated with MITRE ATT&CK techniques and OPSEC noise level.*

<br>

<img src="docs/assets/screens/modules-result-hd.png" alt="Finding card after a module run" width="840"><br>
*Results — finding card with severity, confidence, remediation and one-click pivot to the next module.*

<br>

<img src="docs/assets/screens/attack-graph-hd.png" alt="Attack graph" width="840"><br>
*Attack graph — perimeter firewall (fire animation), targets, pivot edges. Read-only beacon telemetry per node.*

<br>

<img src="docs/assets/screens/campaigns-scope-hd.png" alt="Campaign scope" width="840"><br>
*Campaign scope — target campaign picker, Restore Vault / Dry-Run Plan / Delete controls.*

</div>

---

## Features

- **Fail-closed scope enclave** — dual-layer ScopeGuard (application pre-check + OS/transport firewall) guarantees zero offensive packets reach out-of-scope hosts. [→ security model](docs/security-model.md)
- **Goal-directed attack planning** — set `domain_admin` or `cloud_audit`, and the decision engine synthesizes multi-stage execution paths (graph heuristics, optional LLM agents under explicit authorization). [→ engine design](docs/engine_design.md)
- **Multi-vector attack graph (DAG)** — ingest BloodHound or map sessions in real time. Shortest-path, chokepoints, lateral pivot feasibility. [→ attack graph](docs/engine_design.md)
- **Zero-trust auth model** — memory-only short-lived JWTs, HttpOnly rotating refresh, HMAC CSRF, AES-256-GCM AEAD vault (PBKDF2-HMAC-SHA256 600k). [→ security model](docs/security-model.md)
- **66 active production modules** across 60+ MITRE ATT&CK techniques (AD, cloud, credential access, exfil, lateral, recon, Windows, Linux, EDR). [→ module catalog](docs/modules.md)
- **Automated deliverables** — one-click branded PDF/HTML/Markdown/JSON reports via headless browser (no GTK deps on Windows/Linux). [→ dashboard guide](docs/dashboard-guide.md)
- **MCP Gateway** — Cursor/Claude Desktop/Windsurf/Cline can drive ARES safely under Pre-Flight ScopeGuard, anti-prompt-injection taint isolation and single-use HMAC confirmation tokens. [→ MCP spec](docs/mcp-server.md)
- **Type-safe Python SDK** — write custom modules with `BaseModule[P, R]` + `@ares_module`, simulate in `ModuleTestHarness`, automate with `AresClient`. [→ SDK docs](docs/module_sdk.md) · [→ module dev guide](docs/module-development.md)

---

## Quickstart

### Prerequisites

- **Python** 3.11 or 3.12 (3.12 recommended on Windows)
- **Node.js** v18+ (tested on v20 LTS)
- **OS** Windows 11/10, Linux (Ubuntu/Debian/Kali) or macOS

### 60 seconds (PowerShell on Windows)

```powershell
git clone https://github.com/Mafifrizi/ARES.git
Set-Location .\ARES

py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev,pdf]"

Set-Location frontend ; & "C:\Program Files\nodejs\npm.cmd" ci ; Set-Location ..

$env:ARES_PDF_BROWSER = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
.\.venv\Scripts\ares.exe doctor --pdf-smoke

.\.venv\Scripts\ares.exe dashboard dev --no-reload
```

Open `http://127.0.0.1:5173/dashboard/`.
Initial operator: `admin`. Password: set `ARES_DEFAULT_ADMIN_PASSWORD` in `.env` (mandatory, minimum 12 characters, no hardcoded default).

### Tests

```powershell
pytest tests/unit -n auto -q                    # 5,074 tests, parallel
pytest tests/integration/test_postgres_*.py -q  # Postgres integration
```

### In-place upgrades (no git clone / rebuild needed)

```powershell
ares update              # add new modules only
ares upgrade             # full-system upgrade (core + db + modules + UI)
ares upgrade --check     # preview, no changes on disk
```

User databases, credentials, config and plugins are mathematically blacklisted from modification — see [in-place upgrade guarantees](docs/execution-policy.md).

---

## Documentation

Everything deep lives in [`docs/`](docs/). The main entry points:

- [**Quickstart engagement guide**](QUICKSTART.md)
- [**Documentation portal & subsystem index**](docs/README.md)
- [**Dashboard surface-by-surface manual**](docs/dashboard-guide.md)
- [**Module catalog & schemas**](docs/modules.md) · [**Module development**](docs/module-development.md) · [**SDK spec**](docs/module_sdk.md)
- [**API reference**](docs/api-reference.md) · [**MCP gateway**](docs/mcp-server.md) · [**Enterprise SSO (SAML/OIDC)**](docs/sso-setup.md)
- [**Security & threat model**](docs/security-model.md) · [**Execution policy**](docs/execution-policy.md) · [**Validation lab**](docs/validation-lab.md)
- [**Architecture**](docs/architecture.md) · [**Engine design**](docs/engine_design.md) · [**Worker architecture**](docs/worker_architecture.md) · [**Database migrations**](docs/database-migrations.md)
- [**Market comparison**](docs/comparison.md) · [**RFC 001: Linux AD cross-platform tradecraft**](docs/research/linux-active-directory-tradecraft.md)

---

## Support

If ARES has accelerated your assessments or protected your infrastructure, consider sponsoring continued feature development, threat research and lab infrastructure:

<div align="center">

| | |
| :--- | :--- |
| [![GitHub Sponsors](https://img.shields.io/badge/GitHub_Sponsors-ea4aaa?style=flat-square&logo=github-sponsors)](https://github.com/sponsors/Mafifrizi) | International (recurring / one-time) |
| [![Saweria](https://img.shields.io/badge/Saweria-faae2b?style=flat-square&logo=kofi&logoColor=black)](https://saweria.co/mafifrizi) | Indonesia (QRIS, GoPay, OVO, Dana) |

</div>

---

## Credits

<div align="center">

<a href="https://www.linkedin.com/in/muhamad-d-alvito-58607934b/">
  <img src="docs/assets/credits/muhamad-d-alvito.png" width="88" height="88" alt="Muhamad D Alvito" style="border-radius:50%;">
</a>

**[Muhamad D Alvito](https://www.linkedin.com/in/muhamad-d-alvito-58607934b/)** — UI & UX partner

</div>

---

## Responsible use & legal disclaimer

> [!IMPORTANT]
> **ARES is a dual-use software framework designed exclusively for authorized cybersecurity research, internal enterprise resilience validation and professional red-team engagements with explicit written permission.**

- **Do not** execute ARES against any network, host or cloud infrastructure without prior written authorization from the system owners.
- Unauthorized system access or testing violates national and international cybercrime legislation (for example 18 U.S.C. § 1030 Computer Fraud and Abuse Act).
- The creators and maintainers of ARES assume no liability for misuse, damages or regulatory violations caused by this software.

To report security vulnerabilities in ARES itself, follow the [Security Policy](SECURITY.md).

### No affiliation with any cryptocurrency or token

> [!NOTE]
> This project is an **open-source security software platform**. It has **no affiliation, endorsement, partnership or association** with any cryptocurrency, coin, token, NFT, airdrop or financial instrument that uses the name "ARES" or any similar brand. We do not issue, promote or endorse any digital asset. Any such product is unrelated to this project and operates without our involvement or approval. Do not purchase or trade any such asset expecting a connection to this repository.

---

## License

ARES is distributed under the open-source **[MIT License](LICENSE)**.

<br>

<div align="center">

**ARES — Modern Red Team Engagement & Continuous Security Validation System.**<br>
*Continuous security validation. Deterministic scope containment.*

</div>
