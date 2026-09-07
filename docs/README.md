# ARES Documentation Portal

Welcome to the technical documentation repository for **ARES (Automated Red team Engagement System)**. This directory contains detailed architecture specifications, security models, developer guides, operator manuals, and API references.

---

## 1. Documentation Index

The documentation is organized into five functional pillars:

### Architecture and Core Engine
| Document | Description | Target Audience |
| --- | --- | --- |
| [architecture.md](architecture.md) | High-level system architecture, component boundaries, and subsystem relationships. | Architects, Contributors |
| [engine_design.md](engine_design.md) | Deep dive into the autonomous planner, knowledge base, and graph execution engine. | Core Engineers |
| [ENGINE_FLOW.md](ENGINE_FLOW.md) | Complete end-to-end execution flow from CLI/API dispatch down to worker execution. | Developers, Operators |
| [execution-lifecycle.md](execution-lifecycle.md) | Deterministic state machine, CAS transitions, and settlement contracts. | Core Engineers, Auditors |
| [execution-policy.md](execution-policy.md) | Safety policies, scope guardrails, rate limiting, and dangerous action gates. | Red Team Leads, SecOps |
| [worker_architecture.md](worker_architecture.md) | Subprocess worker isolation, process boundaries, and IPC communication. | Systems Engineers |

### Attack Modules and Module SDK
| Document | Description | Target Audience |
| --- | --- | --- |
| [modules.md](modules.md) | Comprehensive catalog of all 28 attack modules and 81 capability definitions. | Operators, Red Team |
| [MODULE_GUIDE.md](MODULE_GUIDE.md) | Operator quickstart for executing and chaining modules across target hosts. | Operators |
| [module-development.md](module-development.md) | Step-by-step developer guide for writing, testing with `ModuleTestHarness`, and signing attack modules. | Module Developers |
| [module_sdk.md](module_sdk.md) | Modern v2 SDK specification (`BaseModule[P, R]`, Pydantic v2 params, testing harness, and `AresClient`). | Developers, Integrators |
| [mcp-server.md](mcp-server.md) | Universal Model Context Protocol (MCP) server architecture, 7 security guarantees, and multi-client setup. | AI Engineers, Operators |

### API, Security and Database
| Document | Description | Target Audience |
| --- | --- | --- |
| [api-reference.md](api-reference.md) | Full FastAPI endpoint specification, query parameters, and JSON payloads. | API Consumers, Integrators |
| [security-model.md](security-model.md) | Formal threat model, credential encryption, memory protection, and CSRF isolation. | Security Architects, Auditors |
| [database-migrations.md](database-migrations.md) | Alembic revision chain (0001 to 0011), SQLite/PostgreSQL schema parity, and adoption. | DBAs, DevOps |
| [validation-lab.md](validation-lab.md) | Local hermetic validation lab specification and automated safety test harness. | QA, Core Engineers |

### Frontend and Operator Interface
| Document | Description | Target Audience |
| --- | --- | --- |
| [frontend.md](frontend.md) | React 18 + Vite dashboard architecture, Web Locks, session management, and state coordination. | Frontend Engineers |
| [dashboard-guide.md](dashboard-guide.md) | Complete operational cockpit guide: campaigns, modules, telemetry, and live telemetry. | Red Team Operators |

### Release and Community
| Document | Description | Target Audience |
| --- | --- | --- |
| [github-publish-guide.md](github-publish-guide.md) | Checklist for version tagging, repository sanitization, and release publication. | Maintainers |
| [community-posts.md](community-posts.md) | Announcement templates and release communications for community platforms. | Maintainers |

---

## 2. System Architecture Overview

ARES decouples policy enforcement, orchestration, data storage, and presentation into distinct, audited layers:

```text
+-------------------------------------------------------------------------+
|                         OPERATOR SURFACES                               |
|   ARES CLI (typer_main.py)           React 18 Dashboard (frontend/)     |
+-------------------------------------------------------------------------+
                                    |
                       HTTP REST / Secure WebSocket
                                    |
+-------------------------------------------------------------------------+
|                           FASTAPI SERVER                                |
|   Authentication & RBAC             CSRF & SameSite Origin Boundary     |
|   Campaign & Target Handlers        Single-Use WebSocket Ticket Engine  |
+-------------------------------------------------------------------------+
                                    |
+-------------------------------------------------------------------------+
|                           ARES CORE ENGINE                              |
|   AresEngine (orchestration)        ExecutionPolicyKernel (gatekeeping) |
|   OutcomeKnowledgeBase (learning)   ScopeGuard (CIDR enforcement)       |
+-------------------------------------------------------------------------+
        |                                                 |
+------------------------------+        +---------------------------------+
|      ATTACK MODULES          |        |        PERSISTENCE LAYER        |
|  28 Built-in Attack Modules  |        |  AresDatabase (SQLite / PG)     |
|  81 Capability Bindings      |        |  Fernet Vault Encryption        |
|  Safe Preview & Execution    |        |  Alembic Migrations (Head 0011) |
+------------------------------+        +---------------------------------+
```

---

## 3. Enterprise Design Principles (Anti-Slop Guidelines)

The ARES user interface adheres to strict enterprise product design principles, benchmarked against platforms like Datadog, Linear, and SentinelOne:

1. **Zero AI-Slop / Frivolous Sci-Fi Tropes**:
   - The login surface is a clean, focused, authoritative card (`width: 380px`) with clear input labels, crisp focus rings, and high-contrast solid buttons.
   - Blinking status lights, fake cipher text streams, and decorative padlock icons are strictly prohibited.
   - Frivolous badges such as `AIRGAPPED ENCLAVE` have been eliminated from navigation sidebars.

2. **Tailored HSL Design Tokens**:
   - Interface colors are structured through semantic HSL tokens: `--ares-bg`, `--ares-surface`, `--ares-surface-elevated`, and `--ares-border`.
   - Functional accent colors convey actionable state: `--ares-accent` (enterprise blue), `--ares-success`, `--ares-warning`, and `--ares-danger`.

3. **High-Density Typography and Clean Data Presentation**:
   - Monospace fonts are reserved exclusively for machine evidence: IP addresses, CIDR blocks, SHA-256 hashes, Kerberos tickets, and CVSS vector strings.
   - Metric cards display pure numeric values, clean trend deltas, and concise titles without decorative floating icons.
   - Action buttons are text-first, functional, and explicit (`Restore Vault`, `Dry Run Plan`, `Create Campaign`).

---

## 4. Security and Execution Guarantees

ARES enforces security controls at the kernel level:

- **Strict Origin and CSRF Isolation**:
  - Browser requests are bound to same-origin with strict CSRF cookie verification.
  - Refresh tokens reside exclusively in host-only HttpOnly cookies and are rotated under origin-global Web Locks (`ares-refresh-cookie-v2`).
- **Single-Use WebSocket Tickets**:
  - Live campaign streams authenticate using time-limited (30s) single-use tickets verified through atomic Compare-And-Swap (CAS) database transactions.
  - Tokens and API keys are never transmitted over WebSocket URLs or stored in browser storage.
- **Scope and Opsec Boundaries**:
  - Every network action is strictly validated against user-defined CIDR scope boundaries. Out-of-scope executions are blocked immediately with hard exceptions.
  - Execution preview mode (`dry_run=True`) validates inputs and schema without dispatching any packets across the network.

---

## 5. Verification and Quality Assurance

The codebase maintains rigorous automated test coverage across all layers:

- **Frontend Suite**: 128 / 128 Vitest assertions passing with 0 TypeScript compilation errors.
- **Module Catalog**: 942 / 942 unit tests verifying contract adherence, descriptor readiness, and execute adapters.
- **Core Engine and Security**: 1,141 / 1,141 tests covering execution policies, ticket CAS mechanics, rate limiters, and worker admission.
- **API and Integration**: 277 REST/WebSocket endpoint tests, 70 end-to-end scenario simulations, and 148 database integration tests.
- **Total Verification**: Over 2,800 automated tests passing with zero failures.

---

## 6. Getting Started

For immediate hands-on setup, consult the following guides:
- [QUICKSTART.md](../QUICKSTART.md): Initial repository clone, Python virtual environment, and first campaign execution.
- [dashboard-guide.md](dashboard-guide.md): Running the local development launcher and navigating the operator cockpit.
- [module-development.md](module-development.md): Developing custom attack modules using the ARES Module SDK.
