# IE3142 DevSecOps Project — OWASP NodeGoat Hardening & Automation

[![DevSecOps Pipeline](https://img.shields.io/badge/CI%2FCD-4%20Security%20Gates-brightgreen)](.github/workflows/devsecops.yml)
[![Semgrep](https://img.shields.io/badge/SAST-Semgrep%20Passing-blue)](evidence/sast/semgrep-after.txt)
[![Trivy](https://img.shields.io/badge/Container%20Scan-Trivy%20Enforced-orange)](docs/cicd-pipeline.md)
[![License](https://img.shields.io/badge/Academic-SLIIT%20IE3142-red)](CLAUDE.md)

Academic DevSecOps implementation and security assessment for the **SLIIT IE3142** module, targeting OWASP NodeGoat (Node.js/Express + MongoDB).

---

## 👥 Team Roster & Responsibility Matrix

| Member Name | Email | Module Scope | Key Deliverables |
| :--- | :--- | :--- | :--- |
| **Nethika Fernando** | `nethikafernando887@gmail.com` | Infrastructure & Docker | [Dockerfile](Dockerfile), [docker-compose.yml](docker-compose.yml), non-root execution, `backend-net` isolation. |
| **Chanidu Deshan** | `deshanchanidu@gmail.com` | Threat Modeling | [docs/threat-model.md](docs/threat-model.md), STRIDE analysis, 5x5 risk matrix, threat-to-control mapping. |
| **Malith Fernando** | `member3@example.com` | Secure Coding & SAST | [app/](app/), [tests/security-regression.test.js](tests/security-regression.test.js), Semgrep diffs, [evidence/](evidence/). |
| **Supun Adithya** | `hi@supunadithya.com` | DevOps & Security CI/CD | [.github/workflows/devsecops.yml](.github/workflows/devsecops.yml), [docs/cicd-pipeline.md](docs/cicd-pipeline.md), [docs/secrets-management.md](docs/secrets-management.md). |

---

## 🏗️ System Architecture & Container Isolation

The deployment architecture is partitioned into a two-tier container environment communicating across an internal bridge network:

```
+-----------------------------------------------------------------------------+
|                            UNTRUSTED ZONE                                   |
|               [ Public Internet / External User: Port 4000 ]                |
+-----------------------------------------------------------------------------+
                                       |
============================== TRUST BOUNDARY 1 ===============================
                                       v
+-----------------------------------------------------------------------------+
| DOCKER BRIDGE NETWORK: backend-net (Isolated)                               |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  | Web Container (`web`) - Execution Context: USER node (UID 1000)        |  |
|  | - Node.js 14 Alpine Base Image                                        |  |
|  | - Port 4000 Ingress                                                   |  |
|  +-----------------------------------------------------------------------+  |
|                                     |                                       |
|============================= TRUST BOUNDARY 2 ==============================|
|                                     v (mongodb://db:27017 - No Host Port)   |
|  +-----------------------------------------------------------------------+  |
|  | Database Container (`db`) - Service: mongo:4.4                         |  |
|  | - Port 27017 Strictly Internal to `backend-net`                       |  |
|  | - Zero Host Port Bindings                                             |  |
|  +-----------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------+
```

### Key Architectural Hardening Steps:
1. **Non-Root Execution:** The web container drops root privileges and executes as unprivileged user `node` in [Dockerfile](Dockerfile).
2. **Database Isolation:** Port `27017` is bound exclusively to `backend-net` in [docker-compose.yml](docker-compose.yml) with zero host exposure.
3. **Dynamic Configuration:** Secrets and environment settings are dynamically passed via `.env` (template at [.env.example](.env.example)).

---

## 🛡️ Vulnerability Remediation Summary (LO2)

Four core vulnerabilities in OWASP NodeGoat were identified, remediated, regression-tested, and verified with Semgrep SAST:

| # | Vulnerability Class | CWE | Location | Remediation Mechanism | Semgrep Before | Semgrep After |
| :-: | :--- | :-: | :--- | :--- | :-: | :-: |
| **1** | **NoSQL Injection** | CWE-943 | [app/data/user-dao.js](app/data/user-dao.js)<br>[app/routes/session.js](app/routes/session.js) | Enforced strict `typeof === 'string'` guards on all query arguments. | 1 HIGH | **0 (Clean)** |
| **2** | **SSJS / `eval()` RCE** | CWE-95 | [app/routes/contributions.js](app/routes/contributions.js) | Removed `eval()`; implemented strict regex validation & safe `Number()` math. | 1 CRITICAL | **0 (Clean)** |
| **3** | **Stored XSS** | CWE-79 | [app/routes/profile.js](app/routes/profile.js) | Applied `validator.escape()` on all profile inputs before persistence. | 1 MEDIUM | **0 (Clean)** |
| **4** | **Insecure Deserialization** | CWE-502 | [app/routes/profile.js](app/routes/profile.js) | Removed `node-serialize`; replaced with `JSON.parse()` & schema whitelisting. | 1 CRITICAL | **0 (Clean)** |

*Complete technical diffs, root-cause analyses, and scan logs are detailed in [evidence/security-remediation-report.md](evidence/security-remediation-report.md).*

---

## 🚀 DevSecOps CI/CD Pipeline (LO3)

The GitHub Actions workflow at [.github/workflows/devsecops.yml](.github/workflows/devsecops.yml) implements four automated security gates:

```
[ Push / PR to main ]
          │
          ├──► Gate 1: SAST (Semgrep p/javascript & p/owasp-top-ten) ────► Blocks on High/Critical
          ├──► Gate 2: SCA (npm audit --audit-level=high) ───────────────► Scans Dependencies
          ├──► Gate 3: Secrets (Gitleaks) ───────────────────────────────► Scans Git History
          │
          ▼
   [ Docker Build ]
          │
          └──► Gate 4: Container Scan (Aquasec Trivy) ───────────────────► Blocks on CVEs (exit-code: 1)
          │
          ▼
   [ Deploy & Runtime Secret Injection (SESSION_SECRET, MONGODB_URI) ]
```

*For complete gate policies, SARIF reporting, and instructions on testing passing vs. blocked pipeline builds, refer to [docs/cicd-pipeline.md](docs/cicd-pipeline.md).*

---

## 🔐 Secrets Management & Runtime Injection

- **Zero-Credential Policy:** Source code and configuration files contain zero plaintext secrets or connection strings.
- **Runtime Injection:** `SESSION_SECRET` and `MONGODB_URI` are injected at runtime via GitHub Actions Encrypted Secrets (`${{ secrets.SESSION_SECRET }}`).
- **Local Development:** Run `cp .env.example .env` and supply local non-production keys.
- **Enterprise Design:** See [docs/secrets-management.md](docs/secrets-management.md) for dynamic secret rotation patterns using HashiCorp Vault.

---

## 🧪 Local Verification & Testing

### 1. Run the Security Regression Suite
```bash
node tests/security-regression.test.js
```

### 2. Start the Hardened Container Stack
```bash
cp .env.example .env
docker compose up --build -d
```

### 3. Verify Database Isolation
```bash
# Verify MongoDB port 27017 is NOT accessible on host:
nc -zv 127.0.0.1 27017 || echo "MongoDB is strictly isolated to backend-net"
```

---

## 📁 Repository Structure

```text
.
├── .github/
│   └── workflows/
│       └── devsecops.yml            # 4-Gate DevSecOps CI/CD Workflow
├── app/
│   ├── data/
│   │   └── user-dao.js              # Remediated NoSQLi Query DAO
│   └── routes/
│       ├── contributions.js         # Remediated eval() Contributions Handler
│       ├── profile.js               # Remediated XSS & Deserialization Handler
│       └── session.js               # Remediated Authentication Route
├── docs/
│   ├── cicd-pipeline.md             # Pipeline Design & Gate Documentation
│   ├── secrets-management.md        # Secrets Architecture & Vault Blueprint
│   └── threat-model.md              # STRIDE Threat Model & 5x5 Risk Matrix
├── evidence/
│   ├── sast/
│   │   ├── semgrep-before.txt       # Baseline Semgrep Scan Output
│   │   └── semgrep-after.txt        # Post-Remediation Semgrep Scan Output
│   └── security-remediation-report.md # Comprehensive LO2 Remediation Walkthrough
├── tests/
│   └── security-regression.test.js  # Automated Security Regression Suite
├── .dockerignore
├── .env.example
├── CLAUDE.md                        # Project Guidelines & Attribution Rules
├── Dockerfile                       # Hardened Non-Root Container Spec
├── docker-compose.yml               # Isolated 2-Tier Stack Definition
└── README.md                        # Project Documentation
```
