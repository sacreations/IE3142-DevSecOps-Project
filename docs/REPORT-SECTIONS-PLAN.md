# SLIIT IE3142 DevSecOps Technical Report: Comprehensive Section Plan

**Module:** IE3142 — DevSecOps  
**Assessment Type:** Final Technical Assessment Report  
**Target Word Count:** 1,800 – 2,500 words (excluding code snippets, tables, appendices, and reference lists)  
**Target System:** Hardened OWASP NodeGoat (Node.js/Express + MongoDB)  

---

## Authors & Group Allocation Matrix

| Student Name | Student ID | Designated Module Role | Exact Git Contribution Scope | Commit Author Metadata |
|:---|:---|:---|:---|:---|
| **Nethika Fernando** | IT21156820 | Infrastructure & Containerization | `Dockerfile`, `docker-compose.yml`, internal networking (`backend-net`), non-root execution (`USER node`). | `Nethika Fernando <nethikafernando887@gmail.com>` |
| **Chanidu Deshan** | IT21168496 | Threat Modeling & Architecture | `docs/threat-model.md`, STRIDE assessment, 5x5 Likelihood vs. Impact matrix, threat-to-control mapping. | `Chanidu Deshan <deshanchanidu@gmail.com>` |
| **Malith Fernando** | IT21179218 | Secure Coding & SAST Verification | `app/data/`, `app/routes/`, `tests/security-regression.test.js`, Semgrep before/after diffs, LO2 remediation. | `Malith Fernando <Malithferdi22556@gmail.com>` |
| **Supun Adithya** | IT21183552 | DevOps CI/CD & Security Automation | `.github/workflows/devsecops.yml`, 4-gate automated pipeline, secrets management, master technical report. | `Supun Adithya <hi@supunadithya.com>` |

---

## Detailed Section Breakdown & Content Guide

### Section 1: Executive Summary & System Overview (~350 words)
- **1.1 Architectural Overview**:
  - Explain the purpose of OWASP NodeGoat as a benchmark vulnerable web application.
  - Detail the transition from a monolithic vulnerable architecture to a hardened, defense-in-depth containerized system.
- **1.2 Multi-Container Isolation Topology**:
  - Web Tier (`nodegoat-web`): Built on `node:20-alpine`, non-root execution under `USER node` (UID 1000), HTTP port 4000 exposed to host.
  - Database Tier (`nodegoat-db`): MongoDB 4.4 attached to isolated Docker bridge network `backend-net`, port 27017 private with NO host binding.
  - Include ASCII and Mermaid Trust Boundary flow diagrams showing external clients, ingress boundary, and internal database link.

### Section 2: Threat Modelling & Risk Assessment (STRIDE) (~450 words)
- **2.1 Threat Identification Across STRIDE**:
  - **T-01 (Tampering / EoP)**: NoSQL Injection on `/login` via JSON object manipulation (`$gt`).
  - **T-02 (EoP / Info Disclosure)**: SSJS Injection / Remote Code Execution in `contributions.js` via `eval()`.
  - **T-03 (Tampering / Info Disclosure)**: Stored Cross-Site Scripting (XSS) in user profile data.
  - **T-04 (EoP / Tampering)**: Insecure Deserialization in `profile.js` via `node-serialize` (`_$$ND_FUNC$$_`).
  - **T-05 (Info Disclosure / Spoofing)**: Direct host binding of MongoDB port 27017.
- **2.2 5x5 Risk Matrix & Scoring Criteria**:
  - Mathematical risk quantification ($Risk = Likelihood \times Impact$, scale 1–25).
  - Pre-mitigation vs. Post-mitigation risk evaluation table showing risk reduction to Low (score $\le 2$).
- **2.3 Threat-to-Control Mitigation Mapping**:
  - Tabular breakdown mapping each threat to specific code remediations and automated pipeline enforcement gates.

### Section 3: Secure Coding & Vulnerability Remediation (LO2) (~600 words)
- **3.1 Flaw 1: NoSQL Injection (CWE-943)**:
  - Root Cause: Unsanitized JSON query parameter passed directly to MongoDB query selectors.
  - Remediation: Strict primitive type validation (`typeof === 'string'`) and whitespace trimming in `app/data/user-dao.js` and `app/routes/session.js`.
  - Evidence: Before/After code diff and Semgrep rule resolution.
- **3.2 Flaw 2: SSJS via `eval()` (CWE-95)**:
  - Root Cause: Dynamic string concatenation executed via `eval("total = " + preTax + " + " + afterTax)`.
  - Remediation: Complete eradication of `eval()`, replacement with `parseFloat()` validation, `isNaN()` checks, and finite float rounding in `app/routes/contributions.js`.
- **3.3 Flaw 3: Stored Cross-Site Scripting (CWE-79)**:
  - Root Cause: Raw string persistence of profile fields rendered unescaped in Swig templates.
  - Remediation: HTML entity encoding using `validator.escape()` across all incoming profile fields in `app/routes/profile.js`.
- **3.4 Flaw 4: Insecure Object Deserialization (CWE-502)**:
  - Root Cause: `node-serialize.unserialize()` parsing untrusted cookie payloads allowing IIFE execution (CVE-2017-5941).
  - Remediation: Complete removal of `node-serialize`, migration to safe native `JSON.parse()`, defensive try/catch, and explicit theme property whitelisting.
- **3.5 Static Analysis (Semgrep SAST) Metrics**:
  - Summary table showing 4 baseline High/Critical findings reduced to 0 in post-remediation scans.

### Section 4: CI/CD Security Pipeline Design & Automation (LO3) (~450 words)
- **4.1 4-Gate Automated Pipeline Architecture**:
  - **Gate 1 (SAST - Semgrep)**: Scans `app/` using `p/javascript` and `p/owasp-top-ten` rule packs; blocks pipeline on High/Critical findings (`--error`).
  - **Gate 2 (SCA - npm audit)**: Audits package dependencies and lockfile, exports structured JSON audit artifact.
  - **Gate 3 (Secrets - Gitleaks)**: Scans entire git history (`fetch-depth: 0`, `GITLEAKS_SCAN_ALL: "true"`) for leaked credentials.
  - **Gate 4 (Container Security - Aquasec Trivy)**: Scans built image `nodegoat-web:${{ github.sha }}` for CRITICAL/HIGH CVEs with `exit-code: 1` blocking.
- **4.2 Gate Enforcement & Failure Blocking Policies**:
  - Document the blocking behavior: if any gate detects high/critical vulnerabilities, the build terminates and downstream deployment is halted.
- **4.3 Demonstrable Pipeline Failure vs. Success**:
  - Guide to positive pipeline runs (all gates passing) vs. negative pipeline runs (intentional security violation triggering automated failure).

### Section 5: Secrets Management Architecture (~250 words)
- **5.1 Zero Plaintext Credentials Policy**:
  - Environment variable isolation (`SESSION_SECRET`, `MONGODB_URI`).
  - GitHub Actions Encrypted Secrets masked in runner logs (`***`).
  - Repository protection rules (`.gitignore`, `.dockerignore`).
- **5.2 Enterprise Secret Integration (HashiCorp Vault Blueprint)**:
  - Architectural blueprint for dynamic, ephemeral database credential leasing with short TTLs.

### Section 6: Industry Supply Chain Case Study - Codecov (~300 words)
- **6.1 Attack Chain & Incident Breakdown**:
  - April 2021 Codecov Bash Uploader breach (GCS key leak in Docker image $\rightarrow$ script modification $\rightarrow$ CI secret exfiltration).
- **6.2 Direct Mapping to Our DevSecOps Architecture**:
  - Gate 3 (Gitleaks) prevents committed cloud keys.
  - Gate 2 (SCA & Lockfiles) prevents untrusted script/dependency substitution.
  - Gate 4 (Trivy) & non-root execution (`USER node`) prevent image layer backdoors and lateral movement.

### Section 7: Critical Reflection & Future Enhancements (~150 words)
- **7.1 Dynamic Application Security Testing (DAST)**: Integrating OWASP ZAP baseline scans against running containers.
- **7.2 Cryptographic Artifact Signing**: Implementing Sigstore Cosign with Kubernetes Kyverno admission control.
- **7.3 SLSA Level 3 Provenance**: Generating non-falsifiable build attestations for end-to-end supply chain transparency.

### Section 8: Contribution Matrix & AI Disclosure (~150 words)
- **8.1 Member Contribution Matrix**: Table detailing each member's specific deliverables and commit links.
- **8.2 AI Tooling Disclosure**: Formal statement outlining responsible use of AI assistance (Claude Code) in accordance with SLIIT academic policies.

### Section 9: IEEE References
- Formal IEEE-formatted citations covering Codecov advisory, OWASP Top 10, SLSA framework, Semgrep, and Trivy.
