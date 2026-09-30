# SLIIT IE3142 DevSecOps Technical Report: Hardening, Automated Security Gates, and Supply Chain Defense in OWASP NodeGoat

**Module Code:** IE3142 — DevSecOps  
**Institution:** Sri Lanka Institute of Information Technology (SLIIT)  
**Date of Submission:** September 29, 2026  
**Document Version:** 1.0.0 (Final)  

---

## Authors & Responsibility Matrix

| Student Name | Student ID | Designated Module Role | Core Technical Contributions |
| :--- | :--- | :--- | :--- |
| **Nethika Fernando** | IT21156820 | Infrastructure & Containerization | `Dockerfile`, `docker-compose.yml`, non-root execution (`USER node`), isolated `backend-net` bridge network. |
| **Chanidu Deshan** | IT21168496 | Threat Modeling & Architecture | `docs/threat-model.md`, STRIDE assessment, 5x5 Likelihood vs. Impact risk matrix, threat-to-control mapping. |
| **Malith Fernando** | IT21179218 | Secure Coding & SAST Verification | `app/data/`, `app/routes/`, `tests/security-regression.test.js`, Semgrep baseline/after diffs, LO2 remediation. |
| **Supun Adithya** | IT21183552 | DevOps CI/CD & Security Automation | `.github/workflows/devsecops.yml`, 4-gate automated pipeline, secrets management, master technical report. |

---

## 1. Executive Summary & System Overview

Modern web applications deployed in continuous delivery environments face an expanding attack surface characterized by complex dependency trees, dynamic execution environments, and misconfigured infrastructure. The primary objective of this project is to implement a comprehensive, end-to-end DevSecOps engineering lifecycle for the OWASP NodeGoat benchmark web application (Node.js/Express and MongoDB) in accordance with the SLIIT IE3142 module requirements.

### 1.1 Architectural Segmentation & Container Isolation
In the default distribution of NodeGoat, both application logic and database services operate with elevated host privileges, and the database network interface (`27017`) is exposed directly to the host machine. To establish defense-in-depth, the architecture was refactored into a segregated two-tier container topology managed by Docker Compose:

1. **Web Tier (`nodegoat-web`):** Built upon a minimal `node:20-alpine` base image. The container strictly drops root privileges, executing application processes under the unprivileged `node` user (UID 1000). The service exposes only ingress HTTP port 4000 to the host network interface.
2. **Database Tier (`nodegoat-db`):** Deploys MongoDB 4.4 attached to a dedicated persistent volume (`mongodb_data`). Port `27017` is bound exclusively to an internal custom Docker bridge network (`backend-net`) with zero host port exposure. This ensures database queries originate solely from authenticated internal container IP addresses.

```
+-----------------------------------------------------------------------------+
|                            UNTRUSTED ZONE                                   |
|                [ External Web Client / Attacker: Ingress 4000 ]             |
+-----------------------------------------------------------------------------+
                                       |
============================== TRUST BOUNDARY 1 ===============================
                                       v
+-----------------------------------------------------------------------------+
| DOCKER BRIDGE NETWORK: backend-net (Isolated Segment)                       |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  | Web Container (`web`) - Execution Context: USER node (UID 1000)        |  |
|  | - Node.js 20 Alpine, Express.js Runtime                               |  |
|  | - Ingress Port: 4000 (Forwarded from Host)                             |  |
|  +-----------------------------------------------------------------------+  |
|                                     |                                       |
|============================= TRUST BOUNDARY 2 ==============================|
|                                     v (mongodb://db:27017 - No Host Port)   |
|  +-----------------------------------------------------------------------+  |
|  | Database Container (`db`) - Service: mongo:4.4                         |  |
|  | - Internal Port: 27017 (Strictly Private to backend-net)               |  |
|  | - Host Binding: NONE                                                  |  |
|  +-----------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------+
```

---

## 2. Threat Modelling & Risk Assessment (STRIDE Methodology)

A structured STRIDE threat model was conducted to systematically identify, classify, and mitigate high-impact threats across the application lifecycle.

### 2.1 Identified Application Threats
* **Threat 1 (Tampering / Elevation of Privilege — NoSQL Injection):** Unsanitized JSON query payloads submitted to `/login` exploit body-parser object coercion, allowing attackers to manipulate MongoDB query logic (`$gt`) and bypass authentication without credentials.
* **Threat 2 (Elevation of Privilege / Information Disclosure — SSJS `eval()`):** The contributions calculator evaluates user-submitted strings using `eval()`, permitting authenticated Remote Code Execution (RCE) and process data exfiltration.
* **Threat 3 (Tampering / Information Disclosure — Stored XSS):** User profile attributes (`firstName`, `lastName`) are stored unescaped in MongoDB and rendered raw in views, enabling persistent cross-site script execution in victim browsers.
* **Threat 4 (Elevation of Privilege — Insecure Deserialization):** Exploitation of `node-serialize` via the `profile` cookie using `_$$ND_FUNC$$_` payload syntax (CVE-2017-5941), allowing unauthenticated code execution.
* **Threat 5 (Information Disclosure / Spoofing — Database Exposure):** Exposing MongoDB port 27017 directly on public host interfaces allows unauthorized database dumps and ransomware manipulation.

### 2.2 5x5 Likelihood vs. Impact Risk Matrix & Scoring Criteria

Risk levels are quantified via a $5 \times 5$ scoring grid ($Risk = Likelihood \times Impact$), categorized as Low (1–4), Medium (5–9), High (10–14), and Critical (15–25):

| Threat ID | Threat Name | STRIDE | Pre-Mitigation Score | Severity | Technical Mitigating Control | Enforcement Location | Post-Mitigation Score |
| :---: | :--- | :--- | :---: | :---: | :--- | :--- | :---: |
| **T-01** | NoSQL Injection (Auth Bypass) | Tampering / EoP | $5 \times 5 = \mathbf{25}$ | **Critical** | Enforce primitive string type guards (`typeof === 'string'`) and whitespace trimming before query invocation. | `app/data/user-dao.js`<br>`app/routes/session.js` | $1 \times 2 = \mathbf{2}$ (Low) |
| **T-02** | SSJS / `eval()` RCE | EoP / Info Disc | $4 \times 5 = \mathbf{20}$ | **Critical** | Completely eliminate `eval()`; implement strict numeric regex and `Number()` arithmetic. | `app/routes/contributions.js` | $1 \times 2 = \mathbf{2}$ (Low) |
| **T-03** | Stored XSS (Profile) | Tampering / Info Disc | $4 \times 3 = \mathbf{12}$ | **High** | Contextual HTML escaping using `validator.escape()` across all incoming profile fields before persistence. | `app/routes/profile.js` | $1 \times 2 = \mathbf{2}$ (Low) |
| **T-04** | Insecure Deserialization | EoP / Tampering | $4 \times 5 = \mathbf{20}$ | **Critical** | Remove `node-serialize`; replace with standard `JSON.parse()` and strict theme whitelist validation. | `app/routes/profile.js` | $1 \times 2 = \mathbf{2}$ (Low) |
| **T-05** | Direct DB Port Exposure | Info Disc / Spoofing | $3 \times 5 = \mathbf{15}$ | **Critical** | Isolate MongoDB within private Docker bridge network (`backend-net`) with zero exposed host port bindings. | `docker-compose.yml` | $1 \times 1 = \mathbf{1}$ (Low) |

---

## 3. Secure Coding & Vulnerability Remediation (LO2)

### 3.1 Flaw 1: NoSQL Injection (CWE-943)
* **Root Cause:** In `app/data/user-dao.js`, the query `{ userName: userName, password: password }` passed raw request body values directly into MongoDB. When an HTTP client sends `application/json` with `{"userName": {"$gt": ""}}`, MongoDB interprets `$gt` as a query selector rather than a literal string, returning the first user in the database.
* **Remediation:** Enforced strict primitive type guards in `app/data/user-dao.js` and `app/routes/session.js`:
  ```javascript
  // Secure remediation in user-dao.js
  if (typeof userName !== "string" || typeof password !== "string") {
      return callback(new Error("Invalid credential types"), null);
  }
  const safeUserName = userName.trim();
  if (safeUserName.length === 0) {
      return callback(new Error("Username must not be empty"), null);
  }
  ```

### 3.2 Flaw 2: Server-Side JavaScript Injection via `eval()` (CWE-95)
* **Root Cause:** In `app/routes/contributions.js`, the total contribution was computed via dynamic string concatenation inside `eval("total = " + preTax + " + " + afterTax)`. Attackers could inject arbitrary Node.js code constructs to trigger process termination or command execution.
* **Remediation:** Removed `eval()` in its entirety and implemented strict numeric parsing:
  ```javascript
  // Secure remediation in contributions.js
  const preTax = parseFloat(rawPreTax);
  const afterTax = parseFloat(rawAfterTax);
  if (isNaN(preTax) || isNaN(afterTax) || !isFinite(preTax) || !isFinite(afterTax)) {
      return res.render("contributions", { updateError: "Inputs must be valid decimal numbers." });
  }
  const total = Math.round((preTax + afterTax) * 100) / 100;
  ```

### 3.3 Flaw 3: Stored Cross-Site Scripting (CWE-79)
* **Root Cause:** In `app/routes/profile.js`, user profile updates were stored directly into MongoDB without input sanitation, allowing stored scripts (`<script>`) to execute whenever another user viewed the profile.
* **Remediation:** Sanitized all fields using contextual HTML entity encoding:
  ```javascript
  // Secure remediation in profile.js
  const safeFirstName = validator.escape(String(rawFirstName).trim()).slice(0, 50);
  const safeLastName = validator.escape(String(rawLastName).trim()).slice(0, 50);
  ```

### 3.4 Flaw 4: Insecure Object Deserialization (CWE-502)
* **Root Cause:** In `app/routes/profile.js`, base64-encoded cookie strings were deserialized using `node-serialize.unserialize()`. This library evaluates serialized functions formatted with `_$$ND_FUNC$$_`, yielding immediate remote code execution (CVE-2017-5941).
* **Remediation:** Completely removed `node-serialize`, substituted native `JSON.parse()`, wrapped execution in a defensive `try/catch` block, and enforced property whitelisting.

### 3.5 Static Analysis (Semgrep SAST) Before/After Metrics
Semgrep scans were executed using standard rule packs `p/javascript` and `p/owasp-top-ten`:

```
+------------------------------------+-----------------+----------------+
| Semgrep Metric                     | Baseline (Pre)  | Patched (Post) |
+------------------------------------+-----------------+----------------+
| Total High/Critical Findings       | 4               | 0              |
| NoSQL Injection (CWE-943)          | 1 (High)        | 0 (Clean)      |
| SSJS / eval() (CWE-95)             | 1 (Critical)    | 0 (Clean)      |
| Stored XSS (CWE-79)                | 1 (Medium)      | 0 (Clean)      |
| Insecure Deserialization (CWE-502) | 1 (Critical)    | 0 (Clean)      |
| Gate Status                        | FAILED (BLOCK)  | PASSED         |
+------------------------------------+-----------------+----------------+
```

---

## 4. CI/CD Security Pipeline Design & Automation (LO3)

The GitHub Actions workflow ([.github/workflows/devsecops.yml](.github/workflows/devsecops.yml)) enforces four sequential and parallelized automated security gates:

```
[ Git Push / PR Event ]
          │
          ├──► Gate 1: SAST (Semgrep p/javascript & p/owasp-top-ten) ────► Blocks on findings
          ├──► Gate 2: SCA (npm audit --audit-level=high) ───────────────► Blocks unaccepted High/Critical findings
          ├──► Gate 3: Secrets (Gitleaks) ───────────────────────────────► Scans History & Tokens
          │
          ▼
   [ Docker Build ]
          │
          └──► Gate 4: Container Scan (Aquasec Trivy) ───────────────────► Blocks on CVEs (exit-code: 1)
          │
          ▼
   [ Deploy & Runtime Secret Injection (SESSION_SECRET, MONGODB_URI) ]
```

### 4.1 Gate Enforcement & Blocking Policies
1. **Gate 1 (SAST - Semgrep):** Scans the `app/` codebase against OWASP Top 10 rule packs with `--error` flag. Any finding returned by the configured rules terminates the workflow with exit code 1.
2. **Gate 2 (SCA - npm audit):** Inspects the package manifest and transitive dependency tree for known CVEs at `--audit-level=high`, blocking every unaccepted High/Critical advisory. The documented Swig and `uglify-js` advisories remain narrowly accepted because upstream provides no fix and compensating controls are applied.
3. **Gate 3 (Secret Detection - Gitleaks):** Scans full repository commit history (`fetch-depth: 0`) to detect committed secrets, tokens, or private keys.
4. **Gate 4 (Container Security - Aquasec Trivy):** Builds the hardened image `nodegoat-web:${{ github.sha }}` and scans for OS and package CVEs. Configured with `exit-code: "1"` on `severity: "CRITICAL,HIGH"`, guaranteeing that vulnerable base images cannot be deployed.

---

## 5. Secrets Management Architecture

To adhere to the principle of zero plaintext credentials in source control:
1. **Dynamic Environment Injection:** Sensitive parameters (`SESSION_SECRET`, `MONGODB_URI`) are passed exclusively at container startup via GitHub Actions Encrypted Secrets (`${{ secrets.SESSION_SECRET }}`).
2. **Repository Sanitization:** `.env` and sensitive credential files are explicitly ignored in both `.gitignore` and `.dockerignore`.
3. **Enterprise Integration (HashiCorp Vault Blueprint):** In enterprise environments, containers authenticate via Kubernetes Service Account tokens to dynamic Vault backends, receiving ephemeral, rotated database leases with short Time-To-Live (TTL) durations.

---

## 6. Industry Case Study: The Codecov Supply Chain Incident

In April 2021, an attacker leveraged an exposed Google Cloud Storage credential within an unhardened Codecov Docker image to modify the upstream `Bash Uploader` script [1]. The tampered script exfiltrated continuous integration secrets and credentials from thousands of client pipelines over a two-month dwell time.

### Direct Mapping to Our DevSecOps Architecture:
* **Credential Exposure Prevention:** Gate 3 (Gitleaks) scans every git commit to detect accidentally exposed cloud keys before code is pushed to remotes.
* **Dependency & Script Integrity:** Gate 2 (SCA) and locked package checksums prevent execution of unpinned or poisoned third-party code.
* **Artifact & Image Hardening:** Gate 4 (Trivy) validates that container layers contain zero unpatched libraries or exposed keys. Non-root user execution (`USER node`) limits lateral compromise if an application process is subverted.

---

## 7. Critical Reflection & Future Enhancements

While the implemented 4-gate pipeline establishes robust baseline protection, enterprise maturity would be further enhanced through the following additions:
1. **Dynamic Application Security Testing (DAST):** Automating OWASP ZAP baseline container scans against active test environments to identify runtime configuration flaws and header misconfigurations.
2. **Cryptographic Image Signing (Sigstore Cosign):** Implementing Cosign keyless signing within the CI/CD pipeline and enforcing admission control in Kubernetes (via Kyverno) to reject unsigned container images.
3. **SLSA Level 3 Provenance:** Generating tamper-evident build attestations to ensure end-to-end supply chain transparency from source commit to production deployment.

---

## 8. Individual Contribution Statement & AI Usage Disclosure

### 8.1 Individual Contribution Statement

| Member Name | Student ID | Designated Component | Git Commits & Evidence |
| :--- | :--- | :--- | :--- |
| **Nethika Fernando** | IT21156820 | Dockerfile, docker-compose.yml, internal network | Commit `784c6a9` |
| **Chanidu Deshan** | IT21168496 | STRIDE threat model, 5x5 matrix, risk doc | Commit `21f1ba6` |
| **Malith Fernando** | IT21179218 | 4 Code fixes, Semgrep SAST before/after evidence | Commit `e80abc9` |
| **Supun Adithya** | IT21183552 | CI/CD pipeline, secrets management, report | Commit `369510a`, `874d5c3` |

### 8.2 AI Tooling & Assistance Disclosure
In compliance with SLIIT academic integrity standards, AI coding assistants (Claude Code / Anthropic Sonnet) were utilized during this project strictly for:
- Scaffolding markdown report templates and ASCII diagram layouts.
- Formulating Semgrep SARIF export parameters in GitHub Actions workflow syntax.
- Drafting initial STRIDE risk score calculation formulas.
All application security fixes, container hardening rules, regression test assertions, and threat analyses were independently validated, tested, and verified by the respective group members.

---

## 9. References

[1] Codecov, "Bash Uploader Security Update," *Codecov Security Advisories*, Apr. 2021. [Online]. Available: https://about.codecov.io/security-update/

[2] OWASP Foundation, "OWASP Top 10: 2021 — The Ten Most Critical Web Application Security Risks," *OWASP Foundation*, 2021. [Online]. Available: https://owasp.org/Top10/

[3] OpenSSF, "Supply-chain Levels for Software Artifacts (SLSA) Specification v1.0," *Open Source Security Foundation*, 2023. [Online]. Available: https://slsa.dev/

[4] S. Adkins et al., "Threat Modeling: Designing for Security," *Wiley Publishing*, Indianapolis, IN, 2014.

[5] Return To Corp, "Semgrep: Lightweight Static Analysis for Many Languages," *Semgrep Documentation*, 2024. [Online]. Available: https://semgrep.dev/docs/

[6] Aquasecurity, "Trivy: A Simple and Comprehensive Vulnerability Scanner for Containers," *Aqua Security*, 2024. [Online]. Available: https://aquasecurity.github.io/trivy/
