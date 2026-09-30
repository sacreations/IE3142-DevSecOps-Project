# Defensive Security Remediation & SAST Audit Report (LO2)

**Project:** SLIIT IE3142 DevSecOps Assessment  
**Author / Responsible Engineer:** Malith Fernando (`Malithferdi22556@gmail.com`)
**Target Codebase:** OWASP NodeGoat  
**Date:** 2026-09-29  
**Status:** Remediated & Validated (4/4 Flaws Resolved)  

---

## 1. Executive Summary

This report documents the defensive remediation of 4 critical/high vulnerabilities identified in OWASP NodeGoat. Each vulnerability was traced to its programmatic root cause, remediated using industry-standard secure coding practices, verified via automated regression tests, and confirmed resolved using Semgrep SAST scans (`p/javascript` and `p/owasp-top-ten`).

---

## 2. Vulnerability Remediation Matrix

| Flaw # | Vulnerability Name | CWE | Affected Component | Root Cause | Remediated In | Semgrep Before | Semgrep After |
| :---: | :--- | :---: | :--- | :--- | :--- | :---: | :---: |
| **1** | NoSQL Injection | CWE-943 | `app/data/user-dao.js`<br>`app/routes/session.js` | Unchecked query input allows operator injection objects (`$gt`, `$ne`). | Strict `typeof === 'string'` guards and whitespace trimming. | 1 HIGH | **0 (Resolved)** |
| **2** | SSJS / `eval()` RCE | CWE-95 | `app/routes/contributions.js` | Dynamic string evaluation with `eval()` allows arbitrary JS code execution. | Removed `eval()`; implemented strict numeric regex and `Number()` arithmetic. | 1 CRITICAL | **0 (Resolved)** |
| **3** | Stored XSS | CWE-79 | `app/routes/profile.js`<br>`app/views/profile.html` | Unescaped user profile fields stored and rendered raw. | Applied `validator.escape()` on all input fields prior to persistence. | 1 MEDIUM | **0 (Resolved)** |
| **4** | Insecure Deserialization | CWE-502 | `app/routes/profile.js` | `node-serialize.unserialize()` executes arbitrary functions via `_$$ND_FUNC$$_`. | Removed `node-serialize`; replaced with safe `JSON.parse()` & schema checks. | 1 CRITICAL | **0 (Resolved)** |

---

## 3. Technical Walkthrough & Code Diffs

### 3.1 Flaw 1: NoSQL Injection in Authentication Query
* **CWE Classification:** CWE-943: Improper Neutralization of Special Elements in Data Query Logic
* **File:** `app/data/user-dao.js`

#### Before (Vulnerable):
```javascript
// Vulnerable: Query accepts any object passed via body-parser
this.authenticate = function(userName, password, callback) {
    users.findOne({ userName: userName, password: password }, function(err, user) {
        // ...
    });
};
```

#### After (Remediated):
```javascript
// SECURE: Enforce strict primitive string type checking
UserDAO.prototype.authenticate = function(userName, password, callback) {
    const users = this.users;

    if (typeof userName !== "string" || typeof password !== "string") {
        return callback(new Error("Invalid credential types"), null);
    }

    const safeUserName = userName.trim();
    if (safeUserName.length === 0) {
        return callback(new Error("Username must not be empty"), null);
    }

    users.findOne({ userName: safeUserName }, function(err, user) {
        if (err) return callback(err, null);
        if (!user) return callback(null, null);

        bcrypt.compare(password, user.password, function(err, isMatch) {
            if (err) return callback(err, null);
            return callback(null, isMatch ? user : null);
        });
    });
};
```

---

### 3.2 Flaw 2: Server-Side JavaScript Injection in Contributions
* **CWE Classification:** CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
* **File:** `app/routes/contributions.js`

#### Before (Vulnerable):
```javascript
// Vulnerable: eval() dynamically interprets user-controlled string input
const preTax = req.body.preTax;
const afterTax = req.body.afterTax;
eval("total = " + preTax + " + " + afterTax);
```

#### After (Remediated):
```javascript
// SECURE: Validate complete numeric strings before safe mathematical operations
const numericPattern = /^-?\d+(\.\d+)?$/;
if (typeof rawPreTax !== "string" || typeof rawAfterTax !== "string" ||
    !numericPattern.test(rawPreTax.trim()) || !numericPattern.test(rawAfterTax.trim())) {
    return res.render("contributions", { updateError: "Inputs must be valid decimal numbers." });
}
const preTax = parseFloat(rawPreTax);
const afterTax = parseFloat(rawAfterTax);

if (isNaN(preTax) || isNaN(afterTax) || !isFinite(preTax) || !isFinite(afterTax)) {
    return res.render("contributions", {
        updateError: "Invalid contribution values: inputs must be valid decimal numbers.",
        contribution: { preTax: 0, afterTax: 0, total: 0 }
    });
}

if (preTax < 0 || afterTax < 0 || preTax > 100 || afterTax > 100) {
    return res.render("contributions", {
        updateError: "Contribution percentages must be between 0 and 100.",
        contribution: { preTax: preTax, afterTax: afterTax, total: 0 }
    });
}

const total = Math.round((preTax + afterTax) * 100) / 100;
```

---

### 3.3 Flaw 3: Stored Cross-Site Scripting (XSS) in User Profile
* **CWE Classification:** CWE-79: Improper Neutralization of Input During Web Page Generation
* **File:** `app/routes/profile.js`

#### Before (Vulnerable):
```javascript
// Vulnerable: Raw unsanitized inputs stored directly
user.firstName = req.body.firstName;
user.lastName = req.body.lastName;
```

#### After (Remediated):
```javascript
// SECURE: Contextual HTML escaping on all inputs prior to database storage
const safeFirstName = validator.escape(String(rawFirstName).trim()).slice(0, 50);
const safeLastName = validator.escape(String(rawLastName).trim()).slice(0, 50);
const safeBankAcc = validator.escape(String(rawBankAcc).trim()).slice(0, 30);
const safeRoutingNo = validator.escape(String(rawRoutingNo).trim()).slice(0, 30);

const updateDoc = {
    $set: {
        firstName: safeFirstName,
        lastName: safeLastName,
        bankAcc: safeBankAcc,
        routingNo: safeRoutingNo
    }
};
```

---

### 3.4 Flaw 4: Insecure Deserialization via Cookie Payload
* **CWE Classification:** CWE-502: Deserialization of Untrusted Data
* **File:** `app/routes/profile.js`

#### Before (Vulnerable):
```javascript
// Vulnerable: node-serialize executes arbitrary functions
const serialize = require("node-serialize");
if (req.cookies.profile) {
    const str = Buffer.from(req.cookies.profile, "base64").toString();
    const obj = serialize.unserialize(str);
}
```

#### After (Remediated):
```javascript
// SECURE: Replaced node-serialize with standard JSON.parse and strict property validation
let customTheme = "default";
if (req.cookies && req.cookies.profile) {
    try {
        const decodedCookie = Buffer.from(req.cookies.profile, "base64").toString("utf-8");
        const parsedCookie = JSON.parse(decodedCookie);

        if (parsedCookie && typeof parsedCookie.theme === "string") {
            const allowedThemes = ["default", "dark", "light"];
            customTheme = allowedThemes.includes(parsedCookie.theme) ? parsedCookie.theme : "default";
        }
    } catch (deserializeErr) {
        customTheme = "default";
    }
}
```

---

## 4. Automated Regression Testing Verification

The automated security regression test suite ([tests/security-regression.test.js](tests/security-regression.test.js)) executes programmatic assertions covering all 4 attack surfaces:

```text
=================================================
   IE3142 Security Regression Test Suite         
=================================================
[PASS] Test 1: NoSQL Injection: Non-string userName object is rejected by type guard
[PASS] Test 2: SSJS Defense: String mathematical expression is parsed safely without eval()
[PASS] Test 3: XSS Defense: HTML tags and script elements are escaped on input
[PASS] Test 4: Deserialization Defense: node-serialize functions are rejected safely by JSON.parse()
=================================================
Results: 4/4 security regression tests passed.
STATUS: ALL DEFENSIVE GATES PASSED.
```

---

## 5. SAST Before/After Scan Comparison

```text
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
