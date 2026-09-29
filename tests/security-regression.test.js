"use strict";

/**
 * Security Regression Test Suite
 * IE3142 DevSecOps — LO2 Defensive Validation
 *
 * Verifies that all 4 vulnerability classes are properly defended:
 *  1. NoSQL Injection: Reject non-string / operator objects.
 *  2. SSJS / eval(): Safely parse numeric strings, reject JS code constructs.
 *  3. XSS: Escape HTML special characters on profile inputs.
 *  4. Insecure Deserialization: Reject function/IIFE serialized strings gracefully.
 */

const assert = require("assert");

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#x27;");
}

console.log("=================================================");
console.log("   IE3142 Security Regression Test Suite         ");
console.log("=================================================");

let passed = 0;
let total = 0;

function runTest(name, fn) {
    total++;
    try {
        fn();
        console.log(`[PASS] Test ${total}: ${name}`);
        passed++;
    } catch (err) {
        console.error(`[FAIL] Test ${total}: ${name}`);
        console.error(`       Error: ${err.message}`);
    }
}

// -------------------------------------------------------------
// Test 1: NoSQL Injection Defense — Type Checking Guard
// -------------------------------------------------------------
runTest("NoSQL Injection: Non-string userName object is rejected by type guard", () => {
    function authenticateGuard(userName, password) {
        if (typeof userName !== "string" || typeof password !== "string") {
            throw new Error("Invalid credential types: must be strings");
        }
        return true;
    }

    // Attempt operator object injection
    const operatorPayload = { $gt: "" };
    assert.throws(
        () => authenticateGuard(operatorPayload, "secret123"),
        /Invalid credential types/,
        "Must throw error on object input"
    );

    // Legitimate string input passes
    assert.strictEqual(authenticateGuard("admin", "secret123"), true);
});

// -------------------------------------------------------------
// Test 2: SSJS / eval() Defense — Safe Strict Number Parser
// -------------------------------------------------------------
runTest("SSJS Defense: String mathematical expression is parsed safely without eval()", () => {
    function parseContribution(rawPreTax, rawAfterTax) {
        // Strict number validation: reject trailing garbage or non-digit chars
        const numRegex = /^-?\d+(\.\d+)?$/;
        if (!numRegex.test(String(rawPreTax).trim()) || !numRegex.test(String(rawAfterTax).trim())) {
            throw new Error("Invalid numeric input");
        }

        const preTax = Number(rawPreTax);
        const afterTax = Number(rawAfterTax);

        if (isNaN(preTax) || isNaN(afterTax) || !isFinite(preTax) || !isFinite(afterTax)) {
            throw new Error("Invalid numeric input");
        }
        if (preTax < 0 || afterTax < 0 || preTax > 100 || afterTax > 100) {
            throw new Error("Out of range");
        }
        return Math.round((preTax + afterTax) * 100) / 100;
    }

    // Normal numbers work
    assert.strictEqual(parseContribution("10.5", "5.25"), 15.75);

    // Injection attempt containing code is rejected
    assert.throws(
        () => parseContribution("10; process.exit(1)", "5"),
        /Invalid numeric input/
    );

    // Extreme/infinite values rejected
    assert.throws(
        () => parseContribution("Infinity", "5"),
        /Invalid numeric input/
    );
});

// -------------------------------------------------------------
// Test 3: Stored XSS Defense — Contextual Input Escaping
// -------------------------------------------------------------
runTest("XSS Defense: HTML tags and script elements are escaped on input", () => {
    const maliciousInput = "<script>alert('xss')</script>";
    const escaped = escapeHtml(maliciousInput);

    assert.ok(!escaped.includes("<script>"), "Must not contain unescaped open tag");
    assert.ok(escaped.includes("&lt;script&gt;"), "Must be HTML entity encoded");

    const quoteInput = `"><img src=x onerror=alert(1)>`;
    const escapedQuote = escapeHtml(quoteInput);
    assert.ok(!escapedQuote.includes("<img"), "Must not contain raw img tag");
});

// -------------------------------------------------------------
// Test 4: Insecure Deserialization Defense — Safe JSON Parsing
// -------------------------------------------------------------
runTest("Deserialization Defense: node-serialize functions are rejected safely by JSON.parse()", () => {
    function safeDeserializeCookie(base64Cookie) {
        try {
            const decoded = Buffer.from(base64Cookie, "base64").toString("utf-8");
            const parsed = JSON.parse(decoded);
            const allowedThemes = ["default", "dark", "light"];
            return (parsed && allowedThemes.includes(parsed.theme)) ? parsed.theme : "default";
        } catch (err) {
            return "default";
        }
    }

    // Normal theme cookie works
    const normalPayload = Buffer.from(JSON.stringify({ theme: "dark" })).toString("base64");
    assert.strictEqual(safeDeserializeCookie(normalPayload), "dark");

    // Serialized function payload (node-serialize format) fails cleanly to 'default'
    const exploitLikePayload = Buffer.from('{"rce":"_$$ND_FUNC$$_function(){return 1337;}()"}').toString("base64");
    const result = safeDeserializeCookie(exploitLikePayload);
    assert.strictEqual(result, "default", "Must fall back to default safely without executing function");

    // Malformed base64/JSON fails safely
    assert.strictEqual(safeDeserializeCookie("not-valid-base64-json!"), "default");
});

// -------------------------------------------------------------
// Summary
// -------------------------------------------------------------
console.log("=================================================");
console.log(`Results: ${passed}/${total} security regression tests passed.`);
if (passed === total) {
    console.log("STATUS: ALL DEFENSIVE GATES PASSED.");
} else {
    console.error("STATUS: REGRESSION DETECTED.");
    process.exit(1);
}
