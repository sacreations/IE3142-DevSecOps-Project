"use strict";

// NodeGoat contributions.js — SECURE (patched)
// Original vulnerability:
//   eval("total = " + preTax + " + " + afterTax);
// Allowed arbitrary Server-Side JavaScript Execution (SSJS / RCE) when
// user submitted JavaScript expressions in place of numeric strings.

const ContributionsDAO = function(db) {
    this.contributions = db.collection("contributions");
};

const ContributionsHandler = function(db) {
    this.contributionsDAO = new ContributionsDAO(db);
};

ContributionsHandler.prototype.displayContributions = function(req, res, next) {
    const userId = req.session.userId;
    this.contributionsDAO.getByUserId(userId, function(err, contribution) {
        if (err) return next(err);
        return res.render("contributions", { contribution: contribution });
    });
};

ContributionsHandler.prototype.handleContributionsUpdate = function(req, res, next) {
    const userId = req.session.userId;
    const rawPreTax = req.body.preTax;
    const rawAfterTax = req.body.afterTax;

    // SECURE: Validate the complete input before native math arithmetic.
    const numericPattern = /^-?\d+(\.\d+)?$/;
    if (typeof rawPreTax !== "string" || typeof rawAfterTax !== "string" ||
        !numericPattern.test(rawPreTax.trim()) || !numericPattern.test(rawAfterTax.trim())) {
        return res.render("contributions", {
            updateError: "Invalid contribution values: inputs must be valid decimal numbers.",
            contribution: { preTax: 0, afterTax: 0, total: 0 }
        });
    }

    const preTax = parseFloat(rawPreTax);
    const afterTax = parseFloat(rawAfterTax);

    // Guard: reject non-numeric inputs or NaN results explicitly
    if (isNaN(preTax) || isNaN(afterTax) || !isFinite(preTax) || !isFinite(afterTax)) {
        return res.render("contributions", {
            updateError: "Invalid contribution values: inputs must be valid decimal numbers.",
            contribution: { preTax: 0, afterTax: 0, total: 0 }
        });
    }

    // Business rule guards: contributions cannot be negative or exceed 100%
    if (preTax < 0 || afterTax < 0 || preTax > 100 || afterTax > 100) {
        return res.render("contributions", {
            updateError: "Contribution percentages must be between 0 and 100.",
            contribution: { preTax: preTax, afterTax: afterTax, total: 0 }
        });
    }

    // Safe mathematical calculation — no string evaluation
    const total = Math.round((preTax + afterTax) * 100) / 100;

    this.contributionsDAO.update(userId, preTax, afterTax, total, function(err) {
        if (err) return next(err);
        return res.render("contributions", {
            updateSuccess: true,
            contribution: { preTax: preTax, afterTax: afterTax, total: total }
        });
    });
};

module.exports = ContributionsHandler;
