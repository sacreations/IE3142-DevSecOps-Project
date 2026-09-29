"use strict";

// NodeGoat profile.js — SECURE (patched)
// Original vulnerabilities:
//   1. node-serialize deserialized base64 cookies, permitting RCE via _$$ND_FUNC$$_ syntax (CVE-2017-5941).
//   2. User profile fields were saved without input escaping, leading to Stored XSS when rendered.

const validator = require("validator");

const ProfileDAO = function(db) {
    this.users = db.collection("users");
};

const ProfileHandler = function(db) {
    this.profileDAO = new ProfileDAO(db);
};

ProfileHandler.prototype.displayProfile = function(req, res, next) {
    const userId = req.session.userId;

    this.profileDAO.users.findOne({ _id: userId }, function(err, user) {
        if (err) return next(err);

        // SECURE DESERIALIZATION: Use standard JSON.parse wrapped in a try/catch.
        // node-serialize is completely eliminated.
        let customTheme = "default";
        if (req.cookies && req.cookies.profile) {
            try {
                const decodedCookie = Buffer.from(req.cookies.profile, "base64").toString("utf-8");
                const parsedCookie = JSON.parse(decodedCookie);

                // Strict schema validation: only allow expected primitive fields
                if (parsedCookie && typeof parsedCookie.theme === "string") {
                    // Restrict to allowed theme whitelist
                    const allowedThemes = ["default", "dark", "light"];
                    customTheme = allowedThemes.includes(parsedCookie.theme) ? parsedCookie.theme : "default";
                }
            } catch (deserializeErr) {
                // Ignore malformed cookies safely without throwing or executing code
                customTheme = "default";
            }
        }

        return res.render("profile", {
            user: user,
            theme: customTheme
        });
    });
};

ProfileHandler.prototype.handleProfileUpdate = function(req, res, next) {
    const userId = req.session.userId;

    // SECURE INPUT ENCODING: Apply validator.escape() to neutralize HTML special chars
    // (<, >, &, ", ') before persistence to prevent Stored XSS.
    const rawFirstName = req.body.firstName || "";
    const rawLastName = req.body.lastName || "";
    const rawBankAcc = req.body.bankAcc || "";
    const rawRoutingNo = req.body.routingNo || "";

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

    this.profileDAO.users.updateOne({ _id: userId }, updateDoc, function(err) {
        if (err) return next(err);
        return res.redirect("/profile");
    });
};

module.exports = ProfileHandler;
