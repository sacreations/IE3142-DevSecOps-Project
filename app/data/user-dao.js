"use strict";

const bcrypt = require("bcrypt-nodejs");

// NodeGoat user-dao.js — SECURE (patched)
// Original vulnerability: userName and password were passed directly into
// users.findOne() without type checking, permitting MongoDB operator injection
// (e.g. {"$gt":""}) to bypass authentication entirely.

const UserDAO = function(db) {
    "use strict";

    this.db = db;
    this.users = db.collection("users");
};

// SECURE: Validate that login credentials are plain strings before querying.
// This blocks operator-injection objects such as { "$gt": "" }.
UserDAO.prototype.authenticate = function(userName, password, callback) {
    const users = this.users;

    // Guard: reject non-string inputs so MongoDB never sees operator objects
    if (typeof userName !== "string" || typeof password !== "string") {
        return callback(new Error("Invalid credential types"), null);
    }

    // Trim to prevent whitespace-only bypass attempts
    const safeUserName = userName.trim();
    if (safeUserName.length === 0) {
        return callback(new Error("Username must not be empty"), null);
    }

    users.findOne({ userName: safeUserName }, function(err, user) {
        if (err) return callback(err, null);
        if (!user) return callback(null, null);

        // Compare submitted password against stored bcrypt hash
        bcrypt.compare(password, user.password, function(err, isMatch) {
            if (err) return callback(err, null);
            return callback(null, isMatch ? user : null);
        });
    });
};

UserDAO.prototype.getUserById = function(userId, callback) {
    this.users.findOne({ _id: userId }, callback);
};

UserDAO.prototype.getUserByUserName = function(userName, callback) {
    // Guard: same type enforcement for any direct user lookup
    if (typeof userName !== "string") {
        return callback(new Error("Invalid userName type"), null);
    }
    this.users.findOne({ userName: userName.trim() }, callback);
};

UserDAO.prototype.getNextSequence = function(name, callback) {
    this.db.collection("counters").findAndModify(
        { _id: name },
        [],
        { $inc: { seq: 1 } },
        { new: true, upsert: true },
        function(err, doc) {
            if (err) return callback(err, null);
            callback(null, doc.value.seq);
        }
    );
};

UserDAO.prototype.addUser = function(userName, firstName, lastName, password, email, callback) {
    const users = this.users;

    this.getNextSequence("userId", function(err, seq) {
        if (err) return callback(err, null);

        bcrypt.hash(password, null, null, function(err, hash) {
            if (err) return callback(err, null);

            const user = {
                userId: seq,
                userName: userName,
                firstName: firstName,
                lastName: lastName,
                password: hash,
                email: email
            };

            users.insert(user, function(err, result) {
                if (err) return callback(err, null);
                callback(null, result.ops[0]);
            });
        });
    });
};

module.exports = { UserDAO };
