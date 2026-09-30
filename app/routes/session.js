"use strict";

// NodeGoat session.js — SECURE (patched)
// Original vulnerability: req.body values were passed directly to user-dao
// without validation; HTTP body parsers can coerce JSON objects into query
// operators when Content-Type: application/json is sent.

const SessionHandler = function(db) {
    const UserDAO = require("../data/user-dao").UserDAO;
    this.userDAO = new UserDAO(db);
};

SessionHandler.prototype.displayLoginPage = function(req, res) {
    return res.render("login", {
        userName: "",
        password: "",
        loginError: ""
    });
};

SessionHandler.prototype.handleLoginRequest = function(req, res, next) {
    if (typeof req.body.userName !== "string" || typeof req.body.password !== "string") {
        return res.render("login", {
            userName: "",
            password: "",
            loginError: "Invalid credentials."
        });
    }

    const userName = req.body.userName;
    const password = req.body.password;

    // Additional length guards prevent excessive DB load from huge payloads
    if (userName.length > 200 || password.length > 200) {
        return res.render("login", {
            userName: "",
            password: "",
            loginError: "Invalid credentials."
        });
    }

    this.userDAO.authenticate(userName, password, function(err, user) {
        if (err) return next(err);

        if (user) {
            req.session.regenerate(function(err) {
                if (err) return next(err);
                req.session.userId = user._id;
                req.session.userName = user.userName;
                return res.redirect("/dashboard");
            });
        } else {
            return res.render("login", {
                userName: userName,
                password: "",
                loginError: "Invalid credentials."
            });
        }
    });
};

SessionHandler.prototype.handleLogout = function(req, res, next) {
    req.session.destroy(function(err) {
        if (err) return next(err);
        return res.redirect("/login");
    });
};

module.exports = SessionHandler;
