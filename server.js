"use strict";

const express = require("express");
const bodyParser = require("body-parser");
const expressSession = require("express-session");
const MongoStore = require("connect-mongo")(expressSession);
const consolidate = require("consolidate");
const morgan = require("morgan");
const mongodb = require("mongodb");

const SessionHandler = require("./app/routes/session");
const ProfileHandler = require("./app/routes/profile");
const ContributionsHandler = require("./app/routes/contributions");

const app = express();
const port = Number(process.env.PORT || 4000);
const mongoUri = process.env.MONGODB_URI || "mongodb://localhost:27017/nodegoat";
const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret) {
    throw new Error("SESSION_SECRET must be set");
}

app.engine("html", consolidate.swig);
app.set("view engine", "html");
app.set("views", __dirname + "/app/views");
app.disable("x-powered-by");
app.use(morgan("combined"));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json({ limit: "10kb" }));
app.use(function(req, res, next) {
    req.cookies = {};
    const header = req.headers.cookie || "";
    header.split(";").forEach(function(pair) {
        const separator = pair.indexOf("=");
        if (separator > 0) {
            const name = pair.slice(0, separator).trim();
            const value = pair.slice(separator + 1).trim();
            req.cookies[name] = decodeURIComponent(value);
        }
    });
    return next();
});

mongodb.MongoClient.connect(mongoUri, function(err, client) {
    if (err) throw err;

    const db = client.db();
    app.use(expressSession({
        secret: sessionSecret,
        resave: false,
        saveUninitialized: false,
        store: new MongoStore({ url: mongoUri }),
        cookie: { httpOnly: true, sameSite: "lax" }
    }));

    const sessionHandler = new SessionHandler(db);
    const profileHandler = new ProfileHandler(db);
    const contributionsHandler = new ContributionsHandler(db);

    function requireLogin(req, res, next) {
        if (!req.session.userId) return res.redirect("/login");
        return next();
    }

    app.get("/", function(req, res) {
        return res.redirect(req.session.userId ? "/dashboard" : "/login");
    });
    app.get("/login", sessionHandler.displayLoginPage.bind(sessionHandler));
    app.post("/login", sessionHandler.handleLoginRequest.bind(sessionHandler));
    app.get("/logout", sessionHandler.handleLogout.bind(sessionHandler));
    app.get("/dashboard", requireLogin, function(req, res) {
        return res.render("dashboard", { userName: req.session.userName });
    });
    app.get("/profile", requireLogin, profileHandler.displayProfile.bind(profileHandler));
    app.post("/profile", requireLogin, profileHandler.handleProfileUpdate.bind(profileHandler));
    app.get("/contributions", requireLogin, contributionsHandler.displayContributions.bind(contributionsHandler));
    app.post("/contributions", requireLogin, contributionsHandler.handleContributionsUpdate.bind(contributionsHandler));

    app.use(function(err, req, res, next) {
        if (res.headersSent) return next(err);
        return res.status(500).render("error", { message: "An internal error occurred." });
    });

    app.listen(port, function() {
        console.log("NodeGoat listening on port " + port);
    });
});
