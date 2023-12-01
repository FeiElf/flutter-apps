"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const functions = require("firebase-functions");
const admin = require("firebase-admin");
const node_fetch_1 = require("node-fetch");
const nodemailer = require("nodemailer");
const secrete = require("../../secrete.json");
admin.initializeApp();
async function postData(url = "", data = {}, token) {
    const h = new node_fetch_1.Headers();
    h.append("Content-Type", "application/json");
    if (token)
        h.append("token", token);
    const response = await (0, node_fetch_1.default)(url, {
        method: "POST",
        headers: h,
        body: JSON.stringify(data),
    });
    return response.ok ? response.json() : false;
}
const isAuthorisedClient = async (udiHash, token, sessionId, host) => {
    const checkHash = { action: "select", udihash: udiHash };
    const r1 = (await postData("https://license02.usm.net.au/api/v1/udi/", checkHash));
    functions.logger.info(`checkHash request: ${JSON.stringify(r1)}`, {
        structuredData: true,
    });
    if (!r1 || r1.error)
        return false;
    const checkToken = { action: "select", session_id: sessionId };
    const r2 = (await postData(`https://core.${host}/v1/User/`, checkToken, token));
    functions.logger.info(`checkToken request: ${JSON.stringify(r2)}`, {
        structuredData: true,
    });
    if (!r2 || r2.error)
        return false;
    return true;
};
const emailRegExp = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
exports.sendMailOverHTTP = functions.https.onRequest(async (req, res) => {
    const udiHash = /^[\w\d+/]+$/.test(req.body.udiHash) && req.body.udiHash;
    const token = /^[\w\d+/]+$/.test(req.body.token) && req.body.token;
    const sessionId = /^[\d]+$/.test(req.body.sessionId) && parseInt(req.body.sessionId);
    const host = req.body.host;
    const to = emailRegExp.test(req.body.to) && req.body.to;
    // subject is expected to be printable characters
    const subject = /^[\u0020-\u007e\u00a0-\u00ff]*$/.test(req.body.subject) &&
        req.body.subject;
    // content is expected to be a base64 encoded string
    const content = /^[\w\d=+/]+$/.test(req.body.content) && req.body.content;
    if (!(udiHash && token && sessionId && host && to && subject && content)) {
        functions.logger.info("Invalid request", { structuredData: true });
        res.status(400).send({ error: "Invalid request" });
        return;
    }
    let isAuthorised = false;
    try {
        isAuthorised = await isAuthorisedClient(udiHash, token, sessionId, host);
        if (!isAuthorised) {
            res.status(401).send({ error: "Unauthorised client" });
            return;
        }
    }
    catch (error) {
        functions.logger.info(`HTTP error: ${error}`, { structuredData: true });
        res.status(500).send({ error: "HTTP error" });
        return;
    }
    const html = Buffer.from(content, "base64").toString("utf-8");
    const transporter = nodemailer.createTransport({
        host: "email-smtp.ap-southeast-2.amazonaws.com",
        port: 2587,
        secure: false,
        requireTLS: true,
        auth: {
            user: secrete.user,
            pass: secrete.pass,
        },
    });
    const mailOptions = {
        from: "notification@usm.net.au",
        to: to,
        subject: subject,
        html: html,
    };
    return transporter.sendMail(mailOptions, (error, data) => {
        if (error) {
            return res.status(500).send({ error: error.toString() });
        }
        data = JSON.stringify(data);
        functions.logger.info(data, { structuredData: true });
        return res.status(200).send(data);
    });
});
//# sourceMappingURL=index.js.map