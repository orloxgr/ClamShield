import { englishText } from "../../shared/localization/runtime";
import { randomBytes } from "crypto";
import express from "express";
export const apiSessionToken = process.env.CLAMSHIELD_API_TOKEN || randomBytes(32).toString("hex");
export const apiCookieName = "clamshield_session";
export const apiHeaderName = "x-clamshield-session";
export function readCookie(req: express.Request, name: string) {
    const cookieHeader = req.headers.cookie || "";
    const cookies = cookieHeader.split(";").map(part => part.trim());
    const prefix = `${name}=`;
    const match = cookies.find(cookie => cookie.startsWith(prefix));
    try { return match ? decodeURIComponent(match.slice(prefix.length)) : ""; }
    catch { return ""; }
}
export function requireLocalApiSession(req: express.Request, res: express.Response, next: express.NextFunction) {
    if (!req.path.startsWith("/api"))
        return next();
    // Binding to loopback alone does not reject hostile Host/Origin values.
    try {
        const host = new URL(`http://${req.headers.host}`);
        if (!['127.0.0.1', 'localhost', '[::1]'].includes(host.hostname) || Number(host.port || 80) !== req.socket.localPort || host.username || host.password)
            return res.status(403).json({ error: englishText("backend.core.invalid_local_api_session") });
        const origin = req.header('origin');
        if (origin && origin !== host.origin)
            return res.status(403).json({ error: englishText("backend.core.invalid_local_api_session") });
    } catch { return res.status(403).json({ error: englishText("backend.core.invalid_local_api_session") }); }
    if (readCookie(req, apiCookieName) === apiSessionToken)
        return next();
    if (req.header(apiHeaderName) === apiSessionToken)
        return next();
    res.status(403).json({ error: englishText("backend.core.invalid_local_api_session") });
}
