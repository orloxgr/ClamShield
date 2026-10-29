const { t, englishText, localizeText, desktopLanguage } = require('./public/desktop-localization.cjs');
const { app, BrowserWindow, Tray, Menu, nativeImage, session, shell, powerMonitor, ipcMain } = require('electron');
const path = require('path');
const { spawn, fork } = require('child_process');
const fs = require('fs');
const net = require('net');
const { randomBytes } = require('crypto');
const http = require('http');
const os = require('os');
const { clipboard } = require('electron');
const { sanitize, createDiagnostic, errorHtml } = require('./public/desktop-diagnostics.cjs');
const windowDiagnostics = new WeakMap();
const { notificationLayout } = require('./public/notification-layout.cjs');
app.commandLine.appendSwitch('autoplay-policy', 'no-user-gesture-required');
let mainWindow;
let serverProcess;
let tray = null;
let isQuiting = false;
let activeAlerts = new Map();
const notificationWindows = new Map();
const dismissedAlerts = new Set();
let notificationScreenListeners = false;
let resultsReminderWindow = null;
let scanSummaryWindow = null;
let updateAvailableWindow = null;
let debugLoggingEnabled = false;
const lastUpdateCheckAt = {};
let appUpdateChecking = false;
let scheduledScanChecking = false;
let scheduledScanRun = null;
let currentApiPort = null;
const apiSessionToken = randomBytes(32).toString('hex');
const contextMenuBridgeToken = randomBytes(32).toString('hex');
let contextMenuBridgeServer = null;
let contextMenuBridgePort = null;
const gotSingleInstanceLock = app.requestSingleInstanceLock();
const scheduledScanTransientErrorLimit = 6;
const transientApiErrorCodes = new Set(["ECONNRESET", "ECONNABORTED", "ECONNREFUSED", "ETIMEDOUT", "EPIPE"]);
const maxDebugLogBytes = 25 * 1024 * 1024;
if (!gotSingleInstanceLock) {
    app.quit();
}
function apiHeaders(extra = {}) {
    return { ...extra, 'X-ClamShield-Session': apiSessionToken };
}
function isTransientApiConnectionError(error) {
    const code = error && (error.code || error.errno);
    const message = String(error?.message || error || '');
    return transientApiErrorCodes.has(code) ||
        /\b(?:ECONNRESET|ECONNABORTED|ECONNREFUSED|ETIMEDOUT|EPIPE)\b|socket hang up/i.test(message);
}
async function setApiSessionCookie(port) {
    await session.defaultSession.cookies.set({
        url: `http://127.0.0.1:${port}`,
        name: "clamshield_session",
        value: apiSessionToken,
        path: '/',
        httpOnly: true,
        secure: false,
        sameSite: 'strict'
    });
}
function getProgramDataDir() {
    return process.platform === 'win32'
        ? path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'ClamShield')
        : path.join(__dirname, 'data', 'ClamShield');
}
function getContextMenuBridgePath() {
    return path.join(getProgramDataDir(), 'context-menu-bridge.json');
}
function getLogsDir() {
    return path.join(getProgramDataDir(), 'logs');
}
function getAppStateDbPath() {
    return path.join(getProgramDataDir(), 'app_state.sqlite');
}
function logArgToString(arg) {
    if (arg instanceof Error)
        return arg.stack || arg.message;
    if (typeof arg === 'string')
        return arg;
    try {
        return JSON.stringify(arg);
    }
    catch {
        return String(arg);
    }
}
function writeMainLog(level, args) {
    try {
        fs.mkdirSync(getLogsDir(), { recursive: true });
        const logPath = path.join(getLogsDir(), 'electron-main.log');
        rotateLogIfNeeded(logPath);
        const line = `[${new Date().toISOString()}] [${String(level).toUpperCase()}] ${sanitize(args, [apiSessionToken, contextMenuBridgeToken]).map(logArgToString).join(' ')}\n`;
        fs.appendFileSync(logPath, line, 'utf8');
    }
    catch {
        // Logging must never stop the app from launching.
    }
}
function rotateLogIfNeeded(logPath) {
    try {
        if (!fs.existsSync(logPath) || fs.statSync(logPath).size < maxDebugLogBytes)
            return;
        const rotatedPath = `${logPath}.1`;
        try {
            fs.rmSync(rotatedPath, { force: true });
        }
        catch { }
        fs.renameSync(logPath, rotatedPath);
    }
    catch {
        // Best-effort only; logging must never break app startup.
    }
}
const originalConsole = {
    log: console.log.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
    debug: console.debug.bind(console)
};
console.log = (...args) => {
    originalConsole.log(...args);
    if (debugLoggingEnabled)
        writeMainLog('info', args);
};
console.debug = (...args) => {
    originalConsole.debug(...args);
    if (debugLoggingEnabled)
        writeMainLog('debug', args);
};
console.warn = (...args) => {
    originalConsole.warn(...args);
    if (debugLoggingEnabled)
        writeMainLog('warn', args);
};
console.error = (...args) => {
    originalConsole.error(...args);
    writeMainLog('error', args);
};
process.on('uncaughtException', (error) => {
    writeMainLog('fatal', [englishText("desktop.electron_main.uncaught_exception"), error]);
    originalConsole.error(englishText("desktop.electron_main.uncaught_exception_d780875"), error);
});
process.on('unhandledRejection', (reason) => {
    writeMainLog('fatal', [englishText("desktop.electron_main.unhandled_rejection"), reason]);
    originalConsole.error(englishText("desktop.electron_main.unhandled_rejection_d6cb551"), reason);
});
function showWindowFailure(win, input) {
    if (!win || win.isDestroyed() || isQuiting)
        return;
    const previous = windowDiagnostics.get(win);
    if (previous)
        return;
    win.stopBackendWait?.();
    clearTimeout(win.uiReadyTimer);
    const diagnostic = createDiagnostic(input, { version: app.getVersion(), os: `${os.platform()} ${os.release()} ${os.arch()}` }, [apiSessionToken, contextMenuBridgeToken]);
    const pageUrl = `data:text/html;charset=utf-8,${encodeURIComponent(errorHtml(diagnostic))}`;
    windowDiagnostics.set(win, { diagnostic, pageUrl });
    writeMainLog('error', [englishText("desktop.electron_main.interface_failure"), diagnostic]);
    win.loadURL(pageUrl).catch(error => writeMainLog('fatal', [englishText("desktop.electron_main.could_not_display_the_diagnostic_page"), error]));
}
function trustedMainSender(event) {
    if (!mainWindow || mainWindow.isDestroyed() || event.sender !== mainWindow.webContents || event.senderFrame !== event.sender.mainFrame)
        throw new Error(englishText("desktop.electron_main.untrusted_diagnostics_request"));
    const url = event.sender.getURL();
    const diagnostic = windowDiagnostics.get(mainWindow);
    const fileUrl = require('url').pathToFileURL(getPublicAssetPath('startup.html')).href;
    let local = false;
    try {
        local = new URL(url).origin === `http://127.0.0.1:${currentApiPort}`;
    }
    catch { }
    if (!local && url !== fileUrl && url !== diagnostic?.pageUrl)
        throw new Error(englishText("desktop.electron_main.diagnostics_are_only_available_in_the_local_app"));
    return mainWindow;
}
function getDesktopLanguage(refresh = false) {
    const directory = app.isPackaged ? path.dirname(app.getPath('exe')) : __dirname;
    return desktopLanguage([path.join(directory, 'languages'), path.join(getProgramDataDir(), 'languages')], path.join(getProgramDataDir(), 'language.json'), refresh);
}
function trustedLanguageSender(event) {
    if (event.senderFrame !== event.sender.mainFrame) throw new Error('Untrusted language request');
    const windows = [mainWindow, resultsReminderWindow, scanSummaryWindow, updateAvailableWindow, ...activeAlerts.values()];
    const win = windows.find(win => win && typeof win.isDestroyed === 'function' && !win.isDestroyed() && win.webContents === event.sender);
    if (!win) throw new Error('Untrusted language request');
    if (win === mainWindow) return trustedMainSender(event);
    const parsed = new URL(event.sender.getURL());
    const pages = ['/alert.html', '/results-reminder.html', '/scan-summary.html', '/update-available.html'];
    const localHttp = parsed.origin === 'http://127.0.0.1:' + currentApiPort && pages.includes(parsed.pathname);
    let localFile = false;
    if (parsed.protocol === 'file:') {
        parsed.search = ''; parsed.hash = '';
        localFile = pages.some(page => parsed.href === require('node:url').pathToFileURL(getPublicAssetPath(page.slice(1))).href);
    }
    if (!localHttp && !localFile) throw new Error('Untrusted language page');
    return win;
}
ipcMain.handle('clamshield-language', event => { trustedLanguageSender(event); return getDesktopLanguage(); });
ipcMain.handle('clamshield-language-refresh', event => {
    trustedMainSender(event);
    const pack = getDesktopLanguage(true);
    updateTrayLanguage();
    for (const win of [mainWindow, resultsReminderWindow, scanSummaryWindow, updateAvailableWindow, ...activeAlerts.values()])
        if (win && typeof win.isDestroyed === 'function' && !win.isDestroyed()) win.webContents.send('clamshield-language-changed', pack);
    return true;
});
ipcMain.handle('clamshield-open-external', async (event, value) => {
    trustedMainSender(event);
    if (typeof value !== 'string' || value.length > 64000 || !/^(https:\/\/|mailto:)/i.test(value))
        throw new Error(englishText("desktop.electron_main.unsupported_report_address"));
    await shell.openExternal(value);
});
ipcMain.handle('clamshield-ui-error', (event, payload = {}) => {
    const win = trustedMainSender(event);
    showWindowFailure(win, { stage: payload.stage, code: payload.code, message: payload.message, details: payload.details, url: win.webContents.getURL() });
    return windowDiagnostics.get(win)?.diagnostic.id;
});
ipcMain.handle('clamshield-copy-diagnostics', async (event) => {
    const win = trustedMainSender(event);
    const diagnostic = windowDiagnostics.get(win)?.diagnostic;
    if (!diagnostic)
        throw new Error(englishText("desktop.electron_main.no_diagnostic_record_is_available"));
    await clipboard.writeText(JSON.stringify(diagnostic, null, 2));
});
ipcMain.handle('clamshield-open-logs', async (event) => {
    trustedMainSender(event);
    fs.mkdirSync(getLogsDir(), { recursive: true });
    const error = await shell.openPath(getLogsDir());
    if (error)
        throw new Error(error);
});
ipcMain.handle('clamshield-retry-ui', async (event) => {
    const win = trustedMainSender(event);
    windowDiagnostics.delete(win);
    await win.loadFile(getPublicAssetPath('startup.html')).catch(error => { showWindowFailure(win, { stage: englishText("desktop.electron_main.loading_startup_screen"), code: error.code, message: error.message }); throw error; });
    waitForWindowBackend(win, currentApiPort);
});
function markWindowUiReady(event) {
    const win = trustedMainSender(event);
    win.uiMounted = true;
    clearTimeout(win.uiReadyTimer);
    if (debugLoggingEnabled)
        writeMainLog('debug', [englishText("desktop.electron_main.interface_ready"), { document: win.uiDocumentGeneration }]);
    return true;
}
ipcMain.handle('clamshield-ui-ready', markWindowUiReady);
process.on('clamshield-backend-failed', error => showWindowFailure(mainWindow, { stage: englishText("desktop.electron_main.starting_local_service"), code: error.code || 'BACKEND_START_FAILED', message: error.message, details: error.stack }));
async function verifyWindowStartup(win, generation, url) {
    if (win.isDestroyed() || win.uiMounted || generation !== win.uiDocumentGeneration)
        return;
    try {
        // A missing IPC acknowledgement is not proof that the interface failed.
        const state = await win.webContents.executeJavaScript(`(() => {
      const root = document.getElementById('root');
      return { mounted: document.documentElement.dataset.clamshieldUiReady === 'true' ||
        Boolean(root && root.children.length && !root.querySelector('.startup-shell')),
        readyState: document.readyState };
    })()`);
        if (win.isDestroyed() || win.uiMounted || generation !== win.uiDocumentGeneration)
            return;
        if (state.mounted) {
            win.uiMounted = true;
            writeMainLog('warn', [englishText("desktop.electron_main.interface_rendered_without_a_readiness_acknowledgement"), { generation }]);
            return;
        }
        showWindowFailure(win, { stage: englishText("desktop.electron_main.starting_interface"), code: 'UI_START_TIMEOUT', message: englishText("desktop.electron_main.the_application_interface_did_not_finish_starting_within_30_secon"), url, details: state });
    }
    catch (error) {
        // HTTP, resource and renderer-crash events handle confirmed failures separately.
        // An inconclusive readiness probe must never replace a working page.
        writeMainLog('warn', [englishText("desktop.electron_main.could_not_verify_interface_readiness"), error]);
    }
}
function attachWindowLogging(win, label) {
    if (!win || !win.webContents)
        return;
    win.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL, isMainFrame) => {
        if (errorCode === -3)
            return; // An intentionally replaced navigation is not a failure.
        writeMainLog('error', [`${label} failed to load`, { errorCode, errorDescription, validatedURL, isMainFrame }]);
        if (win === mainWindow && isMainFrame !== false && !validatedURL.startsWith('data:'))
            showWindowFailure(win, { stage: englishText("desktop.electron_main.loading_interface"), code: errorCode, message: errorDescription, url: validatedURL });
    });
    win.webContents.on('did-navigate', (_event, url, status) => {
        if (win === mainWindow && status >= 400)
            showWindowFailure(win, { stage: englishText("desktop.electron_main.loading_interface"), code: `HTTP ${status}`, message: englishText("desktop.electron_main.the_local_service_could_not_serve_the_application_page"), url });
    });
    win.webContents.on('did-start-navigation', (event, url, isInPlace, isMainFrame) => {
        const targetUrl = event.url ?? url;
        const sameDocument = event.isSameDocument ?? isInPlace;
        const mainFrame = event.isMainFrame ?? isMainFrame;
        // BrowserRouter changes the URL without replacing the mounted React document.
        if (sameDocument || mainFrame !== true || win !== mainWindow)
            return;
        clearTimeout(win.uiReadyTimer);
        win.uiMounted = false;
        const generation = win.uiDocumentGeneration = (win.uiDocumentGeneration || 0) + 1;
        if (targetUrl.startsWith(`http://127.0.0.1:${currentApiPort}/`)) {
            windowDiagnostics.delete(win);
            win.uiReadyTimer = setTimeout(() => verifyWindowStartup(win, generation, targetUrl), 30000);
        }
    });
    win.webContents.on('preload-error', (_event, preloadPath, error) => {
        writeMainLog('error', [`${label} preload failed`, { preloadPath, error }]);
        if (win === mainWindow)
            showWindowFailure(win, { stage: englishText("desktop.electron_main.starting_interface_bridge"), code: 'PRELOAD_FAILED', message: error.message, details: error.stack });
    });
    win.webContents.on('render-process-gone', (_event, details) => {
        writeMainLog('fatal', [`${label} renderer process gone`, details]);
        if (win === mainWindow && details.reason !== 'clean-exit')
            showWindowFailure(win, { stage: englishText("common.main.running_interface"), code: `RENDERER_${details.reason}`, message: englishText("desktop.electron_main.the_interface_process_stopped_unexpectedly"), details });
    });
    win.webContents.on('unresponsive', () => writeMainLog('warn', [`${label} window became unresponsive`]));
    win.webContents.on('console-message', (event, level, message, line, sourceId) => {
        const severity = event.level || (level === 3 ? 'error' : level === 2 ? 'warning' : 'info');
        if (debugLoggingEnabled || severity === 'error')
            writeMainLog(severity === 'error' ? 'error' : 'debug', [`${label} console`, { message: event.message || message, line: event.lineNumber || line, sourceId: event.sourceId || sourceId }]);
    });
    win.once('closed', () => { clearTimeout(win.uiReadyTimer); win.stopBackendWait?.(); });
}
function parseStoredSettingValue(value) {
    if (typeof value !== 'string')
        return null;
    try {
        return JSON.parse(value);
    }
    catch {
        return null;
    }
}
function sanitizeSettingsForStorage(settings) {
    const safeSettings = { ...(settings || {}) };
    delete safeSettings.securiteInfoToken;
    delete safeSettings.securiteInfoUrl;
    delete safeSettings.securiteInfoSetupText;
    return safeSettings;
}
function readSettingsFromSqlite() {
    let db = null;
    try {
        const { DatabaseSync } = require('node:sqlite');
        db = new DatabaseSync(getAppStateDbPath());
        db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
        const rows = db.prepare('SELECT key, value FROM settings').all();
        if (!rows.length)
            return null;
        return rows.reduce((settings, row) => {
            settings[row.key] = parseStoredSettingValue(row.value);
            return settings;
        }, {});
    }
    catch {
        return null;
    }
    finally {
        try {
            db && db.close();
        }
        catch { }
    }
}
function writeSettingsToSqlite(settings) {
    let db = null;
    try {
        fs.mkdirSync(getProgramDataDir(), { recursive: true });
        const { DatabaseSync } = require('node:sqlite');
        db = new DatabaseSync(getAppStateDbPath());
        db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
        const safeSettings = sanitizeSettingsForStorage(settings);
        const insert = db.prepare('INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)');
        db.exec("BEGIN IMMEDIATE");
        try {
            db.prepare('DELETE FROM settings').run();
            for (const [key, value] of Object.entries(safeSettings)) {
                insert.run(key, JSON.stringify(value ?? null));
            }
            db.exec('COMMIT');
        }
        catch (error) {
            db.exec('ROLLBACK');
            throw error;
        }
    }
    catch {
        // Startup settings are best-effort; the server owns normal persistence.
    }
    finally {
        try {
            db && db.close();
        }
        catch { }
    }
}
function readLegacySettings() {
    try {
        const settingsPath = path.join(getProgramDataDir(), 'settings.json');
        return JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    }
    catch {
        return null;
    }
}
function readAppSettings() {
    const sqliteSettings = readSettingsFromSqlite();
    const settings = sqliteSettings || readLegacySettings() || {};
    if (!sqliteSettings && Object.keys(settings).length > 0) {
        writeSettingsToSqlite(settings);
    }
    debugLoggingEnabled = settings.enableDebugLog === true;
    return settings;
}
async function handleThreatEvent(threat, port) {
    if (!threat || !threat.id || dismissedAlerts.has(threat.id))
        return;
    if (activeAlerts.has(threat.id)) {
        const win = activeAlerts.get(threat.id);
        if (win !== true && !win.isDestroyed()) {
            win.latestThreat = threat;
            win.webContents.send('clamshield-alert-update', threat);
        }
        return;
    }
    const existing = [...activeAlerts.values()].find(win => win !== true && !win.isDestroyed() &&
        win.threatPath === String(threat.originalPath || '').toLowerCase());
    if (existing)
        return;
    activeAlerts.set(threat.id, true);
    // Reading /api/status here delayed every alert behind aggregate engine stats.
    const settings = readAppSettings();
    createAlertWindow(threat, port, settings.playSoundOnAlert === true);
}
function handleApiEvent(eventName, data, port) {
    if (eventName === 'threat') {
        handleThreatEvent(data, port).catch(error => console.warn(englishText("desktop.electron_main.failed_to_handle_threat_event"), error.message));
    }
    else if (eventName === 'threat-resolved') {
        const win = activeAlerts.get(data?.id);
        if (win && win !== true && !win.isDestroyed())
            win.close();
    }
    else if (eventName === 'scan-summary') {
        if (data && !(scanSummaryWindow && !scanSummaryWindow.isDestroyed())) {
            createScanSummaryWindow(data, port);
        }
    }
    else if (eventName === 'results-reminder') {
        if (data && data.show && !(resultsReminderWindow && !resultsReminderWindow.isDestroyed())) {
            createResultsReminderWindow(data, port);
        }
    }
}
function connectApiEvents(port) {
    let retryTimer = null;
    const scheduleReconnect = () => {
        if (isQuiting || retryTimer)
            return;
        retryTimer = setTimeout(() => {
            retryTimer = null;
            connectApiEvents(port);
        }, 3000);
        retryTimer.unref?.();
    };
    const req = http.request({
        hostname: '127.0.0.1',
        port,
        path: '/api/events',
        method: 'GET',
        headers: apiHeaders({ Accept: 'text/event-stream' })
    }, (res) => {
        if (res.statusCode !== 200) {
            res.resume();
            scheduleReconnect();
            return;
        }
        let buffer = '';
        res.on('data', chunk => {
            buffer += chunk.toString();
            let boundary = buffer.indexOf('\n\n');
            while (boundary !== -1) {
                const block = buffer.slice(0, boundary);
                buffer = buffer.slice(boundary + 2);
                let eventName = 'message';
                const dataLines = [];
                for (const line of block.split('\n')) {
                    if (line.startsWith(':'))
                        continue;
                    if (line.startsWith('event:'))
                        eventName = line.slice(6).trim();
                    if (line.startsWith('data:'))
                        dataLines.push(line.slice(5).trim());
                }
                if (dataLines.length) {
                    try {
                        handleApiEvent(eventName, JSON.parse(dataLines.join('\n')), port);
                    }
                    catch (error) {
                        console.warn(englishText("desktop.electron_main.failed_to_parse_clamshield_event"), error.message);
                    }
                }
                boundary = buffer.indexOf('\n\n');
            }
        });
        res.on('end', scheduleReconnect);
        res.on('error', scheduleReconnect);
    });
    req.on('error', scheduleReconnect);
    req.end();
}
function reflowNotifications() {
    const { screen } = require('electron');
    const displays = screen.getAllDisplays();
    for (const entry of notificationWindows.values()) {
        if (!displays.some(display => display.id === entry.displayId))
            entry.displayId = screen.getPrimaryDisplay().id;
    }
    for (const display of displays) {
        const entries = [...notificationWindows.entries()].filter(([win, entry]) => !win.isDestroyed() && entry.ready && entry.displayId === display.id);
        const bounds = notificationLayout(display.workArea, entries.map(([win]) => win.getBounds()));
        entries.forEach(([win], index) => {
            if (!bounds[index]) {
                win.hide();
                return;
            }
            win.setBounds(bounds[index]);
            if (!win.isVisible())
                win.showInactive();
        });
    }
}
function trackNotification(win) {
    const { screen } = require('electron');
    const display = screen.getDisplayNearestPoint(screen.getCursorScreenPoint());
    notificationWindows.set(win, { displayId: display.id, ready: false });
    win.once('ready-to-show', () => {
        const entry = notificationWindows.get(win);
        if (entry)
            entry.ready = true;
        reflowNotifications();
    });
    win.once('closed', () => { notificationWindows.delete(win); reflowNotifications(); });
    if (!notificationScreenListeners) {
        notificationScreenListeners = true;
        for (const event of ['display-added', 'display-removed', 'display-metrics-changed'])
            screen.on(event, reflowNotifications);
    }
}
function createAlertWindow(threat, port, playSound) {
    const alertWidth = 460;
    const alertHeight = 240;
    const alertWin = new BrowserWindow({
        width: alertWidth,
        height: alertHeight,
        show: false,
        frame: false,
        transparent: false,
        backgroundColor: '#0f172a',
        alwaysOnTop: true,
        skipTaskbar: true,
        resizable: false,
        title: t("desktop.alert.clamshield_alert"),
        icon: path.join(__dirname, 'public/icon.png'),
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: getPublicAssetPath('alert-preload.cjs')
        }
    });
    activeAlerts.set(threat.id, alertWin);
    alertWin.threatPath = String(threat.originalPath || '').toLowerCase();
    alertWin.latestThreat = threat;
    trackNotification(alertWin);
    attachWindowLogging(alertWin, englishText("desktop.electron_main.threat_alert"));
    alertWin.webContents.on('did-finish-load', () => alertWin.webContents.send('clamshield-alert-update', alertWin.latestThreat));
    alertWin.on('closed', () => {
        activeAlerts.delete(threat.id);
        dismissedAlerts.add(threat.id);
        if (dismissedAlerts.size > 1000)
            dismissedAlerts.delete(dismissedAlerts.values().next().value);
    });
    console.debug(englishText("desktop.electron_main.opening_threat_alert_window"), { threatId: threat.id, playSound });
    alertWin.loadFile(getPublicAssetPath('alert.html'), {
        query: {
            id: String(threat.id || ''),
            name: String(threat.threatName || englishText("desktop.alert.html.unknown_threat")),
            path: String(threat.originalPath || 'Unknown path'),
            mode: String(threat.mode || 'decision'),
            title: String(threat.title || ''),
            subtitle: String(threat.subtitle || ''),
            playSound: playSound ? 'true' : 'false'
        }
    }).catch(err => {
        console.error(englishText("desktop.electron_main.failed_to_load_alert_html"), err);
        activeAlerts.delete(threat.id);
        if (!alertWin.isDestroyed())
            alertWin.close();
    });
}
function createResultsReminderWindow(reminder, port) {
    resultsReminderWindow = new BrowserWindow({
        width: 440,
        height: 180,
        show: false,
        frame: false,
        transparent: false,
        backgroundColor: '#0f172a',
        alwaysOnTop: true,
        skipTaskbar: true,
        resizable: false,
        title: t("desktop.electron_main.clamshield_results_reminder"),
        icon: path.join(__dirname, 'public/icon.png'),
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: getPublicAssetPath('results-reminder-preload.cjs')
        }
    });
    trackNotification(resultsReminderWindow);
    attachWindowLogging(resultsReminderWindow, englishText("desktop.electron_main.results_reminder"));
    resultsReminderWindow.on('closed', () => {
        resultsReminderWindow = null;
    });
    resultsReminderWindow.webContents.on('will-navigate', (event, targetUrl) => {
        if (targetUrl === `http://127.0.0.1:${port}/results`) {
            event.preventDefault();
            if (mainWindow) {
                mainWindow.show();
                mainWindow.loadURL(targetUrl).catch(err => console.error(englishText("desktop.electron_main.failed_to_open_results"), err));
            }
            if (resultsReminderWindow && !resultsReminderWindow.isDestroyed()) {
                resultsReminderWindow.close();
            }
        }
    });
    const reminderUrl = `http://127.0.0.1:${port}/results-reminder.html?count=${encodeURIComponent(reminder.count || 0)}&port=${port}`;
    resultsReminderWindow.loadURL(reminderUrl).catch(err => console.error(englishText("desktop.electron_main.failed_to_load_results_reminder_html"), err));
}
function createScanSummaryWindow(summary, port) {
    scanSummaryWindow = new BrowserWindow({
        width: 460,
        height: 205,
        show: false,
        frame: false,
        transparent: false,
        backgroundColor: '#0f172a',
        alwaysOnTop: true,
        skipTaskbar: true,
        resizable: false,
        title: t("desktop.scan_summary.clamshield_scan_summary"),
        icon: path.join(__dirname, 'public/icon.png'),
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: getPublicAssetPath('language-preload.cjs')
        }
    });
    trackNotification(scanSummaryWindow);
    attachWindowLogging(scanSummaryWindow, englishText("desktop.electron_main.scan_summary"));
    scanSummaryWindow.on('closed', () => {
        scanSummaryWindow = null;
    });
    scanSummaryWindow.webContents.on('will-navigate', (event, targetUrl) => {
        if (targetUrl === `http://127.0.0.1:${port}/results` || targetUrl === `http://127.0.0.1:${port}/quarantine`) {
            event.preventDefault();
            if (mainWindow) {
                mainWindow.show();
                mainWindow.loadURL(targetUrl).catch(err => console.error(englishText("desktop.electron_main.failed_to_open_scan_summary_target"), err));
            }
            if (scanSummaryWindow && !scanSummaryWindow.isDestroyed()) {
                scanSummaryWindow.close();
            }
        }
    });
    const params = new URLSearchParams({
        port: String(port),
        title: String(summary.title || englishText("desktop.scan_summary.scan_finished")),
        message: String(summary.message || ''),
        detail: String(summary.detail || ''),
        target: String(summary.target || ''),
        action: String(summary.action || 'results')
    });
    scanSummaryWindow.loadURL(`http://127.0.0.1:${port}/scan-summary.html?${params.toString()}`)
        .catch(err => console.error(englishText("desktop.electron_main.failed_to_load_scan_summary_html"), err));
}
function createUpdateAvailableWindow(update, config, port) {
    if (updateAvailableWindow && !updateAvailableWindow.isDestroyed()) {
        updateAvailableWindow.close();
    }
    updateAvailableWindow = new BrowserWindow({
        width: 460,
        height: 190,
        show: false,
        frame: false,
        transparent: false,
        backgroundColor: '#0f172a',
        alwaysOnTop: true,
        skipTaskbar: true,
        resizable: false,
        title: `${config.label} Update`,
        icon: path.join(__dirname, 'public/icon.png'),
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: getPublicAssetPath('language-preload.cjs')
        }
    });
    trackNotification(updateAvailableWindow);
    attachWindowLogging(updateAvailableWindow, 'Update available');
    updateAvailableWindow.on('closed', () => {
        updateAvailableWindow = null;
    });
    updateAvailableWindow.webContents.on('will-navigate', (event, targetUrl) => {
        if (targetUrl === `http://127.0.0.1:${port}/updates`) {
            event.preventDefault();
            openUpdatesTab(port);
            if (updateAvailableWindow && !updateAvailableWindow.isDestroyed()) {
                updateAvailableWindow.close();
            }
        }
    });
    const params = new URLSearchParams({
        port: String(port),
        label: String(config.label || 'ClamShield'),
        current: String(update.currentVersion || update.currentLabel || "Unknown"),
        latest: String(update.latestVersion || "Unknown"),
        mode: String(config.mode || 'available'),
        installPath: String(config.installPath || ''),
        skipPath: String(config.skipPath || ''),
        remindPath: String(config.remindPath || '')
    });
    updateAvailableWindow.loadURL(`http://127.0.0.1:${port}/update-available.html?${params.toString()}`).catch(err => {
        console.error("Failed to load update popup HTML", err);
        if (updateAvailableWindow && !updateAvailableWindow.isDestroyed()) {
            updateAvailableWindow.close();
        }
    });
}
function getFreePort() {
    return new Promise((resolve) => {
        const srv = net.createServer();
        srv.listen(0, () => {
            const port = srv.address().port;
            srv.close(() => resolve(port));
        });
    });
}
function requestJson(port, pathName, method = 'GET', body = null, timeoutMs = 0) {
    return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const req = http.request({
            hostname: '127.0.0.1',
            port,
            path: pathName,
            method,
            headers: payload ? {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                ...apiHeaders()
            } : apiHeaders()
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = data ? JSON.parse(data) : {};
                    if (res.statusCode >= 400) {
                        reject(new Error(parsed.error || `HTTP ${res.statusCode}`));
                    }
                    else {
                        resolve(parsed);
                    }
                }
                catch (error) {
                    reject(error);
                }
            });
        });
        req.on('error', reject);
        if (timeoutMs)
            req.setTimeout(timeoutMs, () => req.destroy(new Error(englishText("desktop.electron_main.the_action_timed_out_check_results_before_trying_again"))));
        if (payload)
            req.write(payload);
        req.end();
    });
}
function writeContextMenuBridgeFile() {
    if (process.platform !== 'win32' || !contextMenuBridgePort)
        return;
    const bridgePath = getContextMenuBridgePath();
    fs.mkdirSync(path.dirname(bridgePath), { recursive: true });
    fs.writeFileSync(bridgePath, JSON.stringify({
        port: contextMenuBridgePort,
        token: contextMenuBridgeToken,
        pid: process.pid,
        updatedAt: new Date().toISOString()
    }, null, 2));
}
function removeContextMenuBridgeFile() {
    try {
        fs.rmSync(getContextMenuBridgePath(), { force: true });
    }
    catch { }
}
function readJsonBody(req, limitBytes = 64 * 1024) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => {
            data += chunk;
            if (Buffer.byteLength(data) > limitBytes) {
                reject(new Error(englishText("desktop.electron_main.request_body_is_too_large")));
                req.destroy();
            }
        });
        req.on('end', () => {
            try {
                resolve(data ? JSON.parse(data) : {});
            }
            catch (error) {
                reject(error);
            }
        });
        req.on('error', reject);
    });
}
function startContextMenuBridge() {
    if (process.platform !== 'win32' || contextMenuBridgeServer)
        return;
    contextMenuBridgeServer = http.createServer(async (req, res) => {
        try {
            if (req.method !== 'POST' || req.url !== '/context-menu') {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: englishText("desktop.electron_main.not_found") }));
                return;
            }
            if (req.headers['x-clamshield-bridge'] !== contextMenuBridgeToken) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: englishText("desktop.electron_main.invalid_bridge_token") }));
                return;
            }
            const body = await readJsonBody(req);
            const action = normalizeContextMenuAction(body.action);
            const targets = Array.isArray(body.targets) ? body.targets : [];
            if (!action || targets.length === 0) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: englishText("desktop.electron_main.invalid_context_menu_request") }));
                return;
            }
            queueLegacyContextMenuRequest(action, targets);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
        }
        catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: error.message || String(error) }));
        }
    });
    contextMenuBridgeServer.on('error', error => {
        console.warn(englishText("desktop.electron_main.context_menu_bridge_failed"), error.message);
        removeContextMenuBridgeFile();
    });
    contextMenuBridgeServer.listen(0, '127.0.0.1', () => {
        contextMenuBridgePort = contextMenuBridgeServer.address().port;
        writeContextMenuBridgeFile();
    });
}
function getContextMenuRequestFile(argv = []) {
    const index = argv.findIndex(arg => arg === '--context-menu-request');
    if (index >= 0 && argv[index + 1])
        return argv[index + 1];
    const prefixed = argv.find(arg => String(arg || '').startsWith('--context-menu-request='));
    return prefixed ? prefixed.slice('--context-menu-request='.length) : '';
}
function getContextMenuLegacyRequest(argv = []) {
    const index = argv.findIndex(arg => arg === '--context-menu-legacy');
    let action = '';
    let targets = [];
    if (index >= 0) {
        action = String(argv[index + 1] || '');
        targets = argv.slice(index + 2).filter(Boolean);
    }
    else {
        const prefixed = argv.find(arg => String(arg || '').startsWith('--context-menu-legacy='));
        if (prefixed) {
            action = prefixed.slice('--context-menu-legacy='.length);
            const actionIndex = argv.indexOf(prefixed);
            targets = actionIndex >= 0 ? argv.slice(actionIndex + 1).filter(Boolean) : [];
        }
    }
    action = normalizeContextMenuAction(action);
    targets = targets.map(target => String(target || '').trim()).filter(Boolean);
    return action && targets.length > 0 ? { action, targets } : null;
}
function normalizeContextMenuAction(action) {
    const value = String(action || '').toLowerCase();
    return ['clamav', 'clamav-yara', 'clamav-yara-vt', 'add-exception'].includes(value) ? value : '';
}
function focusMainWindow() {
    if (!mainWindow || mainWindow.isDestroyed())
        return;
    if (!mainWindow.isVisible())
        mainWindow.show();
    if (mainWindow.isMinimized())
        mainWindow.restore();
    mainWindow.focus();
}
async function executeContextMenuAction(action, targets) {
    action = normalizeContextMenuAction(action) || 'clamav';
    targets = Array.from(new Set((Array.isArray(targets) ? targets : []).map(target => String(target || '').trim()).filter(Boolean)));
    if (targets.length === 0)
        return true;
    try {
        if (action === 'add-exception') {
            await requestJson(currentApiPort, '/api/context-menu/exceptions', 'POST', { targets });
            focusMainWindow();
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.loadURL(`http://127.0.0.1:${currentApiPort}/exceptions`).catch(error => console.warn(englishText("desktop.electron_main.failed_to_open_exceptions_page"), error.message));
            }
            return true;
        }
        const result = await requestJson(currentApiPort, '/api/scan', 'POST', {
            source: 'context-menu',
            contextAction: action,
            targets
        });
        focusMainWindow();
        if (mainWindow && !mainWindow.isDestroyed()) {
            const jobId = encodeURIComponent(result.jobId || '');
            mainWindow.loadURL(`http://127.0.0.1:${currentApiPort}/scan${jobId ? `?jobId=${jobId}` : ''}`).catch(error => console.warn(englishText("desktop.electron_main.failed_to_open_scan_page"), error.message));
        }
    }
    catch (error) {
        console.warn(englishText("desktop.electron_main.failed_to_process_context_menu_request"), error.message);
        focusMainWindow();
    }
    return true;
}
const pendingLegacyContextMenu = new Map();
function queueLegacyContextMenuRequest(action, targets) {
    action = normalizeContextMenuAction(action);
    if (!action || !Array.isArray(targets) || targets.length === 0)
        return true;
    const existing = pendingLegacyContextMenu.get(action) || { targets: new Set(), timer: null };
    for (const target of targets) {
        if (target)
            existing.targets.add(String(target));
    }
    if (existing.timer)
        clearTimeout(existing.timer);
    existing.timer = setTimeout(() => {
        pendingLegacyContextMenu.delete(action);
        executeContextMenuAction(action, Array.from(existing.targets)).catch(error => {
            console.warn(englishText("desktop.electron_main.legacy_context_menu_request_failed"), error.message);
        });
    }, 650);
    pendingLegacyContextMenu.set(action, existing);
    focusMainWindow();
    return true;
}
async function handleContextMenuRequest(argv = process.argv) {
    const legacyRequest = getContextMenuLegacyRequest(argv);
    if (legacyRequest) {
        return queueLegacyContextMenuRequest(legacyRequest.action, legacyRequest.targets);
    }
    const requestFile = getContextMenuRequestFile(argv);
    if (!requestFile || !currentApiPort)
        return false;
    let request = null;
    try {
        request = JSON.parse(fs.readFileSync(requestFile, 'utf8'));
    }
    catch (error) {
        console.warn(englishText("desktop.electron_main.failed_to_read_context_menu_request"), error.message);
        return true;
    }
    finally {
        fs.rm(requestFile, { force: true }, () => { });
    }
    const action = String(request.action || 'clamav');
    const targets = Array.isArray(request.paths) ? request.paths.filter(Boolean) : [];
    return executeContextMenuAction(action, targets);
}
function getPublicAssetPath(fileName) {
    return path.join(__dirname, 'public', fileName);
}
function trustedAlertSender(event, threatId) {
    const win = trustedLanguageSender(event);
    const entry = [...activeAlerts.entries()].find(([, value]) => value === win);
    const url = new URL(event.sender.getURL());
    if (!entry || !url.pathname.endsWith('/alert.html') || url.searchParams.get('id') !== String(entry[0]) || (threatId !== undefined && String(entry[0]) !== threatId))
        throw new Error('Untrusted threat alert request');
    return win;
}
ipcMain.handle('clamshield-alert-action', async (event, payload = {}) => {
    const threatId = String(payload.id || '');
    const action = String(payload.action || '');
    trustedAlertSender(event, threatId);
    if (!['quarantine', 'exception', 'results'].includes(action)) throw new Error('Invalid threat alert action');
    if (!currentApiPort || !threatId || !action) {
        throw new Error(englishText("desktop.electron_main.the_alert_action_is_missing_required_data"));
    }
    try {
        return await requestJson(currentApiPort, `/api/pending-threats/${encodeURIComponent(threatId)}/action`, 'POST', { action }, 30000);
    }
    catch (error) {
        return { success: false, error: error.message || englishText("desktop.alert.html.the_action_failed_try_again_or_choose_decide_later") };
    }
});
ipcMain.handle('clamshield-alert-log', async (event, payload = {}) => {
    trustedAlertSender(event);
    if (!currentApiPort)
        return { success: false };
    try {
        return await requestJson(currentApiPort, '/api/client-log', 'POST', {
            level: String(payload.level || 'error'),
            message: String(payload.message || englishText("desktop.electron_main.threat_popup_log")),
            details: payload.details || {}
        });
    }
    catch {
        return { success: false };
    }
});
ipcMain.handle('clamshield-results-reminder-action', async (event, payload = {}) => {
    if (trustedLanguageSender(event) !== resultsReminderWindow || !new URL(event.sender.getURL()).pathname.endsWith('/results-reminder.html')) throw new Error('Untrusted results reminder request');
    const action = String(payload.action || '');
    if (!['remind-10', 'remind-60', 'forget', 'open'].includes(action)) throw new Error('Invalid results reminder action');
    if (!currentApiPort || !action) {
        throw new Error(englishText("desktop.electron_main.the_results_reminder_action_is_missing_required_data"));
    }
    return requestJson(currentApiPort, '/api/results-reminder/action', 'POST', { action });
});
function openUpdatesTab(port) {
    if (!mainWindow)
        return;
    if (mainWindow.isMinimized())
        mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
    mainWindow.loadURL(`http://127.0.0.1:${port}/updates`).catch(err => console.error(englishText("desktop.electron_main.failed_to_open_updates"), err));
}
async function checkUpdatePrompt(port, settings, config) {
    if (settings[config.enabledKey] === false)
        return;
    if (settings[config.notifyAvailableKey] === false)
        return;
    if (Number(settings[config.remindAfterKey] || 0) > Date.now())
        return;
    if (config.skipWhenSilent && settings.appSilentAutoInstall === true)
        return;
    if (config.requiresInstalledStatusKey && config.status && config.status[config.requiresInstalledStatusKey] !== true)
        return;
    const intervalMs = Math.max(1, Number(settings[config.intervalKey] || config.defaultIntervalHours)) * 60 * 60 * 1000;
    if (Date.now() - Number(lastUpdateCheckAt[config.id] || 0) < intervalMs)
        return;
    lastUpdateCheckAt[config.id] = Date.now();
    try {
        const update = await requestJson(port, config.checkPath);
        if (!update.updateAvailable)
            return;
        if (updateAvailableWindow && !updateAvailableWindow.isDestroyed())
            return;
        createUpdateAvailableWindow(update, config, port);
    }
    catch (error) {
        console.warn(`${config.label} update prompt failed`, error.message);
        if (settings[config.notifyFailedKey] === true) {
            createUpdateAvailableWindow({
                currentVersion: error.message || String(error),
                latestVersion: '',
                updateAvailable: false
            }, {
                ...config,
                mode: 'failed'
            }, port);
        }
    }
}
function pollAppUpdates(port) {
    setInterval(async () => {
        if (appUpdateChecking)
            return;
        appUpdateChecking = true;
        try {
            const status = await requestJson(port, '/api/status');
            const settings = status.settings || {};
            debugLoggingEnabled = settings.enableDebugLog === true;
            const updateConfigs = [
                {
                    id: 'app',
                    label: 'ClamShield',
                    enabledKey: 'appUpdateCheckEnabled',
                    notifyAvailableKey: 'appUpdateNotifyAvailable',
                    notifyFailedKey: 'appUpdateNotifyFailed',
                    remindAfterKey: 'appUpdateRemindAfter',
                    intervalKey: 'appUpdateIntervalHours',
                    defaultIntervalHours: 168,
                    checkPath: '/api/app-update',
                    installPath: '/api/app-update/install',
                    skipPath: '/api/app-update/skip',
                    remindPath: '/api/app-update/remind',
                    skipWhenSilent: true
                },
                {
                    id: 'clamav-engine',
                    label: t("updates.clamav_engine"),
                    enabledKey: 'clamavEngineUpdateCheckEnabled',
                    notifyAvailableKey: 'clamavEngineUpdateNotifyAvailable',
                    notifyFailedKey: 'clamavEngineUpdateNotifyFailed',
                    remindAfterKey: 'clamavEngineRemindAfter',
                    intervalKey: 'clamavEngineUpdateIntervalHours',
                    defaultIntervalHours: 24,
                    requiresInstalledStatusKey: 'hasEngine',
                    checkPath: '/api/clamav-engine-update',
                    installPath: '/api/clamav-engine-update/install',
                    skipPath: '/api/clamav-engine-update/skip',
                    remindPath: '/api/clamav-engine-update/remind'
                },
                {
                    id: 'yara-engine',
                    label: t("updates.yara_engine"),
                    enabledKey: 'yaraEngineUpdateCheckEnabled',
                    notifyAvailableKey: 'yaraEngineUpdateNotifyAvailable',
                    notifyFailedKey: 'yaraEngineUpdateNotifyFailed',
                    remindAfterKey: 'yaraEngineRemindAfter',
                    intervalKey: 'yaraEngineUpdateIntervalHours',
                    defaultIntervalHours: 24,
                    requiresInstalledStatusKey: 'hasYaraEngine',
                    checkPath: '/api/yara-engine-update',
                    installPath: '/api/yara-engine-update/install',
                    skipPath: '/api/yara-engine-update/skip',
                    remindPath: '/api/yara-engine-update/remind'
                }
            ];
            for (const config of updateConfigs) {
                await checkUpdatePrompt(port, settings, { ...config, status });
            }
        }
        finally {
            appUpdateChecking = false;
        }
    }, 60000);
}
function localDateKey(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}
function getScheduledScanTiming(settings, now) {
    const frequency = settings.scheduledScanFrequency === 'monthly' ? 'monthly' : 'weekly';
    const time = /^([01]\d|2[0-3]):[0-5]\d$/.test(settings.scheduledScanTime || '')
        ? settings.scheduledScanTime
        : '03:00';
    const [hours, minutes] = time.split(':').map(Number);
    const dueAt = new Date(now);
    dueAt.setHours(hours, minutes, 0, 0);
    if (frequency === 'monthly') {
        const monthDays = Array.isArray(settings.scheduledScanMonthDays) ? settings.scheduledScanMonthDays.map(Number) : [1];
        if (!monthDays.includes(now.getDate()))
            return null;
    }
    else {
        const weekdays = Array.isArray(settings.scheduledScanWeekdays) ? settings.scheduledScanWeekdays.map(Number) : [0];
        if (!weekdays.includes(now.getDay()))
            return null;
    }
    const idleThresholdSeconds = Math.max(1, Number(settings.scheduledScanIdleMinutes || 15)) * 60;
    return {
        frequency,
        time,
        dueAt,
        monitorFrom: new Date(dueAt.getTime() - idleThresholdSeconds * 1000),
        idleThresholdSeconds,
        runKey: `${frequency}:${localDateKey(now)}:${time}`
    };
}
function getScheduledRunKey(settings, now) {
    const timing = getScheduledScanTiming(settings, now);
    if (!timing || now < timing.dueAt)
        return null;
    return timing.runKey;
}
function buildScheduledScanQueue(settings) {
    const queue = [];
    if (settings.scheduledScanFullDisk === true) {
        queue.push({ type: 'disk', label: t("scheduler.full_disk_scan") });
    }
    if (settings.scheduledScanFullDisk !== true && Array.isArray(settings.scheduledScanDirectories)) {
        const seen = new Set();
        for (const directory of settings.scheduledScanDirectories) {
            const target = String(directory || '').trim();
            const key = target.toLowerCase();
            if (!target || seen.has(key))
                continue;
            seen.add(key);
            queue.push({ type: 'folder', target, label: target });
        }
    }
    if (settings.scheduledScanMemory === true) {
        queue.push({ type: 'memory', label: t("scheduler.running_process_memory") });
    }
    return queue;
}
async function publishScheduledScanRuntime(port, payload) {
    try {
        await requestJson(port, '/api/scheduled-scan/runtime', 'POST', payload);
    }
    catch (error) {
        console.warn(englishText("desktop.electron_main.failed_to_publish_scheduled_scan_status"), error.message);
    }
}
function activeScanJobIds(status, currentJobId = '') {
    return Array.isArray(status?.activeScanJobIds)
        ? status.activeScanJobIds.filter(jobId => jobId && jobId !== currentJobId)
        : [];
}
async function publishScheduledScanWaitingForScan(port, idleSeconds, queueIndex = 0, totalTargets = 0) {
    await publishScheduledScanRuntime(port, {
        state: 'waiting-scan',
        message: englishText("desktop.electron_main.waiting_for_the_current_on_demand_or_scheduled_scan_to_finish"),
        activeJobId: '',
        currentTarget: '',
        queueIndex,
        totalTargets,
        idleSeconds
    });
}
async function startScheduledScanTarget(port) {
    if (!scheduledScanRun || scheduledScanRun.index >= scheduledScanRun.queue.length)
        return false;
    const status = await requestJson(port, '/api/status');
    const idleSeconds = scheduledScanRun.idleOnly ? powerMonitor.getSystemIdleTime() : 0;
    if (activeScanJobIds(status, scheduledScanRun.jobId).length > 0) {
        await publishScheduledScanWaitingForScan(port, idleSeconds, scheduledScanRun.index + 1, scheduledScanRun.queue.length);
        return false;
    }
    const target = scheduledScanRun.queue[scheduledScanRun.index];
    let response;
    try {
        response = await requestJson(port, '/api/scan', 'POST', {
            type: target.type,
            target: target.target,
            source: 'scheduled'
        });
    }
    catch (error) {
        if (/another .*scan.*running/i.test(error.message || '')) {
            await publishScheduledScanWaitingForScan(port, idleSeconds, scheduledScanRun.index + 1, scheduledScanRun.queue.length);
            return false;
        }
        throw error;
    }
    scheduledScanRun.jobId = response.jobId;
    scheduledScanRun.currentTarget = target;
    scheduledScanRun.transientApiErrors = 0;
    await publishScheduledScanRuntime(port, {
        state: 'running',
        message: englishText("desktop.electron_main.scanning", {
            label: String(target.label)
        }),
        activeJobId: response.jobId,
        currentTarget: target.label,
        queueIndex: scheduledScanRun.index + 1,
        totalTargets: scheduledScanRun.queue.length,
        idleSeconds
    });
    return true;
}
async function stopScheduledScan(port, reason, resultLabel, options = {}) {
    const discardProgress = options.discard !== false;
    if (scheduledScanRun?.jobId) {
        await requestJson(port, `/api/scan/${encodeURIComponent(scheduledScanRun.jobId)}/cancel`, 'POST', {
            discard: discardProgress,
            reason
        }).catch(error => console.warn(englishText("desktop.electron_main.failed_to_stop_scheduled_scan_job"), error.message));
    }
    const completedAt = new Date().toISOString();
    await publishScheduledScanRuntime(port, {
        state: 'stopped',
        message: reason,
        activeJobId: '',
        currentTarget: scheduledScanRun?.currentTarget?.label || '',
        queueIndex: scheduledScanRun ? scheduledScanRun.index + 1 : 0,
        totalTargets: scheduledScanRun?.queue?.length || 0,
        idleSeconds: scheduledScanRun?.idleOnly ? powerMonitor.getSystemIdleTime() : 0,
        lastRunAt: completedAt,
        lastResult: resultLabel,
        persist: true
    });
    scheduledScanRun = null;
}
function pollScheduledScans(port) {
    const tick = async () => {
        if (scheduledScanChecking)
            return;
        scheduledScanChecking = true;
        try {
            const status = await requestJson(port, '/api/status');
            const settings = status.settings || {};
            if (scheduledScanRun) {
                const idleSeconds = scheduledScanRun.idleOnly ? powerMonitor.getSystemIdleTime() : 0;
                if (settings.scheduledScanEnabled !== true) {
                    await stopScheduledScan(port, englishText("desktop.electron_main.scheduled_scanning_was_disabled"), englishText("desktop.electron_main.stopped_because_scheduled_scanning_was_disabled"));
                    return;
                }
                const previousIdleSeconds = Number(scheduledScanRun.lastIdleSeconds || idleSeconds);
                const userActivityResumed = idleSeconds + 2 < previousIdleSeconds;
                scheduledScanRun.lastIdleSeconds = idleSeconds;
                if (settings.scheduledScanIdleOnly !== false && userActivityResumed) {
                    await stopScheduledScan(port, englishText("desktop.electron_main.user_activity_resumed_the_scheduled_scan_was_paused"), englishText("desktop.electron_main.paused_when_user_activity_resumed"), { discard: false });
                    return;
                }
                if (!scheduledScanRun.jobId) {
                    if (scheduledScanRun.index >= scheduledScanRun.queue.length) {
                        scheduledScanRun = null;
                        return;
                    }
                    if (activeScanJobIds(status).length > 0) {
                        await publishScheduledScanWaitingForScan(port, idleSeconds, scheduledScanRun.index + 1, scheduledScanRun.queue.length);
                        return;
                    }
                    await startScheduledScanTarget(port);
                    return;
                }
                const job = await requestJson(port, `/api/scan/${encodeURIComponent(scheduledScanRun.jobId)}`);
                scheduledScanRun.transientApiErrors = 0;
                if (job.status !== 'done') {
                    await publishScheduledScanRuntime(port, {
                        state: 'running',
                        message: englishText("desktop.electron_main.scanning", {
                            label: String(scheduledScanRun.currentTarget.label)
                        }),
                        activeJobId: scheduledScanRun.jobId,
                        currentTarget: scheduledScanRun.currentTarget.label,
                        queueIndex: scheduledScanRun.index + 1,
                        totalTargets: scheduledScanRun.queue.length,
                        idleSeconds
                    });
                    return;
                }
                if (Number(job.result || 0) < 0) {
                    await stopScheduledScan(port, englishText("desktop.electron_main.the_scheduled_scan_stopped_because_the_scanner_returned_an_error"), englishText("desktop.electron_main.scanner_error"));
                    return;
                }
                if (Number(job.result || 0) === 1)
                    scheduledScanRun.detections = true;
                scheduledScanRun.index += 1;
                scheduledScanRun.jobId = '';
                if (scheduledScanRun.index < scheduledScanRun.queue.length)
                    return;
                const completedAt = new Date().toISOString();
                const lastResult = scheduledScanRun.detections ? englishText("desktop.electron_main.completed_with_detections") : englishText("desktop.electron_main.completed_with_no_detections");
                await publishScheduledScanRuntime(port, {
                    state: 'complete',
                    message: lastResult,
                    activeJobId: '',
                    currentTarget: '',
                    queueIndex: scheduledScanRun.queue.length,
                    totalTargets: scheduledScanRun.queue.length,
                    idleSeconds,
                    lastRunAt: completedAt,
                    lastResult,
                    persist: true
                });
                scheduledScanRun = null;
                return;
            }
            if (settings.scheduledScanEnabled !== true) {
                if (status.scheduledScanRuntime?.state !== 'disabled') {
                    await publishScheduledScanRuntime(port, {
                        state: 'disabled',
                        message: englishText("desktop.electron_main.scheduled_scanning_is_disabled"),
                        idleSeconds: 0
                    });
                }
                return;
            }
            if (settings.lastScheduledScanResult === 'Running') {
                await publishScheduledScanRuntime(port, {
                    state: 'stopped',
                    message: englishText("desktop.electron_main.the_previous_scheduled_scan_ended_when_clamshield_closed"),
                    idleSeconds: 0,
                    lastRunAt: new Date().toISOString(),
                    lastResult: englishText("desktop.electron_main.interrupted_when_clamshield_closed"),
                    persist: true
                });
                return;
            }
            const now = new Date();
            const timing = getScheduledScanTiming(settings, now);
            if (!timing) {
                if (status.scheduledScanRuntime?.state === 'waiting-idle') {
                    await publishScheduledScanRuntime(port, {
                        state: 'idle',
                        message: englishText("desktop.electron_main.waiting_for_the_next_scheduled_scan"),
                        idleSeconds: 0
                    });
                }
                return;
            }
            if (settings.scheduledScanIdleOnly === false && now < timing.dueAt) {
                return;
            }
            if (settings.scheduledScanIdleOnly !== false && now < timing.monitorFrom) {
                if (status.scheduledScanRuntime?.state === 'waiting-idle') {
                    await publishScheduledScanRuntime(port, {
                        state: 'idle',
                        message: englishText("desktop.electron_main.inactivity_monitoring_starts_minutes_before_the_scheduled_scan", {
                            value1: String(Math.round(timing.idleThresholdSeconds / 60))
                        }),
                        idleSeconds: 0
                    });
                }
                return;
            }
            const idleSeconds = settings.scheduledScanIdleOnly !== false ? powerMonitor.getSystemIdleTime() : 0;
            if (settings.scheduledScanIdleOnly !== false && now < timing.dueAt) {
                const minutesUntilStart = Math.max(1, Math.ceil((timing.dueAt.getTime() - now.getTime()) / 60000));
                await publishScheduledScanRuntime(port, {
                    state: 'waiting-idle',
                    message: englishText("desktop.electron_main.monitoring_keyboard_and_mouse_inactivity_for_the_scheduled_scan_i", {
                        minutesUntilStart: String(minutesUntilStart),
                        value2: String(minutesUntilStart === 1 ? '' : "s")
                    }),
                    idleSeconds
                });
                return;
            }
            const runKey = getScheduledRunKey(settings, now);
            if (!runKey || settings.lastScheduledScanRunKey === runKey)
                return;
            const queue = buildScheduledScanQueue(settings);
            if (queue.length === 0) {
                await publishScheduledScanRuntime(port, {
                    state: 'error',
                    message: englishText("desktop.electron_main.the_scheduled_scan_has_no_selected_targets"),
                    idleSeconds,
                    lastRunKey: runKey,
                    lastRunAt: new Date().toISOString(),
                    lastResult: englishText("desktop.electron_main.no_scan_targets_selected"),
                    persist: true
                });
                return;
            }
            if (activeScanJobIds(status).length > 0) {
                await publishScheduledScanWaitingForScan(port, idleSeconds);
                return;
            }
            if (settings.scheduledScanIdleOnly !== false && idleSeconds < timing.idleThresholdSeconds) {
                const remainingMinutes = Math.max(1, Math.ceil((timing.idleThresholdSeconds - idleSeconds) / 60));
                await publishScheduledScanRuntime(port, {
                    state: 'waiting-idle',
                    message: englishText("desktop.electron_main.waiting_for_more_minute_of_keyboard_and_mouse_inactivity", {
                        remainingMinutes: String(remainingMinutes),
                        value2: String(remainingMinutes === 1 ? '' : "s")
                    }),
                    idleSeconds
                });
                return;
            }
            scheduledScanRun = {
                runKey,
                queue,
                index: 0,
                jobId: '',
                currentTarget: null,
                detections: false,
                lastIdleSeconds: idleSeconds,
                idleOnly: settings.scheduledScanIdleOnly !== false,
                transientApiErrors: 0
            };
            await publishScheduledScanRuntime(port, {
                state: 'running',
                message: englishText("desktop.electron_main.starting_scheduled_scan"),
                activeJobId: '',
                currentTarget: '',
                queueIndex: 0,
                totalTargets: queue.length,
                idleSeconds,
                lastRunKey: runKey,
                lastRunAt: new Date().toISOString(),
                lastResult: "Running",
                persist: true
            });
            await startScheduledScanTarget(port);
        }
        catch (error) {
            console.warn(englishText("desktop.electron_main.scheduled_scan_check_failed"), error.message);
            if (scheduledScanRun) {
                if (isTransientApiConnectionError(error)) {
                    scheduledScanRun.transientApiErrors = Number(scheduledScanRun.transientApiErrors || 0) + 1;
                    if (scheduledScanRun.jobId || scheduledScanRun.transientApiErrors <= scheduledScanTransientErrorLimit) {
                        await publishScheduledScanRuntime(port, {
                            state: 'running',
                            message: scheduledScanRun.jobId
                                ? englishText("desktop.electron_main.scanner_is_still_running_reconnecting_to_local_status", {
                                    transientApiErrors: String(scheduledScanRun.transientApiErrors)
                                }) : englishText("desktop.electron_main.scanner_is_starting_retrying_local_status", {
                                transientApiErrors: String(scheduledScanRun.transientApiErrors),
                                scheduledScanTransientErrorLimit: String(scheduledScanTransientErrorLimit)
                            }),
                            activeJobId: scheduledScanRun.jobId || '',
                            currentTarget: scheduledScanRun.currentTarget?.label || '',
                            queueIndex: scheduledScanRun.index + 1,
                            totalTargets: scheduledScanRun.queue.length,
                            idleSeconds: scheduledScanRun.idleOnly ? powerMonitor.getSystemIdleTime() : 0
                        });
                        return;
                    }
                }
                await publishScheduledScanRuntime(port, {
                    state: 'error',
                    message: englishText("desktop.electron_main.scheduled_scan_error", {
                        message: String(error.message)
                    }),
                    activeJobId: scheduledScanRun.jobId || '',
                    currentTarget: scheduledScanRun.currentTarget?.label || '',
                    queueIndex: scheduledScanRun.index + 1,
                    totalTargets: scheduledScanRun.queue.length,
                    idleSeconds: scheduledScanRun.idleOnly ? powerMonitor.getSystemIdleTime() : 0,
                    lastRunAt: new Date().toISOString(),
                    lastResult: englishText("updates.error", {
                        message: String(error.message)
                    }),
                    persist: true
                });
                scheduledScanRun = null;
            }
        }
        finally {
            scheduledScanChecking = false;
        }
    };
    const timer = setInterval(tick, 10000);
    timer.unref?.();
    setTimeout(tick, 3000);
}
function waitForWindowBackend(window, port) {
    window.stopBackendWait?.();
    const startedAt = Date.now();
    const origin = `http://127.0.0.1:${port}`;
    let stopped = false;
    let timer = null;
    let request = null;
    const stop = () => {
        stopped = true;
        if (timer)
            clearTimeout(timer);
        request?.destroy();
        request = null;
        window.removeListener?.('closed', stop);
    };
    window.stopBackendWait = stop;
    window.once('closed', stop);
    const probe = () => {
        if (stopped || window.isDestroyed() || isQuiting)
            return stop();
        if (Date.now() - startedAt >= 45000) {
            stop();
            showWindowFailure(window, { stage: englishText("desktop.electron_main.connecting_to_local_service"), code: 'BACKEND_TIMEOUT', message: englishText("desktop.electron_main.the_local_service_did_not_become_ready_within_45_seconds") });
            return;
        }
        // Keep a page opened by a tray/context-menu action instead of resetting its route.
        if (window.webContents.getURL().startsWith(`${origin}/`))
            return stop();
        let settled = false;
        const retry = () => {
            if (settled || stopped)
                return;
            settled = true;
            request = null;
            timer = setTimeout(probe, 300);
        };
        request = http.get({ hostname: '127.0.0.1', port, path: '/api/ready', headers: apiHeaders() }, response => {
            response.resume();
            response.on('end', () => {
                if (settled || stopped)
                    return;
                if (response.statusCode !== 200)
                    return retry();
                settled = true;
                request = null;
                window.loadURL(origin).then(stop).catch(() => { settled = false; retry(); });
            });
            response.on('error', retry);
        });
        request.on('error', retry);
        request.setTimeout(1500, () => request?.destroy());
    };
    probe();
    return stop;
}
function createWindow(port, startHidden = false) {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        title: 'ClamShield',
        backgroundColor: '#020617',
        autoHideMenuBar: true,
        show: !startHidden,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: getPublicAssetPath('desktop-preload.cjs')
        },
        icon: path.join(__dirname, 'public/icon.png')
    });
    const window = mainWindow;
    const painted = new Promise(resolve => {
        window.once('ready-to-show', resolve);
        window.once('closed', resolve);
    });
    attachWindowLogging(mainWindow, englishText("desktop.electron_main.main_window"));
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        if (/^(https?:\/\/|mailto:)/i.test(url)) {
            shell.openExternal(url).catch(error => console.warn(englishText("desktop.electron_main.failed_to_open_external_link"), error.message));
        }
        return { action: 'deny' };
    });
    mainWindow.webContents.on('will-navigate', (event, targetUrl) => {
        const localOrigin = `http://127.0.0.1:${port}`;
        try {
            if (new URL(targetUrl).origin === localOrigin)
                return;
        }
        catch { }
        event.preventDefault();
        if (/^(https?:\/\/|mailto:)/i.test(targetUrl)) {
            shell.openExternal(targetUrl).catch(error => console.warn(englishText("desktop.electron_main.failed_to_open_external_link"), error.message));
        }
    });
    // This local page paints before the backend module is loaded, including cold starts.
    const startup = window.loadFile(getPublicAssetPath('startup.html'))
        .then(() => painted)
        .then(() => { if (!window.isDestroyed())
        waitForWindowBackend(window, port); })
        .catch(error => {
        console.warn(englishText("desktop.electron_main.could_not_load_the_startup_shell"), error.message);
        if (!window.isDestroyed())
            waitForWindowBackend(window, port);
    });
    mainWindow.on('close', function (event) {
        if (!isQuiting) {
            event.preventDefault();
            mainWindow.hide();
            event.returnValue = false;
        }
    });
    mainWindow.on('closed', function () {
        mainWindow = null;
    });
    return startup;
}
function createTray() {
    const iconExt = process.platform === 'win32' ? 'favicon.ico' : 'icon.png';
    const iconPath = path.join(__dirname, `public/${iconExt}`);
    const trayIcon = fs.existsSync(iconPath) ? nativeImage.createFromPath(iconPath) : nativeImage.createEmpty();
    tray = new Tray(trayIcon);
    updateTrayLanguage();
    tray.on('click', () => {
        if (mainWindow) mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
    });
}
function updateTrayLanguage() {
    if (!tray) return;
    const contextMenu = Menu.buildFromTemplate([
        { label: t("desktop.electron_main.open_clamshield"), click: () => { if (mainWindow)
                mainWindow.show(); } },
        { type: 'separator' },
        { label: t("desktop.electron_main.quit"), click: () => {
                isQuiting = true;
                app.quit();
            } }
    ]);
    tray.setToolTip(t("desktop.electron_main.clamshield_windows_gui_for_clamav"));
    tray.setContextMenu(contextMenu);
}
function startServer(port) {
    const serverPath = path.join(__dirname, 'dist/server.cjs');
    const serverDevPath = path.join(__dirname, 'server.ts');
    try {
        if (fs.existsSync(serverPath)) {
            // Production build (run directly in main process)
            process.env.PORT = port.toString();
            process.env.NODE_ENV = 'production';
            process.env.CLAMSHIELD_API_TOKEN = apiSessionToken;
            require(serverPath);
            serverProcess = { kill: () => { } }; // dummy object to maintain compatibility
        }
        else {
            // Fallback to dev server
            serverProcess = spawn(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['tsx', `"${serverDevPath}"`], {
                cwd: __dirname,
                env: { ...process.env, PORT: port.toString(), CLAMSHIELD_API_TOKEN: apiSessionToken },
                shell: true
            });
        }
        if (serverProcess && serverProcess.stdout && typeof serverProcess.stdout.on === 'function') {
            serverProcess.stdout.on('data', (data) => console.log(englishText("desktop.electron_main.server", {
                data: String(data)
            })));
        }
        if (serverProcess && serverProcess.stderr && typeof serverProcess.stderr.on === 'function') {
            serverProcess.stderr.on('data', (data) => console.error(englishText("desktop.electron_main.server_error", {
                data: String(data)
            })));
        }
    }
    catch (err) {
        console.error(englishText("desktop.electron_main.failed_to_start_server"), err);
        showWindowFailure(mainWindow, { stage: englishText("desktop.electron_main.starting_local_service"), code: err.code || 'BACKEND_START_FAILED', message: err.message, details: err.stack });
    }
}
app.on('ready', async () => {
    if (!gotSingleInstanceLock)
        return;
    getDesktopLanguage(true);
    const port = await getFreePort();
    currentApiPort = port;
    const settings = readAppSettings();
    const startHidden = process.argv.includes('--minimized');
    writeMainLog('info', [englishText("desktop.electron_main.clamshield_electron_ready"), { port, startHidden, argv: process.argv, version: app.getVersion() }]);
    console.log(englishText("desktop.electron_main.clamshield_electron_starting"), { port, startHidden, debugLoggingEnabled });
    await setApiSessionCookie(port);
    createTray();
    await createWindow(port, startHidden);
    if (isQuiting || !mainWindow || mainWindow.isDestroyed())
        return;
    startServer(port);
    writeMainLog('info', [englishText("desktop.electron_main.clamshield_backend_process_requested"), { port }]);
    startContextMenuBridge();
    connectApiEvents(port);
    pollAppUpdates(port);
    pollScheduledScans(port);
    handleContextMenuRequest(process.argv).catch(error => console.warn(englishText("desktop.electron_main.initial_context_menu_request_failed"), error.message));
});
app.on('second-instance', (_event, argv) => {
    focusMainWindow();
    handleContextMenuRequest(argv).catch(error => console.warn(englishText("desktop.electron_main.second_instance_context_menu_request_failed"), error.message));
});
app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') {
        if (serverProcess)
            serverProcess.kill();
        app.quit();
    }
});
app.on('activate', function () {
    if (mainWindow === null) {
        // Note: getFreePort should ideally be reused, but here we just pass the existing process.env.PORT
        createWindow(process.env.PORT || 3000);
    }
});
app.on('before-quit', () => {
    removeContextMenuBridgeFile();
    if (contextMenuBridgeServer)
        contextMenuBridgeServer.close();
    if (serverProcess)
        serverProcess.kill();
});
