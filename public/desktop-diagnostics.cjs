const { randomUUID } = require("node:crypto");

function sanitize(value, secrets = []) {
  const clean = (input, key = "", depth = 0) => {
    if (/token|api.?key|authorization|cookie|password|secret/i.test(key))
      return "[redacted]";
    if (depth > 8) return "[truncated]";
    if (input instanceof Error)
      return clean(
        { message: input.message, stack: input.stack, code: input.code },
        "",
        depth + 1,
      );
    if (Array.isArray(input))
      return input.slice(0, 40).map((item) => clean(item, "", depth + 1));
    if (input && typeof input === "object")
      return Object.fromEntries(
        Object.entries(input)
          .slice(0, 40)
          .map(([k, v]) => [k, clean(v, k, depth + 1)]),
      );
    if (typeof input !== "string") return input;
    let text = input.slice(0, 16000);
    for (const secret of secrets)
      if (secret) text = text.split(secret).join("[redacted]");
    return text
      .replace(/https?:\/\/[^\s<>"']+/gi, (url) => {
        try {
          const parsed = new URL(url);
          return parsed.origin + parsed.pathname;
        } catch {
          return "[URL redacted]";
        }
      })
      .replace(
        /((?:api[-_ ]?key|token|authorization|cookie|password|secret)\s*[=:]\s*)(?:Bearer\s+)?[^\s,;]+/gi,
        "$1[redacted]",
      );
  };
  return clean(value);
}

function createDiagnostic(input, environment, secrets = []) {
  return sanitize(
    {
      id: randomUUID(),
      time: new Date().toISOString(),
      version: environment.version,
      os: environment.os,
      stage: String(input.stage || "Loading interface"),
      code: String(input.code || "UNKNOWN"),
      message: String(
        input.message || "The application could not finish loading.",
      ),
      url: input.url || "",
      details: input.details || "",
    },
    secrets,
  );
}

function errorHtml(record) {
  const escape = (value) =>
    String(value).replace(
      /[&<>"']/g,
      (char) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[char],
    );
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';script-src 'unsafe-inline'"><title>ClamShield — could not load</title><style>
  *{box-sizing:border-box}body{margin:0;min-height:100vh;background:#020617;color:#e2e8f0;font:15px/1.55 system-ui,sans-serif;display:grid;place-items:center;padding:28px}.card{width:min(820px,100%);background:#0f172a;border:1px solid #7f4b26;border-radius:18px;padding:30px}h1{font-size:26px;margin:0 0 10px;color:#fef3c7}p{overflow-wrap:anywhere}.muted{color:#94a3b8}dl{display:grid;grid-template-columns:110px 1fr;gap:8px;margin:24px 0}dt{color:#94a3b8}dd{margin:0;overflow-wrap:anywhere}nav{display:flex;flex-wrap:wrap;gap:10px}button{background:#1e293b;color:#e2e8f0;border:1px solid #475569;border-radius:8px;padding:10px 15px;font:inherit;cursor:pointer}button:first-child{background:#4338ca}button:focus-visible{outline:2px solid #a5b4fc;outline-offset:3px}details{margin-top:22px}summary{cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:240px;overflow:auto;font-size:12px;background:#020617;padding:14px;border-radius:8px}#feedback{color:#fcd34d;min-height:24px}
  </style></head><body><main class="card"><h1>ClamShield could not load</h1><p>${escape(record.message)}</p><p class="muted">Protection status could not be verified from this screen. Retry the interface or copy the diagnostics for troubleshooting.</p><dl><dt>Stage</dt><dd>${escape(record.stage)}</dd><dt>Error</dt><dd>${escape(record.code)}</dd><dt>Time</dt><dd>${escape(record.time)}</dd><dt>Diagnostic ID</dt><dd>${escape(record.id)}</dd><dt>Version</dt><dd>${escape(record.version)}</dd></dl><nav aria-label="Troubleshooting"><button data-action="retry">Retry</button><button data-action="copyDiagnostics">Copy diagnostics</button><button data-action="openLogs">Open logs folder</button></nav><p id="feedback" role="status" aria-live="polite"></p><details><summary>Technical details</summary><pre>${escape(JSON.stringify(record, null, 2))}</pre></details></main><script>
    document.querySelectorAll('button').forEach(button=>button.addEventListener('click',async()=>{const output=document.getElementById('feedback');try{if(!window.clamshieldDesktop)throw new Error('Desktop diagnostics are unavailable. Copy the technical details manually.');await window.clamshieldDesktop[button.dataset.action]();output.textContent=button.dataset.action==='copyDiagnostics'?'Diagnostics copied.':button.dataset.action==='openLogs'?'Opened the logs folder.':'Retrying…';}catch(error){output.textContent=error.message;}}));
  </script></body></html>`;
}

module.exports = { sanitize, createDiagnostic, errorHtml };
