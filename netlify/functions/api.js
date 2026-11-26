/* Netlify 包装层：把 Netlify 的 event 转成 api/index.js 需要的 req/res */
const core = require("../../api/index.js");

function toReq(event) {
  const raw = event.rawUrl || ("https://x" + (event.path || "/"));
  const u = new URL(raw, "https://x");
  const headers = {};
  for (const k in (event.headers || {})) headers[String(k).toLowerCase()] = event.headers[k];
  let body = "";
  if (event.body) body = event.isBase64Encoded ? Buffer.from(event.body, "base64").toString("utf8") : event.body;
  const ip = event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || "unknown";
  const req = {
    method: (event.httpMethod || "GET").toUpperCase(),
    url: u.pathname + u.search,
    headers,
    body,
    socket: { remoteAddress: ip },
  };
  req.on = (name, cb) => { if (name === "data" && body) cb(body); if (name === "end") cb(); };
  return req;
}

exports.handler = async (event) => {
  const req = toReq(event);
  const out = { statusCode: 200, headers: {}, body: "" };
  const res = {
    writeHead(code, headers) { out.statusCode = code; if (headers) for (const k in headers) out.headers[k] = headers[k]; return res; },
    setHeader(k, v) { out.headers[k] = v; },
    end(b) { if (b !== undefined && b !== null) out.body = typeof b === "string" ? b : String(b); },
  };
  await core(req, res);
  return { statusCode: out.statusCode, headers: out.headers, body: out.body, isBase64Encoded: false };
};
