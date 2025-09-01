import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..", "src");
const port = process.env.PORT || 8080;

const csp = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'"
].join("; ");

const mime = {
  ".html": "text/html; charset=utf-8",
  ".js":   "text/javascript; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".svg":  "image/svg+xml",
  ".ib":   "application/x-ironbox"
};

const server = http.createServer((req, res) => {
  const urlPath = new URL(req.url, `http://${req.headers.host}`).pathname;
  let p = path.normalize(path.join(root, urlPath));
  if (!p.startsWith(root)) return send(403, "Forbidden");
  if (fs.existsSync(p) && fs.statSync(p).isDirectory()) p = path.join(p, "index.html");
  if (!fs.existsSync(p)) return send(404, "Not Found");

  const ext = path.extname(p);
  res.setHeader("Content-Type", mime[ext] || "application/octet-stream");
  res.setHeader("Content-Security-Policy", csp);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.writeHead(200);
  res.end(fs.readFileSync(p));

  function send(code, msg) {
    res.writeHead(code, { "Content-Type": "text/plain; charset=utf-8" });
    res.end(msg);
  }
});

server.listen(port, () => {
  console.log(`Static app on http://localhost:${port}`);
});
