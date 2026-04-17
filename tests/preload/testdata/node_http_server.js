#!/usr/bin/env node
// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

const fs = require("fs");
const http = require("http");

if (process.argv.length < 5) {
  console.error("usage: node_http_server.js <host> <port> <mark-file>");
  process.exit(2);
}

const host = process.argv[2];
const port = Number(process.argv[3]);
const markFile = process.argv[4];

const html = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>uwgs-wrapper-smoke</title>
  </head>
  <body>booting<script src="/client.js"></script></body>
</html>`;

const clientJS = `
window.addEventListener("load", async () => {
  try {
    const res = await fetch("/report", {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "chrome-post-ok"
    });
    document.body.textContent = "script-ok:" + res.status;
  } catch (err) {
    document.body.textContent = "script-failed:" + err.message;
  }
});
`;

const server = http.createServer((req, res) => {
  console.error(`REQ ${req.method} ${req.url}`);
  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(html);
    return;
  }
  if (req.method === "GET" && req.url === "/client.js") {
    res.writeHead(200, {
      "content-type": "application/javascript; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(clientJS);
    return;
  }
  if (req.method === "POST" && req.url === "/report") {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      fs.writeFileSync(markFile, body);
      res.writeHead(204);
      res.end();
    });
    return;
  }
  res.writeHead(404);
  res.end("not found");
});

server.listen(port, host, () => {
  process.stdout.write("READY\n");
});
