import http from "node:http";

/**
 * Minimal fixture server used to manually verify the scanner detects real,
 * known-good vs known-bad configurations — never used as a source of mock
 * scan results in the product itself, only as a target to scan against.
 * Run with: node tests/fixtures/server.mjs
 */

const PORT = process.env.FIXTURE_PORT ? Number(process.env.FIXTURE_PORT) : 4000;

const INDEX_HTML = `<!doctype html><html><body>
<h1>Scanner Test Fixtures</h1>
<ul>
  <li><a href="/secure">/secure — good headers, secure cookie, locked-down CORS</a></li>
  <li><a href="/insecure">/insecure — missing headers, insecure cookie, permissive CORS, HTTP password form</a></li>
</ul>
</body></html>`;

const SECURE_HTML = `<!doctype html><html><body>
<h1>Secure Page</h1>
<form action="/login" method="post"><input type="password" name="p"><button>Login</button></form>
</body></html>`;

const INSECURE_HTML = `<!doctype html><html><body>
<h1>Insecure Page</h1>
<form action="http://example.com/login" method="post"><input type="password" name="p"><button>Login</button></form>
<script src="http://cdn.example.com/legacy.js"></script>
</body></html>`;

const server = http.createServer((req, res) => {
  const origin = req.headers.origin;

  if (req.url === "/secure") {
    res.writeHead(200, {
      "Content-Type": "text/html",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "geolocation=()",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Set-Cookie": "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
    });
    res.end(SECURE_HTML);
    return;
  }

  if (req.url === "/insecure") {
    const headers = {
      "Content-Type": "text/html",
      Server: "Apache/2.4.41 (Ubuntu)",
      "X-Powered-By": "Express",
      "Set-Cookie": "sessionid=abc123; Path=/",
    };
    if (origin) {
      headers["Access-Control-Allow-Origin"] = origin;
      headers["Access-Control-Allow-Credentials"] = "true";
    }
    res.writeHead(200, headers);
    res.end(INSECURE_HTML);
    return;
  }

  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(INDEX_HTML);
});

server.listen(PORT, () => {
  console.log(`Fixture server running at http://localhost:${PORT}`);
  console.log(`  http://localhost:${PORT}/secure`);
  console.log(`  http://localhost:${PORT}/insecure`);
});
