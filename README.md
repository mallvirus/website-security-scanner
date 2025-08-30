## website-security-scanner

Fast, lightweight website security scanner for Node.js (headers, TLS, ports, basic vulns) with optional OWASP ZAP integration.

### Quick start
```bash
npm install -g website-security-scanner
website-security-scanner https://example.com --json
```

Programmatic:
```js
const { runScan, loadConfig } = require('website-security-scanner');

(async () => {
  const config = loadConfig();
  const results = await runScan({ targetUrl: 'https://example.com', useZap: false, config });
  console.log(JSON.stringify(results, null, 2));
})();
```

### Features
- Security headers and cookie flags (CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy; Secure/HttpOnly/SameSite)
- TLS certificate checks (validity, expiry, protocol); HTTP/2 via ALPN; HTTP/3 via Alt-Svc
- Open ports scan (common ports) with concurrency limits
- Basic reflected XSS and SQLi heuristics
- DOM heuristics (inline scripts, inline event handlers, mixed content)
- Configurable timeouts, concurrency, and severity threshold
- Optional OWASP ZAP daemon integration

### CLI usage
```bash
website-security-scanner <url> [--json] [--zap] [--config path] [--min-sev Sev]
```
- --json: print JSON
- --zap: run OWASP ZAP (requires ZAP daemon)
- --config: path to a JSON config file
- --min-sev: Info | Low | Medium | High | Critical (filters display)

Exit codes:
- 0: success, no Critical findings
- 2: at least one Critical finding
- 1: runtime error

Examples:
```bash
website-security-scanner https://example.com
website-security-scanner https://example.com --json --min-sev Low
website-security-scanner http://example.com --config scanner.config.json
```

### Configuration
Create `scanner.config.json`:
```json
{
  "minSeverity": "Low",
  "timeouts": { "defaultMs": 8000, "tlsMs": 10000, "portProbeMs": 1500 },
  "concurrency": { "portProbes": 10 }
}
```

### ZAP integration (optional)
Run ZAP daemon and set env vars:
```bash
zap.sh -daemon -config api.addrs.addr.name=127.0.0.1 -config api.addrs.addr.regex=false -config api.key=YOURKEY
export ZAP_HOST=127.0.0.1 ZAP_PORT=8090 ZAP_API_KEY=YOURKEY
website-security-scanner https://example.com --zap --json
```

### How it works
- Orchestrator runs scanners in parallel with timeouts and aggregates results
- Scanners: headers, ssl, ports, vulns (XSS/SQLi + DOM), zap (optional)
- Reporter prints human or JSON output; exit code signals severity


### License
MIT
