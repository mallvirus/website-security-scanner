const https = require('https');
const http = require('http');
const cheerio = require('cheerio');

function httpGet(urlObj, pathWithQuery) {
	const httpLib = urlObj.protocol === 'https:' ? https : http;
	return new Promise((resolve, reject) => {
		httpLib.get({
			hostname: urlObj.hostname,
			port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
			path: pathWithQuery,
			headers: { 'User-Agent': 'web-scanner/1.0' }
		}, res => {
			let data = '';
			res.on('data', chunk => (data += chunk));
			res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
		}).on('error', reject);
	});
}

function makeFinding(severity, title, details, remediation, evidence) {
	return { severity, title, details, remediation, evidence };
}

async function checkReflectedXss(urlObj) {
	const payload = "<script>alert('xss')</script>";
	const path = `${urlObj.pathname || '/'}?q=${encodeURIComponent(payload)}`;
	try {
		const res = await httpGet(urlObj, path);
		if (res.statusCode >= 200 && res.statusCode < 400 && res.body && res.body.includes(payload)) {
			return [makeFinding('High', 'Potential reflected XSS', `Payload reflected at ${path}`,'HTML-encode user input and use a strict CSP.', payload)];
		}
	} catch (err) {
		return [makeFinding('Info', 'XSS check failed', err.message, 'Ensure the target is reachable.')];
	}
	return [];
}

async function checkBasicSqli(urlObj) {
	const payload = "' OR '1'='1";
	const path = `${urlObj.pathname || '/'}?id=${encodeURIComponent(payload)}`;
	try {
		const res = await httpGet(urlObj, path);
		if (res.statusCode >= 500) {
			return [makeFinding('Medium', 'Possible SQL injection error behavior', `500 error for payload at ${path}`, 'Use parameterized queries and input validation.')];
		}
		if (/sql syntax|mysql|sqlite|postgres|odbc|oracle/i.test(res.body || '')) {
			return [makeFinding('Medium', 'Potential SQL error leakage', `SQL keywords in response at ${path}`, 'Disable detailed error messages in production; sanitize inputs.')];
		}
	} catch (err) {
		return [makeFinding('Info', 'SQLi check failed', err.message, 'Ensure the target is reachable.')];
	}
	return [];
}

async function checkBasicVulns(urlObj) {
	const findings = [];
	const xss = await checkReflectedXss(urlObj);
	findings.push(...xss);
	const sqli = await checkBasicSqli(urlObj);
	findings.push(...sqli);

	// DOM-based checks on root page
	try {
		const res = await httpGet(urlObj, urlObj.pathname || '/');
		if (res.body) {
			const $ = cheerio.load(res.body);
			// Inline scripts detection
			$('script:not([src])').each((_, el) => {
				const content = $(el).html() || '';
				if (content.trim().length > 0) {
					findings.push(makeFinding('Low', 'Inline script detected', 'Inline <script> present', 'Avoid inline scripts; use external scripts and CSP nonces/hashes.'));
				}
			});
			// Inline event handlers
			$('*').each((_, el) => {
				for (const attr of Object.keys(el.attribs || {})) {
					if (/^on[a-z]+$/i.test(attr)) {
						findings.push(makeFinding('Low', 'Inline event handler detected', `${attr} on <${el.name}>`, 'Avoid inline event handlers; use addEventListener and CSP.'));
					}
				}
			});
			// Mixed content: http resources on https page
			if (urlObj.protocol === 'https:') {
				$('img,script,link,iframe,video,audio,source').each((_, el) => {
					const src = el.attribs && (el.attribs.src || el.attribs.href);
					if (src && /^http:\/\//i.test(src)) {
						findings.push(makeFinding('Medium', 'Mixed content resource', src, 'Serve all resources over HTTPS.'));
					}
				});
			}
		}
	} catch (err) {
		findings.push(makeFinding('Info', 'DOM checks failed', err.message, 'Ensure the target is reachable.'));
	}
	return { findings };
}

module.exports = { checkBasicVulns };


