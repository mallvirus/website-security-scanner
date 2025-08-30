const https = require('https');
const http = require('http');

function requestHead(urlObj) {
	const httpLib = urlObj.protocol === 'https:' ? https : http;
	return new Promise((resolve, reject) => {
		const req = httpLib.request({
			hostname: urlObj.hostname,
			port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
			method: 'GET',
			path: urlObj.pathname || '/',
			headers: { 'User-Agent': 'web-scanner/1.0' }
		}, res => {
			resolve({ statusCode: res.statusCode, headers: res.headers });
		});
		req.on('error', reject);
		req.end();
	});
}

function makeFinding(severity, title, details, remediation) {
	return { severity, title, details, remediation };
}

async function checkHeaders(urlObj, config) {
	const findings = [];
	try {
		const { headers, statusCode } = await requestHead(urlObj);
		const header = (name) => headers[name.toLowerCase()];

		if (!header('content-security-policy')) {
			findings.push(makeFinding('High', 'Missing Content-Security-Policy', 'CSP header not set', 'Define a strict CSP to mitigate XSS and data injection.'));
		}
		if (!header('x-frame-options')) {
			findings.push(makeFinding('Medium', 'Missing X-Frame-Options', 'Clickjacking protection header not set', 'Add X-Frame-Options: DENY or SAMEORIGIN.'));
		}
		if (!header('x-content-type-options')) {
			findings.push(makeFinding('Medium', 'Missing X-Content-Type-Options', 'MIME-sniffing protection absent', 'Add X-Content-Type-Options: nosniff.'));
		}
		if (!header('referrer-policy')) {
			findings.push(makeFinding('Low', 'Missing Referrer-Policy', 'Referrer policy not set', 'Add a strict Referrer-Policy, e.g., no-referrer or strict-origin-when-cross-origin.'));
		}
		if (!header('permissions-policy')) {
			findings.push(makeFinding('Low', 'Missing Permissions-Policy', 'No control over powerful browser features', 'Define Permissions-Policy to limit features like camera, microphone, geolocation.'));
		}
		if (header('server')) {
			findings.push(makeFinding('Info', 'Server header reveals software', `Server: ${header('server')}`, 'Remove or obfuscate the Server header to reduce fingerprinting.'));
		}
		if (header('set-cookie')) {
			const setCookies = Array.isArray(header('set-cookie')) ? header('set-cookie') : [header('set-cookie')];
			for (const c of setCookies) {
				if (!/;\s*Secure/i.test(c) && urlObj.protocol === 'https:') {
					findings.push(makeFinding('High', 'Cookie without Secure flag', c, 'Set Secure on cookies over HTTPS.'));
				}
				if (!/;\s*HttpOnly/i.test(c)) {
					findings.push(makeFinding('Medium', 'Cookie without HttpOnly flag', c, 'Set HttpOnly to mitigate XSS cookie theft.'));
				}
				if (!/;\s*SameSite=(Lax|Strict|None)/i.test(c)) {
					findings.push(makeFinding('Low', 'Cookie without SameSite attribute', c, 'Set SameSite=Lax/Strict/None as appropriate.'));
				}
			}
		}

		if ([200, 301, 302, 304].indexOf(statusCode) === -1) {
			findings.push(makeFinding('Info', 'Unusual HTTP status code', `Status: ${statusCode}`, 'Review the endpoint behavior or redirections.'));
		}

		// HSTS check (only meaningful over HTTPS)
		if (urlObj.protocol === 'https:') {
			if (!header('strict-transport-security')) {
				findings.push(makeFinding('Medium', 'Missing HSTS header', 'Strict-Transport-Security not set', 'Add HSTS with includeSubDomains and preload if appropriate.'));
			}
		}

		// Redirect to HTTPS check if starting with HTTP
		if (urlObj.protocol === 'http:') {
			if (!(statusCode === 301 || statusCode === 302) || !header('location') || !/^https:\/\//i.test(header('location'))) {
				findings.push(makeFinding('Medium', 'HTTP not redirected to HTTPS', 'No 301/302 to https detected', 'Force HTTP→HTTPS with 301 and HSTS.'));
			}
		}

		// HTTP/2 and HTTP/3 indicators
		if (header('alt-svc')) {
			if (/h3/i.test(header('alt-svc'))) {
				findings.push(makeFinding('Info', 'HTTP/3 advertised', header('alt-svc'), 'Ensure QUIC/HTTP3 configuration is hardened.'));
			}
		}
	} catch (err) {
		findings.push(makeFinding('High', 'Failed to fetch headers', err.message, 'Ensure the host is reachable and not blocking requests.'));
	}
	return { findings };
}

module.exports = { checkHeaders };


