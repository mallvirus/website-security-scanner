const tls = require('tls');

function makeFinding(severity, title, details, remediation) {
	return { severity, title, details, remediation };
}

async function checkSsl(urlObj, config) {
	const findings = [];
	if (urlObj.protocol !== 'https:') {
		findings.push(makeFinding('Medium', 'Site not using HTTPS', 'HTTP URL provided', 'Redirect HTTP to HTTPS and use HSTS.'));
		return { findings };
	}

	const host = urlObj.hostname;
	const port = Number(urlObj.port) || 443;

	try {
		const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'] });
		await new Promise((resolve, reject) => {
			socket.once('secureConnect', resolve);
			socket.once('error', reject);
			setTimeout(() => reject(new Error('TLS timeout')), 10000);
		});
		const cert = socket.getPeerCertificate(true);
		if (!cert || Object.keys(cert).length === 0) {
			findings.push(makeFinding('High', 'No certificate returned', '', 'Install a valid certificate.'));
		} else {
			const now = Date.now();
			const validFrom = Date.parse(cert.valid_from);
			const validTo = Date.parse(cert.valid_to);
			if (isNaN(validFrom) || isNaN(validTo)) {
				findings.push(makeFinding('High', 'Certificate validity unknown', JSON.stringify(cert), 'Ensure certificate has valid dates.'));
			} else {
				if (now < validFrom) {
					findings.push(makeFinding('High', 'Certificate not yet valid', `${cert.valid_from}`, 'Verify system time and certificate issuance.'));
				}
				if (now > validTo) {
					findings.push(makeFinding('High', 'Certificate expired', `${cert.valid_to}`, 'Renew the TLS certificate.'));
				}
				const msRemaining = validTo - now;
				const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));
				if (daysRemaining >= 0 && daysRemaining <= 30) {
					findings.push(makeFinding('Medium', 'Certificate near expiry', `${daysRemaining} days remaining`, 'Plan certificate renewal.'));
				}
			}
			if (cert.issuer && cert.issuer.O && /let's encrypt/i.test(cert.issuer.O)) {
				// fine, but often short validity
			}
		}

		const protocol = socket.getProtocol();
		if (!protocol || /TLSv1(\.0|\.1)/i.test(protocol)) {
			findings.push(makeFinding('High', 'Insecure TLS protocol negotiated', protocol, 'Disable TLS 1.0/1.1; require TLS 1.2+'));
		}
		// HTTP/2 detection via ALPN
		const negotiatedAlpn = socket.alpnProtocol || socket.getALPNProtocol && socket.getALPNProtocol();
		if (negotiatedAlpn === 'h2') {
			findings.push(makeFinding('Info', 'HTTP/2 negotiated via ALPN', 'h2', 'Harden HTTP/2 settings and DoS protections.'));
		}

		socket.end();
	} catch (err) {
		findings.push(makeFinding('High', 'TLS connection failed', err.message, 'Ensure port 443 is open and a valid cert is installed.'));
	}

	return { findings };
}

module.exports = { checkSsl };


