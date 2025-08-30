// Optional OWASP ZAP integration (requires ZAP daemon and API key)
const http = require('http');

function makeFinding(severity, title, details, remediation, evidence) {
	return { severity, title, details, remediation, evidence };
}

function getEnv(name, fallback) {
	return process.env[name] || fallback;
}

async function runZapScan(urlObj) {
	const findings = [];
	const zapHost = getEnv('ZAP_HOST', '127.0.0.1');
	const zapPort = Number(getEnv('ZAP_PORT', '8090'));
	const zapApiKey = getEnv('ZAP_API_KEY', '');

	async function zapGet(path) {
		return new Promise((resolve, reject) => {
			http.get({ host: zapHost, port: zapPort, path }, res => {
				let data = '';
				res.on('data', c => (data += c));
				res.on('end', () => {
					try { resolve(JSON.parse(data)); } catch (e) { resolve({}); }
				});
			}).on('error', reject);
		});
	}

	try {
		// Start active scan
		const target = `${urlObj.protocol}//${urlObj.host}`;
		await zapGet(`/JSON/ascan/action/scan/?apikey=${encodeURIComponent(zapApiKey)}&url=${encodeURIComponent(target)}&recurse=true`);
		// Poll status
		for (let i = 0; i < 30; i++) {
			const status = await zapGet(`/JSON/ascan/view/status/?apikey=${encodeURIComponent(zapApiKey)}`);
			if (status && status.status === '100') break;
			await new Promise(r => setTimeout(r, 2000));
		}
		const alerts = await zapGet(`/JSON/alert/view/alerts/?apikey=${encodeURIComponent(zapApiKey)}&baseurl=${encodeURIComponent(target)}`);
		if (alerts && Array.isArray(alerts.alerts)) {
			for (const a of alerts.alerts) {
				findings.push(makeFinding(a.risk || 'Info', a.alert, a.description, a.solution, a.evidence));
			}
		}
	} catch (err) {
		findings.push(makeFinding('Info', 'ZAP scan failed', err.message, 'Ensure ZAP is running with API enabled.'));
	}

	return { findings };
}

module.exports = { runZapScan };


