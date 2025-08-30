const net = require('net');

function makeFinding(severity, title, details, remediation) {
	return { severity, title, details, remediation };
}

function checkPort(host, port, timeoutMs = 1500) {
	return new Promise((resolve) => {
		const socket = new net.Socket();
		let resolved = false;
		const onDone = (open) => {
			if (resolved) return;
			resolved = true;
			try { socket.destroy(); } catch {}
			resolve({ port, open });
		};
		socket.setTimeout(timeoutMs);
		socket.once('connect', () => onDone(true));
		socket.once('timeout', () => onDone(false));
		socket.once('error', () => onDone(false));
		socket.connect(port, host);
	});
}

async function checkCommonPorts(urlObj, config) {
	const findings = [];
	const host = urlObj.hostname;
	const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8000, 8080, 8443];
	const concurrency = Math.max(1, config?.concurrency?.portProbes || 10);
	const timeoutMs = config?.timeouts?.portProbeMs || 1500;
	const results = [];
	let idx = 0;
	async function worker() {
		while (idx < ports.length) {
			const p = ports[idx++];
			try {
				const r = await checkPort(host, p, timeoutMs);
				results.push(r);
			} catch {
				results.push({ port: p, open: false });
			}
		}
	}
	const workers = Array.from({ length: concurrency }, () => worker());
	await Promise.all(workers);
	for (const r of results) {
		if (r.open) {
			// Report non-standard open ports besides target port
			const isExpected = (urlObj.protocol === 'https:' && r.port === 443) || (urlObj.protocol === 'http:' && r.port === 80);
			if (!isExpected) {
				findings.push(makeFinding('Info', 'Open port detected', `Port ${r.port} open on ${host}`, 'Ensure only necessary services are exposed; restrict via firewall.'));
			}
		}
	}
	return { findings };
}

module.exports = { checkCommonPorts };


