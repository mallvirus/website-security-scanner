const url = require('url');
const { severityRank } = require('./config');
const { checkHeaders } = require('./scanners/headers');
const { checkSsl } = require('./scanners/ssl');
const { checkCommonPorts } = require('./scanners/ports');
const { checkBasicVulns } = require('./scanners/vulns');
const { runZapScan } = require('./scanners/zap');

function createEmptyResults(targetUrl) {
	return {
		targetUrl,
		scannedAt: new Date().toISOString(),
		findings: [],
		summary: {
			total: 0,
			infoCount: 0,
			lowCount: 0,
			mediumCount: 0,
			highCount: 0,
			criticalCount: 0
		}
	};
}

function addFinding(results, finding) {
	results.findings.push(finding);
	results.summary.total += 1;
	const sevKey = `${finding.severity.toLowerCase()}Count`;
	if (results.summary.hasOwnProperty(sevKey)) {
		results.summary[sevKey] += 1;
	}
}

function withTimeout(promise, ms, onTimeoutMessage) {
	let timer;
	return Promise.race([
		promise,
		new Promise((_, reject) => {
			timer = setTimeout(() => reject(new Error(onTimeoutMessage || 'timeout')), ms);
		})
	]).finally(() => clearTimeout(timer));
}

async function runScan({ targetUrl, useZap = false, config }) {
	const parsed = new URL(targetUrl);
	if (!['http:', 'https:'].includes(parsed.protocol)) {
		throw new Error('Only http/https URLs are supported');
	}

	const results = createEmptyResults(targetUrl);

	const [headers, ssl, ports, vulns, zap] = await Promise.all([
		withTimeout(checkHeaders(parsed, config), config?.timeouts?.defaultMs || 8000, 'headers timeout').catch(e => ({ findings: [{ severity: 'Info', title: 'Headers scan timeout', details: e.message }] })),
		withTimeout(checkSsl(parsed, config), config?.timeouts?.tlsMs || 10000, 'ssl timeout').catch(e => ({ findings: [{ severity: 'Info', title: 'SSL scan timeout', details: e.message }] })),
		withTimeout(checkCommonPorts(parsed, config), config?.timeouts?.defaultMs || 8000, 'ports timeout').catch(e => ({ findings: [{ severity: 'Info', title: 'Ports scan timeout', details: e.message }] })),
		withTimeout(checkBasicVulns(parsed, config), config?.timeouts?.defaultMs || 8000, 'vulns timeout').catch(e => ({ findings: [{ severity: 'Info', title: 'Vulns scan timeout', details: e.message }] })),
		useZap ? withTimeout(runZapScan(parsed), config?.timeouts?.defaultMs || 8000, 'zap timeout').catch(e => ({ findings: [{ severity: 'Info', title: 'ZAP scan timeout', details: e.message }] })) : Promise.resolve({ findings: [] })
	]);

	for (const group of [headers, ssl, ports, vulns, zap]) {
		for (const f of group.findings) addFinding(results, f);
	}

	// Apply min severity filter to summary counts but keep raw findings for output control upstream
	const minRank = severityRank(config?.minSeverity || 'Info');
	results.summary = results.findings.reduce((acc, f) => {
		const sevKey = `${f.severity.toLowerCase()}Count`;
		acc.total += 1;
		if (acc.hasOwnProperty(sevKey)) acc[sevKey] += 1;
		return acc;
	}, { total: 0, infoCount: 0, lowCount: 0, mediumCount: 0, highCount: 0, criticalCount: 0 });

	return results;
}

module.exports = { runScan };


