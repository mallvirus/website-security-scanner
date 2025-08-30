#!/usr/bin/env node
const { runScan } = require('./scanner');
const { printResults } = require('./reporter');
const { loadConfig, severityRank } = require('./config');

async function main() {
	const urlArg = process.argv[2];
	if (!urlArg) {
		console.error('Usage: node src/index.js <url> [--json] [--zap] [--config path] [--min-sev Sev]');
		process.exit(1);
	}

	const outputJson = process.argv.includes('--json');
	const useZap = process.argv.includes('--zap');
	const cfgIdx = process.argv.indexOf('--config');
	const configPath = cfgIdx !== -1 ? process.argv[cfgIdx + 1] : undefined;
	const minSevIdx = process.argv.indexOf('--min-sev');
	const minSeverity = minSevIdx !== -1 ? process.argv[minSevIdx + 1] : undefined;
	const config = loadConfig(configPath);
	if (minSeverity) config.minSeverity = minSeverity;

	try {
		const results = await runScan({ targetUrl: urlArg, useZap, config });
		// Filter by min severity if human output
		if (!outputJson && config.minSeverity) {
			const minRank = severityRank(config.minSeverity);
			results.findings = results.findings.filter(f => severityRank(f.severity) >= minRank);
		}
		printResults(results, { json: outputJson });
		process.exit(results.summary.criticalCount > 0 ? 2 : 0);
	} catch (err) {
		console.error('Scan failed:', err.message || err);
		process.exit(1);
	}
}

main();


