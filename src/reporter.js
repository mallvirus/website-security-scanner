function printResults(results, { json = false } = {}) {
	if (json) {
		console.log(JSON.stringify(results, null, 2));
		return;
	}

	console.log(`Target: ${results.targetUrl}`);
	console.log(`Scanned: ${results.scannedAt}`);
	console.log('Summary:', results.summary);
	console.log('Findings:');
	for (const f of results.findings) {
		console.log(`- [${f.severity}] ${f.title}`);
		if (f.details) console.log(`  details: ${f.details}`);
		if (f.evidence) console.log(`  evidence: ${f.evidence}`);
		if (f.remediation) console.log(`  remediation: ${f.remediation}`);
	}
}

module.exports = { printResults };


