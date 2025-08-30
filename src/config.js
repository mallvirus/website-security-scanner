const fs = require('fs');

const DEFAULT_CONFIG = {
	minSeverity: 'Info',
	timeouts: {
		defaultMs: 8000,
		tlsMs: 10000,
		portProbeMs: 1500
	},
	concurrency: {
		portProbes: 10
	}
};

function severityRank(sev) {
	switch ((sev || '').toLowerCase()) {
		case 'critical': return 5;
		case 'high': return 4;
		case 'medium': return 3;
		case 'low': return 2;
		case 'info': return 1;
		default: return 1;
	}
}

function loadConfig(path) {
	if (!path) return { ...DEFAULT_CONFIG };
	try {
		const raw = fs.readFileSync(path, 'utf-8');
		const user = JSON.parse(raw);
		return deepMerge(DEFAULT_CONFIG, user);
	} catch (e) {
		return { ...DEFAULT_CONFIG };
	}
}

function deepMerge(a, b) {
	if (Array.isArray(a) || Array.isArray(b)) return b || a;
	if (typeof a !== 'object' || typeof b !== 'object' || !a || !b) return b ?? a;
	const out = { ...a };
	for (const k of Object.keys(b)) {
		out[k] = deepMerge(a[k], b[k]);
	}
	return out;
}

module.exports = { DEFAULT_CONFIG, loadConfig, severityRank };


