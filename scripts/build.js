#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const outDir = path.join(__dirname, '..', 'dist');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);

function copy(src, dest) {
	fs.copyFileSync(src, dest);
}

// For this simple CJS project, just expose API entry
copy(path.join(__dirname, '..', 'src', 'api.js'), path.join(outDir, 'api.cjs'));
copy(path.join(__dirname, '..', 'src', 'index.js'), path.join(outDir, 'index.cjs'));


