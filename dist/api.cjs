const { runScan } = require('./scanner');
const { printResults } = require('./reporter');
const { loadConfig, severityRank } = require('./config');

module.exports = { runScan, printResults, loadConfig, severityRank };


