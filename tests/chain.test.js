/**
 * AGENT-FIREWALL // Hash Chain Tamper & Deletion Test Suite
 */

const assert = require('assert');
const { AuditLogger, GENESIS_HASH } = require('../engine/audit-logger');

console.log('\n=== RUNNING AGENT-FIREWALL HASH CHAIN AUDIT TESTS ===\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✔ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✖ ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

// 1. Legitimate chain verification
test('Chain: Generates and verifies valid 5-block SHA-256 chain', () => {
  const logger = new AuditLogger();
  logger.createAttestation('ls -la', 'ALLOWED', 'DEVELOPMENT', 0);
  logger.createAttestation('cat package.json', 'ALLOWED', 'DEVELOPMENT', 0);
  logger.createAttestation('rm -rf /tmp/test', 'ALLOWED', 'DEVELOPMENT', 10);
  logger.createAttestation('curl https://api.github.com', 'ALLOWED', 'DEVELOPMENT', 0);
  logger.createAttestation('rm -rf / --no-preserve-root', 'BLOCKED', 'STRICT_CI', 100);

  const check = logger.verifyChain();
  assert.strictEqual(check.valid, true);
  assert.strictEqual(check.count, 5);
});

// 2. Tamper detection on payload
test('Chain: Detects tampered verdict in block 2 of 5', () => {
  const logger = new AuditLogger();
  logger.createAttestation('cmd1', 'ALLOWED', 'DEVELOPMENT', 0);
  logger.createAttestation('cmd2', 'BLOCKED', 'STRICT_CI', 100);
  logger.createAttestation('cmd3', 'ALLOWED', 'DEVELOPMENT', 0);

  // Tamper with record 1 (second block)
  logger.ledger[1].verdict = 'ALLOWED';

  const check = logger.verifyChain();
  assert.strictEqual(check.valid, false);
  assert.strictEqual(check.tamperedIndex, 1);
});

// 3. Deletion detection
test('Chain: Detects deletion of intermediate record (broken chain link)', () => {
  const logger = new AuditLogger();
  logger.createAttestation('cmd1', 'ALLOWED', 'DEVELOPMENT', 0);
  logger.createAttestation('cmd2', 'BLOCKED', 'STRICT_CI', 100);
  logger.createAttestation('cmd3', 'ALLOWED', 'DEVELOPMENT', 0);

  // Remove the middle block
  logger.ledger.splice(1, 1);

  const check = logger.verifyChain();
  assert.strictEqual(check.valid, false);
  assert.strictEqual(check.tamperedIndex, 1);
  assert(check.reason.includes('prevHash mismatch'));
});

// 4. Single record verification
test('Chain: Verifies single record with prevHash', () => {
  const logger = new AuditLogger();
  const r1 = logger.createAttestation('cmd1', 'ALLOWED', 'DEVELOPMENT', 0);
  assert.strictEqual(r1.prevHash, GENESIS_HASH);
  assert.strictEqual(logger.verifyRecord(r1), true);

  r1.command = 'malicious';
  assert.strictEqual(logger.verifyRecord(r1), false);
});

console.log(`\nCHAIN RESULTS: ${passed} passed, ${failed} failed.\n`);
if (failed > 0) process.exit(1);
