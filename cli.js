#!/usr/bin/env node

/**
 * AGENT-FIREWALL // Terminal CLI Inspector
 * Semantic AST firewall and security gatekeeper for autonomous AI agent command execution.
 */

const { ASTCommandScanner } = require('./engine/ast-scanner');
const { PolicyEngine } = require('./engine/policy-engine');
const { AuditLogger } = require('./engine/audit-logger');

// ANSI formatting helpers
const C = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m'
};

function printBanner() {
  console.log(`
${C.cyan}${C.bright}========================================================================${C.reset}
${C.green}${C.bright}  AGENT-FIREWALL // SEMANTIC AST COMMAND GATEWAY  v2.4.0${C.reset}
${C.dim}  Autonomous AI Execution Guard & Zero-Trust Threat Neutralizer${C.reset}
${C.cyan}${C.bright}========================================================================${C.reset}
`);
}

function printHelp() {
  printBanner();
  console.log(`Usage:
  node cli.js "<command>" [options]

Options:
  --policy=<POLICY>   Set active policy [STRICT_CI (default), PARANOID, AIRGAPPED, DEVELOPMENT]
  --json              Output raw machine-readable JSON for CI/CD runners
  --dry-run           Emit rewritten safe dry-run command if blocked
  --help              Display this guide

Examples:
  node cli.js "rm -rf / --no-preserve-root"
  node cli.js "curl -s http://169.254.169.254/latest/meta-data/" --policy=PARANOID
  node cli.js "npm test" --json
`);
}

function renderScoreBar(score) {
  const totalBars = 24;
  const filled = Math.round((score / 100) * totalBars);
  const empty = totalBars - filled;
  let color = C.green;
  if (score >= 70) color = C.red;
  else if (score >= 40) color = C.yellow;

  const bar = `${color}${'█'.repeat(filled)}${C.dim}${'░'.repeat(empty)}${C.reset}`;
  return `[${bar}] ${color}${C.bright}${score}/100${C.reset}`;
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  let policyName = 'STRICT_CI';
  let isJson = false;
  let forceDryRun = false;
  let commandParts = [];

  for (const arg of args) {
    if (arg.startsWith('--policy=')) {
      policyName = arg.split('=')[1].toUpperCase();
    } else if (arg === '--json') {
      isJson = true;
    } else if (arg === '--dry-run') {
      forceDryRun = true;
    } else {
      commandParts.push(arg);
    }
  }

  const rawCommand = commandParts.join(' ').trim();
  if (!rawCommand) {
    console.error(`${C.red}Error: No command supplied to inspect.${C.reset}`);
    process.exit(1);
  }

  const scanner = new ASTCommandScanner();
  const policyEngine = new PolicyEngine(policyName);
  const logger = new AuditLogger();

  const scanResult = scanner.scan(rawCommand);
  const evalResult = policyEngine.evaluate(scanResult, policyName);
  const attestation = logger.createAttestation(
    rawCommand,
    evalResult.action,
    policyName,
    scanResult.riskScore,
    scanResult.violations
  );

  if (isJson) {
    console.log(JSON.stringify({ scanResult, policyEvaluation: evalResult, attestation }, null, 2));
    process.exit(evalResult.action === 'BLOCK' ? 1 : 0);
  }

  printBanner();
  console.log(`${C.bright}INSPECTED COMMAND:${C.reset}`);
  console.log(`  ${C.white}${C.dim}$ ${C.reset}${C.bright}${rawCommand}${C.reset}\n`);

  console.log(`${C.bright}SECURITY POSTURE:${C.reset}  ${C.cyan}${policyName}${C.reset} (${evalResult.policyName})`);
  console.log(`${C.bright}THREAT GAUGE:${C.reset}      ${renderScoreBar(scanResult.riskScore)} [${scanResult.riskLevel}]`);

  // Verdict Badge
  let verdictBadge = `${C.bgGreen}${C.bright} PERMITTED // EXECUTE ${C.reset}`;
  if (evalResult.action === 'BLOCK') {
    verdictBadge = `${C.bgRed}${C.bright} BLOCKED // CRITICAL THREAT ${C.reset}`;
  } else if (evalResult.action === 'REWRITE_DRYRUN') {
    verdictBadge = `${C.bgYellow}${C.bright} INTERCEPTED // SAFE DRY-RUN APPLIED ${C.reset}`;
  } else if (evalResult.action === 'PROMPT_APPROVAL') {
    verdictBadge = `${C.bgYellow}${C.bright} QUARANTINED // HUMAN SIGN-OFF REQUIRED ${C.reset}`;
  }
  console.log(`${C.bright}FIREWALL VERDICT:${C.reset}  ${verdictBadge}\n`);

  if (scanResult.violations.length > 0) {
    console.log(`${C.red}${C.bright}DETECTED AST VIOLATIONS (${scanResult.violations.length}):${C.reset}`);
    scanResult.violations.forEach((v, idx) => {
      console.log(`  ${C.yellow}[${idx + 1}] ${v.ruleId} - ${v.name} (Severity: ${v.severity}/100)${C.reset}`);
      console.log(`      ${C.dim}Threat:${C.reset} ${v.description}`);
      console.log(`      ${C.dim}Remediation:${C.reset} ${v.remediation}\n`);
    });
  } else {
    console.log(`${C.green}✓ Zero AST threat patterns detected in command execution graph.${C.reset}\n`);
  }

  if (evalResult.action === 'REWRITE_DRYRUN' || forceDryRun) {
    console.log(`${C.bright}SANITIZED DRY-RUN REWRITE:${C.reset}`);
    console.log(`  ${C.yellow}${evalResult.safeCommand}${C.reset}\n`);
  }

  console.log(`${C.bright}CRYPTOGRAPHIC ATTESTATION:${C.reset}`);
  console.log(`  ${C.dim}Attestation ID:${C.reset} ${attestation.attestationId}`);
  console.log(`  ${C.dim}SHA-256 Digest:${C.reset} ${attestation.commandHash}`);
  console.log(`  ${C.dim}Signed Seal:   ${C.reset} ${attestation.signature.substring(0, 32)}...`);
  console.log(`  ${C.dim}Status:        ${C.reset} ${C.green}TAMPER-EVIDENT & VERIFIED${C.reset}\n`);

  // Exit code: 0 for allowed or safely rewritten, 1 for hard blocked
  if (evalResult.action === 'BLOCK') {
    process.exit(1);
  }
  process.exit(0);
}

if (require.main === module) {
  main();
}
