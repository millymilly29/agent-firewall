/**
 * AGENT-FIREWALL // Main Package Export
 */

const { CommandPatternScanner } = require('./ast-scanner');
const { PolicyEngine } = require('./policy-engine');
const { AuditLogger, computeDigest, GENESIS_HASH } = require('./audit-logger');

class AgentFirewall {
  constructor(policyMode = 'STRICT_CI') {
    this.scanner = new CommandPatternScanner();
    this.policy = new PolicyEngine(policyMode);
    this.audit = new AuditLogger();
  }

  gate(command) {
    const scan = this.scanner.scan(command);
    const decision = this.policy.evaluate(scan);
    const record = this.audit.createAttestation(
      command,
      scan.verdict,
      this.policy.getActivePolicy().id,
      scan.riskScore,
      scan.violations
    );
    return { scan, decision, record };
  }
}

module.exports = {
  CommandPatternScanner,
  PolicyEngine,
  AuditLogger,
  AgentFirewall,
  computeDigest,
  GENESIS_HASH
};
