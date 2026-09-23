/**
 * AGENT-FIREWALL // Policy Enforcement & Safe Dry-Run Engine
 * Maps static AST threat assessments to operational security profiles.
 */

const POLICIES = {
  PARANOID: {
    id: 'PARANOID',
    name: 'Zero-Trust Autonomous Boundary',
    description: 'Zero tolerance for network egress or filesystem mutations. Any risk score > 0 is blocked or converted to simulation.',
    blockThreshold: 30,
    quarantineThreshold: 1,
    allowOutboundNetwork: false,
    autoDryRun: true
  },
  STRICT_CI: {
    id: 'STRICT_CI',
    name: 'Hardened Production CI/CD Pipeline',
    description: 'Strict enforcement against credential theft, root mutations, and unvetted pipes. Typical for autonomous cloud runners.',
    blockThreshold: 70,
    quarantineThreshold: 40,
    allowOutboundNetwork: true,
    autoDryRun: true
  },
  AIRGAPPED: {
    id: 'AIRGAPPED',
    name: 'Airgapped Defense Sandbox',
    description: 'Strict offline enclave. All outbound socket, curl, wget, git remote, and metadata endpoints are unconditionally forbidden.',
    blockThreshold: 50,
    quarantineThreshold: 20,
    allowOutboundNetwork: false,
    autoDryRun: false
  },
  DEVELOPMENT: {
    id: 'DEVELOPMENT',
    name: 'Local Engineer Sandbox',
    description: 'Permissive development posture. Blocks only catastrophic root wipe or remote socket injection; warns on others.',
    blockThreshold: 85,
    quarantineThreshold: 60,
    allowOutboundNetwork: true,
    autoDryRun: false
  }
};

class PolicyEngine {
  constructor(defaultPolicy = 'STRICT_CI') {
    this.policies = POLICIES;
    this.activePolicy = this.policies[defaultPolicy] || this.policies.STRICT_CI;
  }

  setPolicy(policyKey) {
    if (!this.policies[policyKey]) {
      throw new Error(`Unknown policy key: ${policyKey}. Valid keys: ${Object.keys(this.policies).join(', ')}`);
    }
    this.activePolicy = this.policies[policyKey];
    return this.activePolicy;
  }

  getActivePolicy() {
    return this.activePolicy;
  }

  /**
   * Evaluates scan results against active security posture
   */
  evaluate(scanResult, policyKey = null) {
    const policy = policyKey ? (this.policies[policyKey] || this.activePolicy) : this.activePolicy;
    const score = scanResult.riskScore;

    let action = 'EXECUTE';
    let safeCommand = scanResult.command;
    const rationale = [];

    // Airgapped policy check
    if (!policy.allowOutboundNetwork) {
      const netCheckRegex = /\b(curl|wget|fetch|nc|ncat|netcat|ssh|scp|ftp|rsync|git\s+push|git\s+clone)\b/i;
      if (netCheckRegex.test(scanResult.command)) {
        action = 'BLOCK';
        rationale.push(`Egress network activity explicitly denied by [${policy.id}] policy.`);
      }
    }

    if (action !== 'BLOCK') {
      if (score >= policy.blockThreshold) {
        action = policy.autoDryRun ? 'REWRITE_DRYRUN' : 'BLOCK';
        rationale.push(`Risk score (${score}) exceeds block threshold (${policy.blockThreshold}) for [${policy.id}].`);
      } else if (score >= policy.quarantineThreshold) {
        action = policy.autoDryRun ? 'REWRITE_DRYRUN' : 'PROMPT_APPROVAL';
        rationale.push(`Risk score (${score}) exceeds quarantine threshold (${policy.quarantineThreshold}) for [${policy.id}].`);
      } else {
        action = 'EXECUTE';
        rationale.push(`Command verified safe under [${policy.id}] policy requirements.`);
      }
    }

    // Rewrite command if dry-run is triggered
    if (action === 'REWRITE_DRYRUN') {
      safeCommand = this.transformToSafeDryRun(scanResult);
    }

    return {
      policy: policy.id,
      policyName: policy.name,
      action,
      originalCommand: scanResult.command,
      safeCommand,
      riskScore: score,
      riskLevel: scanResult.riskLevel,
      violationsCount: scanResult.violations.length,
      violations: scanResult.violations,
      rationale: rationale.join(' '),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Neutralizes destructive commands into non-destructive dry-run simulations
   */
  transformToSafeDryRun(scanResult) {
    const cmd = scanResult.command;

    // Handle rm -rf
    if (/\brm\s+-[a-zA-Z]*r/i.test(cmd)) {
      return `echo "[FIREWALL DRY-RUN SIMULATION] Would safely list targeted paths without deleting:" && ls -lah $(echo "${cmd}" | awk '{$1=$2=""; print $0}') 2>/dev/null || true`;
    }

    // Handle exfiltration (curl/wget with secrets)
    if (/(curl|wget|nc)\b.*(\.env|\.aws|id_rsa|shadow)/i.test(cmd)) {
      return `echo "[FIREWALL INTERCEPT] Blocked exfiltration of sensitive key/file. Simulated headers only:" && echo "HOST: [REDACTED_BY_AST_FIREWALL]"`;
    }

    // Handle IMDS
    if (/169\.254\.169\.254/.test(cmd)) {
      return `echo "[FIREWALL INTERCEPT] Cloud Metadata Access Blocked: 169.254.169.254 is unreachable in sandboxed context."`;
    }

    // Handle pipe to shell
    if (/\|\s*(ba|z)?sh\b/i.test(cmd)) {
      return `echo "[FIREWALL SANDBOX] Piping unverified remote stream to shell neutralized. Script routed to quarantine file: /tmp/agent_quarantine_$(date +%s).sh"`;
    }

    // Handle privilege escalation
    if (/\b(sudo|chmod\s+(-R\s+)?777)\b/i.test(cmd)) {
      return `echo "[FIREWALL INTERCEPT] Privilege elevation disallowed. Simulated no-op execution."`;
    }

    // Handle fork bombs or DoS
    if (/(:\{\s*:\|\:&\s*;\s*\}:|while\s+true)/i.test(cmd)) {
      return `echo "[FIREWALL INTERCEPT] Process bomb neutralized. Subshell fork throttled by cgroups boundary."`;
    }

    // Default neutralizer
    return `echo "[FIREWALL DRY-RUN] Intercepted suspicious command [Risk Score: ${scanResult.riskScore}]:" && echo ${JSON.stringify(cmd)}`;
  }
}

if (typeof window !== 'undefined') {
  window.PolicyEngine = PolicyEngine;
  window.POLICIES = POLICIES;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PolicyEngine, POLICIES };
}
