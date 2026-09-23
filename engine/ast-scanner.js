/**
 * AGENT-FIREWALL // Semantic Command Lexer & AST Threat Scanner
 * Intercepts, parses, and audits commands emitted by autonomous AI agents before execution.
 */

const THREAT_RULES = [
  {
    id: 'SEC-001',
    category: 'DESTRUCTIVE_FILESYSTEM',
    severity: 100,
    name: 'Recursive Root / Critical Path Deletion',
    description: 'Attempts to recursively delete root, system, or user directory without safe boundaries.',
    pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f*|-[a-zA-Z]*f*r[a-zA-Z]*)\s+(\/|\/\*|~\/?|\.\/?|\*|\$HOME|\/[a-zA-Z0-9_\-\/]+)/i,
    remediation: 'Scope deletions to specific temporary subdirectories using explicit relative paths.'
  },
  {
    id: 'SEC-002',
    category: 'CREDENTIAL_EXFILTRATION',
    severity: 95,
    name: 'Sensitive Secret / Key Piping to Remote Endpoint',
    description: 'Piping or POSTing environment variables, private keys, or SSH credentials to an external host.',
    pattern: /(curl|wget|http|fetch|nc|ncat)\b.*(\.env|\.aws|id_rsa|id_ed25519|\/etc\/shadow|\.gemini|\.claude)/i,
    remediation: 'Strip credential references from outbound payload parameters.'
  },
  {
    id: 'SEC-003',
    category: 'METADATA_HARVESTING',
    severity: 90,
    name: 'Cloud Instance Metadata Service (IMDS) Query',
    description: 'Attempting to query link-local IP 169.254.169.254 to harvest temporary IAM instance role credentials.',
    pattern: /\b169\.254\.169\.254\b/,
    remediation: 'Enforce IMDSv2 token-boundary requirements or airgap agent from metadata IP.'
  },
  {
    id: 'SEC-004',
    category: 'REMOTE_EXEC_PIPE',
    severity: 85,
    name: 'Unverified Pipe to Shell Execution',
    description: 'Downloading a remote binary or script and immediately piping to sh/bash without checksum audit.',
    pattern: /(curl|wget)\b[^\n|]+\|\s*(ba|z)?sh\b/i,
    remediation: 'Download script to inspectable sandbox artifact, compute SHA256, and verify before execution.'
  },
  {
    id: 'SEC-005',
    category: 'PRIVILEGE_ESCALATION',
    severity: 85,
    name: 'Unconstrained Sudo / System Permissions Mutator',
    description: 'Attempting root permission elevation or global world-writable permission mutation.',
    pattern: /\b(sudo\s+|chmod\s+(-R\s+)?(777|a\+rwx)|chown\s+-R\s+root)\b/i,
    remediation: 'Run agent process within an unprivileged UID container namespace.'
  },
  {
    id: 'SEC-006',
    category: 'DENIAL_OF_SERVICE',
    severity: 90,
    name: 'Process Fork Bomb / Unbounded Subshell Spawn',
    description: 'Classic or obfuscated bash process bomb designed to exhaust system PID table.',
    pattern: /(:(\(\))?\s*\{[^}]*:\|:[^}]*\}\s*;?\s*:|while\s+true\s*;\s*do\s*(\w+\s*&|fork)\s*done)/i,
    remediation: 'Apply cgroups pids.max limit and execution timeout budget.'
  },
  {
    id: 'SEC-007',
    category: 'NETWORK_TUNNELING',
    severity: 75,
    name: 'Reverse Shell / Raw Socket Tunneling',
    description: 'Spawning interactive shell connected to remote TCP/UDP socket or tunneling proxy.',
    pattern: /\b(nc|ncat|netcat)\s+(-[a-zA-Z]*e\s+|[0-9.]+\s+[0-9]+\s+-e|\/bin\/(ba)?sh)|\/dev\/(tcp|udp)\//i,
    remediation: 'Block outbound raw socket primitives; restrict network to declarative HTTP proxy.'
  },
  {
    id: 'SEC-008',
    category: 'SUPPLY_CHAIN_RISK',
    severity: 65,
    name: 'Unvetted Package Install with Lifecycle Scripts',
    description: 'Installing packages with explicit flag to execute arbitrary postinstall lifecycle scripts.',
    pattern: /\b(npm\s+i|yarn\s+add|pnpm\s+add)\b.*--ignore-scripts=false/i,
    remediation: 'Enforce --ignore-scripts default for all AI-triggered package resolutions.'
  },
  {
    id: 'SEC-009',
    category: 'FILESYSTEM_POISONING',
    severity: 80,
    name: 'Direct Block Device / Raw Partition Overwrite',
    description: 'Redirecting output stream directly into raw storage device nodes (/dev/sd*, /dev/nvme*).',
    pattern: />+\s*\/dev\/(sd[a-z]|nvme[0-9]|hd[a-z]|disk[0-9])/i,
    remediation: 'Never mount /dev block nodes inside agent runtime environment.'
  },
  {
    id: 'SEC-010',
    category: 'SECRET_DUMPING',
    severity: 70,
    name: 'Global Environment / Keyring Inspection',
    description: 'Broadly printing out all environment variables or shell history without filtering.',
    pattern: /\b(printenv|env\s*$|history\s*\||export\s*$)/i,
    remediation: 'Isolate agent environment; pass only explicitly whitelisted configuration keys.'
  }
];

class ASTCommandScanner {
  constructor() {
    this.rules = THREAT_RULES;
  }

  /**
   * Tokenizes raw shell string into semantic chunks
   */
  tokenize(rawCommand) {
    if (!rawCommand || typeof rawCommand !== 'string') {
      return { tokens: [], program: '', args: [], pipes: [] };
    }

    const trimmed = rawCommand.trim();
    // Split by pipes and logical operators
    const segments = trimmed.split(/(\|{1,2}|&{1,2}|;)/).map(s => s.trim()).filter(Boolean);

    // Basic word tokenizer supporting quotes
    const regex = /[^\s"']+|"([^"]*)"|'([^']*)'/g;
    const tokens = [];
    let match;
    while ((match = regex.exec(trimmed)) !== null) {
      tokens.push(match[1] || match[2] || match[0]);
    }

    const program = tokens[0] || '';
    const args = tokens.slice(1);

    return {
      raw: trimmed,
      program,
      args,
      tokens,
      segments,
      hasPipes: segments.length > 1
    };
  }

  /**
   * Performs static analysis and security score computation
   */
  scan(commandString) {
    const parsed = this.tokenize(commandString);
    const violations = [];
    let cumulativeThreatScore = 0;

    for (const rule of this.rules) {
      if (rule.pattern.test(parsed.raw)) {
        violations.push({
          ruleId: rule.id,
          name: rule.name,
          category: rule.category,
          severity: rule.severity,
          description: rule.description,
          remediation: rule.remediation
        });
        cumulativeThreatScore = Math.max(cumulativeThreatScore, rule.severity);
      }
    }

    // Secondary heuristic: score based on number of violations
    if (violations.length > 1) {
      cumulativeThreatScore = Math.min(100, cumulativeThreatScore + (violations.length - 1) * 5);
    }

    let verdict = 'ALLOWED';
    let riskLevel = 'CLEAN';

    if (cumulativeThreatScore >= 70) {
      verdict = 'BLOCKED';
      riskLevel = 'CRITICAL';
    } else if (cumulativeThreatScore >= 40) {
      verdict = 'QUARANTINED';
      riskLevel = 'SUSPICIOUS';
    } else if (cumulativeThreatScore > 0) {
      verdict = 'FLAGGED';
      riskLevel = 'LOW';
    }

    return {
      command: parsed.raw,
      program: parsed.program,
      args: parsed.args,
      tokensCount: parsed.tokens.length,
      riskScore: cumulativeThreatScore,
      riskLevel,
      verdict,
      violations,
      timestamp: new Date().toISOString()
    };
  }
}

if (typeof window !== 'undefined') {
  window.ASTCommandScanner = ASTCommandScanner;
  window.THREAT_RULES = THREAT_RULES;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ASTCommandScanner, THREAT_RULES };
}
