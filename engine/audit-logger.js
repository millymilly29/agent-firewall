/**
 * AGENT-FIREWALL // Cryptographic Audit Logger & Attestation Engine
 * Creates immutable, cryptographically hash-chained security attestations for every agent command.
 */

// Pure JS SHA-256 fallback to ensure 100% offline standalone compatibility in any browser or Node.js
function sha256Pure(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  const lengthProperty = 'length';
  let i, j;
  let result = '';
  const words = [];
  const asciiBitLength = ascii[lengthProperty] * 8;
  let hash = [];
  const k = [];
  let primeCounter = 0;

  const isPrime = function(candidate) {
    for (let factor = 2; factor * factor <= candidate; factor++) {
      if (candidate % factor === 0) return false;
    }
    return true;
  };

  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (isPrime(candidate)) {
      if (primeCounter < 8) {
        hash[primeCounter] = (mathPow(candidate, 1 / 2) * maxWord) | 0;
      }
      k[primeCounter] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      primeCounter++;
    }
  }

  ascii += '\x80';
  while ((ascii[lengthProperty] % 64) - 56) ascii += '\x00';
  for (i = 0; i < ascii[lengthProperty]; i++) {
    j = ascii.charCodeAt(i);
    if (j >> 8) return;
    words[i >> 2] |= j << (((3 - i) % 4) * 8);
  }
  words[words[lengthProperty]] = (asciiBitLength / maxWord) | 0;
  words[words[lengthProperty]] = asciiBitLength;

  for (j = 0; j < words[lengthProperty]; ) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash;
    hash = hash.slice(0, 8);

    for (i = 0; i < 64; i++) {
      const w15 = w[i - 15], w2 = w[i - 2];
      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      w[i] = i < 16 ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0;

      const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      const sigma0 = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
      const sigma1 = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
      const temp1 = hash[7] + sigma1 + ch + k[i] + w[i];
      const temp2 = sigma0 + maj;

      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }

  for (i = 0; i < 8; i++) {
    for (j = 3; j >= 0; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

function computeDigest(data) {
  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    try {
      const crypto = require('crypto');
      return crypto.createHash('sha256').update(data).digest('hex');
    } catch (e) {
      // fallback to pure js
    }
  }
  return sha256Pure(data);
}

const GENESIS_HASH = '0'.repeat(64);

class AuditLogger {
  constructor() {
    this.ledger = [];
  }

  /**
   * Generates a SHA-256 hash-chained audit log record.
   * H_i = SHA-256(H_{i-1} | timestamp | commandHash | verdict | policy | riskScore)
   */
  createAttestation(command, verdict, policy, riskScore, violations = []) {
    const timestamp = new Date().toISOString();
    const commandHash = computeDigest(command);
    const prevHash = this.ledger.length > 0 ? this.ledger[this.ledger.length - 1].hash : GENESIS_HASH;
    const payload = `${prevHash}|${timestamp}|${commandHash}|${verdict}|${policy}|${riskScore}`;
    const hash = computeDigest(payload);
    const attestationId = `AF-${hash.substring(0, 12).toUpperCase()}`;

    const record = {
      attestationId,
      timestamp,
      command,
      commandHash,
      prevHash,
      verdict,
      policy,
      riskScore,
      violationsCount: violations.length,
      violations: violations.map(v => ({ id: v.ruleId || v.id, name: v.name, severity: v.severity })),
      hash,
      signature: hash, // kept for backward compatibility
      verified: true
    };

    this.ledger.push(record);
    return record;
  }

  verifyRecord(record, expectedPrevHash = null) {
    if (!record || (!record.hash && !record.signature)) return false;
    const prev = expectedPrevHash !== null ? expectedPrevHash : (record.prevHash || GENESIS_HASH);
    
    // Verify command content matches commandHash
    if (record.command && record.commandHash) {
      if (computeDigest(record.command) !== record.commandHash) {
        return false;
      }
    }

    // Check with prevHash
    const chainedPayload = `${prev}|${record.timestamp}|${record.commandHash}|${record.verdict}|${record.policy}|${record.riskScore}`;
    const chainedHash = computeDigest(chainedPayload);
    if (chainedHash === (record.hash || record.signature)) return true;

    // Legacy unchained fallback
    const legacyPayload = `${record.timestamp}|${record.commandHash}|${record.verdict}|${record.policy}|${record.riskScore}`;
    const legacyHash = computeDigest(legacyPayload);
    return legacyHash === (record.hash || record.signature);
  }

  /**
   * Verifies the entire hash chain integrity across all records in the ledger.
   * Returns { valid: boolean, tamperedIndex: number | null, reason: string | null }
   */
  verifyChain() {
    if (this.ledger.length === 0) {
      return { valid: true, count: 0 };
    }

    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < this.ledger.length; i++) {
      const record = this.ledger[i];

      // Verify link to previous block
      if (record.prevHash && record.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          tamperedIndex: i,
          reason: `Broken chain link at index ${i}: prevHash mismatch (expected ${expectedPrevHash}, got ${record.prevHash})`
        };
      }

      // Verify payload integrity
      const payload = `${expectedPrevHash}|${record.timestamp}|${record.commandHash}|${record.verdict}|${record.policy}|${record.riskScore}`;
      const calculatedHash = computeDigest(payload);
      if (calculatedHash !== (record.hash || record.signature)) {
        return {
          valid: false,
          tamperedIndex: i,
          reason: `Invalid hash signature at index ${i}`
        };
      }

      expectedPrevHash = record.hash || record.signature;
    }

    return { valid: true, count: this.ledger.length };
  }

  getHistory(limit = 50) {
    return this.ledger.slice().reverse().slice(0, limit);
  }

  exportJSON() {
    return JSON.stringify(this.ledger, null, 2);
  }

  clear() {
    this.ledger = [];
  }
}

if (typeof window !== 'undefined') {
  window.AuditLogger = AuditLogger;
  window.computeDigest = computeDigest;
  window.GENESIS_HASH = GENESIS_HASH;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { AuditLogger, computeDigest, GENESIS_HASH };
}
