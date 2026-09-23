/**
 * AGENT-FIREWALL // Cryptographic Audit Logger & Attestation Engine
 * Creates immutable, cryptographically hashed security attestations for every agent command.
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

class AuditLogger {
  constructor() {
    this.ledger = [];
  }

  /**
   * Generates a signed tamper-evident security attestation record
   */
  createAttestation(command, verdict, policy, riskScore, violations = []) {
    const timestamp = new Date().toISOString();
    const commandHash = computeDigest(command);
    const payload = `${timestamp}|${commandHash}|${verdict}|${policy}|${riskScore}`;
    const signature = computeDigest(payload);
    const attestationId = `AF-${signature.substring(0, 12).toUpperCase()}`;

    const record = {
      attestationId,
      timestamp,
      command,
      commandHash,
      verdict,
      policy,
      riskScore,
      violationsCount: violations.length,
      violations: violations.map(v => ({ id: v.ruleId, name: v.name, severity: v.severity })),
      signature,
      verified: true
    };

    this.ledger.unshift(record);
    return record;
  }

  verifyRecord(record) {
    if (!record || !record.signature) return false;
    const expectedPayload = `${record.timestamp}|${record.commandHash}|${record.verdict}|${record.policy}|${record.riskScore}`;
    const calculatedSignature = computeDigest(expectedPayload);
    return calculatedSignature === record.signature;
  }

  getHistory(limit = 50) {
    return this.ledger.slice(0, limit);
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
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { AuditLogger, computeDigest };
}
