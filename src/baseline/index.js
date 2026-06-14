const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class BaselineManager {
  constructor(baselinePath = null) {
    this.baselinePath = baselinePath;
    this.baselineData = null;
  }

  load() {
    if (!this.baselinePath) {
      return null;
    }

    const absolutePath = path.resolve(this.baselinePath);
    if (!fs.existsSync(absolutePath)) {
      return null;
    }

    try {
      const raw = fs.readFileSync(absolutePath, 'utf8');
      this.baselineData = JSON.parse(raw);
      return this.baselineData;
    } catch (e) {
      console.error(`警告: 无法加载基线文件 ${this.baselinePath}: ${e.message}`);
      return null;
    }
  }

  save(findings, options = {}) {
    if (!this.baselinePath) {
      return null;
    }

    const baselineData = {
      version: '1.0',
      createdAt: new Date().toISOString(),
      totalFindings: findings.length,
      findings: findings.map(f => this.normalizeFinding(f))
    };

    const absolutePath = path.resolve(this.baselinePath);
    const dir = path.dirname(absolutePath);

    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(absolutePath, JSON.stringify(baselineData, null, 2), 'utf8');
    return absolutePath;
  }

  normalizeFinding(finding) {
    const valueHash = crypto.createHash('sha256')
      .update(finding.value)
      .digest('hex')
      .substring(0, 16);

    return {
      file: finding.file,
      line: finding.line,
      valueHash,
      patternId: finding.pattern ? finding.pattern.id : null,
      keyName: finding.keyName || null
    };
  }

  getFindingKey(finding) {
    const normalized = this.normalizeFinding(finding);
    return `${normalized.file}:${normalized.line}:${normalized.valueHash}`;
  }

  compare(findings) {
    if (!this.baselineData) {
      return {
        newFindings: findings,
        existingFindings: [],
        resolvedFindings: [],
        isFirstScan: true
      };
    }

    const baselineKeys = new Set(
      this.baselineData.findings.map(f => `${f.file}:${f.line}:${f.valueHash}`)
    );

    const currentKeys = new Set(
      findings.map(f => this.getFindingKey(f))
    );

    const newFindings = findings.filter(f => !baselineKeys.has(this.getFindingKey(f)));
    const existingFindings = findings.filter(f => baselineKeys.has(this.getFindingKey(f)));

    const resolvedFindings = this.baselineData.findings.filter(
      bf => !currentKeys.has(`${bf.file}:${bf.line}:${bf.valueHash}`)
    );

    return {
      newFindings,
      existingFindings,
      resolvedFindings,
      isFirstScan: false
    };
  }

  getStats() {
    if (!this.baselineData) {
      return null;
    }
    return {
      version: this.baselineData.version,
      createdAt: this.baselineData.createdAt,
      totalFindings: this.baselineData.totalFindings
    };
  }
}

module.exports = BaselineManager;
