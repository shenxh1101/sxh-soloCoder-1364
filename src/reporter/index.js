const fs = require('fs');
const path = require('path');
const chalk = require('chalk');

class Reporter {
  constructor(options = {}) {
    this.showValue = options.showValue || false;
    this.showContext = options.showContext || false;
  }

  generateReport(findings, format = 'table') {
    const summary = this.generateSummary(findings);

    switch (format.toLowerCase()) {
      case 'json':
        return this.formatJSON(findings, summary);
      case 'csv':
        return this.formatCSV(findings);
      case 'table':
      default:
        return this.formatTable(findings, summary);
    }
  }

  generateSummary(findings) {
    const files = new Set(findings.map(f => f.file));
    const highRisk = findings.filter(f =>
      f.entropyLevel === 'very_high' || f.entropyLevel === 'high'
    ).length;
    const mediumRisk = findings.filter(f => f.entropyLevel === 'medium').length;
    const lowRisk = findings.filter(f =>
      f.entropyLevel === 'low' || f.entropyLevel === 'very_low'
    ).length;

    const patternStats = {};
    for (const finding of findings) {
      const key = finding.pattern ? finding.pattern.name : (finding.keyName || 'unknown');
      patternStats[key] = (patternStats[key] || 0) + 1;
    }

    return {
      totalFindings: findings.length,
      filesScanned: 0,
      filesWithFindings: files.size,
      highRisk,
      mediumRisk,
      lowRisk,
      patternStats,
      scannedAt: new Date().toISOString()
    };
  }

  formatTable(findings, summary) {
    let output = '';

    output += chalk.bold.cyan('\n╔════════════════════════════════════════════════════════════╗\n');
    output += chalk.bold.cyan('║           API Key Miner - Scan Report                     ║\n');
    output += chalk.bold.cyan('╚════════════════════════════════════════════════════════════╝\n\n');

    output += chalk.bold('📊 扫描摘要:\n');
    output += `  ${chalk.yellow('发现总数:')} ${summary.totalFindings}\n`;
    output += `  ${chalk.yellow('涉及文件:')} ${summary.filesWithFindings}\n`;
    output += `  ${chalk.red('高风险:')}   ${summary.highRisk}\n`;
    output += `  ${chalk.yellow('中风险:')}   ${summary.mediumRisk}\n`;
    output += `  ${chalk.green('低风险:')}   ${summary.lowRisk}\n\n`;

    if (findings.length === 0) {
      output += chalk.green('✅ 未发现可疑的API密钥或硬编码机密。\n');
      return output;
    }

    output += chalk.bold('📋 详细发现:\n\n');

    findings.forEach((finding, index) => {
      const riskColor = this.getRiskColor(finding.entropyLevel);

      output += chalk.bold(`${index + 1}. ${riskColor('▲ ' + this.getRiskLabel(finding.entropyLevel) + ' 风险')}\n`);
      output += `   ${chalk.gray('文件:')} ${chalk.white(finding.file)}\n`;
      output += `   ${chalk.gray('位置:')} 第 ${finding.line} 行, 第 ${finding.column} 列\n`;

      if (finding.pattern) {
        output += `   ${chalk.gray('规则:')} ${chalk.blue(finding.pattern.name)}\n`;
        output += `   ${chalk.gray('描述:')} ${finding.pattern.description}\n`;
      } else if (finding.keyName) {
        output += `   ${chalk.gray('敏感属性:')} ${chalk.magenta(finding.keyName)}\n`;
      }

      output += `   ${chalk.gray('熵值:')} ${finding.entropy.toFixed(4)} (${finding.entropyLabel})\n`;

      if (this.showValue) {
        output += `   ${chalk.gray('值:')} ${chalk.red(finding.value)}\n`;
      } else {
        output += `   ${chalk.gray('掩码值:')} ${chalk.yellow(finding.maskedValue)}\n`;
      }

      if (this.showContext && finding.context) {
        output += `   ${chalk.gray('上下文:')}\n`;
        const contextLines = finding.context.split('\n');
        contextLines.forEach(line => {
          output += `     ${chalk.gray('|')} ${line}\n`;
        });
      }

      output += '\n';
    });

    output += chalk.bold('📈 规则匹配统计:\n');
    for (const [pattern, count] of Object.entries(summary.patternStats)) {
      output += `  ${chalk.blue(pattern)}: ${count} 处\n`;
    }

    output += `\n${chalk.gray(`扫描时间: ${summary.scannedAt}`)}\n`;

    return output;
  }

  formatJSON(findings, summary) {
    const report = {
      summary,
      findings: findings.map(f => ({
        type: f.type,
        file: f.file,
        absolutePath: f.absolutePath,
        line: f.line,
        column: f.column,
        pattern: f.pattern,
        keyName: f.keyName,
        value: this.showValue ? f.value : f.maskedValue,
        entropy: f.entropy,
        entropyLevel: f.entropyLevel,
        entropyLabel: f.entropyLabel,
        context: this.showContext ? f.context : undefined,
        timestamp: f.timestamp
      }))
    };

    return JSON.stringify(report, null, 2);
  }

  formatCSV(findings) {
    const headers = ['文件', '行号', '列号', '类型', '规则/属性', '熵值', '熵值等级', '值', '时间'];

    const rows = findings.map(f => [
      f.file,
      f.line,
      f.column,
      f.type,
      f.pattern ? f.pattern.name : (f.keyName || ''),
      f.entropy.toFixed(4),
      f.entropyLabel,
      this.showValue ? `"${f.value.replace(/"/g, '""')}"` : `"${f.maskedValue}"`,
      f.timestamp
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }

  saveReport(report, outputPath) {
    const absolutePath = path.resolve(outputPath);
    const dir = path.dirname(absolutePath);

    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(absolutePath, report, 'utf8');
    return absolutePath;
  }

  getRiskColor(level) {
    switch (level) {
      case 'very_high':
      case 'high':
        return chalk.red;
      case 'medium':
        return chalk.yellow;
      case 'low':
        return chalk.green;
      default:
        return chalk.gray;
    }
  }

  getRiskLabel(level) {
    switch (level) {
      case 'very_high':
        return '极高';
      case 'high':
        return '高';
      case 'medium':
        return '中';
      case 'low':
        return '低';
      default:
        return '极低';
    }
  }
}

module.exports = Reporter;
