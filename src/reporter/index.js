const fs = require('fs');
const path = require('path');
const chalk = require('chalk');

class Reporter {
  constructor(options = {}) {
    this.showValue = options.showValue || false;
    this.showContext = options.showContext || false;
    this.stats = options.stats || {};
    this.baselineResult = options.baselineResult || null;
  }

  generateReport(findings, format = 'table') {
    const summary = this.generateSummary(findings);

    switch (format.toLowerCase()) {
      case 'json':
        return this.formatJSON(findings, summary);
      case 'csv':
        return this.formatCSV(findings);
      case 'sarif':
        return this.formatSARIF(findings, summary);
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
      filesScanned: this.stats.filesScanned || 0,
      filesWithFindings: this.stats.filesWithFindings || files.size,
      filesWithParseErrors: this.stats.filesWithParseErrors || 0,
      parseErrorFiles: this.stats.parseErrorFiles || [],
      highRisk,
      mediumRisk,
      lowRisk,
      patternStats,
      scannedAt: new Date().toISOString(),
      scanMode: this.stats.scanMode || 'full',
      baselineInfo: this.baselineResult ? {
        isFirstScan: this.baselineResult.isFirstScan,
        newCount: this.baselineResult.newFindings.length,
        existingCount: this.baselineResult.existingFindings.length,
        resolvedCount: this.baselineResult.resolvedFindings.length
      } : null
    };
  }

  formatTable(findings, summary) {
    let output = '';

    output += chalk.bold.cyan('\n╔════════════════════════════════════════════════════════════╗\n');
    output += chalk.bold.cyan('║           API Key Miner - Scan Report                     ║\n');
    output += chalk.bold.cyan('╚════════════════════════════════════════════════════════════╝\n\n');

    output += chalk.bold('📊 扫描摘要:\n');
    output += `  ${chalk.yellow('扫描模式:')} ${this.getScanModeLabel(summary.scanMode)}\n`;
    output += `  ${chalk.yellow('扫描文件:')} ${summary.filesScanned} 个\n`;
    output += `  ${chalk.yellow('命中文件:')} ${summary.filesWithFindings} 个 (含可疑密钥)\n`;

    if (summary.filesWithParseErrors > 0) {
      output += `  ${chalk.red('解析失败:')} ${summary.filesWithParseErrors} 个\n`;
      for (const f of summary.parseErrorFiles) {
        output += `    ${chalk.gray('- ' + f)}\n`;
      }
    }

    output += `  ${chalk.yellow('发现总数:')} ${summary.totalFindings}\n`;
    output += `  ${chalk.red('高风险:')}   ${summary.highRisk}\n`;
    output += `  ${chalk.yellow('中风险:')}   ${summary.mediumRisk}\n`;
    output += `  ${chalk.green('低风险:')}   ${summary.lowRisk}\n`;

    if (summary.baselineInfo) {
      output += `\n${chalk.bold('📍 基线对比:')}\n`;
      if (summary.baselineInfo.isFirstScan) {
        output += `  ${chalk.gray('首次扫描，无基线数据')}\n`;
      } else {
        output += `  ${chalk.red('🆕 新增:')} ${summary.baselineInfo.newCount}\n`;
        output += `  ${chalk.yellow('📌 保留:')} ${summary.baselineInfo.existingCount}\n`;
        output += `  ${chalk.green('✅ 移除:')} ${summary.baselineInfo.resolvedCount}\n`;
      }
    }

    output += '\n';

    if (findings.length === 0) {
      output += chalk.green('✅ 未发现可疑的API密钥或硬编码机密。\n');
      if (summary.filesWithParseErrors > 0) {
        output += chalk.yellow(`⚠️  但有 ${summary.filesWithParseErrors} 个文件解析失败，建议检查。\n`);
      }
      return output;
    }

    if (this.baselineResult && !this.baselineResult.isFirstScan && this.baselineResult.newFindings.length > 0) {
      output += chalk.bold('🆕 新增发现:\n\n');
      this.baselineResult.newFindings.forEach((finding, index) => {
        output += this.formatFindingItem(finding, index + 1, 'new');
      });
      output += '\n';

      if (this.baselineResult.existingFindings.length > 0) {
        output += chalk.bold('📌 已存在 (基线中):\n\n');
        this.baselineResult.existingFindings.forEach((finding, index) => {
          output += this.formatFindingItem(finding, index + 1, 'existing');
        });
        output += '\n';
      }

      if (this.baselineResult.resolvedFindings.length > 0) {
        output += chalk.bold('✅ 已修复 (基线中已不存在):\n\n');
        this.baselineResult.resolvedFindings.forEach((f, index) => {
          output += `  ${index + 1}. ${chalk.green(f.file)}:${f.line}\n`;
        });
        output += '\n';
      }
    } else {
      output += chalk.bold(' 详细发现:\n\n');
      findings.forEach((finding, index) => {
        output += this.formatFindingItem(finding, index + 1);
      });
    }

    output += chalk.bold('📈 规则匹配统计:\n');
    for (const [pattern, count] of Object.entries(summary.patternStats)) {
      output += `  ${chalk.blue(pattern)}: ${count} 处\n`;
    }

    output += `\n${chalk.gray(`扫描时间: ${summary.scannedAt}`)}\n`;

    if (summary.totalFindings > 0) {
      output += chalk.red(`\n退出码: 1 (发现 ${summary.totalFindings} 处风险)\n`);
    }
    if (summary.filesWithParseErrors > 0 && summary.totalFindings === 0) {
      output += chalk.yellow(`\n退出码: 2 (${summary.filesWithParseErrors} 个文件解析失败)\n`);
    }

    return output;
  }

  formatFindingItem(finding, index, status = null) {
    const riskColor = this.getRiskColor(finding.entropyLevel);
    let prefix = '';

    if (status === 'new') {
      prefix = chalk.red('[新增] ');
    } else if (status === 'existing') {
      prefix = chalk.gray('[已有] ');
    }

    let output = '';
    output += chalk.bold(`${index}. ${prefix}${riskColor('▲ ' + this.getRiskLabel(finding.entropyLevel) + ' 风险')}\n`);
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
    return output;
  }

  getScanModeLabel(mode) {
    const labels = {
      'full': '全量扫描',
      'git-diff': 'Git 变更文件',
      'stdin': '标准输入',
      'file': '指定文件'
    };
    return labels[mode] || mode;
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
        timestamp: f.timestamp,
        baselineStatus: f.baselineStatus || null
      }))
    };

    return JSON.stringify(report, null, 2);
  }

  formatCSV(findings) {
    const headers = ['文件', '行号', '列号', '类型', '规则/属性', '熵值', '熵值等级', '值', '时间', '基线状态'];

    const rows = findings.map(f => [
      f.file,
      f.line,
      f.column,
      f.type,
      f.pattern ? f.pattern.name : (f.keyName || ''),
      f.entropy.toFixed(4),
      f.entropyLabel,
      this.showValue ? `"${f.value.replace(/"/g, '""')}"` : `"${f.maskedValue}"`,
      f.timestamp,
      f.baselineStatus || ''
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }

  formatSARIF(findings, summary) {
    const rules = {};
    const results = [];

    for (const finding of findings) {
      const ruleId = finding.pattern
        ? `APIK-${finding.pattern.id}`
        : `APIK-sensitive-${finding.keyName || 'property'}`;

      if (!rules[ruleId]) {
        rules[ruleId] = {
          id: ruleId,
          name: finding.pattern ? finding.pattern.name : `Sensitive Property: ${finding.keyName}`,
          shortDescription: {
            text: finding.pattern
              ? finding.pattern.description
              : `检测到敏感属性 ${finding.keyName} 包含硬编码值`
          },
          defaultConfiguration: {
            level: this.getSarifLevel(finding.entropyLevel)
          },
          help: {
            text: finding.pattern
              ? `检测到 ${finding.pattern.name} 类型的API密钥`
              : `检测到敏感属性 ${finding.keyName} 包含硬编码的字符串值`,
            markdown: finding.pattern
              ? `**${finding.pattern.name}**\n\n${finding.pattern.description}\n\n建议将密钥移至环境变量或密钥管理服务。`
              : `**敏感属性 ${finding.keyName}**\n\n检测到硬编码的敏感值，建议移至环境变量或密钥管理服务。`
          }
        };
      }

      const result = {
        ruleId,
        level: this.getSarifLevel(finding.entropyLevel),
        message: {
          text: finding.pattern
            ? `发现 ${finding.pattern.name}: ${finding.maskedValue}`
            : `敏感属性 ${finding.keyName} 包含硬编码值: ${finding.maskedValue}`
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: finding.file.replace(/\\/g, '/')
              },
              region: {
                startLine: finding.line,
                startColumn: finding.column + 1
              }
            }
          }
        ],
        properties: {
          entropy: finding.entropy,
          entropyLevel: finding.entropyLevel,
          maskedValue: finding.maskedValue
        }
      };

      if (finding.context) {
        result.locations[0].physicalLocation.region.snippet = {
          text: finding.context
        };
      }

      if (finding.baselineStatus) {
        result.properties.baselineStatus = finding.baselineStatus;
      }

      results.push(result);
    }

    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'api-key-miner',
              version: '1.1.0',
              informationUri: 'https://github.com/api-key-miner',
              rules: Object.values(rules)
            }
          },
          invocations: [
            {
              executionSuccessful: summary.filesWithParseErrors === 0,
              startTimeUtc: summary.scannedAt,
              toolExecutionNotifications: summary.parseErrorFiles.map(f => ({
                level: 'error',
                message: { text: `文件解析失败: ${f}` }
              }))
            }
          ],
          results
        }
      ]
    };

    return JSON.stringify(sarif, null, 2);
  }

  getSarifLevel(entropyLevel) {
    switch (entropyLevel) {
      case 'very_high':
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'note';
      default:
        return 'none';
    }
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
