const fs = require('fs');
const path = require('path');
const esprima = require('esprima');
const { calculateEntropy, getEntropyLevel, isLikelySecret } = require('../utils/entropy');
const { isWhitelisted } = require('../config/loader');

class ASTScanner {
  constructor(config) {
    this.config = config;
  }

  scanFile(filePath) {
    const findings = [];
    let code;

    try {
      code = fs.readFileSync(filePath, 'utf8');
    } catch (e) {
      console.error(`警告: 无法读取文件 ${filePath}: ${e.message}`);
      return findings;
    }

    const ext = path.extname(filePath).toLowerCase();
    const language = ext === '.ts' || ext === '.tsx' ? 'ts' : 'js';

    return this.scanCode(code, filePath, { language });
  }

  scanCode(code, filePath = '<stdin>', opts = {}) {
    const findings = [];
    const language = opts.language || 'js';

    let processedCode = code;
    if (processedCode.startsWith('#!')) {
      const firstNewline = processedCode.indexOf('\n');
      if (firstNewline !== -1) {
        processedCode = processedCode.substring(firstNewline + 1);
      } else {
        processedCode = '';
      }
    }

    let ast;
    try {
      ast = esprima.parseScript(processedCode, {
        loc: true,
        range: true,
        tokens: true,
        tolerant: true,
        jsx: true
      });
    } catch (parseError) {
      try {
        ast = esprima.parseModule(processedCode, {
          loc: true,
          range: true,
          tokens: true,
          tolerant: true,
          jsx: true
        });
      } catch (moduleError) {
        throw new Error(parseError.message);
      }
    }

    this.traverseAST(ast, code, filePath, findings, language);

    return this.deduplicateFindings(findings);
  }

  traverseAST(node, code, filePath, findings, language = 'js', parent = null, parentKey = null) {
    if (!node || typeof node !== 'object') return;

    if (node.type === 'Literal' && typeof node.value === 'string') {
      this.checkStringLiteral(node, code, filePath, findings, language);
    }

    if (node.type === 'Property' || node.type === 'ObjectProperty') {
      this.checkObjectProperty(node, code, filePath, findings, language);
    }

    if (node.type === 'VariableDeclarator' && node.init) {
      this.checkVariableDeclaration(node, code, filePath, findings, language);
    }

    if (node.type === 'AssignmentExpression' && node.right) {
      this.checkAssignmentExpression(node, code, filePath, findings, language);
    }

    if (node.type === 'TemplateLiteral') {
      this.checkTemplateLiteral(node, code, filePath, findings, language);
    }

    for (const key in node) {
      if (key === 'loc' || key === 'range' || key === 'parent') continue;
      const child = node[key];

      if (Array.isArray(child)) {
        for (const item of child) {
          this.traverseAST(item, code, filePath, findings, language, node, key);
        }
      } else if (child && typeof child === 'object' && typeof child.type === 'string') {
        this.traverseAST(child, code, filePath, findings, language, node, key);
      }
    }
  }

  checkStringLiteral(node, code, filePath, findings, language = 'js') {
    const value = node.value;

    if (!value || value.length < this.config.minLength) return;

    if (isWhitelisted(value, this.config.whitelist)) return;

    for (const patternRule of this.config.patterns) {
      const match = value.match(patternRule.pattern);
      if (match) {
        const matchedValue = match[0] || value;

        if (isWhitelisted(matchedValue, this.config.whitelist)) continue;

        const entropy = calculateEntropy(matchedValue);
        const minEntropy = patternRule.minEntropy !== undefined
          ? patternRule.minEntropy
          : this.config.minEntropy;

        if (entropy < minEntropy) continue;

        const minLen = patternRule.minLength || this.config.minLength;
        if (matchedValue.length < minLen) continue;

        findings.push(this.createFinding({
          type: 'pattern_match',
          value: matchedValue,
          line: node.loc.start.line,
          column: node.loc.start.column,
          filePath,
          patternRule,
          entropy,
          context: this.extractContext(code, node.loc.start.line),
          language
        }));
      }
    }
  }

  checkObjectProperty(node, code, filePath, findings, language = 'js') {
    let keyName = null;

    if (node.key) {
      if (node.key.type === 'Identifier') {
        keyName = node.key.name;
      } else if (node.key.type === 'Literal' && typeof node.key.value === 'string') {
        keyName = node.key.value;
      }
    }

    if (!keyName) return;

    const isSensitive = this.config.propertyNames.some(
      name => keyName.toLowerCase().includes(name.toLowerCase())
    );

    if (!isSensitive) return;

    let valueNode = null;
    if (node.value) {
      valueNode = node.value;
    }

    if (!valueNode) return;

    this.checkSensitiveValue(valueNode, keyName, code, filePath, findings, language);
  }

  checkVariableDeclaration(node, code, filePath, findings, language = 'js') {
    const varName = node.id && node.id.name ? node.id.name : '';

    const isSensitive = this.config.propertyNames.some(
      name => varName.toLowerCase().includes(name.toLowerCase())
    );

    if (!isSensitive) return;

    this.checkSensitiveValue(node.init, varName, code, filePath, findings, language);
  }

  checkAssignmentExpression(node, code, filePath, findings, language = 'js') {
    let varName = '';

    if (node.left.type === 'Identifier') {
      varName = node.left.name;
    } else if (node.left.type === 'MemberExpression') {
      if (node.left.property) {
        if (node.left.property.type === 'Identifier') {
          varName = node.left.property.name;
        } else if (node.left.property.type === 'Literal') {
          varName = node.left.property.value;
        }
      }
    }

    if (!varName) return;

    const isSensitive = this.config.propertyNames.some(
      name => varName.toLowerCase().includes(name.toLowerCase())
    );

    if (!isSensitive) return;

    this.checkSensitiveValue(node.right, varName, code, filePath, findings, language);
  }

  checkTemplateLiteral(node, code, filePath, findings, language = 'js') {
    for (const quasi of node.quasis) {
      if (quasi.value && quasi.value.raw) {
        const value = quasi.value.raw;
        if (value && value.length >= this.config.minLength) {
          const tempNode = {
            value,
            loc: quasi.loc
          };
          this.checkStringLiteral(tempNode, code, filePath, findings, language);
        }
      }
    }
  }

  checkSensitiveValue(valueNode, keyName, code, filePath, findings, language = 'js') {
    let stringValue = null;
    let loc = null;

    if (valueNode.type === 'Literal' && typeof valueNode.value === 'string') {
      stringValue = valueNode.value;
      loc = valueNode.loc;
    } else if (valueNode.type === 'TemplateLiteral' && valueNode.quasis.length === 1) {
      stringValue = valueNode.quasis[0].value.raw;
      loc = valueNode.loc;
    } else if (valueNode.type === 'BinaryExpression') {
      stringValue = this.extractConcatenatedString(valueNode);
      loc = valueNode.loc;
    }

    if (!stringValue || stringValue.length < this.config.minLength) return;

    if (isWhitelisted(stringValue, this.config.whitelist)) return;

    const entropy = calculateEntropy(stringValue);

    if (!isLikelySecret(entropy)) return;

    findings.push(this.createFinding({
      type: 'sensitive_property',
      value: stringValue,
      line: loc ? loc.start.line : 0,
      column: loc ? loc.start.column : 0,
      filePath,
      keyName,
      entropy,
      context: loc ? this.extractContext(code, loc.start.line) : '',
      language
    }));
  }

  extractConcatenatedString(node) {
    if (node.type === 'Literal' && typeof node.value === 'string') {
      return node.value;
    }

    if (node.type === 'BinaryExpression' && node.operator === '+') {
      const left = this.extractConcatenatedString(node.left);
      const right = this.extractConcatenatedString(node.right);
      if (left !== null && right !== null) {
        return left + right;
      }
    }

    return null;
  }

  extractContext(code, lineNumber) {
    const lines = code.split('\n');
    const start = Math.max(0, lineNumber - 3);
    const end = Math.min(lines.length, lineNumber + 2);
    return lines.slice(start, end).join('\n').trim();
  }

  createFinding({ type, value, line, column, filePath, patternRule, keyName, entropy, context, language }) {
    const entropyInfo = getEntropyLevel(entropy);

    return {
      type,
      value,
      maskedValue: this.maskValue(value),
      line,
      column,
      file: path.relative(process.cwd(), filePath),
      absolutePath: filePath,
      pattern: patternRule ? {
        id: patternRule.id,
        name: patternRule.name,
        description: patternRule.description
      } : null,
      keyName: keyName || null,
      entropy,
      entropyLevel: entropyInfo.level,
      entropyLabel: entropyInfo.label,
      context,
      language: language || 'js',
      timestamp: new Date().toISOString()
    };
  }

  maskValue(value) {
    if (!value || value.length <= 8) return '*'.repeat(value.length);
    const prefix = value.substring(0, 4);
    const suffix = value.substring(value.length - 4);
    const middle = '*'.repeat(value.length - 8);
    return prefix + middle + suffix;
  }

  deduplicateFindings(findings) {
    const seen = new Map();
    const result = [];

    for (const finding of findings) {
      const key = `${finding.file}:${finding.line}:${finding.column}:${finding.value}`;

      if (!seen.has(key)) {
        seen.set(key, finding);
        result.push(finding);
      } else {
        const existing = seen.get(key);
        if (finding.type === 'pattern_match' && existing.type !== 'pattern_match') {
          const index = result.indexOf(existing);
          if (index !== -1) {
            result[index] = finding;
            seen.set(key, finding);
          }
        }
      }
    }

    return result;
  }
}

module.exports = ASTScanner;
