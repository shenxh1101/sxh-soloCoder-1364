const { Command } = require('commander');
const path = require('path');
const { loadConfig } = require('./config/loader');
const FileWalker = require('./scanner/file-walker');
const ASTScanner = require('./scanner/ast-scanner');
const Reporter = require('./reporter');
const BaselineManager = require('./baseline');
const { getGitDiffFiles, isGitRepository } = require('./utils/git-helper');

const EXIT_OK = 0;
const EXIT_RISK_FOUND = 1;
const EXIT_SCAN_ERROR = 2;

const program = new Command();

program
  .name('api-key-miner')
  .description('AST-based JavaScript API key and secret scanner')
  .version('1.1.0');

program
  .argument('[paths...]', '要扫描的文件或目录路径', [process.cwd()])
  .option('-c, --config <path>', '自定义配置文件路径')
  .option('-f, --format <format>', '输出格式: table, json, csv, sarif', 'table')
  .option('-o, --output <path>', '输出报告到指定文件')
  .option('-s, --show-value', '显示完整的密钥值（默认掩码显示）')
  .option('--show-context', '显示代码上下文')
  .option('--no-default-ignore', '不使用默认的忽略目录')
  .option('--include-test', '包含测试目录和文件')
  .option('--min-entropy <value>', '最小熵值阈值', parseFloat)
  .option('--min-length <value>', '最小字符串长度', parseInt)
  .option('--exit-code', '发现问题时以非零状态码退出 (1=风险, 2=扫描出错)')
  .option('--baseline <path>', '基线文件路径，用于对比发现新增问题')
  .option('--baseline-save <path>', '将当前扫描结果保存为基线文件（覆盖写入）')
  .option('--baseline-update <path>', '将当前结果合并回基线（接受新增，保留已有）')
  .option('--baseline-only-new', '只显示基线对比中的新增问题')
  .option('--git-diff', '只扫描 git diff 中的变更文件（默认: 工作区 vs HEAD）')
  .option('--staged', 'git diff 模式: 只扫描已暂存的变更')
  .option('--unstaged', 'git diff 模式: 只扫描未暂存的变更')
  .option('--commits <refs>', 'git diff 模式: 扫描两个提交之间的变更 (格式: base...head)')
  .option('--stdin', '从标准输入读取代码进行检测')
  .option('--stdin-filename <name>', 'stdin 模式下的虚拟文件名（用于报告定位）')
  .option('--stdin-lang <lang>', 'stdin 模式下的语言标签 (js/ts)', 'js')
  .parse(process.argv);

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');

    if (process.stdin.isTTY) {
      resolve('');
      return;
    }

    process.stdin.on('data', chunk => {
      data += chunk;
    });

    process.stdin.on('end', () => {
      resolve(data);
    });

    process.stdin.on('error', reject);
  });
}

function resolveGitDiffMode(options) {
  if (options.commits) return 'commits';
  if (options.staged) return 'staged';
  if (options.unstaged) return 'unstaged';
  return 'working';
}

async function main() {
  const options = program.opts();
  let targetPaths = program.args;

  const config = loadConfig(options.config);

  if (options.minEntropy !== undefined) {
    config.minEntropy = options.minEntropy;
  }
  if (options.minLength !== undefined) {
    config.minLength = options.minLength;
  }

  if (options.defaultIgnore === false) {
    config.ignoreDirs = [];
  }

  if (options.includeTest) {
    const testDirs = [
      'test', 'tests', '__tests__', 'spec', 'specs',
      '__mocks__', '__fixtures__', 'fixtures', 'mock', 'mocks'
    ];
    config.ignoreDirs = config.ignoreDirs.filter(dir => !testDirs.includes(dir));
  }

  const fileWalker = new FileWalker(config);
  const scanner = new ASTScanner(config);
  const baselineManager = options.baseline
    ? new BaselineManager(options.baseline)
    : null;

  if (baselineManager) {
    baselineManager.load();
  }

  let scanMode = 'full';
  let files = [];
  let allFindings = [];
  let scannedCount = 0;
  let parseErrorCount = 0;
  let parseErrorFiles = [];

  if (options.stdin) {
    scanMode = 'stdin';
    const stdinLabel = options.stdinFilename || '<stdin>';

    console.log(`\n🔍 从标准输入读取代码 (${stdinLabel})...`);

    const code = await readStdin();

    if (!code.trim()) {
      console.log('⚠️  标准输入为空。');
      process.exit(EXIT_OK);
    }

    const virtualPath = options.stdinFilename || '<stdin>';
    const findings = scanner.scanCode(code, virtualPath);
    allFindings = findings;
    scannedCount = 1;

    console.log(`✅ 扫描完成，发现 ${findings.length} 处可疑内容\n`);
  } else if (options.gitDiff) {
    scanMode = 'git-diff';

    if (!isGitRepository(process.cwd())) {
      console.error('❌ 当前目录不是 Git 仓库');
      process.exit(EXIT_SCAN_ERROR);
    }

    const diffMode = resolveGitDiffMode(options);
    let baseRef = null;
    let headRef = null;

    if (options.commits) {
      const parts = options.commits.split('...');
      baseRef = parts[0] || 'HEAD';
      headRef = parts[1] || null;
    }

    const diffResult = getGitDiffFiles({
      mode: diffMode,
      baseRef,
      headRef,
      cwd: process.cwd()
    });

    if (!diffResult.success) {
      console.error(`❌ 获取 git diff 失败: ${diffResult.error}`);
      process.exit(EXIT_SCAN_ERROR);
    }

    files = diffResult.files.filter(file => fileWalker.isValidFile(file));
    const modeLabel = diffResult.label;

    console.log(`\n🔍 扫描 Git 变更文件 (${modeLabel})...`);
    console.log(`📁 找到 ${files.length} 个变更的 JavaScript 文件\n`);

    if (files.length === 0) {
      console.log('⚠️  没有找到变更的 JavaScript 文件。');
      process.exit(EXIT_OK);
    }
  } else {
    scanMode = 'full';
    console.log(`\n🔍 开始扫描 ${targetPaths.join(', ')} ...`);

    files = fileWalker.findFiles(targetPaths);
    console.log(`📁 找到 ${files.length} 个待扫描文件\n`);

    if (files.length === 0) {
      console.log('⚠️  没有找到符合条件的JavaScript文件。');
      process.exit(EXIT_OK);
    }
  }

  if (!options.stdin) {
    for (const file of files) {
      const displayPath = path.relative(process.cwd(), file) || file;
      process.stdout.write(`  扫描中: ${displayPath} ... `);

      try {
        const findings = scanner.scanFile(file);
        allFindings = allFindings.concat(findings);
        scannedCount++;

        if (findings.length > 0) {
          process.stdout.write(`发现 ${findings.length} 处\n`);
        } else {
          process.stdout.write('✓\n');
        }
      } catch (e) {
        parseErrorCount++;
        parseErrorFiles.push(displayPath);
        process.stdout.write(`解析失败\n`);
      }
    }

    console.log(`\n✅ 扫描完成: ${scannedCount} 个文件成功, ${parseErrorCount} 个文件解析失败`);
  }

  allFindings = allFindings.sort((a, b) => {
    const riskOrder = { very_high: 0, high: 1, medium: 2, low: 3, very_low: 4 };
    return riskOrder[a.entropyLevel] - riskOrder[b.entropyLevel];
  });

  let baselineResult = null;
  if (baselineManager) {
    baselineResult = baselineManager.compare(allFindings);

    for (const finding of allFindings) {
      const isNew = baselineResult.newFindings.some(
        nf => baselineManager.getFindingKey(nf) === baselineManager.getFindingKey(finding)
      );
      finding.baselineStatus = isNew ? 'new' : 'existing';
    }

    if (options.baselineOnlyNew) {
      allFindings = baselineResult.newFindings;
    }
  }

  const filesWithFindings = new Set(allFindings.map(f => f.file)).size;

  const reporter = new Reporter({
    showValue: options.showValue,
    showContext: options.showContext,
    stats: {
      filesScanned: scannedCount,
      filesWithFindings,
      filesWithParseErrors: parseErrorCount,
      parseErrorFiles,
      scanMode
    },
    baselineResult
  });

  const report = reporter.generateReport(allFindings, options.format);

  console.log(report);

  if (options.output) {
    const savedPath = reporter.saveReport(report, options.output);
    console.log(`💾 报告已保存到: ${savedPath}`);
  }

  if (options.baselineSave) {
    const saveManager = new BaselineManager(options.baselineSave);
    const savedPath = saveManager.save(allFindings);
    console.log(`📌 基线已保存到: ${savedPath}`);
  }

  if (options.baselineUpdate) {
    const updateManager = new BaselineManager(options.baselineUpdate);
    updateManager.load();
    const result = updateManager.merge(allFindings);
    if (result) {
      console.log(`📌 基线已更新: ${result.savedPath}`);
      console.log(`   新增接受: ${result.added}  保留: ${result.retained}  移除: ${result.removed}  基线总数: ${result.totalInBaseline}`);
    }
  }

  if (options.exitCode) {
    if (parseErrorCount > 0 && allFindings.length === 0) {
      process.exit(EXIT_SCAN_ERROR);
    }
    if (allFindings.length > 0) {
      process.exit(EXIT_RISK_FOUND);
    }
  }

  process.exit(EXIT_OK);
}

main().catch(err => {
  console.error('❌ 扫描出错:', err);
  process.exit(EXIT_SCAN_ERROR);
});
