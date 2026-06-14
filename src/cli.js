const { Command } = require('commander');
const path = require('path');
const { loadConfig } = require('./config/loader');
const FileWalker = require('./scanner/file-walker');
const ASTScanner = require('./scanner/ast-scanner');
const Reporter = require('./reporter');
const BaselineManager = require('./baseline');
const { getGitDiffFiles, isGitRepository } = require('./utils/git-helper');

const program = new Command();

program
  .name('api-key-miner')
  .description('AST-based JavaScript API key and secret scanner')
  .version('1.0.0');

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
  .option('--exit-code', '发现问题时以非零状态码退出')
  .option('--baseline <path>', '基线文件路径，用于对比发现新增问题')
  .option('--baseline-save <path>', '将当前扫描结果保存为基线文件')
  .option('--baseline-only-new', '只显示基线对比中的新增问题')
  .option('--git-diff', '只扫描 git diff 中的变更文件')
  .option('--git-base <branch>', 'git diff 的基准分支', 'HEAD')
  .option('--git-compare <branch>', 'git diff 的对比分支（可选）')
  .option('--staged', '只扫描 git 暂存区中的变更文件')
  .option('--stdin', '从标准输入读取 JavaScript 代码进行检测')
  .parse(process.argv);

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');

    process.stdin.on('data', chunk => {
      data += chunk;
    });

    process.stdin.on('end', () => {
      resolve(data);
    });

    process.stdin.on('error', reject);
  });
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
      'test',
      'tests',
      '__tests__',
      'spec',
      'specs',
      '__mocks__',
      '__fixtures__',
      'fixtures',
      'mock',
      'mocks'
    ];
    config.ignoreDirs = config.ignoreDirs.filter(
      dir => !testDirs.includes(dir)
    );
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
  let errorCount = 0;

  if (options.stdin) {
    scanMode = 'stdin';
    console.log('\n🔍 从标准输入读取代码...');

    const code = await readStdin();

    if (!code.trim()) {
      console.log('⚠️  标准输入为空。');
      process.exit(0);
    }

    const findings = scanner.scanCode(code, '<stdin>');
    allFindings = findings;
    scannedCount = 1;

    console.log(`✅ 扫描完成，发现 ${findings.length} 处可疑内容\n`);
  } else if (options.gitDiff) {
    scanMode = 'git-diff';

    if (!isGitRepository(process.cwd())) {
      console.error('❌ 当前目录不是 Git 仓库');
      process.exit(1);
    }

    console.log(`\n🔍 扫描 Git 变更文件 (基准: ${options.gitBase}${options.gitCompare ? ' vs ' + options.gitCompare : ''})...`);

    const diffResult = getGitDiffFiles({
      baseBranch: options.gitBase,
      compareBranch: options.gitCompare,
      staged: options.staged,
      cwd: process.cwd()
    });

    if (!diffResult.success) {
      console.error(`❌ 获取 git diff 失败: ${diffResult.error}`);
      process.exit(1);
    }

    files = diffResult.files.filter(file => fileWalker.isValidFile(file));
    console.log(`📁 找到 ${files.length} 个变更的 JavaScript 文件\n`);

    if (files.length === 0) {
      console.log('⚠️  没有找到变更的 JavaScript 文件。');
      process.exit(0);
    }
  } else {
    scanMode = 'full';
    console.log(`\n🔍 开始扫描 ${targetPaths.join(', ')} ...`);

    files = fileWalker.findFiles(targetPaths);
    console.log(`📁 找到 ${files.length} 个待扫描文件\n`);

    if (files.length === 0) {
      console.log('⚠️  没有找到符合条件的JavaScript文件。');
      process.exit(0);
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
        errorCount++;
        process.stdout.write(`错误: ${e.message}\n`);
      }
    }

    console.log(`\n✅ 扫描完成: 成功 ${scannedCount} 个文件, 错误 ${errorCount} 个文件`);
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

  const reporter = new Reporter({
    showValue: options.showValue,
    showContext: options.showContext,
    stats: {
      filesScanned: scannedCount,
      filesWithErrors: errorCount,
      scanMode
    },
    baselineResult
  });

  const report = reporter.generateReport(allFindings, options.format);

  console.log(report);

  if (options.output) {
    const savedPath = reporter.saveReport(report, options.output);
    console.log(`\n💾 报告已保存到: ${savedPath}`);
  }

  if (options.baselineSave) {
    const saveManager = new BaselineManager(options.baselineSave);
    const savedPath = saveManager.save(allFindings);
    console.log(`📌 基线已保存到: ${savedPath}`);
  }

  if (options.exitCode && allFindings.length > 0) {
    process.exit(1);
  }

  process.exit(0);
}

main().catch(err => {
  console.error('❌ 扫描出错:', err);
  process.exit(1);
});
