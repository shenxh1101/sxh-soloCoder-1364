const { Command } = require('commander');
const path = require('path');
const { loadConfig } = require('./config/loader');
const FileWalker = require('./scanner/file-walker');
const ASTScanner = require('./scanner/ast-scanner');
const Reporter = require('./reporter');

const program = new Command();

program
  .name('api-key-miner')
  .description('AST-based JavaScript API key and secret scanner')
  .version('1.0.0');

program
  .argument('[paths...]', '要扫描的文件或目录路径', [process.cwd()])
  .option('-c, --config <path>', '自定义配置文件路径')
  .option('-f, --format <format>', '输出格式: table, json, csv', 'table')
  .option('-o, --output <path>', '输出报告到指定文件')
  .option('-s, --show-value', '显示完整的密钥值（默认掩码显示）')
  .option('--show-context', '显示代码上下文')
  .option('--no-default-ignore', '不使用默认的忽略目录')
  .option('--include-test', '包含测试目录和文件')
  .option('--min-entropy <value>', '最小熵值阈值', parseFloat)
  .option('--min-length <value>', '最小字符串长度', parseInt)
  .option('--exit-code', '发现问题时以非零状态码退出')
  .parse(process.argv);

async function main() {
  const options = program.opts();
  const targetPaths = program.args;

  const config = loadConfig(options.config);

  if (options.minEntropy !== undefined) {
    config.minEntropy = options.minEntropy;
  }
  if (options.minLength !== undefined) {
    config.minLength = options.minLength;
  }

  if (!options.includeTest) {
    if (options.defaultIgnore === false) {
      config.ignoreDirs = [];
    }
  }

  const fileWalker = new FileWalker(config);
  const scanner = new ASTScanner(config);
  const reporter = new Reporter({
    showValue: options.showValue,
    showContext: options.showContext
  });

  console.log(`\n🔍 开始扫描 ${targetPaths.join(', ')} ...`);

  const files = fileWalker.findFiles(targetPaths);
  console.log(`📁 找到 ${files.length} 个待扫描文件\n`);

  if (files.length === 0) {
    console.log('⚠️  没有找到符合条件的JavaScript文件。');
    process.exit(0);
  }

  let allFindings = [];
  let scannedCount = 0;
  let errorCount = 0;

  for (const file of files) {
    process.stdout.write(`  扫描中: ${path.relative(process.cwd(), file)} ... `);

    try {
      const findings = scanner.scanFile(file);
      allFindings = allFindings.concat(findings);
      scannedCount++;

      if (findings.length > 0) {
        process.stdout.write(`发现 ${findings.length} 处可疑内容\n`);
      } else {
        process.stdout.write('✓\n');
      }
    } catch (e) {
      errorCount++;
      process.stdout.write(`错误: ${e.message}\n`);
    }
  }

  console.log(`\n✅ 扫描完成: 成功 ${scannedCount} 个文件, 错误 ${errorCount} 个文件`);

  allFindings = allFindings.sort((a, b) => {
    const riskOrder = { very_high: 0, high: 1, medium: 2, low: 3, very_low: 4 };
    return riskOrder[a.entropyLevel] - riskOrder[b.entropyLevel];
  });

  const report = reporter.generateReport(allFindings, options.format);

  console.log(report);

  if (options.output) {
    const savedPath = reporter.saveReport(report, options.output);
    console.log(`\n💾 报告已保存到: ${savedPath}`);
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
