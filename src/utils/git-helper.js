const { execSync } = require('child_process');
const path = require('path');

function getGitDiffFiles(options = {}) {
  const {
    baseBranch = 'HEAD',
    compareBranch = null,
    cwd = process.cwd(),
    staged = false,
    cached = false,
    includeDeleted = false
  } = options;

  try {
    let diffCommand = 'git diff --name-only';

    if (staged || cached) {
      diffCommand += ' --cached';
    }

    if (compareBranch) {
      diffCommand += ` ${baseBranch}...${compareBranch}`;
    } else if (!staged && !cached) {
      diffCommand += ` ${baseBranch}`;
    }

    diffCommand += ' --diff-filter=ACM';

    if (includeDeleted) {
      diffCommand += 'D';
    }

    const result = execSync(diffCommand, {
      cwd,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });

    const files = result.trim()
      .split('\n')
      .filter(line => line.trim() !== '')
      .map(file => path.resolve(cwd, file.trim()));

    return {
      success: true,
      files,
      base: baseBranch,
      compare: compareBranch || (staged ? 'staged' : 'working')
    };
  } catch (e) {
    return {
      success: false,
      error: e.message,
      files: []
    };
  }
}

function isGitRepository(cwd = process.cwd()) {
  try {
    execSync('git rev-parse --is-inside-work-tree', {
      cwd,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    return true;
  } catch (e) {
    return false;
  }
}

function getGitRoot(cwd = process.cwd()) {
  try {
    const result = execSync('git rev-parse --show-toplevel', {
      cwd,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    return result.trim();
  } catch (e) {
    return null;
  }
}

module.exports = {
  getGitDiffFiles,
  isGitRepository,
  getGitRoot
};
