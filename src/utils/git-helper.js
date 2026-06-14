const { execSync } = require('child_process');
const path = require('path');

function getGitDiffFiles(options = {}) {
  const {
    cwd = process.cwd(),
    mode = 'working',
    baseRef = null,
    headRef = null
  } = options;

  try {
    let diffCommand = 'git diff --name-only --diff-filter=ACM';

    switch (mode) {
      case 'staged':
        diffCommand += ' --cached';
        break;

      case 'unstaged':
        break;

      case 'commits':
        if (baseRef && headRef) {
          diffCommand += ` ${baseRef}...${headRef}`;
        } else if (baseRef) {
          diffCommand += ` ${baseRef}`;
        } else {
          diffCommand += ' HEAD';
        }
        break;

      case 'working':
      default:
        diffCommand += ' HEAD';
        break;
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

    const modeLabels = {
      'staged': '暂存区',
      'unstaged': '未暂存',
      'commits': `${baseRef || 'HEAD'}...${headRef || 'HEAD'}`,
      'working': '工作区 vs HEAD'
    };

    return {
      success: true,
      files,
      mode,
      label: modeLabels[mode] || mode
    };
  } catch (e) {
    return {
      success: false,
      error: e.message,
      files: [],
      mode,
      label: mode
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
