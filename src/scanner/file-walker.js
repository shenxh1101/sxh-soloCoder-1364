const fs = require('fs');
const path = require('path');
const { globSync } = require('glob');

class FileWalker {
  constructor(config) {
    this.config = config;
  }

  findFiles(targetPaths) {
    const allFiles = new Set();

    for (const targetPath of targetPaths) {
      const absolutePath = path.resolve(targetPath);

      if (!fs.existsSync(absolutePath)) {
        console.error(`警告: 路径不存在: ${targetPath}`);
        continue;
      }

      const stats = fs.statSync(absolutePath);

      if (stats.isFile()) {
        if (this.isValidFile(absolutePath)) {
          allFiles.add(absolutePath);
        }
      } else if (stats.isDirectory()) {
        const files = this.walkDirectory(absolutePath);
        files.forEach(f => allFiles.add(f));
      }
    }

    return Array.from(allFiles).sort();
  }

  walkDirectory(dirPath) {
    const files = [];
    const ignoreSet = new Set(this.config.ignoreDirs);

    const pattern = `**/*.{${this.config.fileExtensions.map(ext => ext.replace('.', '')).join(',')}}`;

    const globOptions = {
      cwd: dirPath,
      absolute: true,
      nodir: true,
      ignore: this.config.ignoreDirs.map(d => `**/${d}/**`)
    };

    try {
      const matches = globSync(pattern, globOptions);
      for (const match of matches) {
        if (this.isValidFile(match)) {
          files.push(match);
        }
      }
    } catch (e) {
      console.error(`警告: 遍历目录 ${dirPath} 时出错: ${e.message}`);
    }

    return files;
  }

  isValidFile(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return this.config.fileExtensions.includes(ext);
  }
}

module.exports = FileWalker;
