const fs = require('fs');
const path = require('path');
const {
  defaultPatterns,
  sensitivePropertyNames,
  defaultWhitelist,
  defaultFileExtensions,
  defaultIgnoreDirs
} = require('./rules');

function loadConfig(customConfigPath = null) {
  let customConfig = {};

  if (customConfigPath) {
    const absolutePath = path.resolve(customConfigPath);
    if (fs.existsSync(absolutePath)) {
      try {
        const raw = fs.readFileSync(absolutePath, 'utf8');
        customConfig = JSON.parse(raw);
      } catch (e) {
        console.error(`警告: 无法加载配置文件 ${customConfigPath}: ${e.message}`);
      }
    } else {
      console.error(`警告: 配置文件不存在: ${customConfigPath}`);
    }
  }

  const patterns = mergePatterns(defaultPatterns, customConfig.patterns || []);
  const whitelist = mergeWhitelist(defaultWhitelist, customConfig.whitelist || {});
  const ignoreDirs = mergeArray(defaultIgnoreDirs, customConfig.ignoreDirs || []);
  const fileExtensions = mergeArray(defaultFileExtensions, customConfig.fileExtensions || []);
  const propertyNames = mergeArray(sensitivePropertyNames, customConfig.propertyNames || []);

  return {
    patterns,
    whitelist,
    ignoreDirs,
    fileExtensions,
    propertyNames,
    minEntropy: customConfig.minEntropy || 3.0,
    minLength: customConfig.minLength || 8
  };
}

function mergePatterns(defaults, custom) {
  const merged = [...defaults];
  const existingIds = new Set(defaults.map(p => p.id));

  for (const customPattern of custom) {
    if (!customPattern.id || !customPattern.pattern) {
      console.error('警告: 跳过无效的自定义规则（缺少id或pattern）');
      continue;
    }

    let pattern;
    if (typeof customPattern.pattern === 'string') {
      try {
        const match = customPattern.pattern.match(/^\/(.*)\/([gimsuy]*)$/);
        if (match) {
          pattern = new RegExp(match[1], match[2]);
        } else {
          pattern = new RegExp(customPattern.pattern);
        }
      } catch (e) {
        console.error(`警告: 无效的正则表达式 ${customPattern.pattern}: ${e.message}`);
        continue;
      }
    } else if (customPattern.pattern instanceof RegExp) {
      pattern = customPattern.pattern;
    } else {
      continue;
    }

    const mergedPattern = {
      id: customPattern.id,
      name: customPattern.name || customPattern.id,
      pattern,
      description: customPattern.description || '',
      minEntropy: customPattern.minEntropy,
      minLength: customPattern.minLength
    };

    if (existingIds.has(customPattern.id)) {
      const index = merged.findIndex(p => p.id === customPattern.id);
      merged[index] = mergedPattern;
    } else {
      merged.push(mergedPattern);
    }
  }

  return merged;
}

function mergeWhitelist(defaults, custom) {
  const result = {
    exact: [],
    regex: []
  };

  result.exact = [...defaults.exact];
  if (custom.exact && Array.isArray(custom.exact)) {
    for (const item of custom.exact) {
      if (!result.exact.includes(item)) {
        result.exact.push(item);
      }
    }
  }

  result.regex = [...defaults.regex];
  if (custom.regex && Array.isArray(custom.regex)) {
    for (const item of custom.regex) {
      let regex;
      if (item instanceof RegExp) {
        regex = item;
      } else if (typeof item === 'string') {
        try {
          const match = item.match(/^\/(.*)\/([gimsuy]*)$/);
          if (match) {
            regex = new RegExp(match[1], match[2]);
          } else {
            regex = new RegExp(item);
          }
        } catch (e) {
          console.error(`警告: 无效的白名单正则表达式 ${item}: ${e.message}`);
          continue;
        }
      } else {
        continue;
      }
      result.regex.push(regex);
    }
  }

  if (Array.isArray(custom)) {
    for (const item of custom) {
      if (typeof item === 'string' && !result.exact.includes(item)) {
        result.exact.push(item);
      }
    }
  }

  return result;
}

function mergeArray(defaults, custom) {
  const merged = new Set(defaults);
  for (const item of custom) {
    merged.add(item);
  }
  return Array.from(merged);
}

function isWhitelisted(value, whitelist) {
  if (!whitelist) return false;

  const trimmed = value.trim();

  if (whitelist.exact && whitelist.exact.length > 0) {
    for (const item of whitelist.exact) {
      if (trimmed === item || trimmed.toLowerCase() === item.toLowerCase()) {
        return true;
      }
    }
  }

  if (whitelist.regex && whitelist.regex.length > 0) {
    for (const regex of whitelist.regex) {
      if (regex.test(trimmed)) {
        return true;
      }
    }
  }

  return false;
}

module.exports = {
  loadConfig,
  isWhitelisted
};
