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

  const config = {
    patterns,
    whitelist,
    ignoreDirs,
    fileExtensions,
    propertyNames,
    minEntropy: customConfig.minEntropy || 3.0,
    minLength: customConfig.minLength || 8
  };

  const validationErrors = validateConfig(customConfig);
  if (validationErrors.length > 0) {
    for (const err of validationErrors) {
      console.error(`配置校验错误: ${err}`);
    }
  }

  return config;
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
      const cloned = new RegExp(regex.source, regex.flags);
      cloned.lastIndex = 0;
      if (cloned.test(trimmed)) {
        return true;
      }
    }
  }

  return false;
}

function validateConfig(config) {
  const errors = [];

  if (config.minEntropy !== undefined && (typeof config.minEntropy !== 'number' || config.minEntropy < 0)) {
    errors.push('minEntropy 必须为非负数字');
  }

  if (config.minLength !== undefined && (typeof config.minLength !== 'number' || config.minLength < 1)) {
    errors.push('minLength 必须为正整数');
  }

  if (config.patterns && Array.isArray(config.patterns)) {
    config.patterns.forEach((p, i) => {
      if (!p.id) errors.push(`patterns[${i}] 缺少 id`);
      if (!p.pattern) errors.push(`patterns[${i}] 缺少 pattern`);
    });
  }

  if (config.whitelist) {
    if (config.whitelist.exact && !Array.isArray(config.whitelist.exact)) {
      errors.push('whitelist.exact 必须为数组');
    }
    if (config.whitelist.regex && !Array.isArray(config.whitelist.regex)) {
      errors.push('whitelist.regex 必须为数组');
    }
  }

  return errors;
}

module.exports = {
  loadConfig,
  isWhitelisted,
  validateConfig
};
