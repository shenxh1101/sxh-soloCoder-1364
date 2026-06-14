const defaultPatterns = [
  {
    id: 'openai-api-key',
    name: 'OpenAI API Key',
    pattern: /sk-[A-Za-z0-9]{20,}/,
    description: 'OpenAI API密钥，以sk-开头'
  },
  {
    id: 'openai-org-id',
    name: 'OpenAI Organization ID',
    pattern: /org-[A-Za-z0-9]{20,}/,
    description: 'OpenAI组织ID'
  },
  {
    id: 'openai-project-id',
    name: 'OpenAI Project ID',
    pattern: /proj-[A-Za-z0-9]{20,}/,
    description: 'OpenAI项目ID'
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    pattern: /AKIA[0-9A-Z]{16}/,
    description: 'AWS访问密钥ID'
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key',
    pattern: /^[0-9a-zA-Z/+]{40}$/,
    description: 'AWS秘密访问密钥',
    minEntropy: 4.2,
    minLength: 40
  },
  {
    id: 'stripe-api-key',
    name: 'Stripe API Key',
    pattern: /sk_(test|live)_[A-Za-z0-9]{24,}/,
    description: 'Stripe API密钥'
  },
  {
    id: 'github-token',
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[A-Za-z0-9]{36}/,
    description: 'GitHub个人访问令牌'
  },
  {
    id: 'github-oauth',
    name: 'GitHub OAuth Token',
    pattern: /gho_[A-Za-z0-9]{36}/,
    description: 'GitHub OAuth令牌'
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/,
    description: 'Slack令牌'
  },
  {
    id: 'json-web-token',
    name: 'JSON Web Token (JWT)',
    pattern: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
    description: 'JSON Web令牌'
  },
  {
    id: 'generic-api-key',
    name: 'Generic API Key',
    pattern: /api[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i,
    description: '通用API密钥赋值模式'
  },
  {
    id: 'generic-secret',
    name: 'Generic Secret',
    pattern: /['"][A-Za-z0-9_\-]{32,}['"]/,
    description: '长随机字符串（可能是密钥）',
    minEntropy: 3.5,
    minLength: 32
  },
  {
    id: 'google-api-key',
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/,
    description: 'Google API密钥'
  },
  {
    id: 'firebase-key',
    name: 'Firebase API Key',
    pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}/,
    description: 'Firebase Cloud Messaging密钥'
  }
];

const sensitivePropertyNames = [
  'apiKey',
  'api_key',
  'apikey',
  'API_KEY',
  'secret',
  'SECRET',
  'secretKey',
  'secret_key',
  'privateKey',
  'private_key',
  'password',
  'PASSWORD',
  'passwd',
  'pwd',
  'token',
  'TOKEN',
  'accessToken',
  'access_token',
  'ACCESS_TOKEN',
  'refreshToken',
  'refresh_token',
  'authToken',
  'auth_token',
  'authentication',
  'credentials',
  'clientSecret',
  'client_secret',
  'signingSecret',
  'signing_secret',
  'webhookSecret',
  'webhook_secret',
  'encryptionKey',
  'encryption_key',
  'masterKey',
  'master_key'
];

const defaultWhitelist = [
  'sk-test',
  'sk-live-test',
  'sk-xxxxxxxxxxxxxxxxxxxx',
  'sk-********************',
  'API_KEY',
  'YOUR_API_KEY',
  'your-api-key',
  'your_secret_key',
  'xxxxxxxxxxxxxxxxxxxx',
  '********************************',
  '00000000000000000000000000000000',
  '12345678901234567890123456789012',
  'abcdefghijklmnopqrstuvwxyz123456',
  'test-api-key',
  'test_secret_key',
  'fake-key',
  'placeholder',
  'dummy',
  'example',
  'change-me',
  'changeme',
  'replace-me',
  'replaceme',
  'TODO',
  'FIXME'
];

const defaultFileExtensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];

const defaultIgnoreDirs = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  'test',
  'tests',
  '__tests__',
  'spec',
  'specs',
  '__mocks__',
  '__fixtures__',
  'fixtures',
  'mock',
  'mocks',
  '.next',
  '.nuxt',
  '.cache',
  '.idea',
  '.vscode'
];

module.exports = {
  defaultPatterns,
  sensitivePropertyNames,
  defaultWhitelist,
  defaultFileExtensions,
  defaultIgnoreDirs
};
