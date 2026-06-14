function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;

  const charMap = {};
  const length = str.length;

  for (const char of str) {
    charMap[char] = (charMap[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char in charMap) {
    const frequency = charMap[char] / length;
    entropy -= frequency * Math.log2(frequency);
  }

  return parseFloat(entropy.toFixed(4));
}

function getEntropyLevel(entropy) {
  if (entropy >= 4.0) return { level: 'very_high', label: '极高' };
  if (entropy >= 3.5) return { level: 'high', label: '高' };
  if (entropy >= 3.0) return { level: 'medium', label: '中等' };
  if (entropy >= 2.0) return { level: 'low', label: '低' };
  return { level: 'very_low', label: '极低' };
}

function isLikelySecret(entropy, minLength = 8) {
  return entropy >= 3.0;
}

module.exports = {
  calculateEntropy,
  getEntropyLevel,
  isLikelySecret
};
