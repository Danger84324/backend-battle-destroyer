const escapeRegex = (str) => {
  if (!str) return '';
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
};

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(String(email).toLowerCase());
};

const validateUsername = (username) => {
  const usernameRegex = /^[a-zA-Z0-9_-]{3,30}$/;
  return usernameRegex.test(String(username));
};

const validatePassword = (password) => {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(String(password));
};

const getPasswordFeedback = (password) => {
  const feedback = [];
  if (!password || password.length < 8) feedback.push('At least 8 characters');
  if (!/[a-z]/.test(password)) feedback.push('At least 1 lowercase letter');
  if (!/[A-Z]/.test(password)) feedback.push('At least 1 uppercase letter');
  if (!/\d/.test(password)) feedback.push('At least 1 number');
  if (!/[@$!%*?&]/.test(password)) feedback.push('At least 1 special character (@$!%*?&)');
  return feedback;
};

const validateNumber = (value, options = {}) => {
  const { min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER, integer = false } = options;
  const num = Number(value);
  if (isNaN(num)) return false;
  if (integer && !Number.isInteger(num)) return false;
  if (num < min || num > max) return false;
  return true;
};

const validateObjectId = (id) => {
  return /^[0-9a-f]{24}$/i.test(String(id));
};

const sanitizeString = (str, maxLength = 255) => {
  if (!str) return '';
  return String(str).trim().substring(0, maxLength).replace(/[<>]/g, '');
};

const sanitizeSearch = (query, maxLength = 50) => {
  if (!query) return null;
  const sanitized = sanitizeString(query, maxLength);
  if (sanitized.length < 3) return null;
  return escapeRegex(sanitized);
};

const validatePage = (page) => {
  const pageNum = parseInt(page, 10);
  return !isNaN(pageNum) && pageNum >= 1 ? pageNum : 1;
};

const validateLimit = (limit, maxLimit = 100) => {
  const limitNum = parseInt(limit, 10);
  if (isNaN(limitNum) || limitNum < 1) return 20;
  if (limitNum > maxLimit) return maxLimit;
  return limitNum;
};

const validateCredits = (amount, maxCredits = 100000) => {
  return validateNumber(amount, { min: 1, max: maxCredits, integer: true });
};

const validateUserInput = (body, allowedFields) => {
  const sanitized = {};
  for (const field of allowedFields) {
    if (body[field] !== undefined) {
      if (typeof body[field] === 'string') {
        sanitized[field] = sanitizeString(body[field]);
      } else {
        sanitized[field] = body[field];
      }
    }
  }
  return sanitized;
};

const validatePaginationQuery = (query) => {
  return {
    page: validatePage(query.page),
    limit: validateLimit(query.limit),
    search: query.search ? sanitizeSearch(query.search) : null
  };
};

module.exports = {
  escapeRegex,
  validateEmail,
  validateUsername,
  validatePassword,
  getPasswordFeedback,
  validateNumber,
  validateObjectId,
  sanitizeString,
  sanitizeSearch,
  validatePage,
  validateLimit,
  validateCredits,
  validateUserInput,
  validatePaginationQuery
};