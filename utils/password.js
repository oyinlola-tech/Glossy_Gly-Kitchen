const bcrypt = require('bcryptjs');

const minLength = () => {
  const fromEnv = Number(process.env.PASSWORD_MIN_LENGTH);
  return Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : 8;
};

const validatePassword = (password) => {
  if (typeof password !== 'string') return 'Password must be a string';
  if (password.length < minLength()) {
    return `Password must be at least ${minLength()} characters`;
  }
  return null;
};

const hashPassword = async (password) => {
  const rounds = Number(process.env.BCRYPT_ROUNDS) || 12;
  return bcrypt.hash(password, rounds);
};

const comparePassword = async (password, hash) => {
  return bcrypt.compare(password, hash);
};

module.exports = {
  validatePassword,
  hashPassword,
  comparePassword,
};
