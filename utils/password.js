const bcrypt = require('bcryptjs');

const minLength = () => {
  const fromEnv = Number(process.env.PASSWORD_MIN_LENGTH);
  return fromEnv;
};

const validatePassword = (password) => {
  if (typeof password !== 'string') return 'Password must be a string';
  if (password.length < minLength()) {
    return `Password must be at least ${minLength()} characters`;
  }
  return null;
};

const hashPassword = async (password) => {
  const rounds = Number(process.env.BCRYPT_ROUNDS);
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
