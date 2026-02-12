const bcrypt = require('bcryptjs');

const minLength = () => {
  const fromEnv = Number(process.env.PASSWORD_MIN_LENGTH);
  if (!Number.isInteger(fromEnv) || fromEnv < 8) {
    return 8;
  }
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
  const safeRounds = Number.isInteger(rounds) && rounds >= 10 && rounds <= 15 ? rounds : 12;
  return bcrypt.hash(password, safeRounds);
};

const comparePassword = async (password, hash) => {
  return bcrypt.compare(password, hash);
};

module.exports = {
  validatePassword,
  hashPassword,
  comparePassword,
};
