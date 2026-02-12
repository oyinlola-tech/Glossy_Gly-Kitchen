const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phoneRegex = /^\+?[0-9]{7,15}$/;

const isUuid = (value) => typeof value === 'string' && uuidRegex.test(value);
const isValidEmail = (value) => typeof value === 'string' && emailRegex.test(value);
const isValidPhone = (value) => typeof value === 'string' && phoneRegex.test(value);

const toNumber = (value) => {
  if (value === null || value === undefined || value === '') return null;
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
};

const toInt = (value) => {
  const num = toNumber(value);
  return Number.isInteger(num) ? num : null;
};

module.exports = {
  isUuid,
  isValidEmail,
  isValidPhone,
  toNumber,
  toInt,
};
