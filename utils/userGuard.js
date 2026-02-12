const requireVerifiedUser = (req, res, next) => {
  if (!req.user || !req.user.id) {
    return res.status(401).json({ error: 'Authorization required' });
  }
  return next();
};

module.exports = {
  requireVerifiedUser,
};
