const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const jwksClient = require('jwks-rsa');

const googleClientId = process.env.GOOGLE_CLIENT_ID;
const appleClientId = process.env.APPLE_CLIENT_ID;

const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;

const appleJwks = jwksClient({
  jwksUri: 'https://appleid.apple.com/auth/keys',
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 24 * 60 * 60 * 1000,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

const getAppleSigningKey = (header, callback) => {
  appleJwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    const signingKey = key.getPublicKey();
    return callback(null, signingKey);
  });
};

const verifyGoogleIdToken = async (idToken) => {
  if (!googleClientId || !googleClient) {
    const err = new Error('Google sign-in is not configured');
    err.code = 'SOCIAL_CONFIG_MISSING';
    throw err;
  }
  const ticket = await googleClient.verifyIdToken({
    idToken,
    audience: googleClientId,
  });
  return ticket.getPayload();
};

const verifyAppleIdentityToken = (identityToken) => {
  if (!appleClientId) {
    const err = new Error('Apple sign-in is not configured');
    err.code = 'SOCIAL_CONFIG_MISSING';
    throw err;
  }
  return new Promise((resolve, reject) => {
    jwt.verify(
      identityToken,
      getAppleSigningKey,
      {
        algorithms: ['RS256'],
        audience: appleClientId,
        issuer: 'https://appleid.apple.com',
      },
      (err, decoded) => {
        if (err) return reject(err);
        return resolve(decoded);
      }
    );
  });
};

module.exports = {
  verifyGoogleIdToken,
  verifyAppleIdentityToken,
};
