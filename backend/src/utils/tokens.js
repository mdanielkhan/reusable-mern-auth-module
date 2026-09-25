const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const RefreshToken = require('../models/RefreshToken');

const signAccessToken = (user) => jwt.sign(
  { sub: user._id.toString(), role: user.role },
  process.env.JWT_ACCESS_SECRET,
  { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
);

const signRefreshToken = (user) => jwt.sign(
  { sub: user._id.toString(), jti: crypto.randomUUID() },
  process.env.JWT_REFRESH_SECRET,
  { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
);

const hashToken = (raw) => crypto.createHash('sha256').update(raw).digest('hex');

const msFromExpiry = (expiresIn) => {
  // supports '15m', '7d', '3600' (seconds) style strings from jsonwebtoken
  const match = /^(\d+)([smhd])?$/.exec(expiresIn);
  if (!match) return 15 * 60 * 1000;
  const value = Number(match[1]);
  const unit = match[2] || 's';
  const unitMs = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
  return value * unitMs[unit];
};

// Issues a new access+refresh pair, persists the refresh token's hash so it
// can be revoked later, and returns both raw tokens for the controller to
// set as cookies.
const issueTokenPair = async (user, { userAgent, ip } = {}) => {
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);

  await RefreshToken.create({
    user: user._id,
    tokenHash: hashToken(refreshToken),
    expiresAt: new Date(Date.now() + msFromExpiry(process.env.JWT_REFRESH_EXPIRES_IN || '7d')),
    userAgent,
    ip,
  });

  return { accessToken, refreshToken };
};

// Rotates a refresh token: verifies it, checks it's still active in the DB
// (not revoked/reused), revokes it, and issues a fresh pair. Rotation means
// a stolen-and-reused refresh token gets detected: if someone replays an
// already-rotated token, we revoke the whole chain.
const rotateRefreshToken = async (rawToken, { userAgent, ip } = {}) => {
  let payload;
  try {
    payload = jwt.verify(rawToken, process.env.JWT_REFRESH_SECRET);
  } catch (err) {
    return { error: 'invalid' };
  }

  const tokenHash = hashToken(rawToken);
  const stored = await RefreshToken.findOne({ tokenHash });

  if (!stored) return { error: 'invalid' };

  if (!stored.isActive()) {
    // Reuse of a revoked/expired token — possible theft. Revoke every
    // active token for this user as a precaution.
    await RefreshToken.updateMany(
      { user: stored.user, revokedAt: null },
      { $set: { revokedAt: new Date() } }
    );
    return { error: 'reused' };
  }

  stored.revokedAt = new Date();

  const User = require('../models/User');
  const user = await User.findById(payload.sub);
  if (!user || !user.isActive) {
    await stored.save();
    return { error: 'invalid' };
  }

  const { accessToken, refreshToken } = await issueTokenPair(user, { userAgent, ip });
  stored.replacedByTokenHash = hashToken(refreshToken);
  await stored.save();

  return { accessToken, refreshToken, user };
};

const revokeRefreshToken = async (rawToken) => {
  if (!rawToken) return;
  const tokenHash = hashToken(rawToken);
  await RefreshToken.updateOne({ tokenHash }, { $set: { revokedAt: new Date() } });
};

const revokeAllForUser = async (userId) => {
  await RefreshToken.updateMany(
    { user: userId, revokedAt: null },
    { $set: { revokedAt: new Date() } }
  );
};

const cookieBaseOptions = () => ({
  httpOnly: true,
  secure: process.env.COOKIE_SECURE === 'true',
  sameSite: process.env.COOKIE_SECURE === 'true' ? 'none' : 'lax',
  domain: process.env.COOKIE_DOMAIN || undefined,
});

const setAuthCookies = (res, { accessToken, refreshToken }) => {
  res.cookie('accessToken', accessToken, {
    ...cookieBaseOptions(),
    maxAge: msFromExpiry(process.env.JWT_ACCESS_EXPIRES_IN || '15m'),
  });
  res.cookie('refreshToken', refreshToken, {
    ...cookieBaseOptions(),
    path: '/api/auth/refresh', // scope refresh cookie to only the endpoint that needs it
    maxAge: msFromExpiry(process.env.JWT_REFRESH_EXPIRES_IN || '7d'),
  });
};

const clearAuthCookies = (res) => {
  res.clearCookie('accessToken', cookieBaseOptions());
  res.clearCookie('refreshToken', { ...cookieBaseOptions(), path: '/api/auth/refresh' });
};

module.exports = {
  signAccessToken,
  signRefreshToken,
  hashToken,
  issueTokenPair,
  rotateRefreshToken,
  revokeRefreshToken,
  revokeAllForUser,
  setAuthCookies,
  clearAuthCookies,
};