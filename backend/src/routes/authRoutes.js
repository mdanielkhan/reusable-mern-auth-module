const express = require('express');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');

const User = require('../models/User');
const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');
const {
  issueTokenPair,
  rotateRefreshToken,
  revokeRefreshToken,
  revokeAllForUser,
  setAuthCookies,
  clearAuthCookies,
} = require('../utils/tokens');
const { sendEmail, verificationEmailHtml, resetPasswordEmailHtml } = require('../utils/sendEmail');

const authenticate = require('../middleware/authenticate');
const authorize = require('../middleware/authorize');
const validate = require('../middleware/validate');
const {
  registerValidators,
  loginValidators,
  forgotPasswordValidators,
  resetPasswordValidators,
  googleLoginValidators,
} = require('../validators/authValidators');

const router = express.Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

function reqMeta(req) {
  return { userAgent: req.headers['user-agent'], ip: req.ip };
}

// Brute-force protection on the endpoints attackers actually hit.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'fail', message: 'Too many attempts. Try again later.' },
});

// ---------------------------------------------------------------------------
// POST /api/auth/register
// ---------------------------------------------------------------------------
router.post(
  '/register',
  authLimiter,
  registerValidators,
  validate,
  catchAsync(async (req, res, next) => {
    const { name, email, password } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      // Don't reveal whether it was created via Google vs local — just a
      // generic conflict message either way.
      return next(new AppError('An account with that email already exists.', 409));
    }

    const user = await User.create({ name, email, password, authProviders: ['local'] });

    const rawToken = user.createEmailVerificationToken();
    await user.save({ validateBeforeSave: false });

    const link = `${process.env.CLIENT_URL}/verify-email?token=${rawToken}`;
    try {
      await sendEmail({
        to: user.email,
        subject: 'Verify your email',
        html: verificationEmailHtml(link),
      });
    } catch (err) {
      // Don't fail registration just because the email provider hiccuped —
      // log it and let the user request a resend later.
      console.error('[email] verification send failed:', err.message);
    }

    res.status(201).json({
      status: 'success',
      message: 'Registered. Check your email to verify your account.',
      data: { user: user.toSafeJSON() },
    });
  })
);

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------
router.post(
  '/login',
  authLimiter,
  loginValidators,
  validate,
  catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');
    // Same message for "no user" and "wrong password" — don't let the error
    // message be used to enumerate registered emails.
    if (!user || !(await user.comparePassword(password))) {
      return next(new AppError('Incorrect email or password.', 401));
    }

    if (!user.isActive) {
      return next(new AppError('This account has been disabled.', 403));
    }

    // Does NOT block login for unverified emails — just flags it in the
    // response. Add `if (!user.isEmailVerified) return next(new AppError(...))`
    // here if your spec requires verified-only login.
    const { accessToken, refreshToken } = await issueTokenPair(user, reqMeta(req));
    setAuthCookies(res, { accessToken, refreshToken });

    res.status(200).json({
      status: 'success',
      data: { user: user.toSafeJSON() },
    });
  })
);

// ---------------------------------------------------------------------------
// POST /api/auth/google
// Frontend gets an ID token from Google Identity Services and sends it here.
// ---------------------------------------------------------------------------
router.post(
  '/google',
  authLimiter,
  googleLoginValidators,
  validate,
  catchAsync(async (req, res, next) => {
    const { idToken } = req.body;

    let payload;
    try {
      const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      payload = ticket.getPayload();
    } catch (err) {
      return next(new AppError('Invalid Google token.', 401));
    }

    if (!payload.email_verified) {
      return next(new AppError('Google account email is not verified.', 401));
    }

    let user = await User.findOne({ email: payload.email });

    if (user) {
      // Link Google to an existing local account rather than creating a
      // second account with the same email.
      if (!user.googleId) {
        user.googleId = payload.sub;
        if (!user.authProviders.includes('google')) user.authProviders.push('google');
        user.isEmailVerified = true;
        await user.save({ validateBeforeSave: false });
      }
    } else {
      user = await User.create({
        name: payload.name || payload.email.split('@')[0],
        email: payload.email,
        googleId: payload.sub,
        authProviders: ['google'],
        isEmailVerified: true,
      });
    }

    if (!user.isActive) {
      return next(new AppError('This account has been disabled.', 403));
    }

    const { accessToken, refreshToken } = await issueTokenPair(user, reqMeta(req));
    setAuthCookies(res, { accessToken, refreshToken });

    res.status(200).json({ status: 'success', data: { user: user.toSafeJSON() } });
  })
);

// ---------------------------------------------------------------------------
// POST /api/auth/refresh
// ---------------------------------------------------------------------------
router.post(
  '/refresh',
  catchAsync(async (req, res, next) => {
    const rawRefreshToken = req.cookies?.refreshToken;
    if (!rawRefreshToken) return next(new AppError('No refresh token provided.', 401));

    const result = await rotateRefreshToken(rawRefreshToken, reqMeta(req));

    if (result.error) {
      clearAuthCookies(res);
      const msg =
        result.error === 'reused'
          ? 'Refresh token reuse detected. All sessions revoked for safety — please log in again.'
          : 'Invalid or expired session. Please log in again.';
      return next(new AppError(msg, 401));
    }

    setAuthCookies(res, { accessToken: result.accessToken, refreshToken: result.refreshToken });
    res.status(200).json({ status: 'success', data: { user: result.user.toSafeJSON() } });
  })
);

// ---------------------------------------------------------------------------
// POST /api/auth/logout
// ---------------------------------------------------------------------------
router.post(
  '/logout',
  catchAsync(async (req, res) => {
    await revokeRefreshToken(req.cookies?.refreshToken);
    clearAuthCookies(res);
    res.status(200).json({ status: 'success', message: 'Logged out.' });
  })
);

// ---------------------------------------------------------------------------
// POST /api/auth/logout-all  (revoke every session for this user)
// ---------------------------------------------------------------------------
router.post(
  '/logout-all',
  authenticate,
  catchAsync(async (req, res) => {
    await revokeAllForUser(req.user._id);
    clearAuthCookies(res);
    res.status(200).json({ status: 'success', message: 'Logged out of all devices.' });
  })
);

// ---------------------------------------------------------------------------
// GET /api/auth/me
// ---------------------------------------------------------------------------
router.get(
  '/me',
  authenticate,
  catchAsync(async (req, res) => {
    res.status(200).json({ status: 'success', data: { user: req.user.toSafeJSON() } });
  })
);

// ---------------------------------------------------------------------------
// GET /api/auth/verify-email?token=...
// ---------------------------------------------------------------------------
router.get(
  '/verify-email',
  catchAsync(async (req, res, next) => {
    const { token } = req.query;
    if (!token) return next(new AppError('Verification token is required.', 400));

    const tokenHash = User.hashToken(token);
    const user = await User.findOne({
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpires: { $gt: new Date() },
    }).select('+emailVerificationTokenHash +emailVerificationExpires');

    if (!user) return next(new AppError('Verification link is invalid or has expired.', 400));

    user.isEmailVerified = true;
    user.emailVerificationTokenHash = undefined;
    user.emailVerificationExpires = undefined;
    await user.save({ validateBeforeSave: false });

    res.status(200).json({ status: 'success', message: 'Email verified.' });
  })
);

// ---------------------------------------------------------------------------
// POST /api/auth/resend-verification  (requires auth)
// ---------------------------------------------------------------------------
router.post(
  '/resend-verification',
  authenticate,
  catchAsync(async (req, res, next) => {
    const user = req.user;
    if (user.isEmailVerified) {
      return next(new AppError('Email is already verified.', 400));
    }
    const rawToken = user.createEmailVerificationToken();
    await user.save({ validateBeforeSave: false });

    const link = `${process.env.CLIENT_URL}/verify-email?token=${rawToken}`;
    await sendEmail({
      to: user.email,
      subject: 'Verify your email',
      html: verificationEmailHtml(link),
    });

    res.status(200).json({ status: 'success', message: 'Verification email sent.' });
  })
);

// ---------------------------------------------------------------------------
// POST /api/auth/forgot-password
// ---------------------------------------------------------------------------
router.post(
  '/forgot-password',
  authLimiter,
  forgotPasswordValidators,
  validate,
  catchAsync(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    // Always return 200 with the same message whether or not the account
    // exists — otherwise this endpoint becomes an email-enumeration oracle.
    const genericResponse = {
      status: 'success',
      message: 'If that email is registered, a reset link has been sent.',
    };

    if (!user || !user.password) {
      // No account, or a Google-only account with no password to reset.
      return res.status(200).json(genericResponse);
    }

    const rawToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    const link = `${process.env.CLIENT_URL}/reset-password?token=${rawToken}`;
    try {
      await sendEmail({
        to: user.email,
        subject: 'Reset your password',
        html: resetPasswordEmailHtml(link),
      });
    } catch (err) {
      // Roll back the token so a failed send doesn't leave a dangling,
      // unusable reset request.
      user.passwordResetTokenHash = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
      console.error('[email] reset send failed:', err.message);
    }

    res.status(200).json(genericResponse);
  })
);

// ---------------------------------------------------------------------------
// POST /api/auth/reset-password
// ---------------------------------------------------------------------------
router.post(
  '/reset-password',
  authLimiter,
  resetPasswordValidators,
  validate,
  catchAsync(async (req, res, next) => {
    const { token, password } = req.body;
    const tokenHash = User.hashToken(token);

    const user = await User.findOne({
      passwordResetTokenHash: tokenHash,
      passwordResetExpires: { $gt: new Date() },
    }).select('+passwordResetTokenHash +passwordResetExpires');

    if (!user) return next(new AppError('Reset link is invalid or has expired.', 400));

    user.password = password;
    user.passwordResetTokenHash = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Resetting the password invalidates every existing session — otherwise
    // an attacker who stole a refresh token keeps access after the "fix".
    await revokeAllForUser(user._id);
    clearAuthCookies(res);

    res.status(200).json({ status: 'success', message: 'Password reset. Please log in again.' });
  })
);

// ---------------------------------------------------------------------------
// Example routes showing the reusable middleware pattern — delete once copied.
// ---------------------------------------------------------------------------
router.get('/admin-only-example', authenticate, authorize('admin'), (req, res) => {
  res.json({ status: 'success', message: `Hello admin ${req.user.email}` });
});
router.get('/staff-only-example', authenticate, authorize('admin', 'manager'), (req, res) => {
  res.json({ status: 'success', message: `Hello ${req.user.role} ${req.user.email}` });
});

module.exports = router;
