const { body } = require('express-validator');
const { ROLES } = require('../models/User');

// Password policy: min 8 chars, at least one letter and one number. Adjust
// to your internship's actual spec — this is a reasonable floor, not a
// standard everyone agrees on.
const strongPassword = body('password')
  .isLength({ min: 8 })
  .withMessage('Password must be at least 8 characters.')
  .matches(/[A-Za-z]/)
  .withMessage('Password must contain a letter.')
  .matches(/[0-9]/)
  .withMessage('Password must contain a number.');

const registerValidators = [
  body('name').trim().notEmpty().withMessage('Name is required.').isLength({ max: 100 }),
  body('email').isEmail().withMessage('A valid email is required.').normalizeEmail(),
  strongPassword,
  // Only allow role to be set here if your app intentionally lets self-registration
  // pick a role (rare — usually 'user' is forced and admins promote people later).
  body('role').optional().isIn(ROLES).withMessage(`Role must be one of: ${ROLES.join(', ')}`),
];

const loginValidators = [
  body('email').isEmail().withMessage('A valid email is required.').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required.'),
];

const forgotPasswordValidators = [
  body('email').isEmail().withMessage('A valid email is required.').normalizeEmail(),
];

const resetPasswordValidators = [
  body('token').notEmpty().withMessage('Reset token is required.'),
  strongPassword,
];

const googleLoginValidators = [
  body('idToken').notEmpty().withMessage('Google ID token is required.'),
];

module.exports = {
  registerValidators,
  loginValidators,
  forgotPasswordValidators,
  resetPasswordValidators,
  googleLoginValidators,
};
