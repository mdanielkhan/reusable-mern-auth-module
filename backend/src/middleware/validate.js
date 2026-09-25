const { validationResult } = require('express-validator');
const AppError = require('../utils/AppError');

// Run after an array of express-validator checks in a route definition.
module.exports = function validate(req, res, next) {
  const errors = validationResult(req);
  if (errors.isEmpty()) return next();

  const message = errors
    .array()
    .map((e) => e.msg)
    .join('. ');
  next(new AppError(message, 400));
};
