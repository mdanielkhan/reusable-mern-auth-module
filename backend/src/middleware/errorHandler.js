const AppError = require('../utils/AppError');

function handleMongoDuplicateKey(err) {
  const field = Object.keys(err.keyValue || {})[0] || 'field';
  return new AppError(`An account with that ${field} already exists.`, 409);
}

function handleMongooseValidation(err) {
  const messages = Object.values(err.errors).map((e) => e.message);
  return new AppError(messages.join('. '), 400);
}

function handleJWTError() {
  return new AppError('Invalid token. Please log in again.', 401);
}

function handleJWTExpired() {
  return new AppError('Session expired. Please log in again.', 401);
}

// eslint-disable-next-line no-unused-vars
module.exports = function errorHandler(err, req, res, next) {
  let error = err;

  if (err.code === 11000) error = handleMongoDuplicateKey(err);
  if (err.name === 'ValidationError') error = handleMongooseValidation(err);
  if (err.name === 'JsonWebTokenError') error = handleJWTError();
  if (err.name === 'TokenExpiredError') error = handleJWTExpired();

  const statusCode = error.statusCode || 500;
  const isOperational = error.isOperational;

  if (!isOperational) {
    // Unexpected/programmer error — log full detail server-side, don't leak it.
    console.error('[UNHANDLED ERROR]', err);
  }

  res.status(statusCode).json({
    status: error.status || 'error',
    message: isOperational ? error.message : 'Something went wrong.',
    ...(process.env.NODE_ENV === 'development' && !isOperational ? { stack: err.stack } : {}),
  });
};
