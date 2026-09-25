const jwt = require('jsonwebtoken');
const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');
const User = require('../models/User');


const authenticate = catchAsync(async (req, res, next) => {
  let token = req.cookies?.accessToken;
  if (!token && req.headers.authorization?.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(new AppError('Not authenticated. Please log in.', 401));
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
  } catch (err) {
    const message = err.name === 'TokenExpiredError' ? 'Session expired.' : 'Invalid token.';
    return next(new AppError(message, 401));
  }

  const user = await User.findById(payload.sub);
  if (!user || !user.isActive) {
    return next(new AppError('User no longer exists or is disabled.', 401));
  }

  req.user = user; 
  next();
});

module.exports = authenticate;
