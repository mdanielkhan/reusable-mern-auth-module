const AppError = require('../utils/AppError');

// Usage: router.delete('/users/:id', authenticate, authorize('admin'), handler)
// Usage: router.get('/reports', authenticate, authorize('admin', 'manager'), handler)
//
// This assumes a flat role hierarchy where roles are independent labels,
// not tiers (i.e. 'admin' does NOT automatically pass an authorize('manager')
// check unless you list it explicitly). If your app actually wants
// admin > manager > user inheritance, that's a different function — say so
// and I'll change this, because bolting it on silently would hide a real
// permissions bug.
function authorize(...allowedRoles) {
  return function checkRole(req, res, next) {
    if (!req.user) {
      return next(new AppError('Not authenticated.', 401));
    }
    if (!allowedRoles.includes(req.user.role)) {
      return next(new AppError('You do not have permission to perform this action.', 403));
    }
    next();
  };
}

module.exports = authorize;
