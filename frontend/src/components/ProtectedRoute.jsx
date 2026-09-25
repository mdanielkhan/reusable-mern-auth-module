import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

/**
 * Usage:
 *   <Route element={<ProtectedRoute />}>
 *     <Route path="/dashboard" element={<Dashboard />} />
 *   </Route>
 *
 *   <Route element={<ProtectedRoute allowedRoles={['admin']} />}>
 *     <Route path="/admin" element={<AdminPanel />} />
 *   </Route>
 *
 * Role checks here are a UX convenience only — they hide/redirect nav in the
 * browser. They are NOT a security boundary. The backend `authorize()`
 * middleware is the actual enforcement; anyone can bypass this component
 * with devtools. Don't let "the frontend checks the role" be the whole
 * story in your internship writeup.
 */
export default function ProtectedRoute({ allowedRoles }) {
  const { user, isAuthenticated, checkingAuth } = useAuth();
  const location = useLocation();

  if (checkingAuth) return null; // or a spinner

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/unauthorized" replace />;
  }

  return <Outlet />;
}
