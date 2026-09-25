import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';


export default function ProtectedRoute({ allowedRoles }) {
  const { user, isAuthenticated, checkingAuth } = useAuth();
  const location = useLocation();

  if (checkingAuth) return null; 

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/unauthorized" replace />;
  }

  return <Outlet />;
}
