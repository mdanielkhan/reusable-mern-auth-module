import { createContext, useCallback, useEffect, useState } from 'react';
import api from '../api/axios';

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  // checkingAuth distinguishes "we don't know yet" from "definitely logged
  // out" — without it, a protected route redirects to /login for a split
  // second on every page refresh before the /me call resolves.
  const [checkingAuth, setCheckingAuth] = useState(true);

  const fetchMe = useCallback(async () => {
    try {
      const { data } = await api.get('/auth/me');
      setUser(data.data.user);
    } catch (err) {
      setUser(null);
    } finally {
      setCheckingAuth(false);
    }
  }, []);

  useEffect(() => {
    fetchMe();
  }, [fetchMe]);

  const login = useCallback(async (email, password) => {
    const { data } = await api.post('/auth/login', { email, password });
    setUser(data.data.user);
    return data.data.user;
  }, []);

  const register = useCallback(async (name, email, password) => {
    const { data } = await api.post('/auth/register', { name, email, password });
    return data; // caller decides whether to redirect to "check your email"
  }, []);

  const loginWithGoogle = useCallback(async (idToken) => {
    const { data } = await api.post('/auth/google', { idToken });
    setUser(data.data.user);
    return data.data.user;
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      setUser(null);
    }
  }, []);

  const value = {
    user,
    checkingAuth,
    isAuthenticated: !!user,
    login,
    register,
    loginWithGoogle,
    logout,
    refetchMe: fetchMe,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
