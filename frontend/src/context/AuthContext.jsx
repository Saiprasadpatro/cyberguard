import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import api from '../api/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadUser = useCallback(async () => {
    const token = localStorage.getItem('cg_token');
    if (!token) { setLoading(false); return; }
    try {
      const { data } = await api.get('/auth/me');
      setUser(data.user);
    } catch (e) {
      localStorage.removeItem('cg_token');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadUser(); }, [loadUser]);

  const login = async (email, password) => {
    const deviceFingerprint = localStorage.getItem('cg_device') || crypto.randomUUID();
    localStorage.setItem('cg_device', deviceFingerprint);
    const { data } = await api.post('/auth/login', { email, password, deviceFingerprint });
    localStorage.setItem('cg_token', data.token);
    setUser(data.user);
    return data;
  };

  const register = async (payload) => {
    const { data } = await api.post('/auth/register', payload);
    localStorage.setItem('cg_token', data.token);
    setUser(data.user);
    return data;
  };

  const setTokenFromOAuth = async (token) => {
    localStorage.setItem('cg_token', token);
    await loadUser();
  };

  const logout = () => {
    localStorage.removeItem('cg_token');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, setTokenFromOAuth }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
