import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Logo } from '../components/Icons';
import { useSystem } from '../context/UiContext';
import { useAuth } from '../context/AuthContext';
import AuthLayout from '../components/AuthLayout';
import { googleLoginUrl } from '../api/api';
import RiskBadge from '../components/RiskBadge';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [params] = useSearchParams();
  const { online } = useSystem();
  const [error, setError] = useState(params.get('error') === 'offline'
    ? 'Google sign-in needs an internet connection. Use your email and password while CyberGuard is offline.'
    : params.get('error') ? 'Google sign-in failed. Please try again or use your email and password.' : '');
  const [loginRisk, setLoginRisk] = useState(null);
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setLoginRisk(null); setBusy(true);
    try {
      const data = await login(email, password);
      if (data.loginRisk && data.loginRisk.riskLevel !== 'Safe') {
        setLoginRisk(data.loginRisk);
        setTimeout(() => navigate('/'), 1800);
      } else {
        navigate('/');
      }
    } catch (err) {
      setError(err.response?.data?.error || (err.response ? 'Login failed' : 'Cannot reach the CyberGuard server. Is the backend running?'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout>
      <div className="cg-auth-card">
        <Logo className="cg-brand-logo" />
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: '14px 0 4px' }}>Sign in to CyberGuard</h1>
        <p style={{ color: 'var(--cg-text-muted)', fontSize: 13.5, margin: '0 0 22px' }}>
          AI cyber threat, phishing and impersonation defence
        </p>

        {error && <div style={{ color: 'var(--cg-critical)', fontSize: 13.5, marginBottom: 14 }}>{error}</div>}
        {loginRisk && (
          <div style={{ marginBottom: 14 }}>
            <RiskBadge level={loginRisk.riskLevel} /> <span style={{ fontSize: 13 }}>Unusual login activity detected — signing you in.</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 14 }}>
            <label>Email</label>
            <input type="email" className="form-control" required value={email}
              onChange={(e) => setEmail(e.target.value)} placeholder="you@organisation.com" />
          </div>
          <div style={{ marginBottom: 18 }}>
            <label>Password</label>
            <input type="password" className="form-control" required value={password}
              onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
          </div>
          <button type="submit" className="cg-btn-primary w-100" disabled={busy}>
            {busy ? <><span className="cg-spinner" />Signing in…</> : 'Sign in'}
          </button>
        </form>

        <div className="cg-divider">or</div>

        {online ? (
          <a href={googleLoginUrl} className="cg-btn-outline w-100" style={{ textDecoration: 'none' }}>
            <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path fill="#4285F4" d="M22.5 12.3c0-.8-.1-1.5-.2-2.2H12v4.2h5.9a5 5 0 0 1-2.2 3.3v2.7h3.5c2.1-1.9 3.3-4.7 3.3-8z" /><path fill="#34A853" d="M12 23c3 0 5.5-1 7.2-2.7l-3.5-2.7c-1 .7-2.2 1-3.7 1-2.9 0-5.3-1.9-6.2-4.5H2.2v2.8A11 11 0 0 0 12 23z" /><path fill="#FBBC05" d="M5.8 14.1a6.6 6.6 0 0 1 0-4.2V7.1H2.2a11 11 0 0 0 0 9.8z" /><path fill="#EA4335" d="M12 5.4c1.6 0 3.1.6 4.2 1.6l3.1-3.1A11 11 0 0 0 2.2 7.1l3.6 2.8C6.7 7.3 9.1 5.4 12 5.4z" /></svg>
            Continue with Google
          </a>
        ) : (
          <button type="button" className="cg-btn-outline w-100" disabled title="Needs an internet connection">Google sign-in unavailable offline</button>
        )}

        <p style={{ fontSize: 13, marginTop: 20, textAlign: 'center', color: 'var(--cg-text-muted)' }}>
          No account? <Link to="/register">Create one</Link>
        </p>
      </div>
    </AuthLayout>
  );
}
