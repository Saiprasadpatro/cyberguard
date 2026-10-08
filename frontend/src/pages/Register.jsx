import React, { useState } from 'react';
import { Logo } from '../components/Icons';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import AuthLayout from '../components/AuthLayout';

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ fullName: '', email: '', organisation: '', password: '' });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const update = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setBusy(true);
    try {
      await register(form);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout>
      <div className="cg-auth-card">
        <Logo className="cg-brand-logo" />
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: '14px 0 4px' }}>Create your account</h1>
        <p style={{ color: 'var(--cg-text-muted)', fontSize: 13.5, margin: '0 0 22px' }}>
          Start monitoring threats in minutes
        </p>

        {error && <div style={{ color: 'var(--cg-critical)', fontSize: 13.5, marginBottom: 14 }}>{error}</div>}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 12 }}>
            <label>Full name</label>
            <input className="form-control" required value={form.fullName} onChange={update('fullName')} placeholder="Sai Prasad Patro" />
          </div>
          <div style={{ marginBottom: 12 }}>
            <label>Work email</label>
            <input type="email" className="form-control" required value={form.email} onChange={update('email')} placeholder="you@organisation.com" />
          </div>
          <div style={{ marginBottom: 12 }}>
            <label>Organisation (optional)</label>
            <input className="form-control" value={form.organisation} onChange={update('organisation')} placeholder="KIT Berhampur" />
          </div>
          <div style={{ marginBottom: 18 }}>
            <label>Password</label>
            <input type="password" className="form-control" required minLength={8} value={form.password} onChange={update('password')} placeholder="At least 8 characters" />
          </div>
          <button type="submit" className="cg-btn-primary w-100" disabled={busy}>
            {busy ? <><span className="cg-spinner" />Creating account…</> : 'Create account'}
          </button>
        </form>

        <p style={{ fontSize: 13, marginTop: 20, textAlign: 'center', color: 'var(--cg-text-muted)' }}>
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </AuthLayout>
  );
}
