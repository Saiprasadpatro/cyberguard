import React, { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function OAuthSuccess() {
  const [params] = useSearchParams();
  const { setTokenFromOAuth } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const token = params.get('token');
    if (token) {
      setTokenFromOAuth(token).then(() => navigate('/'));
    } else {
      navigate('/login?error=missing_token');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="cg-auth-shell">
      <div style={{ color: 'var(--cg-text-muted)' }}>Signing you in…</div>
    </div>
  );
}
