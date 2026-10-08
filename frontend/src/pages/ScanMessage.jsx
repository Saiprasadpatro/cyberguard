import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AppShell from '../components/AppShell';
import RiskBadge from '../components/RiskBadge';
import Icon from '../components/Icons';
import { PageHeader, ResultView, ScanWorkspace } from '../components/ui';
import api from '../api/api';

export function LinkResults({ links }) {
  if (!links?.length) return <div className="cg-muted" style={{ fontSize: 14 }}>No links found in this message.</div>;
  return (
    <div className="cg-table-wrap">
      <table className="cg-table">
        <thead><tr><th>Link</th><th>Real domain</th><th>Risk</th><th>ML</th><th>Top reason</th></tr></thead>
        <tbody>
          {links.map((l, i) => (
            <tr key={i}>
              <td className="cg-mono" style={{ wordBreak: 'break-all', maxWidth: 280, fontSize: 12 }}>{l.url}</td>
              <td className="cg-mono">{l.registrableDomain || l.host}</td>
              <td><RiskBadge level={l.riskLevel} /></td>
              <td className="cg-mono">{l.mlProbability != null ? `${(l.mlProbability * 100).toFixed(0)}%` : '—'}</td>
              <td style={{ fontSize: 12.5 }}>{(l.findings || []).filter((f) => f.weight > 0).sort((a, b) => b.weight - a.weight)[0]?.detail || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function ScanMessage() {
  const [channel, setChannel] = useState('email');
  const [claimedSender, setClaimedSender] = useState('');
  const [text, setText] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setBusy(true); setError(''); setResult(null);
    try {
      const { data } = await api.post('/scan/text', { text, claimedSender, channel }, { timeout: 90000 });
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.error || (err.code === 'ECONNABORTED' ? 'The scan took too long. Please try again.' : 'Scan failed. Check that the backend is running.'));
    } finally {
      setBusy(false);
    }
  };

  const form = (
    <>
      <div className="cg-panel">
        <form onSubmit={handleSubmit}>
          <div className="cg-panel-title">Message to analyse</div>
          <div className="cg-tabs" role="radiogroup" aria-label="Channel">
            {[['email', 'Email'], ['sms', 'SMS / chat']].map(([v, l]) => (
              <button key={v} type="button" role="radio" aria-checked={channel === v} className={`cg-tab${channel === v ? ' active' : ''}`} onClick={() => setChannel(v)}>{l}</button>
            ))}
          </div>
          <label htmlFor="sender">Claimed sender</label>
          <input id="sender" className="form-control" value={claimedSender} onChange={(e) => setClaimedSender(e.target.value)}
            placeholder={channel === 'email' ? 'support@yourbank-security.com' : '+91 98xxxxxx or "HDFC-BANK"'} />
          <label htmlFor="msg" style={{ marginTop: 14 }}>Message content</label>
          <textarea id="msg" className="form-control" rows={9} required value={text} onChange={(e) => setText(e.target.value)}
            placeholder="Paste the full email or message text here…" />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14, gap: 10, flexWrap: 'wrap' }}>
            <span className="cg-faint" style={{ fontSize: 12 }}>{text.length.toLocaleString()} characters</span>
            <button type="submit" className="cg-btn-primary" disabled={busy || !text.trim()}>
              {busy ? <><span className="cg-spinner" />Analysing…</> : <><Icon name="search" />Run analysis</>}
            </button>
          </div>
          {error && <div className="cg-error"><Icon name="alert" size={16} />{error}</div>}
        </form>
      </div>
      <Link to="/gmail" className="cg-panel" style={{ display: 'flex', gap: 14, alignItems: 'center', color: 'var(--cg-text)', textDecoration: 'none' }}>
        <span className="cg-quick-icon"><Icon name="inbox" /></span>
        <span style={{ flex: 1 }}><strong style={{ display: 'block', fontSize: 14 }}>Scan your Gmail inbox instead</strong><span className="cg-muted" style={{ fontSize: 12.5 }}>Read-only connection, SPF / DKIM / DMARC checks on every mail</span></span>
        <Icon name="arrowRight" size={18} />
      </Link>
    </>
  );

  return (
    <AppShell>
      <PageHeader eyebrow="Detect · Phishing & social engineering" title="Message & email scan" art="message"
        subtitle="Paste an email, SMS or chat message. CyberGuard checks the wording, the sender and every link inside it, then explains the verdict." />
      <ScanWorkspace
        form={form} busy={busy}
        emptyHints={['Urgency, threats and credential requests', 'Sender and brand impersonation', 'Every embedded link checked by the URL model', 'ML text model trained on 39,290 messages']}
        result={result && (
          <ResultView
            result={result}
            ml={{ title: 'ML phishing classifier (C++ TF-IDF + Logistic Regression / Naive Bayes)', label: 'likely phishing' }}
            extraTabs={[{ id: 'links', label: 'Links', count: result.links?.length || 0, content: <LinkResults links={result.links} /> }]}
          />
        )}
      />
    </AppShell>
  );
}
