import React, { useCallback, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import AppShell from '../components/AppShell';
import RiskBadge from '../components/RiskBadge';
import Icon from '../components/Icons';
import Illustration from '../components/Illustrations';
import FindingsList from '../components/FindingsList';
import { ActionList, Callout, ConfirmDialog, Gauge, PageHeader, Tabs } from '../components/ui';
import { useDataChanged, useSystem } from '../context/UiContext';
import api from '../api/api';

const authChip = (label, v) => {
  if (!v) return <span className="cg-chip" title={`${label}: not reported`}>{label}: —</span>;
  const good = v === 'pass';
  const bad = ['fail', 'softfail', 'none', 'permerror', 'temperror'].includes(v);
  return <span className={`cg-chip ${good ? 'cg-chip-good' : bad ? 'cg-chip-bad' : ''}`}>{label}: {v}</span>;
};

function MailDetail({ m, onClose }) {
  const actions = String(m.recommendedAction || '').split(/;\s*/).filter(Boolean);
  const tabs = [
    { id: 'why', label: 'Why it was flagged', count: (m.findings || []).filter((f) => f.weight > 0).length, content: <FindingsList findings={m.findings} /> },
    {
      id: 'links', label: 'Links', count: m.links?.length || 0, hidden: !m.links?.length,
      content: (
        <div className="cg-table-wrap"><table className="cg-table">
          <thead><tr><th>Link</th><th>Real domain</th><th>Risk</th><th>ML</th></tr></thead>
          <tbody>{(m.links || []).map((l, i) => (
            <tr key={i}>
              <td className="cg-mono" style={{ wordBreak: 'break-all', fontSize: 12 }}>{l.url}</td>
              <td className="cg-mono">{l.registrableDomain || l.host}</td>
              <td><RiskBadge level={l.riskLevel} /></td>
              <td className="cg-mono">{l.mlProbability != null ? `${(l.mlProbability * 100).toFixed(0)}%` : '—'}</td>
            </tr>))}</tbody>
        </table></div>
      ),
    },
    {
      id: 'att', label: 'Attachments', count: m.attachments?.length || 0, hidden: !m.attachments?.length,
      content: <div className="cg-chip-row">{(m.attachments || []).map((a, i) => <span key={i} className={`cg-chip ${/\.(exe|scr|js|vbs|bat|cmd|iso|img|lnk|hta|jar|msi|html?|docm|xlsm)$/i.test(a.filename || '') ? 'cg-chip-bad' : ''}`}>{a.filename}</span>)}</div>,
    },
  ];
  return (
    <div className="cg-panel" style={{ animation: 'cg-rise 360ms var(--cg-ease) both' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'flex-start' }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 17, fontWeight: 700, lineHeight: 1.35 }}>{m.subject || '(no subject)'}</div>
          <div className="cg-muted" style={{ fontSize: 13, marginTop: 2, wordBreak: 'break-all' }}>
            <span className="cg-mono">{m.from?.name ? `${m.from.name} <${m.from.email}>` : m.from?.email}</span>
            {m.date && <> · {new Date(m.date).toLocaleString()}</>}
          </div>
        </div>
        <button className="cg-icon-btn" onClick={onClose} aria-label="Close"><Icon name="x" /></button>
      </div>
      <div style={{ display: 'flex', gap: 18, alignItems: 'center', margin: '16px 0 4px', flexWrap: 'wrap' }}>
        <Gauge score={m.score} level={m.riskLevel} />
        <div style={{ display: 'grid', gap: 8 }}>
          <RiskBadge level={m.riskLevel} />
          <div className="cg-chip-row">
            {m.mlProbability != null && <span className="cg-chip">ML phishing {(m.mlProbability * 100).toFixed(0)}%</span>}
            {authChip('SPF', m.auth?.spf)}{authChip('DKIM', m.auth?.dkim)}{authChip('DMARC', m.auth?.dmarc)}
          </div>
        </div>
      </div>
      {m.snippet && <div className="cg-explanation" style={{ marginTop: 14 }}>“{m.snippet}…”</div>}
      {m.explanation && <div style={{ fontSize: 13.5, marginTop: 12 }}>{m.explanation}</div>}
      {actions.length > 0 && <div style={{ marginTop: 14 }}><div className="cg-subtitle" style={{ marginTop: 0 }}>Recommended response</div><ActionList actions={actions} /></div>}
      <Tabs tabs={tabs} />
      <div className="cg-faint" style={{ fontSize: 12, marginTop: 14 }}>
        CyberGuard has read-only access: it never deletes, moves or sends mail. Report phishing from Gmail itself (⋮ → Report phishing).
      </div>
    </div>
  );
}

export default function GmailInbox() {
  const [params, setParams] = useSearchParams();
  const { feature } = useSystem();
  const gmailFeature = feature('gmail');
  const offline = gmailFeature.available === false && /offline|internet/i.test(gmailFeature.reason || '');
  const [status, setStatus] = useState(null);
  const [messages, setMessages] = useState(null);
  const [filter, setFilter] = useState('phishing');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(params.get('error') || '');
  const [notice, setNotice] = useState(params.get('connected') ? 'Gmail connected. Click “Scan inbox now” to check your recent mail.' : '');
  const [selected, setSelected] = useState(null);
  const [max, setMax] = useState(25);
  const [query, setQuery] = useState('in:inbox newer_than:30d');
  const [useAi, setUseAi] = useState(false);
  const [confirmOff, setConfirmOff] = useState(false);

  const loadStatus = useCallback(() => api.get('/gmail/status').then((r) => setStatus(r.data)).catch(() => setStatus({ configured: false, connected: false })), []);
  const loadMessages = useCallback((f) => api.get(`/gmail/messages?filter=${f}`).then((r) => setMessages(r.data.messages)).catch(() => setMessages([])), []);

  useEffect(() => {
    loadStatus();
    if (params.get('connected') || params.get('error')) setParams({}, { replace: true });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (status?.connected) loadMessages(filter); }, [status?.connected, filter, loadMessages]);
  useDataChanged(() => { if (status?.connected) loadMessages(filter); });

  const connect = async () => {
    setError('');
    try {
      const { data } = await api.post('/gmail/connect');
      window.location.href = data.url;
    } catch (e) {
      setError(e.response?.data?.error || 'Could not start the Gmail connection');
    }
  };
  const disconnect = async () => {
    try { await api.post('/gmail/disconnect'); } catch (e) { /* the status reload shows the truth */ }
    setConfirmOff(false); setMessages(null); setSelected(null); loadStatus();
  };
  const scan = async () => {
    setBusy(true); setError(''); setNotice('');
    try {
      const { data } = await api.post('/gmail/scan', { max, query, useAi }, { timeout: 300000 });
      setNotice(`Fetched ${data.fetched} mails · ${data.scanned} new scanned · ${data.skippedAlreadyScanned} already scanned · ${data.flagged} flagged`);
      loadStatus(); loadMessages(filter);
    } catch (e) {
      setError(e.response?.data?.error || 'Inbox scan failed');
      if (e.response?.data?.code === 'GMAIL_REAUTH') loadStatus();
    } finally { setBusy(false); }
  };

  return (
    <AppShell>
      <PageHeader eyebrow="Detect · Phishing" title="Gmail phishing inbox" art="inbox"
        subtitle={<>Connect Gmail with read-only access and CyberGuard checks every mail: the text model, every link, and sender authentication (SPF, DKIM, DMARC). Prefer to paste a mail yourself? Use the <Link to="/scan/message">message scan</Link>.</>} />

      {offline && <Callout tone="warn" icon="cloudOff" title="Gmail needs an internet connection" style={{ marginBottom: 16 }}>CyberGuard is offline, so it cannot reach Gmail right now. Mails you already scanned are still listed below.</Callout>}
      {error && <Callout tone="bad" style={{ marginBottom: 16 }}>{error}</Callout>}
      {notice && <Callout tone="good" style={{ marginBottom: 16 }}>{notice}</Callout>}

      {!status && <div className="cg-skeleton" style={{ height: 120 }} />}

      {status && !status.connected && (
        <div className="cg-panel" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', gap: 20, alignItems: 'center' }}>
          <div>
            <div className="cg-panel-title">Connect Gmail</div>
            {status.configured ? (
              <>
                <p style={{ fontSize: 14, maxWidth: 620 }}>
                  You will be sent to Google to approve <strong>read-only</strong> access (<span className="cg-mono">gmail.readonly</span>).
                  The token is stored encrypted (AES-256-GCM) and you can disconnect at any time.
                </p>
                <button className="cg-btn-primary" onClick={connect} disabled={offline}><Icon name="inbox" />Connect with Google</button>
              </>
            ) : (
              <p style={{ fontSize: 14, margin: 0 }}>
                Gmail is not configured on this server. An admin needs to set <span className="cg-mono">GOOGLE_CLIENT_ID</span> and{' '}
                <span className="cg-mono">GOOGLE_CLIENT_SECRET</span>, enable the Gmail API and add the redirect URI{' '}
                <span className="cg-mono">{status.redirectUri}</span> (see README → “Connect Gmail”).
              </p>
            )}
          </div>
          <div style={{ width: 170 }} className="cg-page-art"><Illustration name="inbox" /></div>
        </div>
      )}

      {status?.connected && (
        <div className="cg-panel">
          <div className="cg-panel-head">
            <div>
              <div style={{ fontWeight: 600 }}><span className="cg-live-dot" />Connected as <span className="cg-mono">{status.gmailAddress || 'Gmail account'}</span></div>
              <div className="cg-faint" style={{ fontSize: 12.5 }}>
                {status.messagesScanned} mails scanned{status.lastSyncAt && ` · last scan ${new Date(status.lastSyncAt).toLocaleString()}`}
              </div>
            </div>
            <button className="cg-btn-ghost" onClick={() => setConfirmOff(true)}><Icon name="logout" />Disconnect</button>
          </div>
          <div className="row g-2" style={{ alignItems: 'end' }}>
            <div className="col-md-5">
              <label htmlFor="gq">Gmail search</label>
              <input id="gq" className="form-control cg-mono" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
            <div className="col-md-2">
              <label htmlFor="gmax">Max mails</label>
              <select id="gmax" className="form-select" value={max} onChange={(e) => setMax(Number(e.target.value))}>
                {[10, 25, 50, 100].map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div className="col-md-3">
              <label style={{ display: 'flex', gap: 8, alignItems: 'center', margin: '0 0 10px', opacity: feature('gemini').available ? 1 : 0.55 }}>
                <input type="checkbox" checked={useAi && feature('gemini').available} disabled={!feature('gemini').available} onChange={(e) => setUseAi(e.target.checked)} /> Gemini explanations (slower)
              </label>
            </div>
            <div className="col-md-2">
              <button className="cg-btn-primary w-100" onClick={scan} disabled={busy || offline}>{busy ? <><span className="cg-spinner" />Scanning…</> : <><Icon name="search" />Scan inbox</>}</button>
            </div>
          </div>
        </div>
      )}

      {status?.connected && (
        <div className={`cg-split cg-mail-split${selected ? ' has-detail' : ''}`} style={{ marginTop: 16 }}>
          <div className="cg-panel" style={{ minWidth: 0 }}>
            <div className="cg-tabs">
              <button className={`cg-tab ${filter === 'phishing' ? 'active' : ''}`} onClick={() => setFilter('phishing')}>Phishing & suspicious</button>
              <button className={`cg-tab ${filter === 'all' ? 'active' : ''}`} onClick={() => setFilter('all')}>All scanned mail</button>
            </div>
            {!messages && [0, 1, 2].map((i) => <div key={i} className="cg-skeleton" style={{ height: 48, marginBottom: 8 }} />)}
            {messages && messages.length === 0 && (
              <div className="cg-empty" style={{ minHeight: 220, border: 0 }}>
                <Illustration name="empty" />
                <h3>{filter === 'phishing' ? 'No phishing found' : 'Nothing scanned yet'}</h3>
                <p>{filter === 'phishing' ? 'None of the scanned mails look like phishing.' : 'Click “Scan inbox” to check your recent mail.'}</p>
              </div>
            )}
            {messages && messages.length > 0 && (
              <div className="cg-table-wrap"><table className="cg-table">
                <thead><tr><th>Risk</th><th>From</th><th>Subject</th><th>Auth</th><th>ML</th></tr></thead>
                <tbody>
                  {messages.map((m) => (
                    <tr key={m.scanId} className="cg-mail-row" onClick={() => setSelected(m)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setSelected(m); }}
                      style={selected?.scanId === m.scanId ? { background: 'var(--cg-accent-soft)' } : undefined}>
                      <td><RiskBadge level={m.riskLevel} /></td>
                      <td className="cg-mono" style={{ fontSize: 12.5, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.from?.email}</td>
                      <td style={{ maxWidth: 300 }}>{m.subject || '(no subject)'}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>{m.auth?.dmarc ? authChip('DMARC', m.auth.dmarc) : authChip('SPF', m.auth?.spf)}</td>
                      <td className="cg-mono">{m.mlProbability != null ? `${(m.mlProbability * 100).toFixed(0)}%` : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            )}
          </div>
          {selected && <div className="cg-split-form" style={{ order: 2 }}><MailDetail m={selected} onClose={() => setSelected(null)} /></div>}
        </div>
      )}

      <ConfirmDialog
        open={confirmOff} icon="inbox"
        title="Disconnect Gmail?"
        body="CyberGuard will revoke its read-only access to your mailbox. Mails already scanned stay in your history."
        confirmLabel="Disconnect"
        onConfirm={disconnect}
        onCancel={() => setConfirmOff(false)}
      />
    </AppShell>
  );
}
