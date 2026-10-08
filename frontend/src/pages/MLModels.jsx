import React, { useEffect, useState } from 'react';
import AppShell from '../components/AppShell';
import { PageHeader, Tabs } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import api from '../api/api';

const FEATURE_OF = {
  phishing_text: 'Message / Email phishing + Gmail inbox',
  url_model: 'URL & website detection',
  nids_model: 'Network intrusion detection',
  login_anomaly: 'Login risk (account takeover)',
  log_anomaly: 'Technical threats — log / insider behaviour',
  image_manipulation: 'Image & video-frame manipulation',
  audio_deepfake: 'Voice clone / synthetic audio (+ video voice track)',
};
const SHORT = { phishing_text: 'Phishing text', url_model: 'URL', nids_model: 'Network IDS', login_anomaly: 'Login', log_anomaly: 'Logs', audio_deepfake: 'Voice', image_manipulation: 'Image' };
const ORDER = ['phishing_text', 'url_model', 'nids_model', 'login_anomaly', 'log_anomaly', 'audio_deepfake', 'image_manipulation'];
const METRIC_KEYS = ['accuracy', 'precision', 'recall', 'f1', 'rocAuc', 'macroF1'];
const fmt = (v) => (typeof v === 'number' ? v.toFixed(3) : '—');

// Collect every sub-object that looks like a metrics block, labelled by its path.
function metricRows(metrics, path = []) {
  if (!metrics || typeof metrics !== 'object' || Array.isArray(metrics)) return [];
  const rows = [];
  if (METRIC_KEYS.some((k) => typeof metrics[k] === 'number')) rows.push({ label: path.join(' › ') || 'overall', m: metrics });
  for (const [k, v] of Object.entries(metrics)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && k !== 'confusion') rows.push(...metricRows(v, [...path, k]));
  }
  return rows;
}

function ModelCard({ name, card, bare }) {
  const [open, setOpen] = useState(false);
  const rows = metricRows(card.metrics);
  const notes = [];
  (function collect(o) {
    if (!o || typeof o !== 'object') return;
    for (const [k, v] of Object.entries(o)) {
      if ((k === 'note' || k === 'notes') && typeof v === 'string') notes.push(v);
      else if (typeof v === 'object') collect(v);
    }
  }(card));
  const ds = card.dataset || {};
  const perClass = card.metrics?.randomForest?.perClass;
  return (
    <div className={bare ? undefined : 'cg-panel'}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: 16.5, fontWeight: 600 }}>{FEATURE_OF[name] || name}</div>
          <div className="cg-mono" style={{ fontSize: 12, color: 'var(--cg-text-muted)' }}>{name}.json · {card.engine}{card.trainedAt ? ` · trained ${card.trainedAt}` : ''}</div>
        </div>
        <span className={`cg-chip ${card.loaded ? 'cg-chip-good' : 'cg-chip-bad'}`} style={{ alignSelf: 'flex-start' }}>{card.loaded ? 'loaded' : 'not loaded'}</span>
      </div>
      <div style={{ fontSize: 14, marginTop: 8 }}><strong>Algorithm:</strong> {card.algorithm}</div>
      {card.task && <div style={{ fontSize: 13.5, color: 'var(--cg-text-muted)' }}>{card.task}</div>}
      <div style={{ fontSize: 13.5, marginTop: 4 }}>
        <strong>Data:</strong> {ds.name || (typeof card.dataset === 'string' ? card.dataset : '—')}
        {ds.samples != null && <> · {Number(ds.samples).toLocaleString()} samples</>}
        {ds.split && <> · {ds.split}</>}
      </div>

      {rows.length > 0 && (
        <div style={{ overflowX: 'auto', marginTop: 10 }}>
          <table className="cg-table">
            <thead><tr><th>Held-out evaluation</th>{METRIC_KEYS.map((k) => <th key={k}>{k === 'rocAuc' ? 'ROC-AUC' : k}</th>)}<th>samples</th></tr></thead>
            <tbody>
              {rows.slice(0, open ? 50 : 4).map((r) => (
                <tr key={r.label}>
                  <td className="cg-mono" style={{ fontSize: 12 }}>{r.label}</td>
                  {METRIC_KEYS.map((k) => <td key={k} className="cg-mono">{fmt(r.m[k])}</td>)}
                  <td className="cg-mono">{r.m.samples ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {open && perClass && (
        <>
          <div className="cg-subtitle">Per attack class (Random Forest, 5-class)</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {perClass.map((c) => <span key={c.class} className="cg-chip">{c.class}: P {fmt(c.precision)} · R {fmt(c.recall)} · F1 {fmt(c.f1)}</span>)}
          </div>
        </>
      )}
      {open && card.featureImportance?.length > 0 && (
        <>
          <div className="cg-subtitle">Most important features</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {card.featureImportance.slice(0, 12).map((f) => <span key={f.feature} className="cg-chip">{f.feature} <span style={{ opacity: 0.6 }}>{(f.importance * 100).toFixed(1)}%</span></span>)}
          </div>
        </>
      )}
      {open && card.topMaliciousTerms?.length > 0 && (
        <>
          <div className="cg-subtitle">Strongest phishing terms learned</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {card.topMaliciousTerms.slice(0, 25).map((t) => <span key={t.term || t} className="cg-chip">{(t.term || t).replace(/^__(\w+)__$/, '<$1>')}</span>)}
          </div>
        </>
      )}
      {notes.length > 0 && <div className="cg-note" style={{ marginTop: 10 }}>{notes.join(' ')}</div>}
      <button className="cg-btn-outline" style={{ marginTop: 10 }} onClick={() => setOpen(!open)}>{open ? 'Less' : 'More details'}</button>
    </div>
  );
}

export default function MLModels() {
  const { user } = useAuth();
  const [models, setModels] = useState(null);
  const [error, setError] = useState('');
  const [retrain, setRetrain] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = () => api.get('/ml/models').then((r) => setModels(r.data.models)).catch((e) => setError(e.response?.data?.error || 'Could not load model cards'));
  useEffect(() => { load(); }, []);

  const doRetrain = async () => {
    setBusy(true); setRetrain(null);
    try {
      const { data } = await api.post('/ml/retrain/login', {}, { timeout: 180000 });
      setRetrain({ ok: true, data });
      load();
    } catch (e) {
      setRetrain({ ok: false, msg: e.response?.data?.detail || e.response?.data?.error || 'Retraining failed' });
    } finally { setBusy(false); }
  };

  const names = models ? [...ORDER.filter((n) => models[n]), ...Object.keys(models).filter((n) => !ORDER.includes(n))] : [];
  return (
    <AppShell>
      <PageHeader eyebrow="Workspace · Models" title="Machine-learning models" art="model"
        subtitle={<>Every detection feature has its own model, written from scratch in C++17 and trained with <span className="cg-mono">cg_train</span>. All metrics are measured on held-out data the model never saw.</>} />
      {error && <div className="cg-panel cg-error" style={{ marginTop: 0 }}>{error}</div>}

      {user?.role === 'admin' && (
        <div className="cg-panel" style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <div style={{ fontWeight: 600 }}>Adapt the login-anomaly model to this deployment</div>
            <div style={{ fontSize: 13.5, color: 'var(--cg-text-muted)' }}>Retrains the Isolation Forest on your users' own successful logins (last 180 days) so “normal” matches your organisation.</div>
            {retrain && (retrain.ok && retrain.data.retrained
              ? <div style={{ color: 'var(--cg-safe)', fontSize: 13.5, marginTop: 6 }}>Retrained on {retrain.data.samples} logins (new threshold {Number(retrain.data.threshold).toFixed(3)}).</div>
              : <div style={{ color: retrain.ok ? 'var(--cg-medium)' : 'var(--cg-critical)', fontSize: 13.5, marginTop: 6 }}>{retrain.ok ? `Not retrained: ${retrain.data.reason}` : retrain.msg}</div>)}
          </div>
          <button className="cg-btn-primary" onClick={doRetrain} disabled={busy}>{busy ? <><span className="cg-spinner" />Retraining…</> : 'Retrain login model'}</button>
        </div>
      )}

      {!models && !error && [0, 1, 2].map((i) => <div key={i} className="cg-skeleton" style={{ height: 180, marginTop: 16 }} />)}
      {names.length > 0 && (
        <div className="cg-panel" style={{ marginTop: 16 }}>
          <div className="cg-panel-title" style={{ marginBottom: 0 }}>{names.length} models loaded in the detection engine</div>
          <Tabs tabs={names.map((n) => ({ id: n, label: SHORT[n] || n, content: <ModelCard name={n} card={models[n]} bare /> }))} />
        </div>
      )}
    </AppShell>
  );
}
