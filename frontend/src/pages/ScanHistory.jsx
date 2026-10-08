import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import AppShell from '../components/AppShell';
import RiskBadge from '../components/RiskBadge';
import Icon from '../components/Icons';
import Illustration from '../components/Illustrations';
import { ConfirmDialog, PageHeader } from '../components/ui';
import { emitDataChanged, useDataChanged, useToast } from '../context/UiContext';
import { useAuth } from '../context/AuthContext';
import api from '../api/api';

const TYPES = {
  email: { label: 'Email', icon: 'mail' },
  sms: { label: 'SMS', icon: 'mail' },
  url: { label: 'URL', icon: 'link' },
  image: { label: 'Image', icon: 'image' },
  audio: { label: 'Audio', icon: 'wave' },
  video: { label: 'Video', icon: 'video' },
  login_behavior: { label: 'Login', icon: 'admin' },
  log_upload: { label: 'Logs', icon: 'terminal' },
  network_pcap: { label: 'Network', icon: 'network' },
  network_live: { label: 'Network', icon: 'network' },
};
const FILTERS = [
  ['all', 'All'], ['messages', 'Messages'], ['url', 'URLs'], ['media', 'Media'], ['logs', 'Logs'], ['network', 'Network'],
];
const inFilter = (t, f) => f === 'all'
  || (f === 'messages' && (t === 'email' || t === 'sms'))
  || (f === 'url' && t === 'url')
  || (f === 'media' && ['image', 'audio', 'video'].includes(t))
  || (f === 'logs' && (t === 'log_upload' || t === 'login_behavior'))
  || (f === 'network' && t.startsWith('network'));

function dayLabel(d) {
  const dt = new Date(d);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const that = new Date(dt); that.setHours(0, 0, 0, 0);
  const diff = Math.round((today - that) / 86400000);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  return dt.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: today.getFullYear() === dt.getFullYear() ? undefined : 'numeric' });
}

const PAGE = 30;

export default function ScanHistory() {
  const { user } = useAuth();
  const toast = useToast();
  const [scans, setScans] = useState(null);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [limit, setLimit] = useState(PAGE);
  const [leaving, setLeaving] = useState({});
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [clearing, setClearing] = useState(false);
  const mounted = useRef(true);
  useEffect(() => () => { mounted.current = false; }, []);

  const load = useCallback(() => api.get('/scan/history')
    .then((res) => { if (mounted.current) { setScans(res.data.scans); setError(''); } })
    .catch((err) => { if (mounted.current) { setError(err.response?.data?.error || 'Could not load your history'); setScans((s) => s || []); } }), []);
  useEffect(() => { load(); }, [load]);
  useDataChanged((d) => { if (d?.source !== 'history') load(); });

  const own = useMemo(() => (scans || []).filter((s) => s.userId === user?.id), [scans, user]);
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (scans || []).filter((s) => inFilter(s.scanType || '', filter) && (!q || `${s.inputSummary} ${s.scanType} ${s.riskLevel}`.toLowerCase().includes(q)));
  }, [scans, filter, query]);
  const shown = visible.slice(0, limit);
  const groups = useMemo(() => {
    const out = [];
    shown.forEach((s) => {
      const k = dayLabel(s.createdAt);
      if (!out.length || out[out.length - 1].k !== k) out.push({ k, items: [] });
      out[out.length - 1].items.push(s);
    });
    return out;
  }, [shown]);

  const restore = async (items, label) => {
    try {
      await api.post('/scan/restore', { ids: items.map((x) => x.scan.id) });
      setScans((cur) => {
        const next = [...(cur || [])];
        items.sort((a, b) => a.index - b.index).forEach(({ scan, index }) => { if (!next.some((x) => x.id === scan.id)) next.splice(Math.min(index, next.length), 0, scan); });
        return next;
      });
      emitDataChanged({ source: 'history' });
      toast.show({ message: label, duration: 2200 });
    } catch (e) {
      toast.show({ message: e.response?.data?.error || 'Could not undo', tone: 'error', duration: 3500 });
      load();
    }
  };

  const remove = async (scan) => {
    const index = (scans || []).findIndex((x) => x.id === scan.id);
    setLeaving((l) => ({ ...l, [scan.id]: true }));
    // Let the row slide out, then drop it from the list (optimistic).
    setTimeout(() => {
      if (!mounted.current) return;
      setScans((cur) => (cur || []).filter((x) => x.id !== scan.id));
      setLeaving((l) => { const n = { ...l }; delete n[scan.id]; return n; });
    }, 200);
    try {
      await api.delete(`/scan/${scan.id}`);
      emitDataChanged({ source: 'history' });
      toast.show({
        message: 'Scan deleted',
        duration: 3000,
        action: { label: 'Undo', onClick: () => restore([{ scan, index }], 'Scan restored') },
      });
    } catch (e) {
      setScans((cur) => { const next = [...(cur || [])]; if (!next.some((x) => x.id === scan.id)) next.splice(index, 0, scan); return next; });
      toast.show({ message: e.response?.data?.error || 'Could not delete the scan', tone: 'error', duration: 3500 });
    }
  };

  const clearAll = async () => {
    setClearing(true);
    const before = scans || [];
    try {
      const { data } = await api.delete('/scan/history');
      const ids = new Set(data.deleted || []);
      const removed = before.map((scan, index) => ({ scan, index })).filter((x) => ids.has(x.scan.id));
      setScans(before.filter((s) => !ids.has(s.id)));
      setConfirmOpen(false);
      emitDataChanged({ source: 'history' });
      toast.show({
        message: `History cleared · ${removed.length} scan${removed.length === 1 ? '' : 's'} removed`,
        duration: 5000,
        action: removed.length ? { label: 'Undo', onClick: () => restore(removed, 'History restored') } : undefined,
      });
    } catch (e) {
      toast.show({ message: e.response?.data?.error || 'Could not clear the history', tone: 'error', duration: 3500 });
    } finally {
      setClearing(false);
    }
  };

  return (
    <AppShell>
      <PageHeader eyebrow="Workspace" title="Scan history" art="history"
        subtitle="Every analysis run on your account. Delete single scans or reset the whole history; the dashboard updates straight away.">
        <button type="button" className="cg-btn-danger" onClick={() => setConfirmOpen(true)} disabled={!own.length}>
          <Icon name="reset" />Reset history
        </button>
      </PageHeader>

      <div className="cg-panel">
        <div className="cg-toolbar">
          <div className="cg-search">
            <Icon name="search" />
            <input className="form-control" placeholder="Search scans…" value={query} onChange={(e) => { setQuery(e.target.value); setLimit(PAGE); }} aria-label="Search scans" />
          </div>
          <div className="cg-tabs" style={{ margin: 0 }}>
            {FILTERS.map(([id, l]) => <button key={id} type="button" className={`cg-tab${filter === id ? ' active' : ''}`} onClick={() => { setFilter(id); setLimit(PAGE); }}>{l}</button>)}
          </div>
          <span className="cg-faint" style={{ marginLeft: 'auto', fontSize: 12.5 }}>{scans ? `${visible.length} of ${scans.length}` : ''}</span>
        </div>

        {error && <div className="cg-error" style={{ marginBottom: 12 }}><Icon name="alert" size={16} />{error}</div>}

        {!scans && <div aria-busy="true">{[0, 1, 2, 3, 4].map((i) => <div key={i} className="cg-skeleton" style={{ height: 54, marginBottom: 8 }} />)}</div>}

        {scans && visible.length === 0 && (
          <div className="cg-empty" style={{ minHeight: 280, border: 0 }}>
            <Illustration name="empty" />
            <h3>{scans.length ? 'Nothing matches this filter' : 'No scans yet'}</h3>
            <p>{scans.length ? 'Try another filter or search term.' : 'Run any scan and it will be listed here.'}</p>
          </div>
        )}

        {groups.map((g) => (
          <div key={g.k}>
            <div className="cg-history-day">{g.k}</div>
            {g.items.map((s) => {
              const t = TYPES[s.scanType] || { label: s.scanType, icon: 'shield' };
              const mine = s.userId === user?.id || user?.role === 'admin';
              return (
                <div key={s.id} className={`cg-history-row${leaving[s.id] ? ' leaving' : ''}`}>
                  <span className="cg-type-icon" title={t.label}><Icon name={t.icon} /></span>
                  <div className="cg-history-main">
                    <div className="cg-history-summary" title={s.inputSummary}>{s.inputSummary || '(no summary)'}</div>
                    <div className="cg-history-meta">{t.label}{s.source && s.source !== 'manual' ? ` · ${s.source.replace('_', ' ')}` : ''}</div>
                  </div>
                  <span><RiskBadge level={s.riskLevel} /></span>
                  <span className="cg-history-score">{s.finalScore}</span>
                  <span className="cg-history-time">{new Date(s.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  {mine ? (
                    <button type="button" className="cg-icon-btn danger" aria-label="Delete this scan" title="Delete" onClick={() => remove(s)} disabled={leaving[s.id]}>
                      <Icon name="trash" />
                    </button>
                  ) : <span />}
                </div>
              );
            })}
          </div>
        ))}

        {visible.length > shown.length && (
          <div style={{ textAlign: 'center', marginTop: 14 }}>
            <button type="button" className="cg-btn-outline" onClick={() => setLimit((l) => l + PAGE)}>Show more ({visible.length - shown.length} left)</button>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmOpen}
        title="Reset your scan history?"
        body={`This removes all ${own.length} of your scans and the threats they created from the history and the dashboard. You can undo it for a few seconds afterwards.`}
        confirmLabel="Yes, reset history"
        busy={clearing}
        onConfirm={clearAll}
        onCancel={() => setConfirmOpen(false)}
      />
    </AppShell>
  );
}
