import React, { useEffect, useRef, useState } from 'react';
import AppShell from '../components/AppShell';
import RiskBadge from '../components/RiskBadge';
import Icon from '../components/Icons';
import Dropzone from '../components/Dropzone';
import { MitreList } from '../components/MlPanel';
import { ActionList, Callout, PageHeader, ScanWorkspace, Tabs, Verdict, ModeChip } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { useDataChanged } from '../context/UiContext';
import api from '../api/api';

const fmtBytes = (b) => (b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : b >= 1e3 ? `${(b / 1e3).toFixed(1)} KB` : `${b || 0} B`);
const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleTimeString() : '—');

function AlertCard({ a }) {
  return (
    <div className={`cg-alert cg-alert-${a.severity}`}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <RiskBadge level={a.severity} />
        <span className="cg-mono" style={{ fontWeight: 600 }}>{a.type}</span>
        <span className="cg-chip">{a.category}</span>
        <span className={`cg-chip ${a.detectedBy === 'ml' ? 'cg-chip-warn' : ''}`}>{a.detectedBy === 'ml' ? 'ML model' : a.detectedBy === 'rule' ? 'signature rule' : a.detectedBy}</span>
        {a.count != null && <span className="cg-mono" style={{ fontSize: 12, color: 'var(--cg-text-muted)' }}>{a.count} events</span>}
      </div>
      <div style={{ fontSize: 13.5, marginTop: 6 }}>{a.evidence}</div>
      <div className="cg-mono" style={{ fontSize: 12, color: 'var(--cg-text-muted)', marginTop: 4 }}>
        {a.src} → {a.dst}{a.firstSeen ? ` · ${fmtTime(a.firstSeen)}–${fmtTime(a.lastSeen)}` : ''}
        {a.topSources?.length > 0 && ` · top sources: ${a.topSources.slice(0, 3).map((s) => s.ip || s).join(', ')}`}
      </div>
      {a.mitreAttack?.length > 0 && <div style={{ marginTop: 6 }}><MitreList items={a.mitreAttack} /></div>}
    </div>
  );
}

function FlowTable({ r }) {
  const [flowFilter, setFlowFilter] = useState('attack');
  const [flowLimit, setFlowLimit] = useState(25);
  const flows = (r.flows || []).filter((f) => (flowFilter === 'all' ? true : f.attackProbability >= 0.5 || f.novel));
  return (
    <>
      <div className="cg-tabs">
        <button className={`cg-tab ${flowFilter === 'attack' ? 'active' : ''}`} onClick={() => setFlowFilter('attack')}>Suspicious</button>
        <button className={`cg-tab ${flowFilter === 'all' ? 'active' : ''}`} onClick={() => setFlowFilter('all')}>All (top {r.flows.length})</button>
      </div>
      <div className="cg-table-wrap">
        <table className="cg-table">
          <thead><tr><th>Source</th><th>Destination</th><th>Proto / service</th><th>State</th><th>Bytes ↑/↓</th><th>ML attack</th><th>Class</th><th>Novel</th></tr></thead>
          <tbody>
            {flows.slice(0, flowLimit).map((f, i) => (
              <tr key={i}>
                <td className="cg-mono" style={{ fontSize: 12 }}>{f.src}:{f.sport}</td>
                <td className="cg-mono" style={{ fontSize: 12 }}>{f.dst}:{f.dport}</td>
                <td className="cg-mono" style={{ fontSize: 12 }}>{f.proto} / {f.service}</td>
                <td className="cg-mono" style={{ fontSize: 12 }}>{f.flag}</td>
                <td className="cg-mono" style={{ fontSize: 12 }}>{fmtBytes(f.srcBytes)} / {fmtBytes(f.dstBytes)}</td>
                <td className="cg-mono" style={{ color: f.attackProbability >= 0.5 ? 'var(--cg-high)' : undefined }}>{f.attackProbability != null ? `${(f.attackProbability * 100).toFixed(0)}%` : '—'}</td>
                <td>{f.category}</td>
                <td>{f.novel ? <span className="cg-chip cg-chip-warn">novel</span> : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {flows.length > flowLimit && <button className="cg-btn-outline" style={{ marginTop: 10 }} onClick={() => setFlowLimit(flowLimit + 50)}>Show more ({flows.length - flowLimit} left)</button>}
      {flows.length === 0 && <div className="cg-muted" style={{ fontSize: 13.5 }}>No connections above the ML threshold.</div>}
    </>
  );
}

function AnalysisView({ r }) {
  const s = r.summary || {};
  const alerts = r.alerts || [];
  const stat = (v, l, accent) => (
    <div className="cg-card" style={{ padding: '12px 14px' }}>
      <div className="cg-mono" style={{ fontSize: 20, fontWeight: 600, color: accent }}>{v}</div>
      <div className="cg-faint" style={{ fontSize: 12 }}>{l}</div>
    </div>
  );
  const tabs = [
    {
      id: 'alerts', label: 'Alerts', count: alerts.length,
      content: alerts.length === 0
        ? <Callout tone="good" title="No intrusion indicators">Nothing suspicious was found in this traffic.</Callout>
        : alerts.map((a, i) => <AlertCard key={i} a={a} />),
    },
    { id: 'flows', label: 'Connections', count: r.flows?.length || 0, hidden: !r.flows?.length, content: <FlowTable r={r} /> },
    {
      id: 'traffic', label: 'Traffic profile',
      content: (
        <div className="cg-stack">
          <div className="cg-kv">
            {s.durationSeconds != null && (<><div>Duration</div><div className="cg-mono">{s.durationSeconds.toFixed(1)} s</div></>)}
            {s.protocols && (<><div>Protocols</div><div className="cg-mono">{Object.entries(s.protocols).map(([k, v]) => `${k}: ${v}`).join(' · ')}</div></>)}
            {s.mlByCategory && Object.keys(s.mlByCategory).length > 0 && (<><div>ML classes</div><div className="cg-mono">{Object.entries(s.mlByCategory).map(([k, v]) => `${k}: ${v}`).join(' · ')}</div></>)}
            {s.dnsQueries != null && (<><div>DNS queries</div><div className="cg-mono">{s.dnsQueries}</div></>)}
          </div>
          {s.topTalkers?.length > 0 && (
            <div><div className="cg-subtitle">Top talkers</div>
              <div className="cg-chip-row">{s.topTalkers.map((t) => <span key={t.ip} className="cg-chip"><span className="cg-mono">{t.ip}</span> {fmtBytes(t.bytes)} · {t.internal ? 'internal' : 'external'}</span>)}</div></div>
          )}
        </div>
      ),
    },
    { id: 'response', label: 'Response', hidden: !r.recommendedActions?.length, content: <ActionList actions={r.recommendedActions} /> },
  ];
  return (
    <div className="cg-panel" style={{ animation: 'cg-rise 420ms var(--cg-ease) both' }}>
      <Verdict level={r.riskLevel} score={r.score}
        subtitle={`${s.packets ?? 0} packets · ${s.connections ?? 0} connections · ${fmtBytes(s.bytes)}`}
        chips={<><ModeChip mode={r.analysisMode} />{!r.mlAvailable && <span className="cg-chip cg-chip-warn">ML model not loaded: rules only</span>}</>} />
      <div className="cg-grid-2" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', marginTop: 18 }}>
        {stat(s.packets ?? 0, 'packets')}
        {stat(s.connections ?? 0, 'connections')}
        {stat(fmtBytes(s.bytes), 'traffic')}
        {stat(s.mlFlaggedConnections ?? 0, 'ML-flagged', s.mlFlaggedConnections ? 'var(--cg-high)' : undefined)}
        {stat(alerts.length, 'alerts', alerts.length ? 'var(--cg-critical)' : undefined)}
      </div>
      <Tabs tabs={tabs} />
    </div>
  );
}

function LiveCapture() {
  const [ifaces, setIfaces] = useState(null);
  const [iface, setIface] = useState('');
  const [bpf, setBpf] = useState('');
  const [windowSeconds, setWindowSeconds] = useState(30);
  const [status, setStatus] = useState(null);
  const [error, setError] = useState('');
  const timer = useRef(null);

  const poll = () => api.get('/nids/live/status').then((r) => setStatus(r.data)).catch((e) => setError(e.response?.data?.error || 'Engine unreachable'));
  useEffect(() => {
    api.get('/nids/interfaces').then((r) => {
      setIfaces(r.data);
      const first = (r.data.interfaces || []).find((i) => !i.loopback) || (r.data.interfaces || [])[0];
      if (first) setIface(first.name);
    }).catch((e) => setError(e.response?.data?.error || 'Engine unreachable'));
    poll();
    timer.current = setInterval(poll, 5000);
    return () => clearInterval(timer.current);
  }, []);

  const start = async () => {
    setError('');
    try {
      const { data } = await api.post('/nids/live/start', { iface, bpf, windowSeconds: Number(windowSeconds) });
      if (!data.started) setError(data.error || 'Could not start capture');
    } catch (e) { setError(e.response?.data?.error || 'Could not start capture'); }
    poll();
  };
  const stop = async () => { try { await api.post('/nids/live/stop'); } catch (e) { /* status poll shows the result */ } poll(); };

  if (ifaces && !ifaces.supported) {
    return (
      <div className="cg-panel" style={{ fontSize: 14 }}>
        This detection-engine build has no libpcap support, so it cannot sniff traffic. Upload a .pcap instead, or run the Docker engine / the
        <span className="cg-mono"> nids-sensor</span> profile (see README → Network IDS).
      </div>
    );
  }
  const la = status?.lastAnalysis;
  return (
    <>
      <div className="cg-panel">
        <div className="cg-panel-title">Live capture (runs inside the detection engine)</div>
        {status?.running ? (
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            <div style={{ fontSize: 14 }}>
              <span className="cg-live-dot" />Capturing on <span className="cg-mono">{status.iface}</span>{status.bpf && <> · filter <span className="cg-mono">{status.bpf}</span></>}
              <div className="cg-mono" style={{ fontSize: 12, color: 'var(--cg-text-muted)' }}>
                {status.packetsCaptured} packets · {fmtBytes(status.bytesCaptured)} · analysed every few seconds over a {status.windowSeconds}s sliding window
              </div>
            </div>
            <button className="cg-btn-outline" onClick={stop}>Stop capture</button>
          </div>
        ) : (
          <div className="row g-2" style={{ alignItems: 'end' }}>
            <div className="col-md-4">
              <label>Interface</label>
              <select className="form-select" value={iface} onChange={(e) => setIface(e.target.value)}>
                {(ifaces?.interfaces || []).map((i) => <option key={i.name} value={i.name}>{i.name}{i.description ? ` — ${i.description}` : ''}{i.loopback ? ' (loopback)' : ''}</option>)}
              </select>
            </div>
            <div className="col-md-4">
              <label>BPF filter (optional)</label>
              <input className="form-control" value={bpf} onChange={(e) => setBpf(e.target.value)} placeholder="e.g. not port 22" />
            </div>
            <div className="col-md-2">
              <label>Window (s)</label>
              <input type="number" min={5} max={300} className="form-control" value={windowSeconds} onChange={(e) => setWindowSeconds(e.target.value)} />
            </div>
            <div className="col-md-2"><button className="cg-btn-primary w-100" onClick={start} disabled={!iface}><Icon name="radar" />Start</button></div>
          </div>
        )}
        {(error || status?.lastError) && <div style={{ color: 'var(--cg-critical)', fontSize: 13.5, marginTop: 10 }}>{error || status.lastError}</div>}
        <div style={{ fontSize: 12, color: 'var(--cg-text-muted)', marginTop: 10 }}>
          The engine sees the traffic of the machine/container it runs on. In Docker Desktop (Windows/macOS) that is the container's own network —
          for real host traffic use the <span className="cg-mono">nids-sensor</span> profile on Linux, or capture with Wireshark and upload the .pcap.
        </div>
      </div>
      {status?.alerts?.length > 0 && (
        <div className="cg-panel" style={{ marginTop: 16 }}>
          <div className="cg-panel-title">Live alerts ({status.alerts.length})</div>
          {[...status.alerts].reverse().slice(0, 30).map((a, i) => <AlertCard key={i} a={a} />)}
        </div>
      )}
      {la && la.summary && <div style={{ marginTop: 16 }}><AnalysisView r={la} /></div>}
    </>
  );
}

export default function NetworkIDS() {
  const { user } = useAuth();
  const canLive = ['admin', 'soc_analyst'].includes(user?.role);
  const [tab, setTab] = useState('upload');
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [events, setEvents] = useState([]);

  const loadEvents = () => api.get('/nids/events').then((r) => setEvents(r.data.events)).catch(() => {});
  useEffect(() => { loadEvents(); }, []);
  useDataChanged(() => loadEvents());

  const analyse = async (e) => {
    e?.preventDefault();
    if (!file) return;
    setBusy(true); setError(''); setResult(null);
    try {
      const fd = new FormData();
      fd.append('capture', file);
      const { data } = await api.post('/nids/pcap', fd, { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 300000 });
      setResult(data);
      loadEvents();
    } catch (err) {
      setError(err.response?.data?.detail || err.response?.data?.error || 'Analysis failed');
    } finally { setBusy(false); }
  };

  const form = (
    <div className="cg-panel">
      <form onSubmit={analyse}>
        <div className="cg-panel-title">Capture file</div>
        <Dropzone accept=".pcap,.pcapng,.cap" file={file} onFile={(f) => { setFile(f); setResult(null); setError(''); }}
          hint="pcap / pcapng from Wireshark, tcpdump or dumpcap, up to 200 MB" maxBytes={200 * 1024 * 1024} />
        <button type="submit" className="cg-btn-primary w-100" style={{ marginTop: 16 }} disabled={busy || !file}>
          {busy ? <><span className="cg-spinner" />Analysing traffic…</> : <><Icon name="search" />Analyse traffic</>}
        </button>
        {error && <div className="cg-error"><Icon name="alert" size={16} />{error}</div>}
        <div className="cg-note" style={{ marginTop: 14 }}>
          Samples in <span className="cg-mono">detection-engine-cpp/samples/</span>: <span className="cg-mono">normal_traffic.pcap</span>, <span className="cg-mono">attack_mix.pcap</span> and one file per attack type.
        </div>
      </form>
    </div>
  );

  return (
    <AppShell>
      <PageHeader eyebrow="Monitor · Network" title="Network intrusion detection" art="network"
        subtitle="Upload a traffic capture or monitor live. Every connection is scored by three ML models and 14 signature rules, and alerts are mapped to MITRE ATT&CK." />

      <div className="cg-tabs" role="tablist">
        <button className={`cg-tab ${tab === 'upload' ? 'active' : ''}`} onClick={() => setTab('upload')}>Analyse a capture</button>
        {canLive && <button className={`cg-tab ${tab === 'live' ? 'active' : ''}`} onClick={() => setTab('live')}>Live monitoring</button>}
        <button className={`cg-tab ${tab === 'events' ? 'active' : ''}`} onClick={() => { setTab('events'); loadEvents(); }}>Recent events</button>
      </div>

      {tab === 'upload' && (
        <ScanWorkspace form={form} busy={busy}
          emptyHints={['Gradient Boosting + Random Forest trained on NSL-KDD', 'Isolation Forest flags never-seen traffic', 'Floods, scans, brute force, beaconing, DNS tunnelling', 'One alert per attack, not per packet']}
          result={result && <AnalysisView r={result} />} />
      )}

      {tab === 'live' && canLive && <LiveCapture />}

      {tab === 'events' && (
        <div className="cg-panel">
          {events.length === 0 ? <div className="cg-muted" style={{ fontSize: 14 }}>No network analyses yet.</div> : (
            <div className="cg-table-wrap"><table className="cg-table">
              <thead><tr><th>Risk</th><th>Source</th><th>Summary</th><th>Alerts</th><th>When</th></tr></thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td><RiskBadge level={e.riskLevel} /></td>
                    <td className="cg-mono" style={{ fontSize: 12 }}>{e.source}</td>
                    <td>{e.summary}</td>
                    <td className="cg-mono" style={{ fontSize: 12 }}>{[...new Set((e.alerts || []).map((a) => a.type))].join(', ') || '—'}</td>
                    <td className="cg-mono cg-faint" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{new Date(e.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </div>
      )}
    </AppShell>
  );
}
