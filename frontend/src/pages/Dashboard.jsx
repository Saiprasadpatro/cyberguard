import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area, CartesianGrid } from 'recharts';
import AppShell from '../components/AppShell';
import RiskBadge from '../components/RiskBadge';
import Icon from '../components/Icons';
import { PageHeader } from '../components/ui';
import { useDataChanged, useTheme } from '../context/UiContext';
import { useAuth } from '../context/AuthContext';
import api from '../api/api';

const QUICK = [
  { to: '/scan/message', icon: 'mail', t: 'Check a message', d: 'Email, SMS or chat' },
  { to: '/scan/url', icon: 'link', t: 'Check a link', d: 'Real owner, redirects' },
  { to: '/scan/image', icon: 'image', t: 'Check an image', d: 'Edits and QR codes' },
  { to: '/scan/audio', icon: 'wave', t: 'Check a voice note', d: 'Cloned voices' },
  { to: '/nids', icon: 'network', t: 'Analyse traffic', d: 'pcap or live capture' },
  { to: '/scan/logs', icon: 'terminal', t: 'Analyse logs', d: 'Insider and API abuse' },
];
const LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Safe'];
const nice = (s) => String(s || '').replace(/_/g, ' ');

function greeting() {
  const h = new Date().getHours();
  return h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : 'Good evening';
}

export default function Dashboard() {
  const { user } = useAuth();
  const { colors } = useTheme();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const mounted = useRef(true);
  useEffect(() => () => { mounted.current = false; }, []);

  const load = useCallback(() => api.get('/dashboard/summary')
    .then((res) => { if (mounted.current) { setData(res.data); setError(''); } })
    .catch((err) => { if (mounted.current) setError(err.response?.data?.error || 'Could not load dashboard data'); }), []);
  useEffect(() => { load(); }, [load]);
  // Deleting or restoring scans anywhere refreshes these numbers immediately.
  useDataChanged(() => load());

  const tip = { contentStyle: { background: colors.surface, border: `1px solid ${colors.border}`, borderRadius: 8, fontSize: 12, color: colors.text }, itemStyle: { color: colors.text }, labelStyle: { color: colors.muted } };
  const risk = data ? LEVELS.map((l) => ({ riskLevel: l, count: data.riskBreakdown.find((r) => r.riskLevel === l)?.count || 0 })).filter((r) => r.count > 0) : [];
  const critical = data?.riskBreakdown.find((r) => r.riskLevel === 'Critical')?.count || 0;
  const firstName = (user?.fullName || '').split(' ')[0];

  return (
    <AppShell>
      <PageHeader eyebrow={greeting() + (firstName ? `, ${firstName}` : '')} title="Security command dashboard" art="dashboard"
        subtitle="Everything CyberGuard has analysed on your account: what was found, how serious it is and what needs attention.">
        <Link to="/scan/message" className="cg-btn-primary"><Icon name="search" />New scan</Link>
        <Link to="/history" className="cg-btn-outline"><Icon name="history" />Scan history</Link>
      </PageHeader>

      {error && <div className="cg-panel cg-error" style={{ marginTop: 0, marginBottom: 16 }}><Icon name="alert" size={16} />{error}</div>}

      {!data && !error && (
        <div aria-busy="true" aria-label="Loading dashboard">
          <div className="cg-metric-grid">{[0, 1, 2, 3].map((i) => <div key={i} className="cg-skeleton" style={{ height: 112 }} />)}</div>
          <div className="cg-bento"><div className="cg-span-8"><div className="cg-skeleton" style={{ height: 290 }} /></div><div className="cg-span-4"><div className="cg-skeleton" style={{ height: 290 }} /></div></div>
        </div>
      )}

      {data && (
        <>
          <div className="cg-metric-grid">
            <Metric icon="layers" label="Events analysed" value={data.totalEventsAnalysed} />
            <Metric icon="target" label="Threats detected" value={data.threatsDetected} />
            <Metric icon="flag" label="Open threats" value={data.openThreats} accent="var(--cg-high)" />
            <Metric icon="alert" label="Critical events" value={critical} accent="var(--cg-critical)" />
          </div>

          <div className="cg-bento">
            <section className="cg-panel cg-span-8">
              <div className="cg-panel-head"><div className="cg-panel-title">Attack timeline · last 14 days</div><span className="cg-faint" style={{ fontSize: 12 }}>scans per day</span></div>
              {data.attackTimeline.length === 0 ? <Empty text="No scans in the last 14 days." /> : (
                <ResponsiveContainer width="100%" height={230}>
                  <AreaChart data={data.attackTimeline} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
                    <defs>
                      <linearGradient id="cgArea" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={colors.accent} stopOpacity={0.35} />
                        <stop offset="100%" stopColor={colors.accent} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke={colors.border} strokeDasharray="3 4" vertical={false} />
                    <XAxis dataKey="day" tick={{ fill: colors.faint, fontSize: 11 }} axisLine={false} tickLine={false} tickFormatter={(d) => String(d).slice(5)} />
                    <YAxis tick={{ fill: colors.faint, fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip {...tip} />
                    <Area type="monotone" dataKey="count" name="scans" stroke={colors.accent} strokeWidth={2.2} fill="url(#cgArea)" dot={{ r: 3, fill: colors.accent }} activeDot={{ r: 5 }} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </section>

            <section className="cg-panel cg-span-4">
              <div className="cg-panel-title">Risk levels</div>
              {risk.length === 0 ? <Empty text="No scans yet." /> : (
                <>
                  <div style={{ position: 'relative' }}>
                    <ResponsiveContainer width="100%" height={190}>
                      <PieChart>
                        <Pie data={risk} dataKey="count" nameKey="riskLevel" innerRadius={58} outerRadius={82} paddingAngle={2} stroke={colors.surface} strokeWidth={2}>
                          {risk.map((r) => <Cell key={r.riskLevel} fill={colors.risk[r.riskLevel]} />)}
                        </Pie>
                        <Tooltip {...tip} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', pointerEvents: 'none' }}>
                      <div style={{ textAlign: 'center' }}><div className="cg-mono" style={{ fontSize: 24, fontWeight: 600 }}>{data.totalEventsAnalysed}</div><div className="cg-faint" style={{ fontSize: 11 }}>scans</div></div>
                    </div>
                  </div>
                  <div className="cg-legend">{risk.map((r) => <span key={r.riskLevel}><i style={{ background: colors.risk[r.riskLevel] }} />{r.riskLevel} {r.count}</span>)}</div>
                </>
              )}
            </section>

            <section className="cg-panel cg-span-7">
              <div className="cg-panel-title">Threat categories</div>
              {data.categoryBreakdown.length === 0 ? <Empty text="No threats recorded." /> : (
                <ResponsiveContainer width="100%" height={Math.max(160, data.categoryBreakdown.length * 34)}>
                  <BarChart data={data.categoryBreakdown.map((c) => ({ ...c, category: nice(c.category) }))} layout="vertical" margin={{ left: 8, right: 16 }}>
                    <XAxis type="number" tick={{ fill: colors.faint, fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="category" width={130} tick={{ fill: colors.text, fontSize: 12 }} axisLine={false} tickLine={false} />
                    <Tooltip {...tip} cursor={{ fill: colors.raised }} />
                    <Bar dataKey="count" name="threats" fill={colors.accent} radius={[0, 5, 5, 0]} barSize={14} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </section>

            <section className="cg-panel cg-span-5">
              <div className="cg-panel-title">Start a scan</div>
              <div className="cg-quick" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(min(170px, 100%), 1fr))' }}>
                {QUICK.map((q) => (
                  <Link key={q.to} to={q.to}>
                    <span className="cg-quick-icon"><Icon name={q.icon} /></span>
                    <span style={{ minWidth: 0 }}><strong>{q.t}</strong><small>{q.d}</small></span>
                  </Link>
                ))}
              </div>
            </section>

            <section className="cg-panel cg-span-12">
              <div className="cg-panel-head">
                <div className="cg-panel-title">Recent threats</div>
                <Link to="/history" className="cg-btn-ghost" style={{ fontSize: 13 }}>View all scans<Icon name="arrowRight" size={15} /></Link>
              </div>
              {data.recentThreats.length === 0 ? <Empty text="No threats recorded yet. Run a scan to get started." /> : (
                <div className="cg-table-wrap">
                  <table className="cg-table">
                    <thead><tr><th>Category</th><th>Risk</th><th>Status</th><th>Detected</th><th>Recommended action</th></tr></thead>
                    <tbody>
                      {data.recentThreats.map((t) => (
                        <tr key={t.id}>
                          <td style={{ textTransform: 'capitalize', fontWeight: 500 }}>{nice(t.category)}</td>
                          <td><RiskBadge level={t.riskLevel} /></td>
                          <td><span className={`cg-chip ${t.status === 'open' ? 'cg-chip-warn' : 'cg-chip-good'}`}>{nice(t.status)}</span></td>
                          <td className="cg-mono cg-faint" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{new Date(t.createdAt).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}</td>
                          <td style={{ maxWidth: 380, fontSize: 13 }}>{t.recommendedAction}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>
        </>
      )}
    </AppShell>
  );
}

function Empty({ text }) {
  return <div className="cg-faint" style={{ fontSize: 13.5, padding: '26px 0', textAlign: 'center' }}>{text}</div>;
}

// Animates a number from its previous value to the new one (ease-out).
function useCountUp(target, ms = 800) {
  const [v, setV] = useState(0);
  const from = useRef(0);
  useEffect(() => {
    const end = Number(target) || 0;
    const start = from.current;
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) { setV(end); from.current = end; return undefined; }
    const t0 = performance.now();
    let raf = 0;
    const tick = (now) => {
      const p = Math.min(1, (now - t0) / ms);
      setV(Math.round(start + (end - start) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick); else from.current = end;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

function Metric({ icon, label, value, accent }) {
  const shown = useCountUp(value);
  return (
    <div className="cg-metric">
      <div className="cg-metric-top">
        <span className="cg-metric-icon" style={accent ? { color: accent, background: `color-mix(in srgb, ${accent} 14%, transparent)` } : undefined}><Icon name={icon} /></span>
      </div>
      <div className="cg-metric-value" style={accent && value > 0 ? { color: accent } : undefined}>{shown}</div>
      <div className="cg-metric-label">{label}</div>
    </div>
  );
}
