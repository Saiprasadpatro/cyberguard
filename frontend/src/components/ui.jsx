import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import Icon from './Icons';
import Illustration from './Illustrations';
import RiskBadge from './RiskBadge';
import FindingsList from './FindingsList';
import MlPanel, { MitreList } from './MlPanel';
import { THEMES, useSystem, useTheme } from '../context/UiContext';

/* ---------------------------------------------------------------------------
   Page header with illustration
--------------------------------------------------------------------------- */
export function PageHeader({ eyebrow, title, subtitle, art, children }) {
  return (
    <header className="cg-page-header">
      <div style={{ position: 'relative', zIndex: 1, minWidth: 0 }}>
        {eyebrow && <div className="cg-eyebrow">{eyebrow}</div>}
        <h1 className="cg-page-title">{title}</h1>
        {subtitle && <p className="cg-page-subtitle">{subtitle}</p>}
        {children && <div className="cg-page-actions">{children}</div>}
      </div>
      {art && <div className="cg-page-art"><Illustration name={art} /></div>}
    </header>
  );
}

/* ---------------------------------------------------------------------------
   Callout (info / warning / offline notices)
--------------------------------------------------------------------------- */
export function Callout({ tone = 'info', icon, title, children, style }) {
  const ic = icon || { warn: 'alert', bad: 'alert', good: 'checkCircle', info: 'info' }[tone];
  return (
    <div className={`cg-callout ${tone}`} style={style}>
      <Icon name={ic} />
      <div>{title && <strong>{title}</strong>}{children}</div>
    </div>
  );
}

export function OfflineNote({ feature, children }) {
  const { feature: f } = useSystem();
  const st = f(feature);
  if (st.available) return null;
  return <Callout tone="warn" icon="cloudOff" title={children || 'Not available right now'}>{st.reason}. Core detection (rules and ML models) still works.</Callout>;
}

/* ---------------------------------------------------------------------------
   Scan workspace: sticky form column + results column
--------------------------------------------------------------------------- */
const SCAN_STEPS = ['Parsing input', 'Running rule engines', 'Scoring with C++ ML models', 'Fusing risk score'];

export function ScanWorkspace({ form, result, busy, emptyTitle, emptyText, emptyHints = [], wide }) {
  return (
    <div className={`cg-split${wide ? ' wide-form' : ''}`}>
      <div className="cg-split-form">{form}</div>
      <div>
        {busy ? (
          <div className="cg-panel cg-scanning" aria-busy="true">
            <Illustration name="empty" className="" />
            <h3>Analysing…</h3>
            <p>This usually takes a second or two.</p>
            <div className="cg-scan-steps">
              {SCAN_STEPS.map((s, i) => <span key={s} style={{ animationDelay: `${i * 0.35}s` }}>› {s}</span>)}
            </div>
          </div>
        ) : result || (
          <div className="cg-empty">
            <Illustration name="empty" />
            <h3>{emptyTitle || 'Your verdict will appear here'}</h3>
            <p>{emptyText || 'Run a scan to see the risk score, the evidence behind it and what to do next.'}</p>
            {emptyHints.length > 0 && (
              <ul>{emptyHints.map((h) => <li key={h}><Icon name="check" />{h}</li>)}</ul>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Tabs with a sliding underline
--------------------------------------------------------------------------- */
export function Tabs({ tabs, initial }) {
  const visible = tabs.filter((t) => t && !t.hidden);
  const [active, setActive] = useState(initial && visible.some((t) => t.id === initial) ? initial : visible[0]?.id);
  const listRef = useRef(null);
  const [ink, setInk] = useState({ x: 0, w: 0 });

  useEffect(() => { if (!visible.some((t) => t.id === active)) setActive(visible[0]?.id); }, [visible, active]);

  const measure = useCallback(() => {
    const el = listRef.current?.querySelector(`[data-tab="${active}"]`);
    if (el) setInk({ x: el.offsetLeft, w: el.offsetWidth });
  }, [active]);
  useLayoutEffect(() => { measure(); }, [measure, tabs.length]);
  useEffect(() => {
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [measure]);

  const onKey = (e) => {
    const i = visible.findIndex((t) => t.id === active);
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const n = visible[(i + (e.key === 'ArrowRight' ? 1 : visible.length - 1)) % visible.length];
      setActive(n.id);
      listRef.current?.querySelector(`[data-tab="${n.id}"]`)?.focus();
    }
  };
  const current = visible.find((t) => t.id === active) || visible[0];
  return (
    <>
      <div className="cg-rtabs" role="tablist" ref={listRef} onKeyDown={onKey}>
        {visible.map((t) => (
          <button key={t.id} type="button" role="tab" data-tab={t.id} aria-selected={t.id === active} tabIndex={t.id === active ? 0 : -1}
            className={`cg-rtab${t.id === active ? ' active' : ''}`} onClick={() => setActive(t.id)}>
            {t.label}{t.count != null && <span className="cg-rtab-count">{t.count}</span>}
          </button>
        ))}
        <span className="cg-rtab-ink" style={{ width: ink.w, transform: `translateX(${ink.x}px)` }} />
      </div>
      <div role="tabpanel" key={current?.id} className="cg-rtab-panel">{current?.content}</div>
    </>
  );
}

/* ---------------------------------------------------------------------------
   Verdict: score gauge + headline + chips
--------------------------------------------------------------------------- */
const RISK_COPY = {
  Critical: 'Critical risk: act now', High: 'High risk: treat as malicious', Medium: 'Medium risk: be careful',
  Low: 'Low risk: minor warning signs', Safe: 'No significant threat found',
};
const riskVar = (lvl) => `var(--cg-${String(lvl || 'Safe').toLowerCase()})`;

export function Gauge({ score = 0, level }) {
  const r = 50;
  const c = 2 * Math.PI * r;
  const [shown, setShown] = useState(0);
  useEffect(() => { const t = requestAnimationFrame(() => setShown(Math.max(0, Math.min(100, Number(score) || 0)))); return () => cancelAnimationFrame(t); }, [score]);
  return (
    <div className="cg-gauge" role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg viewBox="0 0 120 120">
        <circle className="cg-gauge-track" cx="60" cy="60" r={r} />
        <circle className="cg-gauge-value" cx="60" cy="60" r={r} stroke={riskVar(level)} strokeDasharray={c} strokeDashoffset={c * (1 - shown / 100)} />
      </svg>
      <div className="cg-gauge-center"><span className="cg-gauge-num" style={{ color: riskVar(level) }}>{score}</span><span className="cg-gauge-of">of 100</span></div>
    </div>
  );
}

export function Verdict({ level, score, title, subtitle, chips }) {
  return (
    <div className="cg-verdict">
      <Gauge score={score} level={level} />
      <div style={{ minWidth: 0 }}>
        <RiskBadge level={level} />
        <div className="cg-verdict-title">{title || RISK_COPY[level] || level}</div>
        {subtitle && <p className="cg-verdict-sub">{subtitle}</p>}
        {chips && <div className="cg-chip-row">{chips}</div>}
      </div>
    </div>
  );
}

export function ModeChip({ mode }) {
  if (!mode) return null;
  return mode === 'offline'
    ? <span className="cg-chip cg-chip-warn" title="Analysed without internet: rules + ML models only"><Icon name="cloudOff" size={13} />Offline analysis</span>
    : <span className="cg-chip" title="Internet features were available for this analysis"><Icon name="cloud" size={13} />Online analysis</span>;
}

/* Score components as horizontal bars */
export function ComponentBars({ components }) {
  if (!components?.length) return null;
  const nice = (s) => String(s).replace(/_/g, ' ').replace(/\bml\b/i, 'ML').replace(/^\w/, (m) => m.toUpperCase());
  return (
    <div className="cg-components">
      {components.map((c, i) => {
        const v = Math.max(0, Math.min(100, Math.round(c.score || 0)));
        const col = v >= 80 ? 'var(--cg-critical)' : v >= 55 ? 'var(--cg-high)' : v >= 30 ? 'var(--cg-medium)' : v >= 10 ? 'var(--cg-low)' : 'var(--cg-safe)';
        return (
          <div key={i} className="cg-component" title={`weight ${c.weight}`}>
            <span className="cg-component-name">{nice(c.source)}</span>
            <span className="cg-component-track"><span style={{ width: `${v}%`, background: col, animationDelay: `${i * 60}ms` }} /></span>
            <span className="cg-component-val">{v}</span>
          </div>
        );
      })}
    </div>
  );
}

export function ActionList({ actions }) {
  if (!actions?.length) return null;
  return (
    <div className="cg-actions">
      {actions.map((a, i) => <div key={i} className="cg-action"><Icon name="shieldCheck" /><span>{a}</span></div>)}
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Standard result view used by every scan page
--------------------------------------------------------------------------- */
export function ResultView({ result, title, subtitle, chips, ml, summaryExtra, evidenceExtra, extraTabs = [], findings, initialTab }) {
  const f = findings || result.findings || [];
  const mitre = result.mitreAttack || [];
  const score = result.score ?? result.finalScore ?? 0;
  const allChips = (
    <>
      <ModeChip mode={result.analysisMode} />
      {result.threatCreated && <span className="cg-chip cg-chip-bad"><Icon name="flag" size={13} />Logged to dashboard</span>}
      {chips}
    </>
  );
  const tabs = [
    {
      id: 'summary', label: 'Summary',
      content: (
        <div className="cg-stack">
          {result.aiExplanation && <div className="cg-explanation">{result.aiExplanation}</div>}
          {summaryExtra}
          {result.recommendedActions?.length > 0 && (<div><div className="cg-subtitle" style={{ marginTop: 0 }}>Recommended response</div><ActionList actions={result.recommendedActions} /></div>)}
          {result.scoreComponents?.length > 0 && (<div><div className="cg-subtitle">How the score was built</div><ComponentBars components={result.scoreComponents} /></div>)}
        </div>
      ),
    },
    {
      id: 'evidence', label: 'Evidence', count: f.filter((x) => (x.weight ?? 1) > 0).length,
      content: (<div className="cg-stack"><FindingsList findings={f} />{evidenceExtra}</div>),
    },
    ...extraTabs,
    ml && { id: 'ml', label: 'ML model', hidden: !result.ml && !ml.node, content: ml.node || <MlPanel ml={result.ml} title={ml.title} label={ml.label} /> },
    { id: 'mitre', label: 'MITRE ATT&CK', count: mitre.length, hidden: mitre.length === 0, content: <MitreList items={mitre} /> },
  ].filter(Boolean);
  return (
    <div className="cg-panel" style={{ animation: 'cg-rise 420ms var(--cg-ease) both' }}>
      <Verdict level={result.riskLevel} score={score} title={title} subtitle={subtitle} chips={allChips} />
      <Tabs tabs={tabs} initial={initialTab} />
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Confirm dialog
--------------------------------------------------------------------------- */
export function ConfirmDialog({ open, title, body, confirmLabel = 'Continue', cancelLabel = 'Cancel', tone = 'danger', icon = 'alert', busy, onConfirm, onCancel }) {
  const cancelRef = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const prev = document.activeElement;
    cancelRef.current?.focus();
    const onKey = (e) => { if (e.key === 'Escape') onCancel(); };
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('keydown', onKey); if (prev && prev.focus) prev.focus(); };
  }, [open, onCancel]);
  if (!open) return null;
  return createPortal(
    <div className="cg-modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onCancel(); }}>
      <div className="cg-modal" role="alertdialog" aria-modal="true" aria-labelledby="cg-modal-title" aria-describedby="cg-modal-body">
        <div className="cg-modal-icon" style={tone === 'danger' ? undefined : { background: 'var(--cg-accent-soft)', color: 'var(--cg-accent-bright)' }}><Icon name={icon} /></div>
        <h2 id="cg-modal-title">{title}</h2>
        <p id="cg-modal-body">{body}</p>
        <div className="cg-modal-actions">
          <button ref={cancelRef} type="button" className="cg-btn-outline" onClick={onCancel} disabled={busy}>{cancelLabel}</button>
          <button type="button" className={tone === 'danger' ? 'cg-btn-danger solid' : 'cg-btn-primary'} onClick={onConfirm} disabled={busy}>
            {busy ? <><span className="cg-spinner" />Working…</> : confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}

/* ---------------------------------------------------------------------------
   Header widgets
--------------------------------------------------------------------------- */
function useOutside(ref, onOut, active) {
  useEffect(() => {
    if (!active) return undefined;
    const fn = (e) => { if (ref.current && !ref.current.contains(e.target)) onOut(); };
    const key = (e) => { if (e.key === 'Escape') onOut(); };
    document.addEventListener('mousedown', fn);
    document.addEventListener('keydown', key);
    return () => { document.removeEventListener('mousedown', fn); document.removeEventListener('keydown', key); };
  }, [ref, onOut, active]);
}

const FEATURE_NAMES = [
  ['coreDetection', 'Rules & C++ ML models'],
  ['gemini', 'Gemini AI explanations'],
  ['gmail', 'Gmail inbox connection'],
  ['liveUrlCheck', 'Live website inspection'],
];

export function SystemBadge() {
  const { status, online, feature } = useSystem();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const close = useCallback(() => setOpen(false), []);
  useOutside(ref, close, open);
  const label = online ? 'Online' : 'Offline';
  return (
    <div className="cg-status-wrap" ref={ref}>
      <button type="button" className={`cg-status${online ? '' : ' offline'}`} onClick={() => setOpen((o) => !o)} aria-expanded={open}
        style={{ cursor: 'pointer' }} title={online ? 'All features available' : 'Running offline: rules and ML still work'}>
        <span className="cg-status-dot" /><span className="cg-status-label">{label}</span>
        {status.mode !== 'auto' && <span className="cg-faint" style={{ fontWeight: 500 }}>· {status.mode === 'offline' ? 'forced' : 'fixed'}</span>}
      </button>
      {open && (
        <div className="cg-status-pop" role="dialog" aria-label="System status">
          <h4>{online ? 'Online mode' : 'Offline mode'} · {status.mode === 'auto' ? 'automatic' : `set to ${status.mode}`}</h4>
          {FEATURE_NAMES.map(([k, n]) => {
            const f = k === 'coreDetection' ? { available: true } : feature(k);
            return (
              <div key={k} className="cg-feature-state">
                <Icon name={f.available ? 'checkCircle' : 'cloudOff'} className={f.available ? 'cg-ok' : 'cg-off'} />
                <div>{n}{!f.available && f.reason && <small>{f.reason}</small>}</div>
              </div>
            );
          })}
          <div className="cg-faint" style={{ fontSize: 11.5, marginTop: 10 }}>Offline mode keeps every scan on this machine: nothing is sent to the internet.</div>
        </div>
      )}
    </div>
  );
}

export function ThemeSwitcher() {
  const { theme, setTheme } = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const close = useCallback(() => setOpen(false), []);
  useOutside(ref, close, open);
  return (
    <div className="cg-theme-wrap" ref={ref}>
      <button type="button" className="cg-icon-btn" aria-label="Change theme" aria-expanded={open} onClick={() => setOpen((o) => !o)} title="Theme">
        <Icon name="palette" />
      </button>
      {open && (
        <div className="cg-theme-pop" role="menu">
          <h4>Theme</h4>
          {THEMES.map((t) => (
            <button key={t.id} type="button" role="menuitemradio" aria-checked={theme === t.id} className={`cg-theme-option${theme === t.id ? ' active' : ''}`}
              onClick={() => { setTheme(t.id); setOpen(false); }}>
              <span className="cg-swatch" style={{ background: t.swatch[0] }}><i style={{ background: t.swatch[1] }} /><i style={{ background: t.swatch[2] }} /></span>
              <span>{t.name}<small>{t.note}</small></span>
              {theme === t.id && <Icon name="check" size={16} className="cg-ok" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
