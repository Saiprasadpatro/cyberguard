import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import api from '../api/api';
import Icon from '../components/Icons';

/* ---------------------------------------------------------------------------
   Safe localStorage (private mode / blocked storage must never crash the app)
--------------------------------------------------------------------------- */
export const store = {
  get(key, fallback) { try { const v = window.localStorage.getItem(key); return v == null ? fallback : v; } catch (e) { return fallback; } },
  set(key, value) { try { window.localStorage.setItem(key, value); } catch (e) { /* ignore */ } },
};

/* ---------------------------------------------------------------------------
   Data-changed bus: when scans are deleted/restored anywhere, open views
   (dashboard, history, Gmail list) refresh themselves.
--------------------------------------------------------------------------- */
const DATA_EVENT = 'cg:data-changed';
export const emitDataChanged = (detail) => window.dispatchEvent(new CustomEvent(DATA_EVENT, { detail }));
export function useDataChanged(handler) {
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => {
    const fn = (e) => ref.current && ref.current(e.detail);
    window.addEventListener(DATA_EVENT, fn);
    return () => window.removeEventListener(DATA_EVENT, fn);
  }, []);
}

/* ---------------------------------------------------------------------------
   Theme
--------------------------------------------------------------------------- */
export const THEMES = [
  { id: 'midnight', name: 'Midnight', note: 'Dark navy, for SOC screens', swatch: ['#0A111D', '#3AA6E8', '#8F9DB4'] },
  { id: 'daylight', name: 'Daylight', note: 'Light, for projectors and print', swatch: ['#F3F5F9', '#1F56A8', '#C4CEDC'] },
  { id: 'graphite', name: 'Graphite', note: 'Neutral dark, low glare', swatch: ['#121316', '#9AAEFF', '#6E737D'] },
];
const ThemeCtx = createContext(null);

function readThemeColors() {
  const cs = getComputedStyle(document.documentElement);
  const v = (n) => cs.getPropertyValue(n).trim();
  return {
    text: v('--cg-text'), muted: v('--cg-text-muted'), faint: v('--cg-text-faint'), border: v('--cg-border'),
    surface: v('--cg-surface'), raised: v('--cg-surface-raised'), accent: v('--cg-accent'), accentBright: v('--cg-accent-bright'),
    risk: { Safe: v('--cg-safe'), Low: v('--cg-low'), Medium: v('--cg-medium'), High: v('--cg-high'), Critical: v('--cg-critical') },
  };
}

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    const saved = store.get('cg_theme', 'midnight');
    return THEMES.some((t) => t.id === saved) ? saved : 'midnight';
  });
  const [colors, setColors] = useState(null);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', THEMES.find((t) => t.id === theme).swatch[0]);
    setColors(readThemeColors());
  }, [theme]);

  const setTheme = useCallback((id) => { setThemeState(id); store.set('cg_theme', id); }, []);
  const value = useMemo(() => ({ theme, setTheme, colors: colors || readThemeColors() }), [theme, setTheme, colors]);
  return <ThemeCtx.Provider value={value}>{children}</ThemeCtx.Provider>;
}
export const useTheme = () => useContext(ThemeCtx);

/* ---------------------------------------------------------------------------
   System status (online / offline mode)
--------------------------------------------------------------------------- */
const SystemCtx = createContext(null);
const DEFAULT_STATUS = { mode: 'auto', effective: 'online', online: true, features: {}, unknown: true };

export function SystemProvider({ children }) {
  const [status, setStatus] = useState(DEFAULT_STATUS);
  const [browserOnline, setBrowserOnline] = useState(typeof navigator === 'undefined' ? true : navigator.onLine !== false);

  const refresh = useCallback(() => api.get('/system/status', { timeout: 6000 })
    .then((r) => setStatus({ ...r.data, unknown: false }))
    .catch(() => setStatus((s) => ({ ...s, unknown: true }))), []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 60000);
    const on = () => { setBrowserOnline(true); refresh(); };
    const off = () => setBrowserOnline(false);
    window.addEventListener('online', on);
    window.addEventListener('offline', off);
    return () => { clearInterval(t); window.removeEventListener('online', on); window.removeEventListener('offline', off); };
  }, [refresh]);

  const value = useMemo(() => {
    const online = status.online !== false;
    const feature = (name) => {
      const f = status.features?.[name];
      if (!f) return { available: online, reason: online ? null : 'Offline mode' };
      return f;
    };
    return { status, online, browserOnline, feature, refresh };
  }, [status, browserOnline, refresh]);
  return <SystemCtx.Provider value={value}>{children}</SystemCtx.Provider>;
}
export const useSystem = () => useContext(SystemCtx);

/* ---------------------------------------------------------------------------
   Toasts: one thin bar at the bottom, with an optional action (e.g. Undo)
--------------------------------------------------------------------------- */
const ToastCtx = createContext(null);

export function ToastProvider({ children }) {
  const [toast, setToast] = useState(null);
  const [leaving, setLeaving] = useState(false);
  const timer = useRef(null);
  const outTimer = useRef(null);
  const seq = useRef(0);

  const dismiss = useCallback((id) => {
    setLeaving(true);
    clearTimeout(outTimer.current);
    outTimer.current = setTimeout(() => {
      setToast((t) => (id == null || (t && t.id === id) ? null : t));
      setLeaving(false);
    }, 190);
  }, []);

  const show = useCallback((opts) => {
    const id = ++seq.current;
    const duration = opts.duration ?? 3000;
    clearTimeout(timer.current);
    clearTimeout(outTimer.current);
    setLeaving(false);
    const t = { id, duration, tone: 'default', ...opts };
    setToast(t);
    timer.current = setTimeout(() => {
      if (t.onExpire) { try { t.onExpire(); } catch (e) { /* ignore */ } }
      dismiss(id);
    }, duration);
    return id;
  }, [dismiss]);

  useEffect(() => () => { clearTimeout(timer.current); clearTimeout(outTimer.current); }, []);

  const runAction = () => {
    if (!toast?.action) return;
    clearTimeout(timer.current);
    const fn = toast.action.onClick;
    dismiss(toast.id);
    try { fn(); } catch (e) { /* ignore */ }
  };

  return (
    <ToastCtx.Provider value={{ show, dismiss }}>
      {children}
      <div className="cg-toast-host" aria-live="polite" role="status">
        {toast && (
          <div key={toast.id} className={`cg-toast${leaving ? ' out' : ''}${toast.tone === 'error' ? ' error' : ''}`}>
            <span className="cg-toast-msg">{toast.message}</span>
            {toast.action && <button type="button" className="cg-toast-action" onClick={runAction}>{toast.action.label}</button>}
            <button type="button" className="cg-toast-close" aria-label="Dismiss" onClick={() => { clearTimeout(timer.current); if (toast.onExpire) { try { toast.onExpire(); } catch (e) { /* ignore */ } } dismiss(toast.id); }}>
              <Icon name="x" />
            </button>
            <span className="cg-toast-progress" style={{ animationDuration: `${toast.duration}ms` }} />
          </div>
        )}
      </div>
    </ToastCtx.Provider>
  );
}
export const useToast = () => useContext(ToastCtx);
