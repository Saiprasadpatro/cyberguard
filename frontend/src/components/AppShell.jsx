import React, { createContext, useContext, useEffect, useRef, useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { store } from '../context/UiContext';
import Icon, { Logo } from './Icons';
import { SystemBadge, ThemeSwitcher } from './ui';

export const NAV = [
  { group: 'Overview', items: [{ to: '/', label: 'Dashboard', icon: 'dashboard' }] },
  {
    group: 'Detect',
    items: [
      { to: '/scan/message', label: 'Message & Email', icon: 'mail' },
      { to: '/gmail', label: 'Gmail Inbox', icon: 'inbox' },
      { to: '/scan/url', label: 'URL & Website', icon: 'link' },
      { to: '/scan/image', label: 'Image & QR', icon: 'image' },
      { to: '/scan/audio', label: 'Voice & Audio', icon: 'wave' },
      { to: '/scan/video', label: 'Video', icon: 'video' },
    ],
  },
  {
    group: 'Monitor',
    items: [
      { to: '/scan/logs', label: 'Log Threats', icon: 'terminal' },
      { to: '/nids', label: 'Network IDS', icon: 'network' },
    ],
  },
  {
    group: 'Workspace',
    items: [
      { to: '/history', label: 'Scan History', icon: 'history' },
      { to: '/ml', label: 'ML Models', icon: 'model' },
    ],
  },
];

const ALL = NAV.flatMap((g) => g.items.map((i) => ({ ...i, group: g.group })));
const initials = (name = '') => name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('') || 'U';

// Pages still wrap themselves in <AppShell>, but the real shell is mounted once
// as a layout route (see App.jsx). Nested shells just render their content, so
// the sidebar never remounts or flickers when you change pages.
const ShellCtx = createContext(false);

export default function AppShell({ children }) {
  const inShell = useContext(ShellCtx);
  if (inShell) return children;
  return <ShellFrame>{children}</ShellFrame>;
}

function ShellFrame({ children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const mainRef = useRef(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(() => store.get('cg_sidebar', 'open') === 'collapsed');

  // New page: close the mobile drawer and start the workspace at the top.
  useEffect(() => {
    setMenuOpen(false);
    if (mainRef.current) mainRef.current.scrollTop = 0;
    window.scrollTo(0, 0);
  }, [location.pathname]);
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') setMenuOpen(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  useEffect(() => {
    document.body.style.overflow = menuOpen ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [menuOpen]);

  const toggleCollapsed = () => setCollapsed((c) => { store.set('cg_sidebar', c ? 'open' : 'collapsed'); return !c; });
  const current = ALL.find((n) => (n.to === '/' ? location.pathname === '/' : location.pathname.startsWith(n.to)))
    || (location.pathname.startsWith('/admin') ? { label: 'Admin Console', group: 'Workspace' } : { label: 'CyberGuard', group: '' });

  useEffect(() => { document.title = `${current.label} · CyberGuard`; }, [current.label]);

  const link = (item) => (
    <NavLink key={item.to} to={item.to} end={item.to === '/'} title={collapsed ? item.label : undefined}
      className={({ isActive }) => `cg-nav-link${isActive ? ' active' : ''}`}>
      <Icon name={item.icon} /><span className="cg-nav-text">{item.label}</span>
    </NavLink>
  );

  return (
    <div className={`cg-app-shell${collapsed ? ' collapsed' : ''}`}>
      {menuOpen && <div className="cg-backdrop" onClick={() => setMenuOpen(false)} aria-hidden="true" />}

      <aside className={`cg-sidebar${menuOpen ? ' open' : ''}`} aria-label="Main navigation">
        <div className="cg-brand">
          <Logo className="cg-brand-logo" />
          <div className="cg-brand-text">
            <div className="cg-brand-name">CyberGuard</div>
            <div className="cg-brand-tag">Threat defence</div>
          </div>
          <button type="button" className="cg-collapse-btn" onClick={toggleCollapsed} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} title={collapsed ? 'Expand' : 'Collapse'}>
            <Icon name="chevronLeft" size={16} />
          </button>
          <button type="button" className="cg-icon-btn cg-close-btn" aria-label="Close menu" onClick={() => setMenuOpen(false)}><Icon name="x" /></button>
        </div>

        <nav>
          {NAV.map((g) => (
            <div className="cg-nav-group" key={g.group}>
              <div className="cg-nav-label">{g.group}</div>
              {g.items.map(link)}
              {g.group === 'Workspace' && user?.role === 'admin' && link({ to: '/admin', label: 'Admin Console', icon: 'admin' })}
            </div>
          ))}
        </nav>

        <div className="cg-sidebar-footer">
          <div className="cg-user" title={collapsed ? user?.fullName : undefined}>
            <div className="cg-avatar">{initials(user?.fullName)}</div>
            <div className="cg-user-meta">
              <div className="cg-user-name">{user?.fullName}</div>
              <div className="cg-user-role">{user?.role?.toUpperCase()}</div>
            </div>
          </div>
          <button className="cg-btn-ghost cg-logout" onClick={() => { logout(); navigate('/login'); }} title="Log out">
            <Icon name="logout" size={16} /><span className="cg-logout-label">Log out</span>
          </button>
        </div>
      </aside>

      <main className="cg-main" ref={mainRef} id="cg-main">
        <header className="cg-header">
          <button type="button" className="cg-menu-btn" aria-label="Open menu" aria-expanded={menuOpen} onClick={() => setMenuOpen(true)}>
            <Icon name="menu" />
          </button>
          <div className="cg-crumbs">
            {current.group && <><span className="cg-crumb-parent">{current.group}</span><Icon name="chevronRight" size={14} className="cg-crumb-parent" /></>}
            <strong>{current.label}</strong>
          </div>
          <div className="cg-header-actions">
            <SystemBadge />
            <ThemeSwitcher />
          </div>
        </header>
        {/* key = route: remounting replays the page-enter animation on every navigation */}
        <div className="cg-content"><ShellCtx.Provider value={true}><div className="cg-page" key={location.pathname}>{children}</div></ShellCtx.Provider></div>
      </main>
    </div>
  );
}
