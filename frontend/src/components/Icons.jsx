import React from 'react';

// One consistent line-icon set (24px grid, 1.8px stroke, currentColor), drawn
// for CyberGuard so the UI does not rely on an external icon font or CDN.
const P = {
  dashboard: <><rect x="3.5" y="3.5" width="7" height="8" rx="1.6" /><rect x="13.5" y="3.5" width="7" height="5" rx="1.6" /><rect x="13.5" y="11.5" width="7" height="9" rx="1.6" /><rect x="3.5" y="14.5" width="7" height="6" rx="1.6" /></>,
  mail: <><rect x="3" y="5.5" width="18" height="13" rx="2.2" /><path d="m3.8 7 8.2 6 8.2-6" /></>,
  inbox: <><path d="M3.5 13.5 6 5.8A1.8 1.8 0 0 1 7.7 4.5h8.6A1.8 1.8 0 0 1 18 5.8l2.5 7.7" /><path d="M3.5 13.5V18a1.5 1.5 0 0 0 1.5 1.5h14a1.5 1.5 0 0 0 1.5-1.5v-4.5h-5l-1.3 2.2h-4.4L8.5 13.5z" /></>,
  link: <><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.2 1.2" /><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.2-1.2" /></>,
  image: <><rect x="3.5" y="4.5" width="17" height="15" rx="2.2" /><circle cx="9" cy="10" r="1.8" /><path d="m4 17.5 4.8-4.5 3.4 3 3.3-3.2L20 17.2" /></>,
  wave: <><path d="M3 12h1.5M6.5 8v8M10 5v14M13.5 9v6M17 7v10M20.5 11v2" /></>,
  video: <><rect x="3" y="6" width="13" height="12" rx="2.2" /><path d="m16 10.2 5-2.7v9l-5-2.7" /></>,
  terminal: <><rect x="3" y="4.5" width="18" height="15" rx="2.2" /><path d="m7 10 3 2.5L7 15M12.5 15h4.5" /></>,
  network: <><circle cx="12" cy="5.5" r="2.2" /><circle cx="5.5" cy="18" r="2.2" /><circle cx="18.5" cy="18" r="2.2" /><path d="M11 7.5 6.6 16M13 7.5l4.4 8.5M7.7 18h8.6" /></>,
  model: <><circle cx="6" cy="6" r="2" /><circle cx="6" cy="18" r="2" /><circle cx="18" cy="12" r="2" /><circle cx="12" cy="12" r="1.6" /><path d="M7.7 7.2 10.6 11M7.7 16.8l2.9-3.8M13.6 12h2.4" /></>,
  history: <><path d="M3.8 12a8.2 8.2 0 1 0 2.4-5.8" /><path d="M3.5 4.5v4h4" /><path d="M12 8v4.3l2.8 1.7" /></>,
  admin: <><path d="M12 3.2 19.5 6v5.2c0 4.6-3.1 8.2-7.5 9.6-4.4-1.4-7.5-5-7.5-9.6V6z" /><circle cx="12" cy="10.5" r="2.3" /><path d="M8.3 16.2c.8-1.5 2.1-2.3 3.7-2.3s2.9.8 3.7 2.3" /></>,
  logout: <><path d="M14.5 4.5h3a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2h-3" /><path d="M10 16.5 5.5 12 10 7.5M5.8 12H15" /></>,
  shield: <><path d="M12 2.8 20 6v5.6c0 5-3.4 8.8-8 10.4-4.6-1.6-8-5.4-8-10.4V6z" /></>,
  shieldCheck: <><path d="M12 2.8 20 6v5.6c0 5-3.4 8.8-8 10.4-4.6-1.6-8-5.4-8-10.4V6z" /><path d="m8.5 12.2 2.4 2.4 4.8-5" /></>,
  check: <path d="m5 12.5 4.2 4.2L19 7" />,
  checkCircle: <><circle cx="12" cy="12" r="8.5" /><path d="m8.3 12.2 2.6 2.6 4.9-5.1" /></>,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  alert: <><path d="M10.4 4.3 2.9 17.5A1.8 1.8 0 0 0 4.5 20.2h15a1.8 1.8 0 0 0 1.6-2.7L13.6 4.3a1.8 1.8 0 0 0-3.2 0z" /><path d="M12 9.5v4.2M12 17h.01" /></>,
  info: <><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5M12 8h.01" /></>,
  trash: <><path d="M4.5 7h15M9.5 7V5.2A1.2 1.2 0 0 1 10.7 4h2.6a1.2 1.2 0 0 1 1.2 1.2V7" /><path d="m6.3 7 .8 11.4A1.8 1.8 0 0 0 8.9 20h6.2a1.8 1.8 0 0 0 1.8-1.6L17.7 7" /><path d="M10.2 11v5M13.8 11v5" /></>,
  reset: <><path d="M4.2 12a7.8 7.8 0 1 0 2.3-5.5" /><path d="M4 4.5v4h4" /></>,
  search: <><circle cx="10.8" cy="10.8" r="6.3" /><path d="m15.5 15.5 4.5 4.5" /></>,
  menu: <path d="M4 7h16M4 12h16M4 17h10" />,
  chevronLeft: <path d="m14.5 6-6 6 6 6" />,
  chevronRight: <path d="m9.5 6 6 6-6 6" />,
  arrowRight: <><path d="M5 12h14M13 6l6 6-6 6" /></>,
  cloud: <path d="M7 18.5h10.5a4 4 0 0 0 .6-7.95A5.5 5.5 0 0 0 7.5 9 4.75 4.75 0 0 0 7 18.5z" />,
  cloudOff: <><path d="M3 3l18 18" /><path d="M9 6.3A5.5 5.5 0 0 1 18.1 10.55 4 4 0 0 1 20.8 16.9M16 18.5H7a4.75 4.75 0 0 1-2.2-8.95" /></>,
  palette: <><path d="M12 3.5a8.5 8.5 0 0 0 0 17c1.2 0 1.8-.9 1.4-2l-.3-.8c-.4-1.2.4-2.2 1.6-2.2h1.8a4 4 0 0 0 4-4c0-4.5-3.8-8-8.5-8z" /><circle cx="7.8" cy="11" r="1.1" /><circle cx="10.5" cy="7.5" r="1.1" /><circle cx="15" cy="7.8" r="1.1" /></>,
  upload: <><path d="M12 15V4.5M7.5 9 12 4.5 16.5 9" /><path d="M4.5 15v3a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-3" /></>,
  bolt: <path d="M13 2.8 5.5 13.2h5.5l-1 8 7.5-10.4h-5.5z" />,
  eye: <><path d="M2.8 12S6.2 5.5 12 5.5 21.2 12 21.2 12 17.8 18.5 12 18.5 2.8 12 2.8 12z" /><circle cx="12" cy="12" r="2.8" /></>,
  flag: <><path d="M5.5 21V4.5" /><path d="M5.5 5h11l-2 4 2 4h-11" /></>,
  target: <><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="4.5" /><circle cx="12" cy="12" r="1" /></>,
  layers: <><path d="m12 3.5 8.5 4.5L12 12.5 3.5 8z" /><path d="m3.5 12 8.5 4.5 8.5-4.5M3.5 16l8.5 4.5 8.5-4.5" /></>,
  wifiOff: <><path d="M3 3l18 18" /><path d="M8.5 16a5 5 0 0 1 6.9-.2M5.2 12.6a9.5 9.5 0 0 1 4-2.4M12 17.8h.01M15.4 10.6a9.6 9.6 0 0 1 3.4 2M2.5 9.3a14 14 0 0 1 4.3-2.6M10.9 5.1a14.2 14.2 0 0 1 10.6 4.2" /></>,
  radar: <><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="4.5" /><path d="M12 12 18 6" /></>,
};

export default function Icon({ name, size, title, className, strokeWidth = 1.8 }) {
  const body = P[name];
  if (!body) return null;
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth={strokeWidth}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden={title ? undefined : true} role={title ? 'img' : undefined}>
      {title && <title>{title}</title>}
      {body}
    </svg>
  );
}

// CyberGuard mark: a shield built from a scan arc and a check.
export function Logo({ className }) {
  return (
    <svg viewBox="0 0 40 40" className={className} aria-hidden="true">
      <path d="M20 3.5 33.5 8.6v9.6c0 8.4-5.7 14.8-13.5 17.6C12.2 33 6.5 26.6 6.5 18.2V8.6z" fill="currentColor" opacity=".14" />
      <path d="M20 3.5 33.5 8.6v9.6c0 8.4-5.7 14.8-13.5 17.6C12.2 33 6.5 26.6 6.5 18.2V8.6z" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
      <path d="M13 19.5a7 7 0 0 1 12.4-4.4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" opacity=".55" />
      <path d="m14.6 20.2 3.9 3.9 7.2-7.6" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
