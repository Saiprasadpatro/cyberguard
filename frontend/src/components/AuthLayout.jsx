import React from 'react';
import { Logo } from './Icons';
import { ThemeSwitcher } from './ui';

// Split-screen layout for Login / Register: an animated brand panel on the
// left (hidden on phones) and the form card on the right.
const POINTS = [
  ['Phishing, spam & deepfakes', 'Email, SMS, Gmail, links, images, voice and video'],
  ['Network intrusion detection', 'pcap analysis and live monitoring in C++'],
  ['Explainable verdicts', 'Rules + machine learning + AI, with evidence for every score'],
];

export default function AuthLayout({ children }) {
  return (
    <div className="cg-auth-split">
      <aside className="cg-auth-hero" aria-hidden="true">
        <div className="cg-hero-grid" />
        <div className="cg-hero-inner">
          <div className="cg-hero-brand">
            <Logo />
            <span>CyberGuard</span>
          </div>
          <div className="cg-radar">
            <div className="cg-radar-ring r1" />
            <div className="cg-radar-ring r2" />
            <div className="cg-radar-ring r3" />
            <div className="cg-radar-sweep" />
            <svg className="cg-radar-shield" viewBox="0 0 64 64" width="64" height="64">
              <path d="M32 6 52 13v17c0 13-8.6 23.5-20 28C20.6 53.5 12 43 12 30V13z" fill="none" stroke="currentColor" strokeWidth="3" strokeLinejoin="round" />
              <path d="m23 32 6.5 6.5L42 26" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span className="cg-blip b1" /><span className="cg-blip b2" /><span className="cg-blip b3" />
          </div>
          <h2 className="cg-hero-title">Detect. Explain. Respond.</h2>
          <ul className="cg-hero-points">
            {POINTS.map(([t, d], i) => (
              <li key={t} style={{ animationDelay: `${0.25 + i * 0.12}s` }}>
                <span className="cg-hero-dot" />
                <div><strong>{t}</strong><small>{d}</small></div>
              </li>
            ))}
          </ul>
        </div>
      </aside>
      <main className="cg-auth-main"><div className="cg-auth-theme"><ThemeSwitcher /></div>{children}</main>
    </div>
  );
}
