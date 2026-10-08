import React from 'react';

// Small hand-built SVG scenes for page headers and empty states. They use CSS
// classes (see theme.css "Illustration palette") so they follow the active theme,
// weigh a few hundred bytes each and never need a network request.
const scenes = {
  dashboard: (
    <>
      <rect className="ill-card" x="18" y="14" width="150" height="96" rx="10" />
      <rect className="ill-bg" x="30" y="26" width="40" height="22" rx="5" />
      <rect className="ill-bg" x="76" y="26" width="40" height="22" rx="5" />
      <rect className="ill-bg" x="122" y="26" width="34" height="22" rx="5" />
      <rect className="ill-acc" x="35" y="37" width="18" height="4" rx="2" />
      <rect className="ill-crit" x="81" y="37" width="12" height="4" rx="2" />
      <rect className="ill-warn" x="127" y="37" width="16" height="4" rx="2" />
      <path className="ill-acc-s" d="M32 92 52 80l16 6 18-18 16 10 18-16 16 8 18-12" />
      <path className="ill-line" d="M30 98h126" />
      <g className="ill-float"><circle className="ill-card" cx="176" cy="88" r="20" /><path className="ill-acc-s" d="M176 76l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10v-6z" /><path className="ill-acc-s" d="m172 86 3 3 5-5" /></g>
    </>
  ),
  message: (
    <>
      <rect className="ill-card" x="30" y="30" width="118" height="78" rx="9" />
      <path className="ill-line" d="m32 34 57 40 57-40" />
      <rect className="ill-bg" x="44" y="84" width="46" height="5" rx="2.5" />
      <rect className="ill-bg" x="44" y="94" width="30" height="5" rx="2.5" />
      <g className="ill-float"><path className="ill-crit-s" d="M166 14v34a12 12 0 0 1-24 0" /><circle className="ill-crit" cx="166" cy="12" r="3.5" /></g>
      <g className="ill-float d2"><rect className="ill-card" x="138" y="76" width="56" height="26" rx="13" /><path className="ill-crit-s" d="M150 83v7M150 94h.01" /><rect className="ill-crit" x="158" y="86" width="26" height="5" rx="2.5" /></g>
    </>
  ),
  inbox: (
    <>
      <rect className="ill-card" x="22" y="18" width="160" height="92" rx="10" />
      <rect className="ill-bg" x="34" y="30" width="136" height="16" rx="5" />
      <rect className="ill-bg" x="34" y="52" width="136" height="16" rx="5" />
      <rect className="ill-bg" x="34" y="74" width="136" height="16" rx="5" />
      <circle className="ill-safe" cx="44" cy="38" r="3.5" /><rect className="ill-bar" x="54" y="36" width="60" height="4" rx="2" />
      <circle className="ill-crit ill-pulse" cx="44" cy="60" r="3.5" /><rect className="ill-bar" x="54" y="58" width="80" height="4" rx="2" />
      <circle className="ill-safe" cx="44" cy="82" r="3.5" /><rect className="ill-bar" x="54" y="80" width="50" height="4" rx="2" />
      <g className="ill-float"><rect className="ill-card" x="140" y="48" width="58" height="26" rx="13" /><path className="ill-crit-s" d="M151 55v7M151 66h.01" /><rect className="ill-crit" x="160" y="58" width="28" height="5" rx="2.5" /></g>
    </>
  ),
  url: (
    <>
      <rect className="ill-card" x="14" y="20" width="170" height="90" rx="10" />
      <path className="ill-line" d="M14 40h170" />
      <circle className="ill-bar" cx="26" cy="30" r="3" /><circle className="ill-bar" cx="36" cy="30" r="3" /><circle className="ill-bar" cx="46" cy="30" r="3" />
      <rect className="ill-bg" x="58" y="25" width="116" height="10" rx="5" />
      <rect className="ill-warn" x="64" y="28.5" width="36" height="3" rx="1.5" /><rect className="ill-acc" x="102" y="28.5" width="30" height="3" rx="1.5" />
      <rect className="ill-bg" x="28" y="52" width="80" height="8" rx="4" />
      <rect className="ill-bg" x="28" y="66" width="60" height="8" rx="4" />
      <rect className="ill-bg" x="28" y="82" width="70" height="16" rx="5" />
      <g className="ill-float"><circle className="ill-card" cx="160" cy="82" r="20" /><circle className="ill-acc-s" cx="157" cy="79" r="8" /><path className="ill-acc-s" d="m163 85 8 8" /></g>
    </>
  ),
  image: (
    <>
      <rect className="ill-card" x="22" y="16" width="130" height="96" rx="10" />
      <rect className="ill-bg" x="32" y="26" width="110" height="76" rx="6" />
      <circle className="ill-bar" cx="60" cy="50" r="9" />
      <path className="ill-line" d="m34 96 30-28 20 18 18-16 38 26" />
      <rect className="ill-crit-s ill-dash" x="84" y="40" width="34" height="30" rx="3" />
      <g className="ill-float"><rect className="ill-card" x="150" y="60" width="44" height="44" rx="7" /><rect className="ill-ink" x="158" y="68" width="10" height="10" rx="1.5" /><rect className="ill-ink" x="176" y="68" width="10" height="10" rx="1.5" /><rect className="ill-ink" x="158" y="86" width="10" height="10" rx="1.5" /><path className="ill-acc-s" d="M178 88h8M178 94h3M184 94h2" /></g>
    </>
  ),
  audio: (
    <>
      <rect className="ill-card" x="14" y="26" width="178" height="76" rx="12" />
      <g className="ill-acc-s">
        <path d="M30 64v0M38 56v16M46 48v32M54 58v12M62 44v40M70 54v20M78 50v28M86 60v8" />
      </g>
      <path className="ill-line" d="M100 38v52" strokeDasharray="3 5" />
      <g className="ill-crit-s">
        <path d="M114 54v20M122 54v20M130 54v20M138 54v20M146 54v20M154 54v20M162 54v20M170 54v20" />
      </g>
      <g className="ill-float"><rect className="ill-card" x="118" y="10" width="64" height="22" rx="11" /><circle className="ill-crit" cx="130" cy="21" r="3.5" /><rect className="ill-bar" x="138" y="19" width="36" height="4" rx="2" /></g>
    </>
  ),
  video: (
    <>
      <rect className="ill-card" x="18" y="18" width="150" height="94" rx="10" />
      <path className="ill-line" d="M18 34h150M18 96h150" />
      <path className="ill-line" d="M34 18v16M54 18v16M74 18v16M94 18v16M114 18v16M134 18v16M154 18v16M34 96v16M54 96v16M74 96v16M94 96v16M114 96v16M134 96v16M154 96v16" />
      <ellipse className="ill-bg" cx="92" cy="65" rx="20" ry="24" />
      <path className="ill-acc-s ill-dash" d="M64 44h56v44H64z" />
      <g className="ill-float"><circle className="ill-card" cx="182" cy="44" r="16" /><path className="ill-crit-s" d="M182 36v9M182 51h.01" /></g>
    </>
  ),
  logs: (
    <>
      <rect className="ill-card" x="16" y="16" width="170" height="96" rx="10" />
      <path className="ill-acc-s" d="m28 32 6 5-6 5" />
      <rect className="ill-bar" x="40" y="35" width="70" height="4" rx="2" />
      <rect className="ill-bar" x="28" y="50" width="120" height="4" rx="2" />
      <rect className="ill-bar" x="28" y="62" width="90" height="4" rx="2" />
      <rect className="ill-crit" x="24" y="72" width="150" height="14" rx="4" opacity=".22" />
      <rect className="ill-crit" x="28" y="77" width="100" height="4" rx="2" />
      <rect className="ill-bar" x="28" y="94" width="110" height="4" rx="2" />
      <g className="ill-float"><rect className="ill-card" x="150" y="8" width="48" height="26" rx="13" /><path className="ill-crit-s" d="M162 15v7M162 26h.01" /><rect className="ill-crit" x="170" y="18" width="18" height="5" rx="2.5" /></g>
    </>
  ),
  network: (
    <>
      <path className="ill-line" d="M40 34 100 64 160 30M100 64 60 100M100 64 150 98M40 34 60 100M160 30 150 98" />
      <path className="ill-crit-s ill-dash" d="M100 64 186 64" />
      <circle className="ill-card" cx="40" cy="34" r="11" /><circle className="ill-card" cx="160" cy="30" r="11" />
      <circle className="ill-card" cx="60" cy="100" r="11" /><circle className="ill-card" cx="150" cy="98" r="11" />
      <circle className="ill-acc-soft" cx="100" cy="64" r="22" /><circle className="ill-card" cx="100" cy="64" r="14" />
      <path className="ill-acc-s" d="M94 64h12M100 58v12" />
      <circle className="ill-crit ill-pulse" cx="190" cy="64" r="6" />
    </>
  ),
  model: (
    <>
      <g className="ill-line"><path d="M40 30 100 22M40 30 100 64M40 64 100 22M40 64 100 64M40 64 100 106M40 98 100 64M40 98 100 106M100 22 160 64M100 64 160 64M100 106 160 64" /></g>
      {[30, 64, 98].map((y) => <circle key={`a${y}`} className="ill-card" cx="40" cy={y} r="9" />)}
      {[22, 64, 106].map((y) => <circle key={`b${y}`} className="ill-card" cx="100" cy={y} r="9" />)}
      <circle className="ill-acc-soft" cx="160" cy="64" r="18" /><circle className="ill-acc" cx="160" cy="64" r="9" />
      <g className="ill-float"><rect className="ill-card" x="150" y="94" width="48" height="22" rx="11" /><rect className="ill-acc" x="160" y="103" width="28" height="4" rx="2" /></g>
    </>
  ),
  history: (
    <>
      <path className="ill-line" d="M46 20v92" />
      {[28, 60, 92].map((y, i) => (
        <g key={y}>
          <circle className={i === 1 ? 'ill-crit' : 'ill-acc'} cx="46" cy={y} r="5" />
          <rect className="ill-card" x="62" y={y - 12} width="120" height="24" rx="7" />
          <rect className="ill-bar" x="72" y={y - 3} width={[70, 90, 56][i]} height="5" rx="2.5" />
        </g>
      ))}
    </>
  ),
  admin: (
    <>
      <rect className="ill-card" x="18" y="22" width="120" height="86" rx="10" />
      {[40, 62, 84].map((y) => (<g key={y}><circle className="ill-bg" cx="38" cy={y} r="7" /><rect className="ill-bar" x="52" y={y - 2.5} width="60" height="5" rx="2.5" /></g>))}
      <g className="ill-float"><circle className="ill-card" cx="164" cy="62" r="26" /><path className="ill-acc-s" d="M164 46l12 4.5v8.5c0 7.5-5 13-12 15.5-7-2.5-12-8-12-15.5v-8.5z" /><path className="ill-acc-s" d="m158 61 4.5 4.5 8-8" /></g>
    </>
  ),
  empty: (
    <>
      <circle className="ill-line" cx="85" cy="60" r="50" strokeDasharray="4 7" />
      <circle className="ill-line" cx="85" cy="60" r="32" />
      <circle className="ill-acc-soft" cx="85" cy="60" r="18" />
      <path className="ill-acc-s" d="M85 48l10 3.8v7c0 6-4.2 10.6-10 12.8-5.8-2.2-10-6.8-10-12.8v-7z" />
      <path className="ill-acc-s" d="m81 60 3 3 6-6" />
      <circle className="ill-crit ill-pulse" cx="124" cy="30" r="4" />
      <circle className="ill-warn ill-pulse" cx="44" cy="90" r="3.5" />
      <circle className="ill-safe" cx="130" cy="92" r="3.5" />
    </>
  ),
};

export default function Illustration({ name, className }) {
  const body = scenes[name] || scenes.empty;
  const box = name === 'empty' ? '0 0 170 120' : '0 0 210 128';
  return <svg viewBox={box} className={className} aria-hidden="true" focusable="false">{body}</svg>;
}
