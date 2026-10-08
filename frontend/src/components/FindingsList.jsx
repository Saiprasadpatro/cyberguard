import React from 'react';

// Evidence list: strongest indicators first, each with its score weight.
const human = (s = '') => String(s).replace(/_/g, ' ');

export default function FindingsList({ findings }) {
  if (!findings || findings.length === 0) {
    return <div className="cg-muted" style={{ fontSize: 14 }}>No indicators detected.</div>;
  }
  const sorted = [...findings].sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0));
  return (
    <div>
      {sorted.map((f, idx) => {
        const w = f.weight;
        const tone = w == null ? undefined : w >= 25 ? 'var(--cg-critical)' : w >= 12 ? 'var(--cg-high)' : w > 0 ? 'var(--cg-medium)' : undefined;
        return (
          <div className="cg-finding" key={idx}>
            <span className="cg-finding-weight" style={tone ? { color: tone, borderColor: `color-mix(in srgb, ${tone} 40%, transparent)` } : undefined}>
              {w == null ? '—' : w > 0 ? `+${w}` : w}
            </span>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--cg-accent-bright)', textTransform: 'capitalize' }}>{human(f.indicator)}</div>
              <div style={{ wordBreak: 'break-word' }}>{f.detail}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
