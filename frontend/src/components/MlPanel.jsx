import React from 'react';
import RiskBadge from './RiskBadge';

// Shows the output of a C++ ML model that ran as part of a scan:
// probability, algorithm, and the features/terms that drove the decision.
const pct = (p) => (p == null ? '—' : `${(p * 100).toFixed(p >= 0.995 || p < 0.005 ? 1 : 0)}%`);

export function ProbabilityBar({ value, threshold }) {
  const v = Math.max(0, Math.min(1, value || 0));
  const color = v >= 0.8 ? 'var(--cg-critical)' : v >= 0.6 ? 'var(--cg-high)' : v >= 0.4 ? 'var(--cg-medium)' : 'var(--cg-safe)';
  return (
    <div className="cg-prob-bar" title={`${(v * 100).toFixed(1)}%`}>
      <div className="cg-prob-fill" style={{ width: `${v * 100}%`, background: color }} />
      {threshold != null && <div className="cg-prob-threshold" style={{ left: `${Math.min(1, threshold) * 100}%` }} title={`decision threshold ${threshold.toFixed(2)}`} />}
    </div>
  );
}

function FeatureList({ items, valueKey = 'contribution', labelKey = 'feature' }) {
  if (!items || !items.length) return null;
  const max = Math.max(...items.map((f) => Math.abs(f[valueKey] || 0)), 1e-9);
  return (
    <div className="cg-feature-list">
      {items.map((f, i) => (
        <div key={i} className="cg-feature-row">
          <span className="cg-mono cg-feature-name">{f[labelKey]}</span>
          <span className="cg-feature-track"><span style={{ width: `${(Math.abs(f[valueKey] || 0) / max) * 100}%` }} /></span>
          <span className="cg-mono cg-feature-val">
            {f.value != null ? `= ${Number(f.value).toFixed(Math.abs(f.value) < 10 ? 2 : 0)}` : (f[valueKey] || 0).toFixed(2)}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function MlPanel({ ml, title = 'Machine-learning verdict (C++ engine)', label = 'likely malicious' }) {
  if (!ml) return null;
  if (!ml.available) {
    return (
      <div className="cg-ml-panel">
        <div className="cg-panel-title">{title}</div>
        <div style={{ color: 'var(--cg-text-muted)', fontSize: 13.5 }}>
          The ML model is not loaded in the detection engine — result is based on rules and forensic checks only.
        </div>
      </div>
    );
  }
  const isAnomalyModel = ml.anomalyScore != null && ml.threshold != null && !ml.components;
  return (
    <div className="cg-ml-panel">
      <div className="cg-panel-title" style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        {title}
        {ml.experimental && <span className="cg-chip cg-chip-warn">experimental</span>}
        {ml.schemeInvariant && <span className="cg-chip" title="http:// vs https:// does not change the ML score">scheme-invariant</span>}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap', marginBottom: 8 }}>
        {ml.riskLevel && <RiskBadge level={ml.riskLevel} />}
        <span className="cg-mono" style={{ fontSize: 22, fontWeight: 600 }}>{pct(ml.probability)}</span>
        <span style={{ color: 'var(--cg-text-muted)', fontSize: 13 }}>{isAnomalyModel ? 'anomaly probability' : label}</span>
      </div>
      <ProbabilityBar value={ml.probability} threshold={isAnomalyModel ? null : ml.threshold} />
      <div className="cg-mono" style={{ fontSize: 12, color: 'var(--cg-text-muted)', marginTop: 8 }}>
        model: {ml.model} · {ml.algorithm}
      </div>
      {ml.adjustment && <div className="cg-note" style={{ marginTop: 8 }}>{ml.adjustment}{ml.rawProbability != null && ` (raw model output ${pct(ml.rawProbability)})`}</div>}
      {ml.note && <div className="cg-note" style={{ marginTop: 8 }}>{ml.note}</div>}

      {ml.components && (
        <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', marginTop: 10, fontSize: 13 }}>
          {Object.entries(ml.components).map(([k, v]) => (
            <span key={k}><span style={{ color: 'var(--cg-text-muted)' }}>{k}:</span> <span className="cg-mono">{typeof v === 'number' ? pct(v) : String(v)}</span></span>
          ))}
        </div>
      )}
      {isAnomalyModel && (
        <div style={{ fontSize: 13, marginTop: 10 }}>
          Isolation-Forest anomaly score <span className="cg-mono">{ml.anomalyScore.toFixed(3)}</span> vs learned threshold{' '}
          <span className="cg-mono">{ml.threshold.toFixed(3)}</span> →{' '}
          <strong style={{ color: ml.isAnomaly ? 'var(--cg-high)' : 'var(--cg-safe)' }}>{ml.isAnomaly ? 'anomalous' : 'normal'}</strong>
          {ml.outOfRangeFeature && <span style={{ color: 'var(--cg-text-muted)' }}> · most unusual feature: <span className="cg-mono">{ml.outOfRangeFeature}</span></span>}
        </div>
      )}

      {ml.topIndicativeTerms?.length > 0 && (
        <>
          <div className="cg-subtitle">Words that pushed the model towards “phishing”</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {ml.topIndicativeTerms.map((t) => (
              <span key={t.term} className="cg-chip" title={`weight ${t.weight}`}>{t.term.replace(/^__(\w+)__$/, '<$1>')} <span style={{ opacity: 0.6 }}>+{t.weight}</span></span>
            ))}
          </div>
        </>
      )}
      {(ml.topFeatures || ml.topGlobalFeatures)?.length > 0 && (
        <>
          <div className="cg-subtitle">Features that drove the decision</div>
          <FeatureList items={ml.topFeatures || ml.topGlobalFeatures} />
        </>
      )}
      {ml.windows != null && <div style={{ fontSize: 12.5, color: 'var(--cg-text-muted)', marginTop: 8 }}>{ml.windows} audio windows analysed</div>}
      {Array.isArray(ml.entities) && ml.entities.length > 0 && (
        <>
          <div className="cg-subtitle">Per-entity behaviour anomaly (Isolation Forest)</div>
          <table className="cg-table">
            <thead><tr><th>Entity</th><th>Anomaly score</th><th>Verdict</th><th>Why</th></tr></thead>
            <tbody>
              {ml.entities.slice(0, 15).map((e) => (
                <tr key={e.entity}>
                  <td className="cg-mono">{e.entity}</td>
                  <td className="cg-mono">{e.anomalyScore.toFixed(3)}</td>
                  <td style={{ color: e.isAnomaly ? 'var(--cg-high)' : 'var(--cg-safe)' }}>{e.isAnomaly ? 'anomalous' : 'normal'}</td>
                  <td className="cg-mono" style={{ fontSize: 12 }}>{(e.topFeatures || []).map((f) => f.feature).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

export function ScoreComponents({ components }) {
  if (!components?.length) return null;
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '4px 0 14px' }}>
      {components.map((c, i) => (
        <span key={i} className="cg-chip" title={`weight ${c.weight}`}>
          {c.source.replace(/_/g, ' ')}: <span className="cg-mono">{c.score}</span>
        </span>
      ))}
    </div>
  );
}

export function MitreList({ items }) {
  if (!items?.length) return null;
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      {items.map((m) => (
        <a key={m.id} className="cg-chip" href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`} target="_blank" rel="noreferrer">
          {m.id} · {m.name}
        </a>
      ))}
    </div>
  );
}
