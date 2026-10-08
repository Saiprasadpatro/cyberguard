import React from 'react';

export default function RiskBadge({ level }) {
  const safeLevel = level || 'Safe';
  return <span className={`cg-risk-badge cg-risk-${safeLevel}`}>{safeLevel}</span>;
}
