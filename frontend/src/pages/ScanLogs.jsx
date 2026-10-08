import React, { useState } from 'react';
import AppShell from '../components/AppShell';
import Icon from '../components/Icons';
import FindingsList from '../components/FindingsList';
import { PageHeader, ResultView, ScanWorkspace } from '../components/ui';
import api from '../api/api';

const SAMPLE_LOGS = [
  { sourceIp: '10.0.0.99', destinationPort: 22, eventType: 'connection' },
  { sourceIp: '10.0.0.99', destinationPort: 3389, eventType: 'connection' },
  { sourceIp: '10.0.0.99', destinationPort: 445, eventType: 'connection' },
  { sourceIp: '10.0.0.99', destinationPort: 8080, eventType: 'connection' },
  { sourceIp: '10.0.0.99', destinationPort: 21, eventType: 'connection' },
  { sourceIp: '203.0.113.5', apiEndpoint: '/api/login', httpStatus: 401 },
  { sourceIp: '203.0.113.5', apiEndpoint: '/api/login', httpStatus: 401 },
  { sourceIp: '203.0.113.5', apiEndpoint: '/api/login', httpStatus: 200 },
  { userId: 'u42', bytesTransferred: 3221225472, hourOfDay: 2 },
  { userId: 'u77', eventType: 'mass_download' },
  { userId: 'u77', eventType: 'admin_access' },
  { processName: 'svc_update.exe', filePath: 'C:\\Users\\a\\AppData\\Local\\Temp\\invoice.pdf.exe' },
  { commandLine: 'powershell -EncodedCommand JAB4ID0gMQ==' },
];

export default function ScanLogs() {
  const [raw, setRaw] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const loadSample = () => { setRaw(JSON.stringify(SAMPLE_LOGS, null, 2)); setError(''); };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    let entries;
    try {
      entries = JSON.parse(raw);
      if (!Array.isArray(entries)) throw new Error('Input must be a JSON array of log entries: [ {...}, {...} ]');
    } catch (err) {
      setError(err.message.startsWith('Input must') ? err.message : `That is not valid JSON: ${err.message}`);
      return;
    }
    setBusy(true); setResult(null);
    try {
      const { data } = await api.post('/scan/logs', { entries }, { timeout: 120000 });
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.error || 'Scan failed. Check that the backend is running.');
    } finally {
      setBusy(false);
    }
  };

  const categories = result ? Object.entries(result.categoryBreakdown || {}).filter(([, f]) => f.length > 0) : [];
  const allFindings = categories.flatMap(([, f]) => f);

  const form = (
    <div className="cg-panel">
      <form onSubmit={handleSubmit}>
        <div className="cg-panel-head">
          <div className="cg-panel-title">Log entries (JSON array)</div>
          <button type="button" className="cg-btn-ghost" onClick={loadSample}><Icon name="layers" />Load sample</button>
        </div>
        <textarea className="form-control cg-mono" rows={14} required value={raw} onChange={(e) => setRaw(e.target.value)} spellCheck={false}
          placeholder='[{"sourceIp":"1.2.3.4","destinationPort":22,"eventType":"connection"}, ...]' style={{ fontSize: 12.5 }} />
        <button type="submit" className="cg-btn-primary w-100" style={{ marginTop: 14 }} disabled={busy || !raw.trim()}>
          {busy ? <><span className="cg-spinner" />Analysing…</> : <><Icon name="search" />Analyse logs</>}
        </button>
        {error && <div className="cg-error"><Icon name="alert" size={16} />{error}</div>}
      </form>
    </div>
  );

  return (
    <AppShell>
      <PageHeader eyebrow="Monitor · Technical threats" title="Log threat analysis" art="logs"
        subtitle="Upload authentication, network, API or system logs to find scanning, brute force, API abuse, data exfiltration, malware and insider misuse." />
      <ScanWorkspace
        form={form} busy={busy} wide
        emptyHints={['Five rule detectors for known attack patterns', 'Per-user and per-IP behaviour anomaly model', 'Threats mapped to MITRE ATT&CK', 'Every alert logged to the dashboard']}
        result={result && (
          <ResultView
            result={result}
            findings={allFindings}
            chips={<span className="cg-chip">{result.entriesAnalyzed} entries</span>}
            summaryExtra={result.threatsCreated?.length > 0 && (
              <div><div className="cg-subtitle" style={{ marginTop: 0 }}>Threats logged to the dashboard</div>
                <div className="cg-chip-row">{result.threatsCreated.map((t, i) => <span key={i} className="cg-chip cg-chip-bad">{String(t.category).replace(/_/g, ' ')} · {t.riskLevel}</span>)}</div></div>
            )}
            extraTabs={[{
              id: 'categories', label: 'By category', count: categories.length, hidden: categories.length === 0,
              content: (
                <div className="cg-stack">
                  {categories.map(([category, findings]) => (
                    <div key={category} className="cg-card">
                      <div className="cg-subtitle" style={{ marginTop: 0 }}>{category.replace(/_/g, ' ')}</div>
                      <FindingsList findings={findings} />
                    </div>
                  ))}
                </div>
              ),
            }]}
            ml={{ title: 'ML behaviour anomaly model (C++ Isolation Forest per user / IP)' }}
          />
        )}
      />
    </AppShell>
  );
}
