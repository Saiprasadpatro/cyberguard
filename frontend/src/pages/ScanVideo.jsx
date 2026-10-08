import React, { useState } from 'react';
import AppShell from '../components/AppShell';
import Icon from '../components/Icons';
import Dropzone from '../components/Dropzone';
import MlPanel from '../components/MlPanel';
import { Callout, PageHeader, ResultView, ScanWorkspace } from '../components/ui';
import api from '../api/api';

function FrameStrip({ ml }) {
  if (!ml?.available) return <MlPanel ml={ml} />;
  return (
    <div className="cg-stack">
      {ml.meanFrameProbability != null && (
        <div className="cg-ml-panel" style={{ margin: 0 }}>
          <div className="cg-panel-title">Frame manipulation model (experimental)</div>
          <div style={{ fontSize: 13.5 }}>
            Mean <span className="cg-mono">{(ml.meanFrameProbability * 100).toFixed(0)}%</span>
            {ml.temporalSwing != null && <> · frame-to-frame swing <span className="cg-mono">{(ml.temporalSwing * 100).toFixed(0)}%</span></>}
          </div>
          <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', height: 64, marginTop: 12 }}>
            {(ml.frames || []).map((p, i) => (
              <div key={i} title={`frame ${i + 1}: ${(p * 100).toFixed(0)}%`}
                style={{ flex: 1, maxWidth: 16, height: `${Math.max(6, p * 100)}%`, background: p > 0.6 ? 'var(--cg-high)' : 'var(--cg-accent)', borderRadius: 3, transformOrigin: 'bottom', animation: `cg-grow-y 600ms var(--cg-ease) ${i * 30}ms both` }} />
            ))}
          </div>
        </div>
      )}
      {ml.voice && <MlPanel ml={ml.voice} title="Voice track: synthetic-voice model" label="likely synthetic voice" />}
    </div>
  );
}

export default function ScanVideo() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) return;
    setBusy(true); setError(''); setResult(null);
    try {
      const formData = new FormData();
      formData.append('video', file);
      const { data } = await api.post('/scan/video', formData, { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 300000 });
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.error || 'Scan failed. Check that the backend is running.');
    } finally {
      setBusy(false);
    }
  };

  const form = (
    <div className="cg-panel">
      <form onSubmit={handleSubmit}>
        <div className="cg-panel-title">Video clip</div>
        <Dropzone accept="video/mp4,video/quicktime,video/webm" file={file} onFile={(f) => { setFile(f); setResult(null); setError(''); }}
          hint="MP4, MOV or WebM, up to 100 MB" maxBytes={100 * 1024 * 1024} />
        <button type="submit" className="cg-btn-primary w-100" style={{ marginTop: 16 }} disabled={busy || !file}>
          {busy ? <><span className="cg-spinner" />Analysing frames…</> : <><Icon name="search" />Analyse video</>}
        </button>
        {error && <div className="cg-error"><Icon name="alert" size={16} />{error}</div>}
        <div className="cg-note" style={{ marginTop: 14 }}>Frames are sampled across the clip and the soundtrack goes through the voice-clone model.</div>
      </form>
    </div>
  );

  return (
    <AppShell>
      <PageHeader eyebrow="Detect · Deepfake video" title="Video scan" art="video"
        subtitle="Sample frames from a clip, look for manipulation traces and check the voice track for cloning." />
      <ScanWorkspace
        form={form} busy={busy}
        emptyHints={['Frames sampled evenly across the clip', 'Per-frame manipulation score', 'Voice track checked for cloning', 'Gemini multimodal review when online']}
        result={result && (
          <ResultView
            result={result}
            chips={<>
              {result.authenticityScore != null && <span className="cg-chip">Authenticity {result.authenticityScore}/100</span>}
              {result.framesAnalyzed != null && <span className="cg-chip">{result.framesAnalyzed} frames</span>}
            </>}
            summaryExtra={!result.geminiConfigured && <Callout tone="warn" icon="cloudOff">AI video review unavailable (offline or no Gemini key): frame forensics and ML models only.</Callout>}
            ml={{ node: <FrameStrip ml={result.ml} /> }}
          />
        )}
      />
    </AppShell>
  );
}
