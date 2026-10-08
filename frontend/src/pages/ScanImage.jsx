import React, { useEffect, useState } from 'react';
import AppShell from '../components/AppShell';
import Icon from '../components/Icons';
import Dropzone from '../components/Dropzone';
import MlPanel from '../components/MlPanel';
import { Callout, PageHeader, ResultView, ScanWorkspace } from '../components/ui';
import api from '../api/api';

// Draws the analysed centre crop and the 32x32 blocks the C++ model found most
// suspicious on top of the uploaded image.
function BlockOverlay({ src, ml }) {
  const [dim, setDim] = useState(null);
  const region = ml?.analysedRegion;
  const blocks = ml?.suspiciousBlocks || [];
  const onLoad = (e) => setDim({ w: e.target.naturalWidth, h: e.target.naturalHeight });
  const box = (x, y, w, h) => {
    if (!dim) return { display: 'none' };
    return { left: `${(x / dim.w) * 100}%`, top: `${(y / dim.h) * 100}%`, width: `${(w / dim.w) * 100}%`, height: `${(h / dim.h) * 100}%` };
  };
  const ox = dim && region ? Math.floor((dim.w - region.width) / 2) : 0;
  const oy = dim && region ? Math.floor((dim.h - region.height) / 2) : 0;
  return (
    <div>
      <div className="cg-img-wrap" style={{ maxWidth: 520 }}>
        <img src={src} alt="analysed" onLoad={onLoad} />
        {region && <div className="cg-analysed-box" style={box(ox, oy, region.width, region.height)} title="region analysed by the ML model" />}
        {blocks.map((b, i) => (
          <div key={i} className="cg-img-box" style={box(ox + b.x, oy + b.y, b.size, b.size)} title={`block score ${(b.score * 100).toFixed(0)}%`} />
        ))}
      </div>
      <div style={{ fontSize: 12, color: 'var(--cg-text-muted)', marginTop: 6 }}>
        Dashed: region analysed · red: blocks whose compression/noise statistics differ most from the rest of the image
        {blocks.length === 0 && ' (none above 70%)'}
      </div>
    </div>
  );
}

export default function ScanImage() {
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  // Free the preview's memory when it changes or the page closes.
  useEffect(() => () => { if (preview) URL.revokeObjectURL(preview); }, [preview]);

  const handleFile = (f) => {
    setFile(f);
    setResult(null);
    setError('');
    setPreview(f ? URL.createObjectURL(f) : null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) return;
    setBusy(true); setError(''); setResult(null);
    try {
      const formData = new FormData();
      formData.append('image', file);
      const { data } = await api.post('/scan/image', formData, { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 120000 });
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
        <div className="cg-panel-title">Image to check</div>
        <Dropzone accept="image/jpeg,image/png" file={file} onFile={handleFile} hint="JPEG or PNG, up to 10 MB. QR codes are decoded automatically." maxBytes={10 * 1024 * 1024} />
        {preview && <img src={preview} alt="Selected upload" style={{ width: '100%', maxHeight: 240, objectFit: 'contain', marginTop: 14, borderRadius: 10, border: '1px solid var(--cg-border)', background: 'var(--cg-surface-sunken)' }} />}
        <button type="submit" className="cg-btn-primary w-100" style={{ marginTop: 16 }} disabled={busy || !file}>
          {busy ? <><span className="cg-spinner" />Analysing…</> : <><Icon name="search" />Analyse image</>}
        </button>
        {error && <div className="cg-error"><Icon name="alert" size={16} />{error}</div>}
      </form>
    </div>
  );

  const imageTab = result && preview && result.ml?.available ? {
    id: 'regions', label: 'Suspicious regions', count: result.ml?.suspiciousBlocks?.length || 0,
    content: <BlockOverlay src={preview} ml={result.ml} />,
  } : null;

  return (
    <AppShell>
      <PageHeader eyebrow="Detect · Deepfake & impersonation" title="Image & QR code scan" art="image"
        subtitle="Check a photo, screenshot or ID for signs of editing, or decode a QR code and check where its link really goes." />
      <ScanWorkspace
        form={form} busy={busy}
        emptyHints={['Compression and noise inconsistencies (ELA)', 'Edited regions boxed on the image', 'QR code links checked like any URL', 'Gemini vision for AI-generated faces (online)']}
        result={result && (
          <ResultView
            result={result}
            chips={<>
              {result.authenticityScore != null && <span className="cg-chip">Authenticity {result.authenticityScore}/100</span>}
              {result.qrDetected && <span className="cg-chip cg-chip-warn">QR code found</span>}
            </>}
            summaryExtra={<>
              {result.qrDetected && <Callout tone="info" icon="link" title="QR code decoded"><span className="cg-mono" style={{ wordBreak: 'break-all' }}>{result.qrPayload}</span></Callout>}
              {!result.geminiConfigured && <Callout tone="warn" icon="cloudOff">AI vision check unavailable (offline or no Gemini key): forensic signals and the ML model only.</Callout>}
            </>}
            ml={{ node: <MlPanel ml={result.ml} title="ML manipulation detector (C++ block-level GBDT, stacked)" label="likely edited / spliced" /> }}
            extraTabs={[imageTab].filter(Boolean)}
            initialTab={imageTab ? 'regions' : undefined}
          />
        )}
      />
    </AppShell>
  );
}
