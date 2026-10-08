import React, { useRef, useState } from 'react';
import Icon from './Icons';

const fmtSize = (b) => (b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1024))} KB`);

// Drag-and-drop file picker (also works with tap / keyboard).
export default function Dropzone({ accept, file, onFile, hint, maxBytes }) {
  const input = useRef(null);
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState('');
  const take = (f) => {
    if (!f) return;
    if (maxBytes && f.size > maxBytes) { setErr(`File is too large (${fmtSize(f.size)}). Maximum is ${fmtSize(maxBytes)}.`); return; }
    setErr('');
    onFile(f);
  };
  return (
    <div>
      <div
        className={`cg-dropzone${drag ? ' drag' : ''}`} role="button" tabIndex={0}
        onClick={() => input.current?.click()}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.current?.click(); } }}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); take(e.dataTransfer.files?.[0]); }}
        style={{ cursor: 'pointer' }}
      >
        <Icon name="upload" size={26} />
        {file ? (
          <div style={{ marginTop: 8 }}>
            <div style={{ color: 'var(--cg-text)', fontWeight: 600, wordBreak: 'break-all' }}>{file.name}</div>
            <div style={{ fontSize: 12 }}>{fmtSize(file.size)} · click to choose another file</div>
          </div>
        ) : (
          <div style={{ marginTop: 8 }}>
            <div style={{ color: 'var(--cg-text)', fontWeight: 600 }}>Drop a file here or click to browse</div>
            {hint && <div style={{ fontSize: 12, marginTop: 2 }}>{hint}</div>}
          </div>
        )}
        <input ref={input} type="file" accept={accept} hidden onChange={(e) => { take(e.target.files?.[0]); e.target.value = ''; }} />
      </div>
      {err && <div className="cg-error"><Icon name="alert" size={16} />{err}</div>}
    </div>
  );
}
