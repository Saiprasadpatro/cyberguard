import React, { useState } from 'react';
import AppShell from '../components/AppShell';
import RiskBadge from '../components/RiskBadge';
import Icon from '../components/Icons';
import { Callout, PageHeader, ResultView, ScanWorkspace } from '../components/ui';
import { useSystem } from '../context/UiContext';
import api from '../api/api';

// Colour-codes each part of the URL so the user can see which domain they
// will REALLY be talking to (the registrable domain), regardless of http/https.
function UrlAnatomy({ a }) {
  if (!a) return null;
  const sub = a.subdomain ? `${a.subdomain}.` : '';
  const reg = a.registrableDomain || a.host;
  const displayHost = a.isIp ? a.host : null;
  return (
    <div>
      <div className="cg-url-anatomy">
        <span className="cg-seg-scheme">{a.scheme}://</span>
        {a.userinfo && <span className="cg-seg-userinfo" title="Everything before @ is ignored by the browser">{a.userinfo}@</span>}
        {displayHost ? <span className="cg-seg-reg">{displayHost}</span> : (<>{sub && <span className="cg-seg-sub">{sub}</span>}<span className="cg-seg-reg">{reg}</span></>)}
        {a.port ? <span className="cg-seg-userinfo">:{a.port}</span> : null}
        <span className="cg-seg-path">{a.path}{a.query ? `?${a.query}` : ''}</span>
      </div>
      <div className="cg-kv" style={{ marginTop: 10 }}>
        <div>Real (registered) domain</div><div className="cg-mono"><strong>{a.isIp ? `IP address ${a.normalizedIp || a.host}` : reg}</strong></div>
        <div>Public suffix</div><div className="cg-mono">{a.publicSuffix || '—'}</div>
        {a.subdomain && (<><div>Subdomain (owner-controlled)</div><div className="cg-mono">{a.subdomain}</div></>)}
        {a.userinfo && (<><div>Userinfo @ trick</div><div className="cg-mono" style={{ color: 'var(--cg-critical)' }}>“{a.userinfo}” is NOT where you are going</div></>)}
        {a.punycode && (<><div>Punycode / IDN</div><div className="cg-mono">displays as <strong>{a.unicodeHost}</strong> · skeleton {a.homographSkeleton}</div></>)}
        {a.mixedScript && (<><div>Mixed scripts</div><div style={{ color: 'var(--cg-critical)' }}>Latin + other alphabet in one label (homograph)</div></>)}
        {a.queryKeys?.length > 0 && (<><div>Query parameters</div><div className="cg-mono">{a.queryKeys.join(', ')}</div></>)}
      </div>
    </div>
  );
}

const yesNo = (v, goodWhenTrue = true) => (v == null ? '—' : (
  <span style={{ color: (v === goodWhenTrue) ? 'var(--cg-safe)' : 'var(--cg-critical)' }}>{v ? 'yes' : 'no'}</span>
));

function LiveReport({ live, destination }) {
  if (!live) return null;
  const c = live.certificate || {};
  const dns = live.dns || {};
  const age = live.domainAge || {};
  const page = live.page || {};
  const lp = live.loginPage || {};
  return (
    <>
      {!live.reachable && <div className="cg-note" style={{ marginBottom: 10 }}>Site not reachable ({live.error || 'no response'}) — structural and ML analysis still apply.</div>}
      <div className="cg-grid-2">
        <div className="cg-card">
          <div className="cg-subtitle" style={{ marginTop: 0 }}>Redirect chain ({(live.redirectChain || []).length} hop{(live.redirectChain || []).length === 1 ? '' : 's'})</div>
          <ul className="cg-chain">
            {(live.redirectChain || []).map((h, i, arr) => (
              <li key={i} className={i === arr.length - 1 ? 'final' : ''}>
                <span className="cg-mono" style={{ wordBreak: 'break-all' }}>{h.url}</span>
                <span className="cg-chip" style={{ marginLeft: 6 }}>{h.status || '—'}{h.metaRefresh ? ' · meta refresh' : ''}</span>
              </li>
            ))}
          </ul>
          {live.crossDomainRedirect && <div style={{ color: 'var(--cg-high)', fontSize: 13, marginTop: 6 }}>⚠ Redirects to a different website</div>}
          {live.finalUrl && <div style={{ fontSize: 13, marginTop: 6 }}>Final page: <span className="cg-mono" style={{ wordBreak: 'break-all' }}>{live.finalUrl}</span></div>}
        </div>

        <div className="cg-card">
          <div className="cg-subtitle" style={{ marginTop: 0 }}>TLS certificate — HTTPS ≠ genuine</div>
          {c.present ? (
            <div className="cg-kv">
              <div>Issuer</div><div>{c.issuer || c.issuerCN}{c.freeDvIssuer && <span className="cg-chip cg-chip-warn" style={{ marginLeft: 6 }}>free DV</span>}</div>
              <div>Issued to</div><div className="cg-mono">{c.subject}</div>
              <div>Hostname matches</div><div>{yesNo(c.hostnameMatches)}</div>
              <div>Trusted chain</div><div>{yesNo(c.authorized)}{c.authorizationError && <span className="cg-mono" style={{ fontSize: 11 }}> {c.authorizationError}</span>}</div>
              <div>Self-signed</div><div>{yesNo(c.selfSigned, false)}</div>
              <div>Certificate age</div><div className="cg-mono">{c.ageDays != null ? `${c.ageDays} days` : '—'}{c.expired && <span style={{ color: 'var(--cg-critical)' }}> EXPIRED</span>}</div>
            </div>
          ) : <div style={{ color: 'var(--cg-text-muted)', fontSize: 13 }}>{c.skipped || 'No certificate (plain http or TLS failed)'}</div>}
          <div className="cg-note" style={{ marginTop: 8 }}>A padlock only means the connection is encrypted. Anyone can get a free certificate for a look-alike domain in seconds.</div>
        </div>

        <div className="cg-card">
          <div className="cg-subtitle" style={{ marginTop: 0 }}>Domain & DNS</div>
          <div className="cg-kv">
            <div>Domain age</div><div className="cg-mono">{age.available ? (age.ageDays != null ? `${age.ageDays} days` : 'unknown') : (age.error || 'unavailable')}</div>
            {age.registrar && (<><div>Registrar</div><div>{age.registrar}</div></>)}
            <div>Resolves</div><div>{yesNo(dns.resolved)}</div>
            <div>A records</div><div className="cg-mono">{(dns.a || []).slice(0, 4).join(', ') || '—'}{dns.minTtl != null && ` (TTL ${dns.minTtl}s)`}</div>
            <div>Name servers</div><div className="cg-mono">{(dns.ns || []).slice(0, 3).join(', ') || '—'}</div>
            <div>Mail (MX)</div><div className="cg-mono">{(dns.mx || []).slice(0, 2).join(', ') || 'none'}</div>
            <div>Safe Browsing</div><div>{live.safeBrowsing?.checked ? (live.safeBrowsing.matches?.length ? <span style={{ color: 'var(--cg-critical)' }}>{live.safeBrowsing.matches.join(', ')}</span> : 'no match') : 'not configured'}</div>
          </div>
        </div>

        <div className="cg-card">
          <div className="cg-subtitle" style={{ marginTop: 0 }}>Page forensics</div>
          <div className="cg-kv">
            <div>Page title</div><div>{lp.title || '—'}</div>
            <div>Password fields</div><div className="cg-mono">{page.passwordFields ?? 0}</div>
            <div>Card / OTP fields</div><div className="cg-mono">{page.cardFields ?? 0} / {page.otpFields ?? 0}</div>
            <div>Forms posting elsewhere</div><div className="cg-mono">{(page.forms || []).filter((f) => f.external).length}</div>
            <div>Brand imitation</div><div>{lp.brandMismatch ? <span style={{ color: 'var(--cg-critical)' }}>mentions “{lp.mentionedBrand}” on a non-official domain</span> : 'none detected'}</div>
            <div>Hidden iframes / JS tricks</div><div className="cg-mono">{page.hiddenIframes ?? 0} · {page.jsRedirect ? 'JS redirect' : 'no JS redirect'}{page.disablesRightClick ? ' · blocks right-click' : ''}</div>
          </div>
        </div>
      </div>

      {destination && (
        <div className="cg-card" style={{ marginTop: 16 }}>
          <div className="cg-subtitle" style={{ marginTop: 0 }}>Final destination re-analysed</div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <RiskBadge level={destination.riskLevel} />
            <span className="cg-mono" style={{ wordBreak: 'break-all', fontSize: 13 }}>{destination.url}</span>
            {destination.ml?.available && <span className="cg-chip">ML {(destination.ml.probability * 100).toFixed(0)}%</span>}
          </div>
        </div>
      )}
    </>
  );
}

const EXAMPLES = ['https://paypal.com.account-verify.secure-login.xyz/signin', 'http://sbi-kyc-update.top/login', 'https://accounts.google.com/signin'];

export default function ScanUrlPage() {
  const { feature } = useSystem();
  const liveOk = feature('liveUrlCheck').available;
  const [url, setUrl] = useState('');
  const [deep, setDeep] = useState(true);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const useDeep = deep && liveOk;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setBusy(true); setError(''); setResult(null);
    try {
      const { data } = await api.post('/scan/url', { url: url.trim(), skipLiveCheck: !useDeep }, { timeout: 90000 });
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.error || (err.code === 'ECONNABORTED' ? 'The scan took too long. Try again without deep inspection.' : 'Scan failed. Check that the backend is running.'));
    } finally {
      setBusy(false);
    }
  };

  const form = (
    <div className="cg-panel">
      <form onSubmit={handleSubmit}>
        <div className="cg-panel-title">Link to check</div>
        <label htmlFor="url">URL</label>
        <input id="url" className="form-control cg-mono" required value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/reset-password" autoComplete="off" spellCheck={false} inputMode="url" />
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
          <span className="cg-faint" style={{ fontSize: 12 }}>Try:</span>
          {EXAMPLES.map((x) => <button key={x} type="button" className="cg-chip" style={{ cursor: 'pointer', maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis' }} onClick={() => setUrl(x)}>{x.replace(/^https?:\/\//, '')}</button>)}
        </div>
        <label style={{ display: 'flex', gap: 10, alignItems: 'flex-start', marginTop: 16, fontSize: 13, cursor: liveOk ? 'pointer' : 'not-allowed', opacity: liveOk ? 1 : 0.6 }}>
          <input type="checkbox" checked={useDeep} disabled={!liveOk} onChange={(e) => setDeep(e.target.checked)} style={{ marginTop: 2 }} />
          <span><strong style={{ color: 'var(--cg-text)', display: 'block' }}>Deep live inspection</strong>
            Follow redirects, check the certificate, DNS, domain age and page content. The server visits the link, not your browser.</span>
        </label>
        {!liveOk && <Callout tone="warn" icon="cloudOff" style={{ marginTop: 12 }}>Live inspection needs the internet. The link is still fully checked by the rules and the URL model.</Callout>}
        <button type="submit" className="cg-btn-primary w-100" style={{ marginTop: 16 }} disabled={busy || !url.trim()}>
          {busy ? <><span className="cg-spinner" />{useDeep ? 'Inspecting…' : 'Scanning…'}</> : <><Icon name="search" />Scan URL</>}
        </button>
        {error && <div className="cg-error"><Icon name="alert" size={16} />{error}</div>}
        <div className="cg-note" style={{ marginTop: 16 }}>https:// only means the connection is encrypted. Our URL model ignores http vs https, so a padlock cannot hide a phishing link.</div>
      </form>
    </div>
  );

  return (
    <AppShell>
      <PageHeader eyebrow="Detect · Malicious links" title="URL & website check" art="url"
        subtitle="Find out who really owns a link, where it redirects and whether the page imitates a brand, even when it uses https." />
      <ScanWorkspace
        form={form} busy={busy}
        emptyHints={['Real registered domain and look-alike letters', 'Brand names hidden in subdomains', 'Redirect chain, certificate and domain age', 'URL model trained on 466,354 URLs']}
        result={result && (
          <ResultView
            result={result}
            subtitle={<span className="cg-mono" style={{ wordBreak: 'break-all' }}>{result.host}</span>}
            chips={result.trustedBrandDomain ? <span className="cg-chip cg-chip-good"><Icon name="checkCircle" size={13} />Verified official domain</span> : null}
            summaryExtra={<div><div className="cg-subtitle" style={{ marginTop: 0 }}>Where this link really goes</div><UrlAnatomy a={result.anatomy} /></div>}
            ml={{ title: 'ML URL classifier (C++ Gradient Boosted Trees + char n-gram LR)' }}
            extraTabs={[{
              id: 'live', label: 'Live inspection', hidden: !result.liveCheck,
              content: <LiveReport live={result.liveCheck} destination={result.destination} />,
            }]}
          />
        )}
      />
    </AppShell>
  );
}
