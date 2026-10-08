# CyberGuard — AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection System

Built for Problem Statement 9 (CYBERGUARD). A working, deployable platform — not a slide-deck mockup — that detects phishing (email/SMS/QR), malicious URLs, deepfake/impersonation across images/audio/video, account-takeover behaviour, and technical threats (malware/network/API-abuse/insider-threat/log-based), scores risk, explains *why* in plain English, maps to MITRE ATT&CK, and recommends a response.

---

## 1. Architecture

```
                        ┌─────────────────────┐
                        │   React + Bootstrap │   (frontend/)
                        │   SPA dashboard      │
                        └──────────┬───────────┘
                                   │ REST (JWT)
                        ┌──────────▼───────────┐
                        │   Node.js / Express   │   (backend-node/)
                        │   auth, orchestration,│
                        │   Gemini AI, QR, live │
                        │   URL checks, ffmpeg  │
                        └──────┬───────────┬────┘
                               │           │
                 ┌─────────────▼───┐   ┌───▼─────────────────┐
                 │  C++ detection   │   │   Google Gemini API  │
                 │  engine (httplib)│   │   (LLM + multimodal) │
                 │  (detection-     │   └───────────────────────┘
                 │   engine-cpp/)   │
                 └──────────────────┘
                               │
                        ┌──────▼───────┐
                        │  PostgreSQL   │   (database/init.sql)
                        └───────────────┘
```

**Why this split, and an honest note on the stack:** the brief asked for C++ for speed/security. C++ is genuinely the right tool for the actual detection math (string/URL analysis, statistical anomaly scoring, image/audio byte parsing, log-pattern analysis) — that's real, hand-written, dependency-light C++ in `detection-engine-cpp/`. But C++ has no mature ecosystem for OAuth, JWT, ORMs, or third-party API integration, so the API/auth/orchestration layer — plus QR decoding, live URL/TLS checks, and ffmpeg-based video frame extraction — is Node.js. This hybrid is what real security products (fast native core behind a higher-level API layer) actually look like.

### Where the PRD's "user / admin / scanning database" requirement lives
One PostgreSQL instance, three logical concerns, cleanly separated by table (see comments at the top of `database/init.sql`):
- **User database** → `users`, `known_devices`, `auth_events`
- **Admin database** → `admin_audit_log` (every privileged action, append-only)
- **Scanning database** → `scans`, `threats`

---

## 2. Full feature coverage against the PRD

### Key Threat Scenarios
| PRD scenario | Status | Where |
|---|---|---|
| Phishing: emails, SMS/messages | ✅ | `text_analyzer.cpp` + Gemini |
| Phishing: QR-code-based | ✅ | `qrService.js` decodes the QR, then reuses the URL/text engines |
| Phishing: fraudulent websites, malicious/deceptive URLs | ✅ | `url_analyzer.cpp` + `liveUrlService.js` |
| Deepfake: images | ✅ | `image_forensics.cpp` + Gemini vision |
| Deepfake: voice/audio clips | ✅ | `audio_forensics.cpp` (WAV signal analysis: clipping, silence, spectral flatness via real DFT) + Gemini audio understanding |
| Deepfake: video / video calls | ✅ | ffmpeg frame sampling + per-frame `image_forensics` + Gemini multi-frame reasoning |
| Digital impersonation (brand/sender/domain) | ✅ | `text_analyzer.cpp`, `url_analyzer.cpp` |
| Credential theft & account takeover | ✅ | `anomaly_detector.cpp` (brute-force, impossible-travel, new-device, off-hours z-score) |
| Malicious URL: domain spoofing, lookalikes | ✅ | `url_analyzer.cpp` (Levenshtein edit-distance vs. trusted brands) |
| Malicious URL: malicious redirects | ✅ | `liveUrlService.js` follows the real redirect chain and flags host mismatches |
| Malicious URL: suspicious SSL/domain characteristics | ✅ | `liveUrlService.js` inspects the live TLS certificate (expiry, self-signed, untrusted chain) |
| Malicious URL: fake login pages | ✅ | `liveUrlService.js` checks fetched HTML for a password field + brand/domain mismatch |
| **Intelligent Cyber Threat Detection** (malware, network traffic, API abuse, exfiltration, insider threats, system/app logs) | ✅ | `log_analyzer.cpp` — new module, see Section 3 |

### Expected Solution Modules
| Module | Status |
|---|---|
| A. Multi-Source Threat Analysis Engine (email/SMS/URL/image/audio/video/auth logs/system logs/network/API logs) | ✅ all sources covered |
| B. AI-Based Detection Engine (hybrid rule + AI, NLP, CV, speech/audio, anomaly detection, LLMs) | ✅ |
| C. Threat Risk Scoring (Safe→Critical, explained) | ✅ `risk_scorer.cpp` |
| D. Explainable AI | ✅ Gemini analyst-style narrative on every scan |
| E. Intelligent Response Recommendation | ✅ drawn from the PRD's own action vocabulary |
| F. Cybersecurity Command Dashboard | ✅ totals, categories, risk levels, timeline, targeted users, incident status |

### Innovation opportunities implemented
- **MITRE ATT&CK mapping** — every detected category maps to real technique IDs (`mitreMapping.js`)
- **Hybrid rule + AI models** — every scenario runs a deterministic rule engine first, then (optionally) Gemini as a second, independent signal
- **Explainable AI** — see above

### Minimum deliverables
All 12 are satisfied, including **#11 (accuracy/performance evaluation)** — see Section 7 — and **#10 (demonstration using simulated datasets)** — the log-analysis page ships with a one-click "load sample dataset" button, and `evaluation/dataset.json` is a labeled synthetic set for the phishing/URL engines.

---

## 3. What's new: the log-based Technical Threat Detection engine

This is the module that was missing from the first delivery and fully closes the PRD's "Intelligent Cyber Threat Detection" requirement. `detection-engine-cpp/src/log_analyzer.cpp` accepts a JSON array of log entries (auth logs, network connection logs, API access logs, or system/process logs — any subset of fields) and runs five independent rule-based detectors:

| Detector | What it catches | Example signal |
|---|---|---|
| Network scanning | Port-scan behaviour | One source IP touching 15+ distinct destination ports |
| API abuse | Rate spikes, credential stuffing, endpoint enumeration | 100+ requests to one endpoint; >50% error rate |
| Data exfiltration | Abnormally large or off-hours transfers | >2GB transferred; large transfer outside 6am-10pm |
| Insider threat | Privileged-action clusters, mass file staging | 3+ role-escalation/bulk-export events by one user; 50+ distinct files touched |
| Malware indicators | Droppers, obfuscation, fork-bomb-like spawning | Double-extension files (`invoice.pdf.exe`), execution from `/tmp`, base64-encoded PowerShell, 20+ spawns of the same process |

Try it immediately from the UI: **Technical Threats (Logs)** page → **Load sample dataset** → **Analyse Logs**. It will correctly flag all five categories and log five separate threats to your dashboard.

---

## 3b. What's new in v2: C++ machine learning in every feature, Connect Gmail, deep URL analysis, Network IDS

Nothing was removed — every earlier rule engine, Gemini layer and page still runs. Each feature now **also** has its own
ML model written from scratch in C++17 (`detection-engine-cpp/src/ml/`, no Python at runtime). The ML probability is
fused with the rule/forensic score and Gemini, and every result explains *why* (top words / features / regions).

### ML model per feature (held-out test results, see the **ML Models** page)

| Feature | Model (C++) | Training data | Held-out result |
|---|---|---|---|
| Message / Email phishing (+ Gmail) | TF-IDF word 1-2 grams → Logistic Regression (AdaGrad) + Multinomial Naive Bayes, weight chosen on validation | UCI SMS Spam + Enron-Spam (39,290) | Acc 0.984 · F1 0.983 · AUC 0.999 (email F1 0.989, SMS F1 0.852) |
| URL & website | Gradient Boosted Trees on 42 lexical/brand/homograph features + char 3-5-gram TF-IDF Logistic Regression | faizann24 URLs + Phishing.Database (466k), **group split by domain** | Acc 0.950 · F1 0.911 · AUC 0.988 |
| Network IDS | GBDT (attack vs normal) + Random Forest (normal/DoS/Probe/R2L/U2R) + Isolation Forest (novel traffic) | NSL-KDD KDDTrain+ → official KDDTest+ | Acc 0.817 · Precision 0.969 · AUC 0.968 |
| Login risk | Isolation Forest + robust envelope (unsupervised, retrainable on your own logins) | synthetic baseline | F1 0.971 on simulated attacks |
| Technical threats (logs) | Isolation Forest per user/IP (12 behaviour features) + robust envelope | synthetic baseline | F1 0.862 · AUC 0.993 |
| Voice clone / audio (+ video voice track) | GBDT on 41 MFCC/spectral features | LibriSpeech vs vocoder + TTS | Acc 0.953 · AUC 0.995 |
| Image / video frames | Block-level GBDT (32×32 ELA/noise/JPEG-grid features) stacked with global GBDT, localises suspicious regions | public-domain photos + synthetic forgeries | Acc 0.64 · AUC 0.70 (**experimental**) |

Retrain any model: `datasets/fetch_datasets.sh` then `./build/cg_train ../datasets models all` (see `datasets/README.md`).
Admins can also click **ML Models → Retrain login model** to fit the login model to their own users' history.

### Connect Gmail (keeps the manual way)
**Message / Email** still works exactly as before (paste text). The new **Gmail Phishing Inbox** page adds
*Connect with Google* (read-only `gmail.readonly` scope) → **Scan inbox now** → a list of phishing mails with ML probability,
SPF/DKIM/DMARC results, look-alike sender / display-name spoof / Reply-To checks, risky attachments and per-link URL analysis.
Mails already scanned are skipped; the refresh token is stored AES-256-GCM encrypted; **Disconnect** revokes access.

Setup (uses the same OAuth client as Google login):
1. Google Cloud Console → *APIs & Services → Library* → enable **Gmail API**.
2. *Credentials →* your OAuth client → add Authorized redirect URI **`http://localhost:4000/api/gmail/callback`** (keep the login one too).
3. *OAuth consent screen →* add scope `.../auth/gmail.readonly` and add your Gmail address under **Test users** (required while the app is in "Testing").
4. `.env`: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, optionally `TOKEN_ENCRYPTION_KEY` (any long random string). Restart the backend.

### Deep URL analysis — "https" is not "safe"
Switching `http://` to `https://` no longer changes the verdict:
- The ML URL model is **scheme-invariant** (scheme and `www.` are stripped before features are computed), and the rule engine treats HTTPS as neutral (`https_is_not_trust`, weight 0) — only missing HTTPS adds risk.
- **URL anatomy**: the real *registered* domain via the Public Suffix List (`paypal.com.secure-login.xyz` → `secure-login.xyz`), brand-in-subdomain / brand-in-path, `user@host` tricks, decimal/hex/octal IP hosts, punycode + homograph skeletons (`pаypal` with Cyrillic а), mixed scripts, open-redirect parameters, shorteners, free hosting, executable downloads.
- **Live inspection** (server-side): follows every redirect hop (incl. meta refresh) and re-analyses the final destination; TLS certificate issuer, age, hostname match, self-signed/untrusted chain, free DV issuer; DNS (fast-flux, dynamic DNS); domain age via RDAP; page forensics (password/card/OTP fields, forms posting to other domains, brand imitation, obfuscated JS, hidden iframes); optional Google Safe Browsing (`SAFE_BROWSING_API_KEY`).
- Real brand domains (e.g. `accounts.google.com`, `onlinesbi.sbi`) are recognised so they are not flagged just for containing "login".

### Works on phones, tablets and desktops
The web app is responsive: below 992 px wide (Android/iOS phones, tablets) the sidebar turns into a slide-out menu (☰ button in the top bar), wide tables scroll sideways and cards stack. To open it on your phone during a demo, connect the phone to the same Wi-Fi and browse to `http://<your-laptop-IP>:8080` — and set `REACT_APP_API_URL=http://<your-laptop-IP>:4000/api` and `FRONTEND_URL=http://<your-laptop-IP>:8080` in `.env`, then rebuild (`docker compose up --build`), because `localhost` on the phone means the phone itself.

### Network Intrusion Detection System (C++)
**Network IDS** page:
- **Analyse capture file** — upload `.pcap`/`.pcapng` (Wireshark, tcpdump, dumpcap). The engine decodes Ethernet/VLAN/Linux-SLL/raw IP, IPv4/IPv6, TCP/UDP/ICMP/DNS, rebuilds connections with Zeek-style TCP states, computes the NSL-KDD traffic features and runs the ML ensemble plus signature rules: port scan, host sweep, SYN/UDP/ICMP floods, ping sweep, brute force, C2 beaconing, DNS tunnelling, large outbound transfer, land attack, malformed fragments, suspicious ports, cleartext protocols — all mapped to MITRE ATT&CK and logged as threats.
  Try `detection-engine-cpp/samples/attack_mix.pcap` (Critical, 9 alerts) and `normal_traffic.pcap` (Safe, 0 alerts).
- **Live monitoring** (admin / SOC analyst) — pick an interface, optional BPF filter, sliding-window analysis every few seconds. Needs the engine built with libpcap (the Docker image is). Under Docker Desktop the container only sees its own traffic; on **Windows**, capture with Wireshark and upload the file, or build natively with Npcap.
- **Always-on sensor (Linux)** — `docker compose --profile live up -d nids-sensor` sniffs the host interface (`NIDS_IFACE` in `.env`) and pushes alerts to `/api/nids/ingest` (set `ENGINE_KEY`).

### Online and offline modes
CyberGuard runs in either mode from the same code. The badge in the top bar shows the current mode; click it to see which features are available.

| Feature | Online | Offline |
|---|---|---|
| Rule engines, 7 C++ ML models, Network IDS, logins, logs | ✔ | ✔ |
| Scan history, dashboard, reset / delete / undo | ✔ | ✔ |
| Gemini AI explanations and vision/audio reasoning | ✔ | skipped (built-in explanation and actions are used) |
| Gmail inbox connection and scanning | ✔ | unavailable (already scanned mails stay listed) |
| Live URL inspection (redirects, certificate, DNS, domain age) | ✔ | skipped (rules + URL model still run) |
| Google sign-in | ✔ | email + password only |

Set `CYBERGUARD_MODE` in `.env`: `auto` (default: checks the connection every minute and switches by itself), `online` or `offline`. Every result shows whether it was an *online* or *offline analysis*. To run fully offline with Docker:

```bash
docker compose -f docker-compose.yml -f docker-compose.offline.yml up --build
```

Fonts and icons are bundled with the app, so the interface looks the same without internet.

### Scan history: delete, undo and reset
- **Delete one scan**: the bin icon on each row. A small bar appears at the bottom for 3 seconds with **Undo**.
- **Reset history**: removes all of your scans after a confirmation dialog (undo available for 5 seconds).
- The dashboard, Gmail list and Network IDS events update immediately. Deleted scans are kept for 60 seconds so undo works, then removed permanently.
- API: `DELETE /api/scan/:id`, `DELETE /api/scan/history`, `POST /api/scan/restore { ids: [...] }`.

### Themes
Three themes (Midnight, Daylight, Graphite) from the palette button in the top bar; the choice is remembered per browser. Daylight is best for projectors.

---

## 4. Prerequisites

- **Docker Desktop** (recommended — one command brings up all services), **or**
- Manually: Node.js ≥ 18, a C++17 compiler + CMake, PostgreSQL ≥ 14
- **ffmpeg** installed on the backend host — required for video deepfake scanning only; every other feature works without it (`apt install ffmpeg` / `brew install ffmpeg`)
- A **Gemini API key** — free tier at https://aistudio.google.com/apikey (the app runs and scores without it, using the C++ rule engines alone, but AI explanations and deepfake/voice-clone reasoning need it)
- (Optional) **Google OAuth credentials** — https://console.cloud.google.com/apis/credentials → OAuth Client ID → Web application → Authorized redirect URI: `http://localhost:4000/api/auth/google/callback`

---

## 5. Quick start (Docker)

```bash
cd cyberguard
cp .env.example .env
# edit .env: at minimum set GEMINI_API_KEY, JWT_SECRET, SESSION_SECRET

docker compose up --build
```

- Frontend: http://localhost:8080
- Backend health: http://localhost:4000/api/health
- Engine health: http://localhost:5050/health

Default seeded admin: `admin@cyberguard.local` / `ChangeMe!123` — change this immediately after first login.

---

## 6. Manual setup in VSCode (no Docker)

### 6a. Database
```bash
psql -U postgres -c "CREATE USER cyberguard WITH PASSWORD 'cyberguard';"
psql -U postgres -c "CREATE DATABASE cyberguard OWNER cyberguard;"
psql -U cyberguard -d cyberguard -f database/init.sql
```

### 6b. C++ detection engine
```bash
cd detection-engine-cpp
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
./build/cyberguard_engine        # listens on :5050
```
Run it from inside `detection-engine-cpp/` so it finds `models/` and `data/` (or set `MODELS_DIR` / `PSL_PATH`).
Live packet capture needs libpcap (`sudo apt install libpcap-dev`; Windows: Npcap SDK) — without it CMake prints a warning and
everything else, including pcap-file analysis, still works. Add `-DWITH_PCAP=OFF` to skip it.
No CMake? `g++ -std=c++17 -O2 -Iinclude -Isrc -pthread $(find src -name '*.cpp' ! -name cg_train.cpp) -o build/cyberguard_engine`

### 6c. Node backend
```bash
cd backend-node
cp .env.example .env     # fill in GEMINI_API_KEY, JWT_SECRET, SESSION_SECRET, DATABASE_URL (FRONTEND_URL=http://localhost:8080)
npm install
npm start                 # listens on :4000
```

### 6d. React frontend
```bash
cd frontend
npm install
npm start                 # opens :8080 (set in frontend/.env)
```

---

## 7. Testing procedure

### 7.1 Automated accuracy/performance evaluation (PRD deliverable #11)
A labeled, reproducible evaluation harness ships in `evaluation/`:
```bash
cd detection-engine-cpp && ./build/cyberguard_engine &   # engine must be running
cd ../evaluation
npm install
npm run evaluate
```
This runs 30 labeled phishing-text/legitimate samples and 30 labeled malicious/legitimate URLs through the live rule engines and writes `evaluation/report.md` + `report.json`. Last run against this build: **91.7% overall accuracy, 100% precision, 83.3% recall, F1 90.9%** (rule engines only — enabling Gemini typically improves recall further; the note at the bottom of `report.md` explains how to extend the harness to the full rule+AI pipeline). `evaluation/dataset.json` documents exactly how the samples were constructed — extend it with real, authorised samples before citing results externally.

### 7.2 Engine smoke tests
```bash
curl -s http://localhost:5050/health
curl -s -X POST localhost:5050/analyze/url  -H "Content-Type: application/json" -d '{"url":"http://paypa1-secure-login.verify-account.xyz/signin"}'
curl -s -X POST localhost:5050/analyze/logs -H "Content-Type: application/json" -d '{"entries":[{"sourceIp":"10.0.0.1","destinationPort":22},{"sourceIp":"10.0.0.1","destinationPort":23}]}'
# http vs https gives the same ML score:
curl -s -X POST localhost:5050/analyze/url -H "Content-Type: application/json" -d '{"url":"https://paypa1-secure-login.verify-account.xyz/signin"}'
# Network IDS on the bundled capture (run inside detection-engine-cpp/)
curl -s -X POST "localhost:5050/analyze/pcap?name=attack_mix.pcap" --data-binary @samples/attack_mix.pcap -H "Content-Type: application/octet-stream"
curl -s localhost:5050/ml/models
```

### 7.3 End-to-end manual test script
1. Register at `/register`.
2. **Phishing (email/SMS):** *Message / Email* page with a sample like the curl example above → expect High/Critical.
3. **Phishing (QR code):** generate a QR code online encoding a suspicious URL, upload it on the *Image / QR / Deepfake* page → expect `qrDetected: true` and the decoded URL scored.
4. **Malicious URL + live checks:** scan any URL on the *URL & Website* page (don't set `skipLiveCheck`) → the response includes `liveCheck` with certificate and redirect info if the site is reachable.
5. **Deepfake image:** upload any JPEG/PNG.
6. **Deepfake audio:** upload a WAV voice clip on the *Voice / Audio* page.
7. **Deepfake video:** upload a short MP4 on the *Video* page (requires ffmpeg).
8. **Technical threat (logs):** *Technical Threats (Logs)* page → **Load sample dataset** → **Analyse Logs** → expect all five categories (network/API-abuse/exfiltration/insider/malware) flagged and five threats logged.
9. **Account takeover:** log out, fail login 6+ times, then succeed → check `auth_events` in Postgres for the recorded risk score.
10. **Admin:** log in as `admin@cyberguard.local`, update a threat's status, deactivate a test user, confirm it in `admin_audit_log`.

### 7.4 Hardening checks
- Kill the C++ engine mid-session → scans should return a clear 5xx, not hang (5s timeout on all engine calls).
- Upload a video without ffmpeg installed → expect a clear 503 with an explanatory message, not a crash.
- Hit any `/api/scan/*` route without a token → expect 401. Hit `/api/admin/*` as a non-admin → expect 403.

---

## 8. Honest scope notes

- **ML metrics are measured on held-out data but from public datasets**, not your organisation's traffic. Phishing-text accuracy on SMS is lower (F1 0.85) than on email (0.99).
- **Image manipulation ML is experimental** (AUC 0.70, trained on 21 photos with synthetic edits) and is **not** a GAN/diffusion face-deepfake detector — fully AI-generated faces rely on the Gemini layer. It carries low weight in the fused score.
- **Voice-clone ML** was trained on 3 real speakers vs vocoder/espeak speech: a useful signal, not proof. Modern neural voice clones need a dataset such as ASVspoof to be detected reliably — retrain with `cg_train` if you have one.
- **NIDS ML (NSL-KDD)** is strong for DoS/probe traffic but weak for R2L/U2R (recall 0.09/0.16) because those attacks live in payloads, which the header-only features cannot see; signature rules cover brute force, beaconing and tunnelling instead. NSL-KDD is an old dataset — modern traffic may produce ML false positives, which is why ML alerts are grouped and shown with the rule evidence.
- **Login and log anomaly models are validated on synthetic behaviour.** Use *Retrain login model* once you have ~200+ real logins.
- **Gmail** access is read-only; while your Google OAuth app is in "Testing" only listed test users can connect, and tokens for testing apps expire after 7 days (just reconnect).
- **Live URL checks (redirects/TLS/DNS/RDAP/fake-login-page) are best-effort.** If the target site is unreachable, rate-limits the scanner, or blocks unusual user agents, `liveCheck.reachable` will be `false` and the scan falls back to static domain-string analysis only.
- **The log analyzer's thresholds (15 ports, 100 requests, 2GB, etc.) are reasonable defaults, not tuned against a production traffic baseline.** For a real deployment, calibrate them against your own normal traffic to reduce false positives/negatives.
- **The evaluation dataset is author-constructed and synthetic**, styled on commonly reported phishing patterns — not sourced from a real breach or a named public dataset. Extend it with real, authorised samples (e.g. PhishTank, or your own inbox with permission) before citing accuracy numbers in a formal submission.
- **The trusted-brand domain list** used for typosquat detection is a small hardcoded seed list for demonstration purposes rather than a live threat-intelligence feed.

---

## 9. Deployment

Same as before — everything is containerized:
```bash
cp .env.example .env && docker compose up --build
```
For a single VM (DigitalOcean/Hetzner/Lightsail): install Docker + ffmpeg, clone, `docker compose up -d --build`, add a reverse proxy for HTTPS. For Render/Railway: deploy each of the three Dockerfiles as separate services plus a managed Postgres add-on.

---

## 10. Project structure

```
cyberguard/
├── database/init.sql              # PostgreSQL schema + seed admin
├── detection-engine-cpp/
│   └── src/
│       ├── url_analyzer.*          # malicious URL / domain detection
│       ├── text_analyzer.*         # phishing / social-engineering text
│       ├── anomaly_detector.*      # login / account-takeover anomalies
│       ├── image_forensics.*       # image deepfake signal extraction
│       ├── audio_forensics.*       # audio/voice-clone signal extraction (WAV/DFT)
│       ├── log_analyzer.*          # malware/network/API-abuse/insider-threat detection
│       ├── risk_scorer.*           # multi-component risk fusion
│       ├── url_parser.*            # PSL registrable domain, punycode, homographs, obfuscated IPs
│       ├── model_registry.*        # loads models/*.json, runs every ML prediction
│       ├── ml/                     # Logistic Regression, Naive Bayes, TF-IDF, GBDT, Random Forest, Isolation Forest
│       ├── features/               # URL / NIDS / behaviour / image / audio feature extraction
│       ├── nids/                   # pcap/pcapng decoder, flow builder, NIDS rules+ML, libpcap live capture
│       └── cg_train.cpp            # trainer: writes models/*.json with held-out metrics
│   ├── models/                     # trained models (JSON) + metrics_summary.json
│   ├── samples/                    # normal_traffic.pcap, attack_mix.pcap
│   └── data/public_suffix_list.dat
├── backend-node/
│   └── src/
│       ├── services/
│       │   ├── geminiService.js     # phishing/image/audio/video AI reasoning
│       │   ├── engineClient.js      # C++ engine HTTP client
│       │   ├── qrService.js         # QR-code decoding (jsQR + Jimp)
│       │   ├── videoService.js      # ffmpeg frame extraction
│       │   ├── liveUrlService.js    # redirect hops, TLS cert, DNS, RDAP age, page forensics, Safe Browsing
│       │   ├── gmailService.js      # Gmail OAuth + message parsing + SPF/DKIM/DMARC checks
│       │   ├── messageAnalysis.js   # shared phishing pipeline (manual scan + Gmail)
│       │   └── mitreMapping.js      # MITRE ATT&CK technique lookup
│       └── controllers/, routes/, models/, middleware/
├── frontend/src/pages/              # Login, Dashboard, Scan{Message,Url,Image,Audio,Video,Logs}, GmailInbox, NetworkIDS, MLModels, Admin
├── datasets/                        # fetch_datasets.sh + README (only needed to retrain)
├── evaluation/                      # accuracy/performance evaluation harness + labeled dataset
├── docker-compose.yml
└── .env.example
```
