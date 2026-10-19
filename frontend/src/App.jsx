import { useCallback, useEffect, useRef, useState } from "react";
import { analyze, getHistory } from "./api.js";
import { SAMPLES } from "./samples.js";
import "./App.css";

/* ── Constants ───────────────────────────────────────────────── */
const TYPES = [
  { id: "message", label: "💬 Message" },
  { id: "sms",     label: "📱 SMS" },
  { id: "url",     label: "🔗 URL" },
  { id: "email",   label: "📧 Email" },
];

const SEV_ICON = {
  critical: "🔴",
  high:     "🟠",
  medium:   "🟡",
  low:      "🟢",
  info:     "🔵",
};

function signalClass(score) {
  if (score >= 76) return "sig-critical";
  if (score >= 51) return "sig-high";
  if (score >= 26) return "sig-moderate";
  return "sig-low";
}

/* ── Score Ring ──────────────────────────────────────────────── */
function ScoreRing({ score, level }) {
  const CIRCUMFERENCE = 283; // 2π × 45
  const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
  return (
    <div className="score-ring-wrap">
      <svg className="score-ring-svg" viewBox="0 0 100 100">
        <circle className="score-ring-track" cx="50" cy="50" r="45" />
        <circle
          className={`score-ring-fill level-${level}`}
          cx="50"
          cy="50"
          r="45"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="score-ring-center">
        <span className="score-number">{score}</span>
        <span className="score-denom">/100</span>
      </div>
    </div>
  );
}

/* ── Signal Bars ─────────────────────────────────────────────── */
function SignalBars({ signals }) {
  return (
    <div className="signals-grid">
      {signals.map((s, i) => (
        <div key={s.name} className="signal-row">
          <span className="signal-label" title={s.label}>{s.name}</span>
          <div className="signal-bar-wrap">
            <span className="signal-score">{s.score}</span>
            <div className="signal-bar-track">
              <div
                className={`signal-bar-fill ${signalClass(s.score)}`}
                style={{
                  width: `${s.score}%`,
                  "--bar-delay": `${i * 0.1}s`,
                }}
              />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ── Loading Skeleton ────────────────────────────────────────── */
function LoadingSkeleton() {
  return (
    <div className="loading-state">
      <div className="loading-spinner">
        <div className="spinner-ring" />
        <span>
          Analyzing
          <span className="loading-dot">.</span>
          <span className="loading-dot">.</span>
          <span className="loading-dot">.</span>
        </span>
      </div>
      <div className="skel-block skeleton" />
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <div className="skel-line skel-sm skeleton" />
        <div className="skel-line skel-md skeleton" />
        <div className="skel-line skel-lg skeleton" />
        <div className="skel-line skel-md skeleton" />
        <div className="skel-line skel-full skeleton" />
      </div>
      <div className="skel-block skeleton" style={{ height: 60 }} />
    </div>
  );
}

/* ── Result Card ─────────────────────────────────────────────── */
function ResultCard({ result }) {
  const lvl = result.risk_level;
  return (
    <div className="result-card">
      {/* Score section */}
      <div className={`score-section level-${lvl}`}>
        <ScoreRing score={result.risk_score} level={lvl} />
        <div className="score-meta">
          <div className={`score-level level-${lvl}`}>{result.risk_label}</div>
          <div className="score-scam-type">{result.scam_type}</div>
          <span className="score-nlp-tag">NLP: {result.nlp_label}</span>
        </div>
        <SignalBars signals={result.signals} />
      </div>

      {/* Technique chips */}
      {result.techniques.length > 0 && (
        <div className="chips-row">
          {result.techniques.map((t) => (
            <span key={t} className="chip">{t}</span>
          ))}
        </div>
      )}

      {/* Why this score */}
      <div className="section-head">Why this score</div>
      <ul className="reasons-list">
        {result.reasons.length === 0 && (
          <li className="reason-item sev-info">
            <span className="reason-icon">🔵</span>
            <div className="reason-body">
              <div className="reason-title">No major red flags</div>
              <div className="reason-detail">No high-risk indicators stood out.</div>
            </div>
          </li>
        )}
        {result.reasons.map((r, i) => (
          <li
            key={i}
            className={`reason-item sev-${r.severity}`}
            style={{ "--reason-delay": `${i * 0.06}s` }}
          >
            <span className="reason-icon">{SEV_ICON[r.severity]}</span>
            <div className="reason-body">
              <div className="reason-title">{r.title}</div>
              <div className="reason-detail">{r.detail}</div>
            </div>
          </li>
        ))}
      </ul>

      {/* Attack narrative */}
      <div className="section-head">Attack narrative</div>
      <div className="narrative-summary">{result.narrative_summary}</div>
      <ol className="narrative-list">
        {result.narrative.map((step) => (
          <li
            key={step.order}
            className="narrative-item"
            style={{ "--nar-delay": `${step.order * 0.08}s` }}
          >
            <div className="narrative-num">{step.order}</div>
            <div className="narrative-body">
              <div className="narrative-title">{step.title}</div>
              <div className="narrative-detail">{step.detail}</div>
            </div>
          </li>
        ))}
      </ol>

      {/* Recommendation */}
      <div className="recommend-box">
        <div className="recommend-label">⚡ Recommended action</div>
        <div className="recommend-title">{result.recommendation_title}</div>
        <div className="recommend-body">{result.recommendation}</div>
      </div>

      {/* URLs found */}
      {result.extracted_urls.length > 0 && (
        <div className="urls-found">
          <strong>🔗 Links found</strong>&nbsp;
          {result.extracted_urls.map((u) => (
            <span key={u} className="url-chip" title={u}>{u}</span>
          ))}
        </div>
      )}

      {/* Disclaimer */}
      <div className="disclaimer">⚠️ {result.disclaimer}</div>
    </div>
  );
}

/* ── History Panel ───────────────────────────────────────────── */
function HistoryPanel({ refreshKey }) {
  const [open, setOpen]       = useState(false);
  const [records, setRecords] = useState([]);

  useEffect(() => {
    if (!open) return;
    getHistory(20)
      .then(setRecords)
      .catch(() => setRecords([]));
  }, [open, refreshKey]);

  function fmt(ts) {
    try {
      return new Date(ts).toLocaleString(undefined, {
        month: "short", day: "numeric",
        hour: "2-digit", minute: "2-digit",
      });
    } catch {
      return ts;
    }
  }

  return (
    <div className="history-section">
      <button
        className="history-toggle"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        id="history-toggle-btn"
      >
        <span>🕓</span>
        <span>Recent analyses</span>
        <span className={`history-toggle-caret ${open ? "open" : ""}`}>▾</span>
      </button>

      {open && (
        <div className="history-panel" role="region" aria-label="Analysis history">
          {records.length === 0 ? (
            <p className="history-empty">No analyses recorded yet.</p>
          ) : (
            <ul className="history-list">
              {records.map((r, i) => (
                <li
                  key={r.id}
                  className="history-item"
                  style={{ animationDelay: `${i * 0.04}s` }}
                >
                  <div className={`history-badge level-${r.risk_level}`}>
                    {r.risk_score}
                  </div>
                  <div className="history-meta">
                    <div className="history-scam">{r.scam_type}</div>
                    <div className="history-sub">{fmt(r.timestamp)}</div>
                  </div>
                  <span className="history-type-pill">{r.input_type}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Main App ────────────────────────────────────────────────── */
export default function App() {
  const [inputType, setInputType] = useState("sms");
  const [content,   setContent]   = useState(SAMPLES.sms.content);
  const [sender,    setSender]    = useState(SAMPLES.sms.sender || "");
  const [subject,   setSubject]   = useState(SAMPLES.sms.subject || "");
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState("");
  const [result,    setResult]    = useState(null);
  const [histKey,   setHistKey]   = useState(0);
  const resultRef = useRef(null);

  const contentPlaceholder =
    inputType === "url"   ? "https://example.com/suspicious-link" :
    inputType === "email" ? "Paste the email body here…" :
                            "Paste the suspicious message or SMS…";

  function switchTab(id) {
    setInputType(id);
    const s = SAMPLES[id] || {};
    setContent(s.content || "");
    setSender(s.sender   || "");
    setSubject(s.subject || "");
    setResult(null);
    setError("");
  }

  const onSubmit = useCallback(
    async (e) => {
      e.preventDefault();
      setLoading(true);
      setError("");
      setResult(null);
      try {
        const data = await analyze({ input_type: inputType, content, sender, subject });
        setResult(data);
        setHistKey((k) => k + 1);
        // Scroll result into view on mobile
        setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
      } catch (err) {
        setError(err.message || "Could not reach the API. Is the backend running on port 8000?");
      } finally {
        setLoading(false);
      }
    },
    [inputType, content, sender, subject]
  );

  return (
    <div className="shell">
      {/* ── Hero ────────────────────────────────────────────────── */}
      <header className="hero">
        <div className="hero-badge">
          <span>🛡️</span>
          Detect · Explain · Educate · Protect
        </div>
        <h1>Personal AI Scam Shield</h1>
        <p className="hero-lede">
          Paste a suspicious message, SMS, link, or email. Get an instant risk score,
          the reasons behind it, the attack pattern, and what to do — in plain language.
        </p>
        <div className="hero-steps">
          {["AI text analysis", "URL intelligence", "Brand impersonation", "Attack narrative", "Defensive guidance"].map((s) => (
            <span key={s} className="hero-step">
              <span className="hero-step-dot" />
              {s}
            </span>
          ))}
        </div>
      </header>

      {/* ── Main Grid ───────────────────────────────────────────── */}
      <main className="main-grid">
        {/* Input Panel */}
        <form className="panel input-panel" onSubmit={onSubmit} noValidate>
          {/* Tab switcher */}
          <div className="tabs" role="tablist">
            {TYPES.map((t) => (
              <button
                key={t.id}
                type="button"
                role="tab"
                aria-selected={inputType === t.id}
                id={`tab-${t.id}`}
                className={`tab ${inputType === t.id ? "tab-active" : ""}`}
                onClick={() => switchTab(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Sender field */}
          {(inputType === "sms" || inputType === "email") && (
            <div className="field">
              <label className="field-label" htmlFor="field-sender">
                {inputType === "email" ? "From (sender email)" : "Sender (if shown)"}
              </label>
              <input
                id="field-sender"
                className="field-input"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder={inputType === "email" ? "support@suspicious-domain.com" : "e.g. SBIBNK or +91-XXXXXXXXXX"}
              />
            </div>
          )}

          {/* Subject field */}
          {inputType === "email" && (
            <div className="field">
              <label className="field-label" htmlFor="field-subject">Subject line</label>
              <input
                id="field-subject"
                className="field-input"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="URGENT: Your account will be suspended"
              />
            </div>
          )}

          {/* Content field */}
          <div className="field">
            <label className="field-label" htmlFor="field-content">
              {inputType === "url" ? "URL / Link to analyze" : "Message content"}
            </label>
            <textarea
              id="field-content"
              className="field-input"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={contentPlaceholder}
              rows={inputType === "url" ? 3 : 8}
              required
            />
          </div>

          {/* Privacy hint */}
          <div className="field-hint">
            <span>🔒</span>
            <span>
              Never paste passwords, OTPs, or PINs here. Links are analyzed locally — never fetched or opened.
            </span>
          </div>

          {/* Buttons */}
          <div className="actions">
            <button
              id="analyze-btn"
              className="btn-primary"
              type="submit"
              disabled={loading || !content.trim()}
            >
              {loading ? "Analyzing…" : "⚡ Analyze risk"}
            </button>
            <button
              id="sample-btn"
              className="btn-ghost"
              type="button"
              onClick={() => {
                switchTab(inputType);
              }}
            >
              Load example
            </button>
          </div>

          {error && <div className="form-error" role="alert">{error}</div>}

          {/* History */}
          <HistoryPanel refreshKey={histKey} />
        </form>

        {/* Result Panel */}
        <section
          className="panel result-panel"
          ref={resultRef}
          aria-live="polite"
          aria-label="Analysis results"
        >
          {!result && !loading && (
            <div className="empty-state">
              <div className="empty-icon">🛡️</div>
              <h2>Ready to analyze</h2>
              <p>
                Paste any suspicious content on the left and click{" "}
                <strong>Analyze risk</strong> to get an instant breakdown.
              </p>
              <div className="feature-pills">
                {["Risk score", "Attack narrative", "Scam type", "Manipulation tactics", "Defensive advice"].map((f) => (
                  <span key={f} className="feature-pill">{f}</span>
                ))}
              </div>
            </div>
          )}

          {loading && <LoadingSkeleton />}

          {result && !loading && <ResultCard result={result} />}
        </section>
      </main>
    </div>
  );
}
