# 🛡️ Personal AI Scam Shield

**AI-powered explainable scam detection and risk analysis system**

Paste a suspicious message, SMS, link, or email and get an instant, plain-language breakdown of:

- ⚡ **Risk score** (0–100) and classification (LOW / MODERATE / HIGH / CRITICAL)
- 🧠 **Why it's suspicious** — severity-coded reason cards
- 🎭 **Manipulation techniques** detected (urgency, fear, authority, reward…)
- 🔢 **Attack narrative** — step-by-step how the scam works
- ✅ **Recommended action** — what you should do

---

## Features

| Feature | Details |
|---|---|
| Input types | Message, SMS, URL, Email |
| NLP model | TF-IDF + Logistic Regression (3-class: legitimate / suspicious / scam) |
| URL model | XGBoost classifier (16 URL-structure features) |
| Brand impersonation | 23 trusted brands checked via string-similarity |
| Social engineering | 6 manipulation techniques detected |
| Rule engine | 7 deterministic security rules |
| Risk fusion | Weighted fusion with peak-bias on critical signals |
| History | SQLite metadata log (no message content stored) |
| Privacy | URLs are never fetched or opened |

---

## Tech Stack

**Backend:** Python · FastAPI · scikit-learn · XGBoost · joblib · SQLite  
**Frontend:** React · Vite · CSS custom properties (design token system)

---

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+

### 1. Clone

```bash
git clone https://github.com/<your-username>/personal-ai-scam-shield.git
cd personal-ai-scam-shield
```

### 2. Backend setup

```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Frontend setup

```bash
cd ../frontend
npm install
```

### 4. Run

**Windows — double-click:**
```
start.bat
```

**Manual (two terminals):**

```bash
# Terminal 1 — Backend
cd backend
.venv/Scripts/python -m uvicorn app.main:app --reload --port 8000

# Terminal 2 — Frontend
cd frontend
npm run dev
```

Open **http://localhost:5173**

> On first launch the backend auto-trains the ML models from `backend/app/ml/seed_data.py` (~5 sec). Subsequent starts load saved models instantly.

---

## Project Structure

```
personal-ai-scam-shield/
├── backend/
│   ├── app/
│   │   ├── engines/          # text, url, impersonation, rules, fusion
│   │   ├── ml/               # seed_data.py, train.py
│   │   ├── main.py           # FastAPI app + endpoints
│   │   ├── pipeline.py       # Central analysis orchestrator
│   │   ├── schemas.py        # Pydantic models
│   │   ├── database.py       # SQLite history (metadata only)
│   │   └── config.py
│   ├── models/               # Auto-generated .joblib files (git-ignored)
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.jsx            # Main UI
│       ├── App.css            # Component styles
│       ├── index.css          # Design system tokens
│       ├── api.js             # Fetch wrapper
│       └── samples.js         # Example inputs per tab
├── start.bat                  # Windows dev launcher
└── README.md
```

---

## API

### `POST /api/analyze`

```json
{
  "input_type": "sms",
  "content": "Your SBI account will be blocked. Click: https://sbi-verify.xyz",
  "sender": "SBIBNK",
  "subject": ""
}
```

**Response fields:** `risk_score`, `risk_level`, `risk_label`, `scam_type`, `nlp_label`, `techniques`, `reasons`, `narrative`, `recommendation`, `extracted_urls`, `signals`, `disclaimer`

### `GET /api/history?limit=20`

Returns last N analyses (metadata only — no message content ever stored).

---

## Privacy

- Raw message content is **never stored**
- URLs are **never fetched or visited**
- All analysis runs locally on your machine
- No external API calls are made

---

## License

MIT
