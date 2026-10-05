# 🛡️ CyberBuddy

### AI-Powered Cybersecurity Assistant for Non-Technical Users

CyberBuddy is a local, AI-powered cybersecurity assistant designed to help non-technical users understand and respond to suspicious messages and URLs.

Instead of requiring cybersecurity knowledge, CyberBuddy analyzes potentially dangerous content, identifies security indicators, assigns a risk level, and explains the result in simple language.

The project uses deterministic security analysis for risk assessment and **Gemma 3 4B**, running locally through **Ollama**, as an AI explanation layer.

---

## 🚀 Why CyberBuddy?

Cybersecurity warnings are often difficult for non-technical users to understand.

A suspicious message may contain:

- Urgent requests
- Phishing links
- Requests for passwords or OTPs
- Fake account warnings
- Financial requests
- Suspicious URLs

CyberBuddy provides a simple workflow:

```text
Suspicious Message / URL
          ↓
   Security Analysis
          ↓
    Risk Assessment
          ↓
      Evidence
          ↓
    Gemma 3 4B AI
          ↓
 Simple Explanation
          ↓
    Safe Actions
```

---

## ✨ Features

### 📩 Suspicious Message Analyzer

Analyze suspicious emails, SMS messages, and other text-based content.

CyberBuddy detects indicators such as:

- Urgent or pressure-based language
- Credential requests
- OTP/password requests
- Financial requests
- Account access threats
- Suspicious URLs
- Phishing-related patterns

The analyzer produces a risk score and possible attack classification.

### 🔗 Suspicious URL Analyzer

Analyze potentially dangerous URLs.

CyberBuddy checks for indicators including:

- HTTP instead of HTTPS
- IP addresses used instead of domain names
- Suspicious URL patterns
- Security-sensitive keywords
- Login and authentication-related paths
- Other URL characteristics

### 🤖 Local AI Explanation

CyberBuddy uses **Gemma 3 4B** through **Ollama** to explain the deterministic analysis in simple language.

The AI explains:

- Why the content may be suspicious
- What the detected indicators mean
- Why the risk level matters
- What the user should do next

The AI does **not** make the final security decision.

### 🛡️ Deterministic Risk Assessment

CyberBuddy separates security analysis from AI generation.

The deterministic analysis engine is responsible for:

- Detecting indicators
- Calculating risk scores
- Assigning risk levels
- Identifying possible attack types
- Generating recommended actions

Gemma only explains the results.

If Ollama or Gemma is unavailable, CyberBuddy can still perform the deterministic security analysis.

### 🔒 Privacy-Focused Local AI

Gemma runs locally through Ollama.

No external AI API key is required for the AI explanation feature.

```text
CyberBuddy
    ↓
Local Ollama
    ↓
Gemma 3 4B
```

---

## 🧠 Architecture

```text
                    ┌─────────────────────┐
                    │      User Input     │
                    │ Message / URL       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Deterministic       │
                    │ Security Analyzer   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Evidence & Indicators│
                    │ Risk Score           │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Risk Engine      │
                    │ LOW / MEDIUM / HIGH │
                    │ / CRITICAL          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Gemma 3 4B        │
                    │   via Ollama        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Simple AI           │
                    │ Explanation         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Recommended Safe    │
                    │ Actions             │
                    └─────────────────────┘
```

### Important Design Principle

> **AI explains the security analysis; AI does not determine the security risk.**

This separation keeps the core security logic deterministic and testable.

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core analysis and backend |
| FastAPI | REST API |
| Pydantic | Request validation |
| JavaScript | Frontend functionality |
| HTML | Frontend structure |
| CSS | Frontend styling |
| Ollama | Local AI inference |
| Gemma 3 4B | AI explanation |
| Pytest | Automated testing |
| Git | Version control |

---

## 📁 Project Structure

```text
Cyberbuddy/
│
├── analyzer/
│   ├── __init__.py
│   ├── message_analyzer.py
│   ├── risk_engine.py
│   ├── url_analyzer.py
│   └── url_risk_engine.py
│
├── backend/
│   ├── __init__.py
│   ├── main.py
│   └── ai/
│       ├── __init__.py
│       └── explainer.py
│
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── tests/
│   ├── __init__.py
│   ├── test_message_analyzer.py
│   ├── test_risk_engine.py
│   ├── test_url_analyzer.py
│   └── test_url_risk_engine.py
│
├── docs/
│
├── .gitignore
├── requirements.txt
└── README.md
```

---

# ⚙️ Installation

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/CyberBuddy.git
cd CyberBuddy
```

Replace `YOUR_USERNAME/CyberBuddy` with the actual GitHub repository.

## 2. Create a Virtual Environment

### Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🤖 Setup Ollama + Gemma

CyberBuddy uses Ollama to run Gemma locally.

Install Ollama for your operating system and download the model:

```bash
ollama pull gemma3:4b
```

Verify that the model is available:

```bash
ollama list
```

You can also test Gemma directly:

```bash
ollama run gemma3:4b
```

Ollama should be running before using the AI explanation feature.

---

# ▶️ Running CyberBuddy

## Start the FastAPI Backend

From the project root:

```bash
uvicorn backend.main:app --reload --port 8000
```

The API will be available at:

```text
http://127.0.0.1:8000
```

Health check:

```text
http://127.0.0.1:8000/health
```

FastAPI documentation:

```text
http://127.0.0.1:8000/docs
```

## Start the Frontend

Serve the project using a local HTTP server:

```bash
python -m http.server 3000
```

Then open:

```text
http://127.0.0.1:3000/frontend/index.html
```

---

# 🧪 Running Tests

Run the complete test suite:

```bash
python -m pytest
```

Current test status:

```text
39 passed
0 failed
```

The tests cover:

- Message analysis
- Message risk scoring
- URL analysis
- URL risk scoring
- Security indicators
- Risk classification

---

# 🔍 Example: Suspicious Message

Input:

```text
URGENT! Your bank account will be blocked.
Please provide your OTP immediately at
https://example.com/login
```

Example result:

```text
Risk: CRITICAL
Score: 95/100
Possible Attack: Phishing
```

Detected indicators may include:

- Urgent or pressure-based language
- Credential or verification information requested
- Financial information requested
- Account access threat
- URL detected

Gemma then converts this technical analysis into an explanation that is easier for a non-technical user to understand.

---

# 🔗 Example: Suspicious URL

Input:

```text
http://192.168.1.10/login
```

Example result:

```text
Risk: MEDIUM
Score: 40/100
Hostname: 192.168.1.10
Protocol: HTTP
```

Detected indicators:

- URL does not use HTTPS
- IP address used instead of a domain name
- Security-sensitive keyword detected: login

The AI explanation helps the user understand why these characteristics deserve caution.

---

# 🛡️ Safety Design

CyberBuddy is designed as an educational and defensive cybersecurity tool.

The project follows several safety principles:

- Never request passwords or OTPs from users
- Never encourage users to interact with suspicious links
- Never claim that an indicator proves malicious activity
- Provide safe verification recommendations
- Keep deterministic security analysis authoritative
- Treat AI output as an explanation layer

CyberBuddy is intended to help users make safer decisions, not replace professional security tools or security analysts.

---

# 🤖 AI Usage

CyberBuddy uses **Gemma 3 4B**, running locally through Ollama.

The model receives the results produced by the deterministic analyzer, including:

- Risk level
- Risk score
- Detected indicators
- Possible attack type
- Recommended actions
- Detected URLs

Gemma then generates a simplified explanation.

### AI does not:

- Calculate the security score
- Override the risk level
- Invent security indicators
- Perform autonomous actions
- Request sensitive credentials

This design keeps the security decision-making layer deterministic.

---

# 🧪 Development Approach

CyberBuddy was developed using an incremental, test-driven approach:

1. Message analysis
2. Deterministic risk scoring
3. URL analysis
4. URL risk scoring
5. FastAPI integration
6. Frontend integration
7. Ollama integration
8. Gemma 3 4B explanation layer
9. Automated testing
10. UI and documentation improvements

Current status:

```text
39 automated tests
39 passing
0 failing
```

---

# 🎯 Future Improvements

Potential future improvements include:

- Security alert/log analyzer
- SIEM log analysis
- Email header analysis
- Browser extension
- More advanced URL reputation checks
- MITRE ATT&CK mapping
- Additional open-source models
- Improved AI explanation formatting
- Exportable security reports
- Threat intelligence integration

---

# ⚠️ Disclaimer

CyberBuddy is an educational cybersecurity project.

A risk score does not guarantee that a message or URL is malicious or safe.

Users should verify suspicious communications through trusted official channels and avoid sharing passwords, OTPs, PINs, API keys, or other sensitive information.

---

# 🏆 Hacktoberfest 2026

CyberBuddy was created for the **Hacktoberfest Weekend Challenge: Build for a Friend 2026**.

The goal of the project is to use open-source AI to solve a practical problem for a non-technical user: understanding suspicious cybersecurity messages and URLs.

The project uses:

- Open-weight Gemma 3 4B
- Local inference through Ollama
- Deterministic cybersecurity analysis
- A simple user-focused interface

---

# 📜 License

This project is open source. See the `LICENSE` file for details.

---

## 👨‍💻 Author

**Akash Jha**

Cybersecurity learner focused on SOC analysis, defensive security, security automation, and practical cybersecurity projects.

---

⭐ If you find CyberBuddy useful, consider giving the repository a star!
