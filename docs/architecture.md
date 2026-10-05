# CyberBuddy Architecture

## Overview

CyberBuddy uses a layered architecture that separates deterministic cybersecurity analysis from AI-generated explanations.

The core principle is:

> **AI explains the security analysis; AI does not determine the security risk.**

This makes the security decision-making process predictable, testable, and easier to validate.

## Architecture Flow

```text
User Input
    |
    v
Message / URL Analyzer
    |
    v
Security Indicators
    |
    v
Risk Engine
    |
    +----> Risk Level
    |
    +----> Risk Score
    |
    +----> Possible Attack
    |
    +----> Recommended Actions
    |
    v
Gemma 3 4B via Ollama
    |
    v
Simple AI Explanation
    |
    v
User
```

## Main Components

### 1. Message Analyzer

`analyzer/message_analyzer.py`

Analyzes suspicious text such as emails and messages.

It looks for indicators including:

- Urgent or pressure-based language
- Credential or verification requests
- Financial or payment requests
- Account access threats
- Suspicious URLs
- Phishing-related patterns

### 2. Message Risk Engine

`analyzer/risk_engine.py`

Converts detected message indicators into a risk score and risk classification.

Possible risk levels include:

- LOW
- MEDIUM
- HIGH
- CRITICAL

### 3. URL Analyzer

`analyzer/url_analyzer.py`

Analyzes URLs and extracts useful characteristics such as:

- Protocol
- Hostname
- IP address usage
- Security-sensitive keywords
- HTTPS usage
- Suspicious URL patterns

### 4. URL Risk Engine

`analyzer/url_risk_engine.py`

Evaluates URL indicators and produces the corresponding risk score and risk level.

### 5. FastAPI Backend

`backend/main.py`

Provides the REST API used by the frontend.

It connects:

```text
Frontend
   |
   v
FastAPI
   |
   +----> Message Analyzer
   |
   +----> URL Analyzer
   |
   +----> AI Explainer
```

### 6. AI Explanation Layer

`backend/ai/explainer.py`

The AI layer sends the deterministic analysis to Gemma 3 4B through Ollama.

Gemma receives evidence such as:

- Risk level
- Risk score
- Possible attack
- Detected indicators
- Recommended actions
- Detected URLs

The model converts this information into a simple explanation.

### 7. Frontend

The frontend uses:

- HTML
- CSS
- JavaScript

It provides separate interfaces for:

- Message analysis
- URL analysis

The results include the risk level, score, indicators, recommendations, and AI explanation.

## Fail-Safe AI Design

If Ollama or Gemma is unavailable, CyberBuddy does not lose its deterministic security analysis.

The AI explanation becomes unavailable, but the core analysis can still return its security findings.

```text
Ollama Available
       |
       +--> Analysis + AI Explanation

Ollama Unavailable
       |
       +--> Analysis only
```

This prevents an AI service failure from becoming a security-analysis failure.
