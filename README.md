# 🛡️ PassGuard - Password Security & Breach Analytics Suite

**PassGuard** is a feature-rich, professional cybersecurity web application built with Python and Streamlit. Designed as a college mini-project (Python Programming), PassGuard helps users create cryptographically strong passwords, evaluate information entropy in real-time, detect common pattern vulnerabilities, and check for public data breach leaks safely using k-anonymity.

---

## 🌟 Key Features

### 1. 🔍 Live Password Strength Analyzer
- **Real-Time Analysis**: Evaluates password strength on every keystroke using `streamlit-keyup`.
- **Entropy Calculation**: Computes mathematical entropy ($E = L \times \log_2 R$) in bits.
- **Threat Model Crack Time**: Estimates time required to brute-force passwords across 3 threat scenarios:
  1. Online Attack (100 guesses/sec)
  2. Offline Fast Hash Attack (10 Billion guesses/sec)
  3. Massive GPU Cluster (1 Trillion guesses/sec)
- **Vulnerability Checklist**: Inspects length, character diversity, character repeats (3+), sequential patterns (`abc`, `123`), keyboard spatial sweeps (`qwerty`, `asdf`), and dictionary lists (>200 common passwords).
- **Smart Suggestions**: Delivers plain-English recommendations tailored to specific missing security rules.

### 2. 🚨 Real-Time Breach Checker (HIBP k-Anonymity)
- **Zero-Knowledge Leak Lookup**: Queries the Have I Been Pwned "Pwned Passwords" API.
- **k-Anonymity Privacy Guarantee**: SHA-1 hashes the password locally, sends **only the first 5 hex characters** to the remote API, and completes suffix matching locally. Plain-text passwords never leave the user's device.

### 3. ⚡ Password & Passphrase Generator
- **Random Password Mode**: Generates cryptographically secure passwords using Python's `secrets` module. Supports length customization (8–64), character set toggles, and exclusion of ambiguous characters (`0, O, l, 1, I`).
- **Memorable Passphrase Mode**: Generates multi-word passphrases (e.g. `maple-tiger-orbit-canyon-47`) from a clean wordlist of >350 words.
- **Batch Generation**: Option to generate 1 or 5 choices simultaneously with entropy and strength indicators.

### 4. 📊 Session Analytics Dashboard
- **Session History Table**: Tracks evaluated and generated passwords. **Never stores raw passwords** — logs only masked representations (e.g., `A******!`), length, strength, and entropy.
- **Interactive Visualizations**: Donut chart of strength distributions and line chart of entropy progression built with Plotly.
- **Export & Clear**: Allows exporting session logs to CSV or clearing session history.

### 5. 📚 Security Education Guide
- Interactive expanders covering password entropy formulas, credential stuffing attacks, password manager benefits, k-anonymity mechanics, and passphrase advantages.

---

## 🛠️ Tech Stack & Architecture

- **Language & UI**: Python 3.10+, Streamlit
- **Data & Analytics**: Pandas, Plotly Express
- **API & Networking**: Requests (HIBP API)
- **Security & Randomness**: Standard Library `secrets`, `hashlib`, `math`, `re`
- **Live Input Handling**: `streamlit-keyup`

### Project Directory Structure
```text
passguard/
├── app.py                  # Main Streamlit UI entry point
├── core/                   # Pure backend business logic
│   ├── __init__.py
│   ├── analyzer.py         # Entropy, crack time, pattern checks, scoring
│   ├── generator.py        # Random password and passphrase generator
│   ├── breach.py           # HIBP API k-anonymity check
│   └── history.py          # Session state history helper
├── data/                   # Data resources
│   ├── common_passwords.txt# Built-in dictionary of common passwords
│   └── wordlist.txt        # Passphrase dictionary (>350 words)
├── assets/                 # UI design assets
│   └── style.css           # Custom CSS styling and dark theme
├── tests/                  # Automated test suite
│   └── test_analyzer.py    # Pytest test cases
├── requirements.txt        # Dependency specification
└── README.md               # Documentation
```

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.10 or higher
- `pip` or `uv` package manager

### Installation

1. **Navigate to project directory**:
   ```bash
   cd passguard
   ```

2. **Create virtual environment (optional but recommended)**:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Pytest unit tests**:
   ```bash
   pytest
   ```

5. **Launch PassGuard Application**:
   ```bash
   python -m streamlit run app.py
   ```
   *(Using `python -m streamlit` ensures Python finds the installed module even if Python's `Scripts/` directory is not added to your system `PATH`.)*


---

## 🔒 Security & Privacy Notes

1. **No Data Persistence**: All evaluation history is stored in memory (`st.session_state`) during the browser session and is wiped when the browser tab is closed.
2. **Masked Storage**: Raw passwords are strictly used for in-memory analysis and are converted to masked strings (`A****!`) before storing in session logs.
3. **k-Anonymity Model**:
   ```text
   [ Plaintext Password ] ──> SHA-1 Local Hash ──> "21BD15DB..."
                                                     │
                             ┌───────────────────────┴───────────────────────┐
                             │                                               │
                    First 5 Chars ("21BD1")                        Remaining 35 Chars
                             │                                               │
               Sent to api.pwnedpasswords.com                         Matched Locally
   ```

---

## 🖼️ Application Screenshots

*(Run the application locally to view the interactive dark theme UI)*

---

## 🔮 Future Improvements

- Add support for custom dictionary uploads for corporate security policy compliance.
- Support additional hashing algorithms (Bcrypt, Argon2, PBKDF2) for offline analysis.
- Multi-language localization (Spanish, French, German).

---
*Created for College Mini-Project (Python Programming)*
