"""
PassGuard - Cybersecurity Password Safety Suite
Main Streamlit Application
"""

import os
import sys
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Try importing streamlit_keyup for live keystroke detection
try:
    from st_keyup import st_keyup
    HAS_KEYUP = True
except ImportError:
    HAS_KEYUP = False

# Import core modules
from core.analyzer import (
    calculate_entropy,
    estimate_crack_times,
    check_patterns,
    evaluate_strength,
    generate_suggestions,
)
from core.generator import (
    generate_batch,
    generate_random_password,
    generate_passphrase,
)
from core.breach import check_pwned_password
from core.history import (
    init_history,
    add_to_history,
    get_history_df,
    clear_history,
)


# Set Streamlit Page Configuration
st.set_page_config(
    page_title="PassGuard - Password Security Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def get_live_input(label: str, key: str, type: str = "default", placeholder: str = "") -> str:
    """Helper to safely wrap st_keyup with graceful fallback to st.text_input."""
    if HAS_KEYUP:
        try:
            val = st_keyup(
                label,
                key=key,
                type=type,
                placeholder=placeholder,
                debounce=100,
            )
            return val if val is not None else ""
        except Exception:
            pass
    return st.text_input(label, key=key, type=type, placeholder=placeholder)


# Load Datasets with Caching
@st.cache_data

def load_data():
    base_dir = os.path.dirname(__file__)
    
    # Load common passwords
    common_path = os.path.join(base_dir, "data", "common_passwords.txt")
    common_set = set()
    if os.path.exists(common_path):
        with open(common_path, "r", encoding="utf-8") as f:
            common_set = {line.strip().lower() for line in f if line.strip()}

    # Load passphrase wordlist
    wordlist_path = os.path.join(base_dir, "data", "wordlist.txt")
    wordlist = []
    if os.path.exists(wordlist_path):
        with open(wordlist_path, "r", encoding="utf-8") as f:
            wordlist = [line.strip().lower() for line in f if line.strip()]

    return common_set, wordlist


# Load Custom CSS Styling
def load_css():
    css_path = os.path.join(os.path.dirname(__file__), "assets", "style.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


# Initialize Application
load_css()
common_passwords, passphrase_wordlist = load_data()
init_history()


# Sidebar Section
st.sidebar.markdown("""
<div style="text-align: center; padding: 10px 0;">
    <h1 style="margin:0; font-size: 2.2rem; color: #38BDF8;">🛡️ PassGuard</h1>
    <p style="margin:0; font-size: 0.9rem; color: #94A3B8;">Cybersecurity & Password Analysis Tool</p>
</div>
<hr style="border: 0.5px solid rgba(255,255,255,0.1); margin: 15px 0;" />
""", unsafe_allow_html=True)

# Sidebar Session Metrics
df_hist = get_history_df()
total_analyzed = len(df_hist)
avg_entropy = round(df_hist["Entropy (bits)"].mean(), 1) if total_analyzed > 0 else 0.0

st.sidebar.markdown(f"""
<div class="metric-box">
    <div class="metric-value">{total_analyzed}</div>
    <div class="metric-label">Session Entries Evaluated</div>
</div>
""", unsafe_allow_html=True)

if total_analyzed > 0:
    st.sidebar.markdown(f"""
    <div class="metric-box" style="margin-top: 10px;">
        <div class="metric-value">{avg_entropy} <span style="font-size: 1rem; color: #94A3B8;">bits</span></div>
        <div class="metric-label">Average Session Entropy</div>
    </div>
    """, unsafe_allow_html=True)

st.sidebar.markdown("<hr style='border: 0.5px solid rgba(255,255,255,0.1); margin: 15px 0;' />", unsafe_allow_html=True)

with st.sidebar.expander("ℹ️ About This Project"):
    st.markdown("""
    **PassGuard** is a Python mini-project built for evaluating password strength, analyzing entropy, checking live data breach leaks, and generating secure passphrases.
    
    **Tech Stack:**
    - Python 3.10+ & Streamlit UI
    - `secrets` for cryptographic randomness
    - HIBP Range API (k-Anonymity SHA-1)
    - Pandas & Plotly Express analytics
    
    **Security Commitment:**
    - No passwords are ever transmitted or stored in plaintext.
    """)

st.sidebar.caption("🔒 100% Client-Side Privacy Guaranteed")


# Main Content - Tabs Layout
tab_analyzer, tab_breach, tab_generator, tab_dashboard, tab_learn = st.tabs([
    "🔍 Password Analyzer",
    "🚨 Breach Check",
    "⚡ Password Generator",
    "📊 Dashboard",
    "📚 Security Guide"
])


# ==========================================
# TAB 1: PASSWORD ANALYZER
# ==========================================
with tab_analyzer:
    st.subheader("🔍 Live Password Strength Analyzer")
    st.caption("Type any password below to analyze its entropy, vulnerability patterns, and crack time estimates in real-time.")

    col_input, col_options = st.columns([3, 1])

    with col_options:
        show_password = st.checkbox("Show Password", value=False)

    input_type = "default" if show_password else "password"

    with col_input:
        password_input = get_live_input(
            "Enter Password to Analyze",
            key="analyzer_password_input",
            type=input_type,
            placeholder="Type password here...",
        )


    if password_input:
        # Core calculations
        entropy, pool_size = calculate_entropy(password_input)
        checklist = check_patterns(password_input, common_passwords)
        label, score, color = evaluate_strength(entropy, checklist, password_input)
        crack_times = estimate_crack_times(entropy)
        suggestions = generate_suggestions(checklist, password_input, entropy)

        # Log to session state history
        add_to_history(password_input, label, entropy, source="Analyzer")

        st.markdown("<br>", unsafe_allow_html=True)

        # Strength Bar & Metrics Header
        m1, m2, m3, m4 = st.columns(4)

        with m1:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-value" style="color: {color};">{label}</div>
                <div class="metric-label">Strength Rating</div>
            </div>
            """, unsafe_allow_html=True)

        with m2:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-value">{len(password_input)}</div>
                <div class="metric-label">Character Length</div>
            </div>
            """, unsafe_allow_html=True)

        with m3:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-value">{entropy} <span style="font-size: 0.9rem; color: #94A3B8;">bits</span></div>
                <div class="metric-label">Information Entropy</div>
            </div>
            """, unsafe_allow_html=True)

        with m4:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-value">{pool_size}</div>
                <div class="metric-label">Character Pool Size</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.progress(score, text=f"Overall Strength Score: {int(score * 100)}%")

        # Two Columns Layout: Left = Checklist + Crack Time; Right = Smart Suggestions
        c_left, c_right = st.columns([1, 1])

        with c_left:
            st.markdown("#### 📋 Security Checklist")
            
            checks = [
                ("Length >= 12 characters", checklist["min_length"]),
                ("Contains Uppercase Letter (A-Z)", checklist["has_uppercase"]),
                ("Contains Lowercase Letter (a-z)", checklist["has_lowercase"]),
                ("Contains Digit (0-9)", checklist["has_digit"]),
                ("Contains Special Symbol (!@#$)", checklist["has_symbol"]),
                ("No repeated characters (3+ in a row)", checklist["no_repeats"]),
                ("No sequential patterns (abc, 123)", checklist["no_sequences"]),
                ("No keyboard patterns (qwerty, asdf)", checklist["no_keyboard"]),
                ("Not in common-password dictionary", checklist["not_common"]),
            ]

            for text, status in checks:
                icon = "✅" if status else "❌"
                css_class = "check-pass" if status else "check-fail"
                st.markdown(f"""
                <div class="check-item {css_class}">
                    <span>{icon}</span> <span>{text}</span>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("#### ⏱️ Estimated Time to Crack")
            
            st.markdown(f"""
            <div class="crack-card">
                <strong>🌐 Online Attack</strong> (100 guesses/sec)<br>
                <span style="font-size: 1.1rem; color: #38BDF8; font-weight: 600;">{crack_times['online']}</span>
            </div>
            <div class="crack-card">
                <strong>💻 Fast Offline Hash Attack</strong> (10 Billion guesses/sec)<br>
                <span style="font-size: 1.1rem; color: #38BDF8; font-weight: 600;">{crack_times['offline_fast']}</span>
            </div>
            <div class="crack-card">
                <strong>🚀 Massive GPU Cluster</strong> (1 Trillion guesses/sec)<br>
                <span style="font-size: 1.1rem; color: #38BDF8; font-weight: 600;">{crack_times['gpu_cluster']}</span>
            </div>
            """, unsafe_allow_html=True)

        with c_right:
            st.markdown("#### 💡 Smart Actionable Tips")
            for tip in suggestions:
                st.info(tip)

            st.markdown("""
            <div class="pg-card" style="margin-top: 20px;">
                <h5 style="color: #38BDF8; margin-top:0;">📚 Understanding Entropy</h5>
                <p style="font-size: 0.9rem; color: #CBD5E1;">
                    Password entropy measures unpredictability in bits. Higher entropy means exponential expansion of the search space:
                </p>
                <ul style="font-size: 0.85rem; color: #94A3B8; padding-left: 1.2rem;">
                    <li><strong>&lt; 28 bits:</strong> Extremely vulnerable (cracked instantly).</li>
                    <li><strong>28–59 bits:</strong> Vulnerable to offline brute-force attacks.</li>
                    <li><strong>60–79 bits:</strong> Strong for standard personal accounts.</li>
                    <li><strong>80+ bits:</strong> Military-grade security (virtually uncrackable).</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

    else:
        st.info("👆 Enter a password in the box above to see real-time analysis, entropy metrics, and crack time estimates.")


# ==========================================
# TAB 2: BREACH CHECK (HIBP API)
# ==========================================
with tab_breach:
    st.subheader("🚨 Real-Time Data Breach Lookup")
    st.caption("Check if your password has been exposed in publicly leaked data breaches using Have I Been Pwned.")

    # Privacy Guarantee Callout Box
    st.markdown("""
    <div class="security-notice">
        <h4 style="margin-top:0; color: #38BDF8;">🛡️ Zero-Knowledge Privacy Guarantee (k-Anonymity)</h4>
        <p style="margin-bottom:0; font-size: 0.92rem; color: #E2E8F0;">
            Your plain-text password <strong>NEVER</strong> leaves your browser/device. We compute a SHA-1 hash locally, send only the 
            <strong>first 5 hex characters</strong> to the Have I Been Pwned API, and match the remaining hash locally on your computer.
        </p>
    </div>
    """, unsafe_allow_html=True)

    c_b_input, c_b_btn = st.columns([3, 1])
    with c_b_input:
        breach_input = st.text_input(
            "Enter password to check breach status",
            type="password",
            key="breach_check_input",
            placeholder="Enter password...",
        )
    with c_b_btn:
        st.markdown("<br>", unsafe_allow_html=True)
        btn_check_breach = st.button("🚨 Check Breach Database", use_container_width=True, type="primary")

    if btn_check_breach and breach_input:
        with st.spinner("🔒 SHA-1 hashing locally and querying HIBP range API..."):
            is_pwned, count, msg = check_pwned_password(breach_input)
            
            if is_pwned:
                st.error(msg)
                st.markdown("""
                <div class="pg-card" style="border-left: 4px solid #EF4444;">
                    <h5 style="color: #EF4444; margin-top:0;">⚠️ Action Required</h5>
                    <p style="font-size: 0.9rem; color: #CBD5E1;">
                        If you are actively using this password anywhere, <strong>change it immediately!</strong> 
                        Hackers use credential-stuffing bots to test leaked passwords across thousands of services.
                    </p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.success(msg)


# ==========================================
# TAB 3: PASSWORD GENERATOR
# ==========================================
with tab_generator:
    st.subheader("⚡ Cryptographically Secure Password Generator")
    st.caption("Generate ultra-strong random passwords or memorable multi-word passphrases using Python's `secrets` module.")

    gen_mode = st.radio(
        "Select Generator Mode",
        ["🎲 Random Password", "💬 Memorable Passphrase"],
        horizontal=True,
    )

    st.markdown("<hr style='border: 0.5px solid rgba(255,255,255,0.08);' />", unsafe_allow_html=True)

    col_gen_opts, col_gen_res = st.columns([1, 1])

    with col_gen_opts:
        if gen_mode == "🎲 Random Password":
            st.markdown("#### Options")
            gen_len = st.slider("Password Length", min_value=8, max_value=64, value=16)
            gen_upper = st.checkbox("Include Uppercase Letters (A-Z)", value=True)
            gen_lower = st.checkbox("Include Lowercase Letters (a-z)", value=True)
            gen_digits = st.checkbox("Include Digits (0-9)", value=True)
            gen_symbols = st.checkbox("Include Symbols (!@#$)", value=True)
            gen_exclude_ambig = st.checkbox("Exclude Ambiguous Characters (0, O, l, 1, I)", value=False)
            gen_count = st.radio("Quantity", [1, 5], horizontal=True)

            btn_generate = st.button("✨ Generate Password(s)", type="primary", use_container_width=True)

            if btn_generate:
                results = generate_batch(
                    mode="Random Password",
                    count=gen_count,
                    wordlist=passphrase_wordlist,
                    common_passwords_set=common_passwords,
                    length=gen_len,
                    use_upper=gen_upper,
                    use_lower=gen_lower,
                    use_digits=gen_digits,
                    use_symbols=gen_symbols,
                    exclude_ambiguous=gen_exclude_ambig,
                )
                st.session_state["gen_results"] = results
                for r in results:
                    add_to_history(r["password"], r["strength"], r["entropy"], source="Generator")

        else:
            st.markdown("#### Passphrase Options")
            word_count = st.slider("Number of Words", min_value=3, max_value=8, value=4)
            separator = st.selectbox("Word Separator", ["-", "_", ".", " space ", "/"], index=0)
            capitalize = st.selectbox("Capitalization", ["Title", "lower", "UPPER"], index=0)
            add_number = st.checkbox("Append Random 2-Digit Number", value=True)
            add_symbol = st.checkbox("Append Random Symbol", value=False)
            gen_count = st.radio("Quantity", [1, 5], horizontal=True)

            btn_generate = st.button("✨ Generate Passphrase(s)", type="primary", use_container_width=True)

            if btn_generate:
                sep_val = " " if separator == " space " else separator
                results = generate_batch(
                    mode="Passphrase",
                    count=gen_count,
                    wordlist=passphrase_wordlist,
                    common_passwords_set=common_passwords,
                    word_count=word_count,
                    separator=sep_val,
                    capitalize=capitalize,
                    add_number=add_number,
                    add_symbol=add_symbol,
                )
                st.session_state["gen_results"] = results
                for r in results:
                    add_to_history(r["password"], r["strength"], r["entropy"], source="Generator")

    with col_gen_res:
        st.markdown("#### Generated Results")
        if "gen_results" in st.session_state and st.session_state["gen_results"]:
            for i, res in enumerate(st.session_state["gen_results"]):
                pwd = res["password"]
                st.markdown(f"""
                <div class="pg-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span class="strength-badge" style="background-color: {res['color']}; font-size: 0.85rem;">{res['strength']}</span>
                        <span style="font-size: 0.85rem; color: #94A3B8;">Entropy: <strong>{res['entropy']} bits</strong></span>
                    </div>
                    <div class="generated-pwd-box">{pwd}</div>
                </div>
                """, unsafe_allow_html=True)
                st.code(pwd, language=None)
        else:
            st.info("👈 Click the Generate button to create secure passwords.")


# ==========================================
# TAB 4: DASHBOARD & HISTORY
# ==========================================
with tab_dashboard:
    st.subheader("📊 Session Analytics Dashboard")
    st.caption("Review evaluation metrics and session history. Passwords are shown in masked format only.")

    df_history = get_history_df()

    if not df_history.empty:
        # Overview Cards
        col_d1, col_d2, col_d3, col_d4 = st.columns(4)
        
        with col_d1:
            st.metric("Total Analyzed/Generated", len(df_history))
        with col_d2:
            st.metric("Average Entropy", f"{round(df_history['Entropy (bits)'].mean(), 1)} bits")
        with col_d3:
            strong_pct = round((df_history["Strength"].isin(["Strong", "Very Strong"]).sum() / len(df_history)) * 100, 1)
            st.metric("Strong / Very Strong %", f"{strong_pct}%")
        with col_d4:
            most_common = df_history["Strength"].mode()[0] if not df_history.empty else "N/A"
            st.metric("Dominant Rating", most_common)

        st.markdown("<br>", unsafe_allow_html=True)

        # Plotly Charts
        ch1, ch2 = st.columns([1, 1])

        with ch1:
            st.markdown("##### Strength Distribution")
            color_map = {
                "Very Weak": "#FF4B4B",
                "Weak": "#FFA500",
                "Fair": "#FFD700",
                "Strong": "#20B2AA",
                "Very Strong": "#00C853",
            }
            counts = df_history["Strength"].value_counts().reset_index()
            counts.columns = ["Strength", "Count"]

            fig_donut = px.pie(
                counts,
                names="Strength",
                values="Count",
                hole=0.45,
                color="Strength",
                color_discrete_map=color_map,
            )
            fig_donut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#F8FAFC",
                margin=dict(t=20, b=20, l=20, r=20),
            )
            st.plotly_chart(fig_donut, use_container_width=True)

        with ch2:
            st.markdown("##### Entropy Progression over Time")
            fig_line = px.line(
                df_history.reset_index(),
                x="index",
                y="Entropy (bits)",
                markers=True,
                title="",
                labels={"index": "Sequence #", "Entropy (bits)": "Entropy (Bits)"},
            )
            fig_line.update_traces(line_color="#38BDF8", marker=dict(size=8, color="#00C853"))
            fig_line.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#F8FAFC",
                margin=dict(t=20, b=20, l=20, r=20),
            )
            st.plotly_chart(fig_line, use_container_width=True)

        st.markdown("<hr style='border: 0.5px solid rgba(255,255,255,0.08);' />", unsafe_allow_html=True)
        st.markdown("##### Session Log Table")
        st.dataframe(df_history, use_container_width=True)

        btn_col1, btn_col2 = st.columns([1, 4])
        with btn_col1:
            csv_data = df_history.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export CSV",
                data=csv_data,
                file_name="passguard_session_history.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with btn_col2:
            if st.button("🗑️ Clear History", type="secondary"):
                clear_history()
                st.rerun()

    else:
        st.info("No passwords analyzed or generated in this session yet. Use the Analyzer or Generator tabs to start tracking analytics!")


# ==========================================
# TAB 5: SECURITY GUIDE (LEARN)
# ==========================================
with tab_learn:
    st.subheader("📚 Security Education & Cybersecurity Guide")
    st.caption("Learn the mathematical principles of password security, crack times, and privacy-preserving protocols.")

    with st.expander("📏 1. What Makes a Password Strong?"):
        st.markdown("""
        A strong password relies primarily on **unpredictability (entropy)** and **length**.
        - **Length matters most**: Each character added exponentially increases the total number of possibilities. A 16-character lowercase password is often vastly harder to crack than an 8-character complex password with symbols.
        - **Character Diversity**: Mixing uppercase letters, lowercase letters, numbers, and symbols increases the size of the character pool ($R$).
        - **Uniqueness**: Never reuse passwords across services. If one site suffers a breach, attackers use credential stuffing to unlock all your accounts.
        """)

    with st.expander("🧮 2. Understanding Password Entropy"):
        st.markdown("""
        **Entropy** measures the amount of randomness or uncertainty in a password, expressed in **bits**:
        
        $$\\text{Entropy (bits)} = L \\times \\log_2(R)$$
        
        Where:
        - $L$ = Length of the password.
        - $R$ = Number of possible characters in the pool (e.g., 26 for lowercase, 62 for alphanumeric, 94 with symbols).
        
        **Why bits matter:**
        Each bit doubles the time required for a brute-force attacker to guess the password. A password with 80 bits of entropy has $2^{80} \\approx 1.2 \\times 10^{24}$ possibilities!
        """)

    with st.expander("🚨 3. What is a Data Breach & Credential Stuffing?"):
        st.markdown("""
        A **data breach** occurs when cybercriminals breach a corporate database and leak stolen user credentials (emails, usernames, hashed passwords) on dark web forums.
        
        **Credential Stuffing** is an automated attack where bots attempt millions of leaked username/password combinations across thousands of major sites (banking, email, social media). Reusing a password makes all your accounts vulnerable if even one service is breached.
        """)

    with st.expander("🔑 4. Why You Should Use a Password Manager"):
        st.markdown("""
        Humans are notoriously bad at remembering dozens of complex, 20-character random passwords.
        
        **Password Managers** (such as Bitwarden, 1Password, or KeePassXC) solve this by:
        - Storing all your credentials in an encrypted vault protected by a single Master Key.
        - Generating unique, 20+ character random passwords for every single service.
        - Automatically detecting phishing websites to protect you from spoofed login pages.
        """)

    with st.expander("🔒 5. What is k-Anonymity & How Does Breach Check Work?"):
        st.markdown("""
        **k-Anonymity** is a mathematical concept used to verify if data exists in a database without revealing the data itself.
        
        **How PassGuard verifies breaches securely:**
        1. PassGuard computes the SHA-1 hash of your password locally in your browser.
        2. It takes only the **first 5 characters** of the hash (`prefix`) and sends them to Have I Been Pwned.
        3. HIBP responds with thousands of hashes that start with those same 5 characters.
        4. PassGuard checks the remaining 35 characters of your hash locally. Your password or full hash **NEVER** leaves your device!
        """)

    with st.expander("🗣️ 6. Why Passphrases are Superior"):
        st.markdown("""
        A **passphrase** combines multiple random words into a long string (e.g., `maple-tiger-orbit-canyon-47`).
        
        **Advantages:**
        - **Easy for Humans to Remember**: Words are easier to recall than random strings like `Xk9#mP2$`.
        - **Extremely Hard for Computers to Crack**: A 4-word passphrase chosen from a 400-word list has an entropy of over 34 bits from words alone, and adding length makes brute-force attacks infeasible.
        """)
