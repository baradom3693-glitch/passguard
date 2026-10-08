"""
Session History Tracker Module
Stores ONLY masked representations of analyzed/generated passwords.
Never saves plain-text passwords into session memory.
"""

from datetime import datetime
from typing import List, Dict, Any
import pandas as pd
import streamlit as st


def mask_password(password: str) -> str:
    """
    Masks a password for safe logging/display.
    Example: 'SecretPassword123!' -> 'S*************!'
    """
    if not password:
        return ""
    length = len(password)
    if length <= 2:
        return "*" * length
    elif length <= 4:
        return password[0] + "*" * (length - 1)
    else:
        return password[0] + "*" * (length - 2) + password[-1]


def init_history():
    """Ensures st.session_state.history is initialized."""
    if "history" not in st.session_state:
        st.session_state.history = []


def add_to_history(password: str, strength_label: str, entropy: float, source: str = "Analyzed"):
    """Adds a entry to the session history (masked only)."""
    init_history()
    if not password:
        return

    masked = mask_password(password)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Avoid duplicate consecutive additions of identical entries
    if st.session_state.history:
        last_entry = st.session_state.history[-1]
        if last_entry["Masked Password"] == masked and last_entry["Source"] == source:
            return

    st.session_state.history.append({
        "Timestamp": timestamp,
        "Source": source,
        "Masked Password": masked,
        "Length": len(password),
        "Strength": strength_label,
        "Entropy (bits)": entropy,
    })


def get_history_df() -> pd.DataFrame:
    """Returns the session history as a Pandas DataFrame."""
    init_history()
    if not st.session_state.history:
        return pd.DataFrame(columns=["Timestamp", "Source", "Masked Password", "Length", "Strength", "Entropy (bits)"])
    return pd.DataFrame(st.session_state.history)


def clear_history():
    """Clears the session history list."""
    st.session_state.history = []
