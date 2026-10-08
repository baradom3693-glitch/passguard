"""
Unit Tests for PassGuard Analyzer and Generator Modules
Run using `pytest` command.
"""

import os
import sys
import pytest

# Add parent directory to path to allow importing core modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.analyzer import (
    calculate_entropy,
    estimate_crack_times,
    check_sequential_patterns,
    check_keyboard_patterns,
    check_patterns,
    evaluate_strength,
)
from core.generator import (
    generate_random_password,
    generate_passphrase,
    AMBIGUOUS_CHARS,
)


def test_calculate_entropy():
    # Empty string
    entropy, pool = calculate_entropy("")
    assert entropy == 0.0
    assert pool == 0

    # 8 lowercase letters: Pool = 26, Entropy = 8 * log2(26) = 37.60 bits
    entropy, pool = calculate_entropy("abcdefgh")
    assert pool == 26
    assert round(entropy, 1) == 37.6

    # 10 chars with lower, upper, digit, symbol: Pool = 26+26+10+32 = 94
    # Entropy = 10 * log2(94) = 65.55 bits
    entropy, pool = calculate_entropy("aA1!bB2@cC")
    assert pool == 94
    assert round(entropy, 1) == 65.5


def test_estimate_crack_times():
    times_zero = estimate_crack_times(0)
    assert times_zero["online"] == "Instantly"

    # High entropy (e.g. 100 bits) should take billions of years
    times_high = estimate_crack_times(100)
    assert "years" in times_high["online"] or "centuries" in times_high["online"] or "Billions" in times_high["online"]
    assert "years" in times_high["offline_fast"] or "centuries" in times_high["offline_fast"] or "Billions" in times_high["offline_fast"]


def test_sequential_patterns():
    assert not check_sequential_patterns("abc12345")
    assert not check_sequential_patterns("pass321")
    assert not check_sequential_patterns("xyz789")
    assert check_sequential_patterns("aB9!mK4#qL")


def test_keyboard_patterns():
    assert not check_keyboard_patterns("qwerty123")
    assert not check_keyboard_patterns("myasdfpass")
    assert not check_keyboard_patterns("1qaz2wsx")
    assert check_keyboard_patterns("k9#mP2$xR")


def test_check_patterns():
    common_set = {"password", "123456", "admin"}
    
    # Common password test
    res1 = check_patterns("password", common_set)
    assert res1["not_common"] is False
    assert res1["min_length"] is False

    # Strong password test
    res2 = check_patterns("Xk9#mP2$xR7!", common_set)
    assert res2["min_length"] is True
    assert res2["has_uppercase"] is True
    assert res2["has_lowercase"] is True
    assert res2["has_digit"] is True
    assert res2["has_symbol"] is True
    assert res2["no_repeats"] is True
    assert res2["no_sequences"] is True
    assert res2["no_keyboard"] is True
    assert res2["not_common"] is True


def test_evaluate_strength():
    common_set = {"password"}
    
    # Very weak (common)
    chk_common = check_patterns("password", common_set)
    label, score, color = evaluate_strength(10.0, chk_common, "password")
    assert label == "Very Weak"

    # Very strong
    pwd_strong = "K9#mP2$xR7!vN4@wQ"
    ent_strong, _ = calculate_entropy(pwd_strong)
    chk_strong = check_patterns(pwd_strong, common_set)
    label_s, score_s, color_s = evaluate_strength(ent_strong, chk_strong, pwd_strong)
    assert label_s in ["Strong", "Very Strong"]
    assert score_s >= 0.8


def test_generate_random_password():
    pwd = generate_random_password(
        length=20,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_symbols=True,
        exclude_ambiguous=True,
    )
    assert len(pwd) == 20
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(not c.isalnum() for c in pwd)
    assert not any(c in AMBIGUOUS_CHARS for c in pwd)


def test_generate_passphrase():
    wordlist = ["maple", "tiger", "orbit", "canyon", "velvet", "falcon"]
    phrase = generate_passphrase(
        wordlist=wordlist,
        word_count=4,
        separator="-",
        capitalize="Title",
        add_number=True,
        add_symbol=True,
    )
    parts = phrase.split("-")
    assert len(parts) == 5  # 4 words + 1 number (or number+symbol attached)
    assert any(c.isdigit() for c in phrase)
