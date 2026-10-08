"""
Password Strength Analyzer Module
Calculates entropy, crack times, pattern checks, strength scoring, and tips.
"""

import math
import re
import string
from typing import Dict, List, Tuple, Set, Any


def calculate_entropy(password: str) -> Tuple[float, int]:
    """
    Calculates the information entropy of a password in bits.
    
    Formula:
        Entropy (bits) = Length * log2(Pool Size)
    
    Returns:
        (entropy_bits, pool_size)
    """
    if not password:
        return 0.0, 0

    pool_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    has_unicode = any(ord(c) > 127 for c in password)

    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32
    if has_unicode:
        pool_size += 30

    if pool_size == 0:
        return 0.0, 0

    length = len(password)
    entropy = length * math.log2(pool_size)
    return round(entropy, 2), pool_size


def format_seconds(seconds: float) -> str:
    """Formats raw seconds into human-readable duration."""
    if seconds < 0.001:
        return "Instantly (< 1 ms)"
    elif seconds < 1:
        return "Instantly (< 1 second)"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        mins = int(seconds // 60)
        return f"{mins} minute" if mins == 1 else f"{mins} minutes"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    elif seconds < 365 * 86400:
        days = int(seconds // 86400)
        return f"{days} day" if days == 1 else f"{days} days"
    elif seconds < 100 * 365 * 86400:
        years = int(seconds // (365 * 86400))
        return f"{years} year" if years == 1 else f"{years:,} years"
    elif seconds < 10000 * 365 * 86400:
        centuries = int(seconds // (100 * 365 * 86400))
        return f"{centuries:,} centuries"
    else:
        return "Billions of years"


def estimate_crack_times(entropy: float) -> Dict[str, str]:
    """
    Estimates crack times under 3 threat model scenarios:
    1. Online attack: 100 guesses/sec
    2. Offline fast hash attack: 10 billion guesses/sec (10^10)
    3. Massive GPU cluster: 1 trillion guesses/sec (10^12)
    """
    if entropy <= 0:
        return {
            "online": "Instantly",
            "offline_fast": "Instantly",
            "gpu_cluster": "Instantly",
        }

    # Total combinations = 2^entropy
    # Average guesses needed before finding match = combinations / 2
    combinations = math.pow(2, entropy)
    avg_guesses = combinations / 2.0

    online_sec = avg_guesses / 100.0
    offline_sec = avg_guesses / 10_000_000_000.0
    gpu_sec = avg_guesses / 1_000_000_000_000.0

    return {
        "online": format_seconds(online_sec),
        "offline_fast": format_seconds(offline_sec),
        "gpu_cluster": format_seconds(gpu_sec),
    }


def check_sequential_patterns(password: str) -> bool:
    """Returns True if password contains NO ascending or descending sequential patterns of length 3+."""
    clean = password.lower()
    if len(clean) < 3:
        return True

    for i in range(len(clean) - 2):
        c1, c2, c3 = ord(clean[i]), ord(clean[i+1]), ord(clean[i+2])
        # Ascending (abc, 123) or Descending (cba, 321)
        if (c2 == c1 + 1 and c3 == c2 + 1) or (c2 == c1 - 1 and c3 == c2 - 1):
            return False
    return True


def check_keyboard_patterns(password: str) -> bool:
    """Returns True if password contains NO common keyboard row/column patterns of length 4+."""
    clean = password.lower()
    keyboard_patterns = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890", "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
        "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.",
        "zaq1", "xsw2", "cde3", "vfr4", "bgt5", "nhy6", "mju7"
    ]
    
    if len(clean) < 4:
        return True

    for i in range(len(clean) - 3):
        sub = clean[i:i+4]
        for pat in keyboard_patterns:
            if sub in pat:
                return False
    return True


def check_patterns(password: str, common_passwords_set: Set[str]) -> Dict[str, Any]:
    """
    Performs full checklist evaluation on a password.
    Returns dictionary with boolean pass/fail status for each rule.
    """
    if not password:
        return {
            "min_length": False,
            "has_uppercase": False,
            "has_lowercase": False,
            "has_digit": False,
            "has_symbol": False,
            "no_repeats": True,
            "no_sequences": True,
            "no_keyboard": True,
            "not_common": True,
        }

    pwd_lower = password.lower().strip()
    
    # Check 3+ consecutive repeats (e.g. aaa, 111)
    has_repeats = bool(re.search(r'(.)\1{2,}', password))

    return {
        "min_length": len(password) >= 12,
        "has_uppercase": any(c.isupper() for c in password),
        "has_lowercase": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_symbol": any(not c.isalnum() for c in password),
        "no_repeats": not has_repeats,
        "no_sequences": check_sequential_patterns(password),
        "no_keyboard": check_keyboard_patterns(password),
        "not_common": pwd_lower not in common_passwords_set,
    }


def evaluate_strength(entropy: float, checklist: Dict[str, Any], password: str) -> Tuple[str, float, str]:
    """
    Evaluates strength based on entropy, pattern safety, and length.
    
    Returns:
        (strength_label, score_0_to_1, color_hex)
    """
    if not password:
        return "Empty", 0.0, "#808080"

    # Hard penalization for common passwords or length < 6
    if not checklist.get("not_common", True) or len(password) < 6:
        return "Very Weak", 0.15, "#FF4B4B"

    # Calculate base score from entropy (0 to 1 scale, maxing at 100 bits)
    entropy_score = min(entropy / 100.0, 1.0)
    
    # Calculate checklist score (number of passed checks / total)
    passed_checks = sum(1 for k, v in checklist.items() if v)
    checklist_score = passed_checks / len(checklist)

    # Combined score
    combined_score = (entropy_score * 0.6) + (checklist_score * 0.4)

    if entropy < 28 or combined_score < 0.3:
        label = "Very Weak"
        color = "#FF4B4B"  # Red
    elif entropy < 45 or combined_score < 0.5:
        label = "Weak"
        color = "#FFA500"  # Orange
    elif entropy < 65 or combined_score < 0.7:
        label = "Fair"
        color = "#FFD700"  # Yellow
    elif entropy < 80 or combined_score < 0.85:
        label = "Strong"
        color = "#20B2AA"  # Light Teal
    else:
        label = "Very Strong"
        color = "#00C853"  # Vibrant Green

    return label, round(combined_score, 2), color


def generate_suggestions(checklist: Dict[str, Any], password: str, entropy: float) -> List[str]:
    """Generates plain-English recommendations to improve the given password."""
    suggestions = []

    if not password:
        return ["Enter a password to get personalized security tips."]

    if not checklist.get("not_common", True):
        suggestions.append("⚠️ **Critical**: This password is in a known dictionary of common passwords. Change it immediately!")

    if len(password) < 12:
        suggestions.append(f"📏 **Increase length**: Your password is currently {len(password)} characters long. Aim for at least 12–16 characters.")

    if not checklist.get("has_uppercase", True):
        suggestions.append("🔠 **Add Uppercase**: Mix in at least one capital letter (A-Z).")

    if not checklist.get("has_lowercase", True):
        suggestions.append("🔡 **Add Lowercase**: Mix in at least one lowercase letter (a-z).")

    if not checklist.get("has_digit", True):
        suggestions.append("🔢 **Add Digits**: Include numbers (0-9).")

    if not checklist.get("has_symbol", True):
        suggestions.append("🔣 **Add Symbols**: Add special characters like `! @ # $ % ^ & * _ -`.")

    if not checklist.get("no_repeats", True):
        suggestions.append("🔁 **Remove Character Repeats**: Avoid 3 or more identical characters in a row (e.g., `aaa` or `111`).")

    if not checklist.get("no_sequences", True):
        suggestions.append("🔤 **Avoid Sequences**: Remove consecutive sequences like `abc`, `123`, or `321`.")

    if not checklist.get("no_keyboard", True):
        suggestions.append("⌨️ **Avoid Keyboard Patterns**: Do not use spatial keyboard sweeps like `qwerty` or `asdf`.")

    if entropy < 60 and len(suggestions) <= 1:
        suggestions.append("💡 **Use a Passphrase**: Combine 4 or 5 random words (e.g. `maple-tiger-orbit-canyon-47`) for high strength and easy memorization.")

    if len(suggestions) == 0:
        suggestions.append("🎉 **Excellent Password!** Your password meets all security criteria and has high entropy.")

    return suggestions
