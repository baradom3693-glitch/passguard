"""
Password and Passphrase Generator Module
Uses Python's secrets module for cryptographically secure random generation.
"""

import secrets
import string
from typing import List, Dict, Any
from core.analyzer import calculate_entropy, evaluate_strength, check_patterns


AMBIGUOUS_CHARS = set("0Ol1I")


def generate_random_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Generates a cryptographically secure random password using secrets.
    Ensures at least one character from each enabled character set.
    """
    upper_pool = string.ascii_uppercase
    lower_pool = string.ascii_lowercase
    digit_pool = string.digits
    symbol_pool = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if exclude_ambiguous:
        upper_pool = "".join(c for c in upper_pool if c not in AMBIGUOUS_CHARS)
        lower_pool = "".join(c for c in lower_pool if c not in AMBIGUOUS_CHARS)
        digit_pool = "".join(c for c in digit_pool if c not in AMBIGUOUS_CHARS)
        symbol_pool = "".join(c for c in symbol_pool if c not in AMBIGUOUS_CHARS)

    pools = []
    if use_upper and upper_pool:
        pools.append(upper_pool)
    if use_lower and lower_pool:
        pools.append(lower_pool)
    if use_digits and digit_pool:
        pools.append(digit_pool)
    if use_symbols and symbol_pool:
        pools.append(symbol_pool)

    if not pools:
        # Fallback if user unchecks all
        pools = [lower_pool if lower_pool else string.ascii_lowercase]

    # Guarantee at least 1 character from each chosen pool
    password_chars = [secrets.choice(pool) for pool in pools]

    # Fill remaining length from combined pool
    combined_pool = "".join(pools)
    remaining_length = max(0, length - len(password_chars))
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(combined_pool))

    # Cryptographically shuffle character order
    # To shuffle securely: pick elements randomly without replacement
    shuffled = []
    temp_chars = list(password_chars)
    while temp_chars:
        idx = secrets.randbelow(len(temp_chars))
        shuffled.append(temp_chars.pop(idx))

    return "".join(shuffled)


def generate_passphrase(
    wordlist: List[str],
    word_count: int = 4,
    separator: str = "-",
    capitalize: str = "Title",  # "Title", "lower", "UPPER"
    add_number: bool = True,
    add_symbol: bool = False,
) -> str:
    """
    Generates a cryptographically secure memorable passphrase from a wordlist.
    """
    if not wordlist:
        wordlist = ["maple", "tiger", "orbit", "canyon", "velvet", "falcon"]

    chosen_words = [secrets.choice(wordlist) for _ in range(word_count)]

    if capitalize == "Title":
        chosen_words = [w.capitalize() for w in chosen_words]
    elif capitalize == "UPPER":
        chosen_words = [w.upper() for w in chosen_words]
    else:
        chosen_words = [w.lower() for w in chosen_words]

    base_passphrase = separator.join(chosen_words)

    if add_number:
        num = secrets.randbelow(90) + 10  # 10 to 99
        base_passphrase += f"{separator}{num}"

    if add_symbol:
        symbols = "!@#$%^&*"
        sym = secrets.choice(symbols)
        base_passphrase += sym

    return base_passphrase


def generate_batch(
    mode: str,
    count: int,
    wordlist: List[str],
    common_passwords_set: set,
    **kwargs
) -> List[Dict[str, Any]]:
    """
    Generates batch of passwords or passphrases with entropy and strength calculations.
    """
    results = []
    for _ in range(count):
        if mode == "Random Password":
            pwd = generate_random_password(**kwargs)
        else:
            pwd = generate_passphrase(wordlist=wordlist, **kwargs)

        entropy, _ = calculate_entropy(pwd)
        checklist = check_patterns(pwd, common_passwords_set)
        label, score, color = evaluate_strength(entropy, checklist, pwd)

        results.append({
            "password": pwd,
            "entropy": entropy,
            "strength": label,
            "score": score,
            "color": color,
            "length": len(pwd),
        })

    return results
