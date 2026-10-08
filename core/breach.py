"""
Have I Been Pwned (HIBP) Breach Checking Module
Uses k-Anonymity model: SHA-1 hash is computed locally, and only the first 5 characters
of the hash are sent over the network to query api.pwnedpasswords.com.
"""

import hashlib
from typing import Tuple
import requests


HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def check_pwned_password(password: str, timeout: float = 5.0) -> Tuple[bool, int, str]:
    """
    Checks if a password has been compromised in known data breaches.
    
    Returns:
        (is_pwned: bool, count: int, message: str)
    """
    if not password:
        return False, 0, "No password provided."

    # Step 1: SHA-1 Hash locally in uppercase
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # Step 2: Query API with prefix
    headers = {
        "User-Agent": "PassGuard-Academic-MiniProject/1.0 (Educational Password Safety Tool)"
    }
    
    try:
        url = f"{HIBP_API_URL}{prefix}"
        response = requests.get(url, headers=headers, timeout=timeout)
        
        if response.status_code == 429:
            return False, 0, "⚠️ HIBP API rate limit exceeded. Please wait a moment and try again."
        elif response.status_code != 200:
            return False, 0, f"⚠️ Unable to query breach database (HTTP {response.status_code})."

        # Step 3: Match suffix locally line by line
        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h.strip() == suffix:
                breach_count = int(count.strip())
                return (
                    True,
                    breach_count,
                    f"🚨 **WARNING**: This password has appeared in **{breach_count:,}** data breaches! You should NEVER use this password."
                )

        return (
            False,
            0,
            "✅ **Good news!** This password was NOT found in any known public data breaches."
        )

    except requests.exceptions.Timeout:
        return False, 0, "⏱️ Request timed out while contacting Have I Been Pwned. Check your internet connection."
    except requests.exceptions.RequestException as e:
        return False, 0, f"📡 Network error while checking breach database: {str(e)}"
