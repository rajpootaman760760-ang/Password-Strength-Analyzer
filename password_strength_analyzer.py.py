"""
Password Strength Analyzer
==========================
Evaluates password strength based on length, complexity, and uniqueness.
Suggests stronger alternatives and stores password hashes to prevent reuse.
Covers basic cryptography concepts using hashlib (SHA-256).

Author : Aman Kumar Rajpoot
"""

import re
import hashlib
import secrets
import string
import json
import os
from datetime import datetime


# ── Common / weak passwords list ──────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "111111",
    "password1", "iloveyou", "admin", "letmein", "monkey", "1234567",
    "12345678", "sunshine", "princess", "football", "welcome", "shadow",
    "superman", "master", "hello", "dragon", "654321", "password123",
    "qwerty123", "1q2w3e4r", "zxcvbnm", "asdfgh", "pass", "test",
    "guest", "root", "toor", "login", "admin123", "user", "123",
    "1234", "12345", "000000", "99999999", "passw0rd", "p@ssword",
}

# ── Keyboard walk patterns ─────────────────────────────────────────────────────
KEYBOARD_PATTERNS = [
    "qwerty", "qwertyu", "qwertyui", "asdf", "asdfgh", "zxcvbn",
    "1234", "12345", "123456", "1234567", "12345678",
    "abcd", "abcde", "abcdef",
]

# ── Hash store file (simulates a database) ────────────────────────────────────
HASH_STORE_FILE = "used_passwords.json"


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTOGRAPHY HELPER — SHA-256 hashing
# ══════════════════════════════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    """Return SHA-256 hex digest of the password (basic cryptography concept)."""
    return hashlib.sha256(password.encode("utf-8")).digest().hex()


# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE SIMULATION — prevent reuse of old passwords
# ══════════════════════════════════════════════════════════════════════════════

def load_hash_store() -> dict:
    """Load previously used password hashes from JSON file."""
    if os.path.exists(HASH_STORE_FILE):
        with open(HASH_STORE_FILE, "r") as f:
            return json.load(f)
    return {"hashes": []}


def save_hash_store(store: dict) -> None:
    """Persist hash store to JSON file."""
    with open(HASH_STORE_FILE, "w") as f:
        json.dump(store, f, indent=2)


def is_password_reused(password: str) -> bool:
    """Check if this password was used before (compare hashes, never raw text)."""
    store = load_hash_store()
    return hash_password(password) in store["hashes"]


def register_password(password: str) -> None:
    """Save hashed password to the store so it cannot be reused later."""
    store = load_hash_store()
    h = hash_password(password)
    if h not in store["hashes"]:
        store["hashes"].append(h)
        save_hash_store(store)


# ══════════════════════════════════════════════════════════════════════════════
#  CORE SCORING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def analyze_password(password: str) -> dict:
    """
    Score a password and return a detailed analysis dict.

    Scoring breakdown (max 100):
      Length          : up to 30 pts
      Uppercase       : 10 pts
      Lowercase       : 10 pts
      Digits          : 10 pts
      Special chars   : 20 pts
      Variety bonus   : 10 pts
      Penalties       : common password, keyboard walk, repeated chars
    """
    score = 0
    feedback = []
    criteria = {}

    # ── 1. Length ──────────────────────────────────────────────────────────
    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        score += 0
        feedback.append("Use at least 8 characters (12+ recommended).")

    criteria["length"] = length

    # ── 2. Character types ─────────────────────────────────────────────────
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password))

    criteria["uppercase"] = has_upper
    criteria["lowercase"] = has_lower
    criteria["digits"] = has_digit
    criteria["special_chars"] = has_special

    if has_upper:
        score += 10
    else:
        feedback.append("Add at least one uppercase letter (A-Z).")

    if has_lower:
        score += 10
    else:
        feedback.append("Add at least one lowercase letter (a-z).")

    if has_digit:
        score += 10
    else:
        feedback.append("Include at least one digit (0-9).")

    if has_special:
        score += 20
    else:
        feedback.append("Add special characters like !@#$%^&* to boost strength.")

    # ── 3. Variety bonus ───────────────────────────────────────────────────
    types_used = sum([has_upper, has_lower, has_digit, has_special])
    if types_used == 4:
        score += 10
        feedback.append("Great mix of character types! ✓")
    elif types_used == 3:
        score += 5

    # ── 4. Repeated characters penalty ────────────────────────────────────
    repeated = bool(re.search(r"(.)\1{2,}", password))   # 3+ same chars in a row
    if repeated:
        score -= 15
        feedback.append("Avoid repeating the same character 3+ times in a row.")

    criteria["repeated_chars"] = repeated

    # ── 5. Keyboard walk penalty ───────────────────────────────────────────
    lower_pw = password.lower()
    is_walk = any(pat in lower_pw for pat in KEYBOARD_PATTERNS)
    if is_walk:
        score -= 20
        feedback.append("Avoid keyboard patterns like 'qwerty' or '1234'.")

    criteria["keyboard_pattern"] = is_walk

    # ── 6. Common password penalty ─────────────────────────────────────────
    is_common = password.lower() in COMMON_PASSWORDS
    if is_common:
        score -= 40
        feedback.append("This is a very common password — change it immediately!")

    criteria["common_password"] = is_common

    # ── 7. Clamp score ─────────────────────────────────────────────────────
    score = max(0, min(100, score))

    # ── 8. Strength label ──────────────────────────────────────────────────
    if score >= 80:
        strength = "Very Strong 💪"
        color_hint = "green"
    elif score >= 60:
        strength = "Strong ✅"
        color_hint = "cyan"
    elif score >= 40:
        strength = "Fair ⚠️"
        color_hint = "yellow"
    else:
        strength = "Weak ❌"
        color_hint = "red"

    # ── 9. Reuse check ─────────────────────────────────────────────────────
    reused = is_password_reused(password)
    if reused:
        score = min(score, 30)          # cap score if reused
        strength = "Reused ♻️ (Dangerous)"
        feedback.append("⚠️  This password was used before. Please choose a new one.")

    criteria["reused"] = reused

    return {
        "password": "*" * len(password),    # never log raw password
        "score": score,
        "strength": strength,
        "color_hint": color_hint,
        "criteria": criteria,
        "feedback": feedback if feedback else ["Looks solid! No major issues found."],
        "hash_sha256": hash_password(password),   # educational: show the hash
    }


# ══════════════════════════════════════════════════════════════════════════════
#  SUGGESTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def suggest_stronger_password(length: int = 16) -> str:
    """
    Generate a cryptographically secure random password using secrets module.
    secrets is safer than random for security-sensitive tasks.
    """
    alphabet = (
        string.ascii_uppercase
        + string.ascii_lowercase
        + string.digits
        + "!@#$%^&*()-_=+"
    )
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        # Ensure all 4 character types are present
        if (any(c.isupper() for c in pwd)
                and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*()-_=+" for c in pwd)):
            return pwd


# ══════════════════════════════════════════════════════════════════════════════
#  DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

COLORS = {
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "green":  "\033[92m",
    "blue":   "\033[94m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}


def colorize(text: str, color: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_bar(score: int) -> None:
    filled = score // 5       # max 20 blocks
    bar = "█" * filled + "░" * (20 - filled)
    color = "red" if score < 40 else "yellow" if score < 60 else "cyan" if score < 80 else "green"
    print(f"  Strength  [{colorize(bar, color)}]  {score}/100")


def print_criteria(criteria: dict) -> None:
    checks = {
        "Length ≥ 8":           criteria["length"] >= 8,
        "Length ≥ 12":          criteria["length"] >= 12,
        "Uppercase letters":    criteria["uppercase"],
        "Lowercase letters":    criteria["lowercase"],
        "Digits":               criteria["digits"],
        "Special characters":   criteria["special_chars"],
        "No repeated chars":    not criteria["repeated_chars"],
        "No keyboard patterns": not criteria["keyboard_pattern"],
        "Not a common password":not criteria["common_password"],
        "Not reused":           not criteria["reused"],
    }
    print()
    print(colorize("  Criteria checklist:", "bold"))
    for label, passed in checks.items():
        icon = colorize("  ✓", "green") if passed else colorize("  ✗", "red")
        print(f"{icon}  {label}")


def print_result(result: dict) -> None:
    print()
    print(colorize("═" * 52, "blue"))
    print(colorize("  PASSWORD STRENGTH ANALYSIS", "bold"))
    print(colorize("═" * 52, "blue"))
    print()
    print_bar(result["score"])
    print()
    color = result["color_hint"]
    print(f"  Result   : {colorize(result['strength'], color)}")
    print(f"  Score    : {colorize(str(result['score']) + ' / 100', color)}")
    print(f"  SHA-256  : {result['hash_sha256'][:32]}…  (truncated)")
    print_criteria(result["criteria"])
    print()
    print(colorize("  Feedback:", "bold"))
    for tip in result["feedback"]:
        print(f"    • {tip}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN CLI LOOP
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print()
    print(colorize("╔══════════════════════════════════════════╗", "blue"))
    print(colorize("║     PASSWORD STRENGTH ANALYZER v1.0     ║", "blue"))
    print(colorize("║     by Aman Kumar Rajpoot               ║", "blue"))
    print(colorize("╚══════════════════════════════════════════╝", "blue"))
    print()
    print("  Commands:  [A]nalyze  |  [S]uggest  |  [R]egister  |  [Q]uit")
    print()

    while True:
        print(colorize("─" * 52, "blue"))
        cmd = input("  Enter command (A/S/R/Q): ").strip().upper()

        if cmd == "Q":
            print(colorize("\n  Goodbye! Stay secure. 🔐\n", "green"))
            break

        elif cmd == "A":
            import getpass
            password = getpass.getpass("  Enter password to analyze (hidden): ")
            if not password:
                print(colorize("  No password entered.", "red"))
                continue
            result = analyze_password(password)
            print_result(result)

        elif cmd == "S":
            try:
                length = int(input("  Desired length (default 16): ").strip() or "16")
                length = max(8, min(64, length))
            except ValueError:
                length = 16
            suggestion = suggest_stronger_password(length)
            print()
            print(colorize(f"  Suggested: {suggestion}", "green"))
            print(colorize("  (Copy it now — it won't be shown again)", "yellow"))
            print()

        elif cmd == "R":
            import getpass
            password = getpass.getpass("  Enter password to register (hidden): ")
            if not password:
                print(colorize("  No password entered.", "red"))
                continue
            result = analyze_password(password)
            if result["score"] < 40:
                print(colorize("  ❌ Password too weak to register. Score must be ≥ 40.", "red"))
            elif result["criteria"]["reused"]:
                print(colorize("  ♻️  Password already registered. Use a new one.", "yellow"))
            else:
                register_password(password)
                print(colorize("  ✅ Password registered successfully! (Hash saved)", "green"))
                print(f"     SHA-256: {hash_password(password)}")
            print()

        else:
            print(colorize("  Unknown command. Use A, S, R, or Q.", "yellow"))


if __name__ == "__main__":
    main()
