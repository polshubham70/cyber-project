# Combined password generator + strength checker
# Save as password_checker.py

from __future__ import annotations
import re
import argparse
import getpass
import random
import string
from typing import Dict, List

COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "qwerty",
    "password",
    "12345678",
    "111111",
    "1234567",
    "iloveyou",
    "123123",
    "admin",
    "welcome",
    "monkey",
    "letmein",
    "football",
    "passw0rd",
    "starwars",
}


def has_sequence(s: str, seq_len: int = 3) -> bool:
    s_lower = s.lower()
    filtered = ''.join(ch for ch in s_lower if ch.isalnum())
    if len(filtered) < seq_len:
        return False
    for i in range(len(filtered) - seq_len + 1):
        chunk = filtered[i : i + seq_len]
        ords = [ord(c) for c in chunk]
        diffs = [ords[j + 1] - ords[j] for j in range(len(ords) - 1)]
        if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
            return True
    return False


def max_repetition(s: str) -> int:
    if not s:
        return 0
    max_run = 1
    current = 1
    for a, b in zip(s, s[1:]):
        if a == b:
            current += 1
            if current > max_run:
                max_run = current
        else:
            current = 1
    return max_run


def check_password_strength(password: str) -> Dict:
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    if length < 8:
        length_points = 0
    elif length < 12:
        length_points = 1
    elif length < 16:
        length_points = 2
    elif length < 20:
        length_points = 3
    else:
        length_points = 4

    variety_points = sum([has_lower, has_upper, has_digit, has_special])

    penalties: List[str] = []
    penalty_points = 0
    if password.lower() in COMMON_PASSWORDS or password in COMMON_PASSWORDS:
        penalties.append("Password is a common password")
        penalty_points += 3

    if has_sequence(password, seq_len=3):
        penalties.append("Contains simple sequential characters (like 'abc' or '123')")
        penalty_points += 1

    if max_repetition(password) >= 4:
        penalties.append("Contains a long run of the same character (e.g., 'aaaa')")
        penalty_points += 1

    raw_score = length_points + variety_points
    raw_score = max(0, raw_score - penalty_points)
    max_raw = 8
    score_percent = int((raw_score / max_raw) * 100)

    if score_percent >= 85:
        rating = "Very Strong"
    elif score_percent >= 70:
        rating = "Strong"
    elif score_percent >= 50:
        rating = "Medium"
    elif score_percent >= 30:
        rating = "Weak"
    else:
        rating = "Very Weak"

    suggestions: List[str] = []
    if length < 12:
        suggestions.append("Use a longer password (at least 12 characters recommended).")
    if not has_upper:
        suggestions.append("Add uppercase letters.")
    if not has_lower:
        suggestions.append("Add lowercase letters.")
    if not has_digit:
        suggestions.append("Add numbers (digits).")
    if not has_special:
        suggestions.append("Add special characters (e.g., !@#$%^&*).")
    if password.lower() in COMMON_PASSWORDS or password in COMMON_PASSWORDS:
        suggestions.append("Avoid common passwords — use a unique phrase or a password manager.")
    if has_sequence(password, seq_len=3):
        suggestions.append("Avoid sequences like 'abc' or '123'.")
    if max_repetition(password) >= 4:
        suggestions.append("Avoid long repeated characters like 'aaaa' or '1111'.")
    if not suggestions:
        suggestions.append("No suggestions — good job! Consider using a password manager to create/remember strong, unique passwords.")

    breakdown = {
        "length": length,
        "length_points": length_points,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_special": has_special,
        "variety_points": variety_points,
        "penalties": penalties,
        "penalty_points": penalty_points,
        "raw_score": raw_score,
        "max_raw_score": max_raw,
    }

    return {
        "score": score_percent,
        "rating": rating,
        "suggestions": suggestions,
        "breakdown": breakdown,
    }


def generate_password(length: int, use_letters: bool = True, use_numbers: bool = True, use_symbols: bool = True) -> str:
    if length <= 0:
        raise ValueError("Length must be positive")
    character_pool = ""
    if use_letters:
        # include both upper and lower by default
        character_pool += string.ascii_letters
    if use_numbers:
        character_pool += string.digits
    if use_symbols:
        # strip whitespace-like punctuation for readability if desired, but keep default punctuation
        character_pool += string.punctuation
    if not character_pool:
        raise ValueError("At least one character type must be selected")
    # Guarantee at least one character from each selected category for better quality
    required_chars = []
    if use_letters:
        required_chars.append(random.choice(string.ascii_letters))
    if use_numbers:
        required_chars.append(random.choice(string.digits))
    if use_symbols:
        required_chars.append(random.choice(string.punctuation))
    if len(required_chars) > length:
        # If requested length is shorter than number of selected categories, trim required characters
        required_chars = required_chars[:length]
    remaining_length = length - len(required_chars)
    password_chars = required_chars + [random.choice(character_pool) for _ in range(remaining_length)]
    random.shuffle(password_chars)
    return ''.join(password_chars)


def print_report(report: Dict) -> None:
    print("\nPassword Strength Report")
    print("------------------------")
    print(f"Score: {report['score']} / 100")
    print(f"Rating: {report['rating']}\n")
    br = report["breakdown"]
    print("Breakdown:")
    print(f" - Length: {br['length']} characters (length points: {br['length_points']})")
    print(f" - Contains lowercase: {br['has_lower']}")
    print(f" - Contains uppercase: {br['has_upper']}")
    print(f" - Contains digits:    {br['has_digit']}")
    print(f" - Contains special:   {br['has_special']}")
    if br["penalties"]:
        print(f" - Penalties: {', '.join(br['penalties'])}")
    print("\nSuggestions:")
    for s in report["suggestions"]:
        print(f" - {s}")
    print("")


def main():
    parser = argparse.ArgumentParser(description="Password generator + complexity checker")
    parser.add_argument("--password", "-p", help="Password to check (not secure on CLI history). If omitted the program will prompt you.", default=None)
    parser.add_argument("--generate", "-g", action="store_true", help="Generate a password with the provided options")
    parser.add_argument("--length", "-l", type=int, default=12, help="Length for generated password (default 12)")
    parser.add_argument("--no-letters", action="store_true", help="Do not include letters in generated password")
    parser.add_argument("--no-numbers", action="store_true", help="Do not include numbers in generated password")
    parser.add_argument("--no-symbols", action="store_true", help="Do not include symbols in generated password")
    args = parser.parse_args()

    # If user requests generation, generate and print password then optionally assess it
    if args.generate:
        use_letters = not args.no_letters
        use_numbers = not args.no_numbers
        use_symbols = not args.no_symbols
        try:
            pwd = generate_password(args.length, use_letters, use_numbers, use_symbols)
        except ValueError as e:
            print(f"Error: {e}")
            return
        print(f"\nGenerated password: {pwd}")
        report = check_password_strength(pwd)
        print_report(report)
        return

    # If password was provided via CLI, check it
    if args.password is not None:
        pwd = args.password
    else:
        # prompt (hidden)
        try:
            pwd = getpass.getpass("Enter password to analyze (input hidden): ")
        except Exception:
            pwd = input("Enter password to analyze: ")

    report = check_password_strength(pwd)
    print_report(report)


if __name__ == "__main__":
    main()
    