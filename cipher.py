"""
cipher.py - Two-stage custom classical cipher: AFFINE  ->  VIGENERE
===================================================================

Educational project for CT-486 (Network and Information Security).
NOT secure for real-world use.

Pipeline
--------
    plaintext --normalize--> P --[Stage 1: Affine (a, b)]--> X
              --[Stage 2: Vigenere (key K, |K| >= 10)]--> ciphertext C

Maths (all arithmetic mod 26, letters A=0 ... Z=25)
    Stage 1 (Affine)  : X_i = (a * P_i + b)  mod 26        gcd(a, 26) = 1
    Stage 2 (Vigenere): C_i = (X_i + K_(i mod m)) mod 26   m = len(K)
    Decryption        : X_i = (C_i - K_(i mod m)) mod 26
                        P_i = a^-1 * (X_i - b)    mod 26

No cryptographic libraries are used; every operation is written by hand.
"""

import secrets

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MODULUS = 26
# Values of 'a' that have a multiplicative inverse mod 26 (gcd(a, 26) == 1)
VALID_A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
MIN_KEY_LENGTH = 10


class CipherError(ValueError):
    """Raised for any invalid input or key."""


# ---------------------------------------------------------------------------
# Section 1: small helpers
# ---------------------------------------------------------------------------
def char_to_num(ch):
    """'A' -> 0, ..., 'Z' -> 25."""
    return ord(ch) - ord("A")


def num_to_char(n):
    """0 -> 'A', ..., 25 -> 'Z' (n is reduced mod 26 first)."""
    return chr((n % MODULUS) + ord("A"))


def gcd(x, y):
    """Euclid's algorithm."""
    while y:
        x, y = y, x % y
    return x


def mod_inverse(a, m=MODULUS):
    """Multiplicative inverse of a modulo m (brute-force; m is only 26)."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise CipherError(f"{a} has no inverse modulo {m} (gcd({a},{m}) != 1)")


# ---------------------------------------------------------------------------
# Section 2: validation and normalisation
# ---------------------------------------------------------------------------
def normalize_text(text):
    """
    Prepare PLAINTEXT for encryption.
      * lowercase -> UPPERCASE
      * every character that is not A-Z (spaces, digits, punctuation,
        accents, ...) is REMOVED.
    Returns (normalized_text, removed_count).
    Raises CipherError if nothing is left.
    """
    if not isinstance(text, str):
        raise CipherError("Text must be a string.")
    upper = text.upper()
    kept = [ch for ch in upper if "A" <= ch <= "Z"]
    removed = len(upper) - len(kept)
    if not kept:
        raise CipherError("Text contains no letters A-Z after normalisation.")
    return "".join(kept), removed


def validate_ciphertext(text):
    """
    Prepare CIPHERTEXT for decryption. Whitespace (e.g. 5-letter groups) is
    ignored, but any other non-letter is an error because a valid ciphertext
    only ever contains A-Z.
    """
    if not isinstance(text, str):
        raise CipherError("Ciphertext must be a string.")
    cleaned = "".join(text.upper().split())
    if not cleaned:
        raise CipherError("Ciphertext is empty.")
    bad = sorted({ch for ch in cleaned if not ("A" <= ch <= "Z")})
    if bad:
        raise CipherError(
            "Ciphertext may contain only letters A-Z and whitespace; "
            f"found invalid characters: {bad}"
        )
    return cleaned


def validate_affine_key(a, b):
    """Check the affine key (a, b) and return it as ints."""
    try:
        a, b = int(a), int(b)
    except (TypeError, ValueError):
        raise CipherError("Affine keys 'a' and 'b' must be integers.")
    if a not in VALID_A:
        raise CipherError(
            f"Invalid 'a' = {a}. It must be coprime with 26, one of {VALID_A}."
        )
    if not 0 <= b <= 25:
        raise CipherError(f"Invalid 'b' = {b}. It must be between 0 and 25.")
    return a, b


def validate_vigenere_key(key):
    """Check the Vigenere keyword: letters only, at least 10 letters."""
    if not isinstance(key, str):
        raise CipherError("Vigenere key must be a string.")
    cleaned = "".join(key.upper().split())
    if not cleaned or not all("A" <= ch <= "Z" for ch in cleaned):
        raise CipherError("Vigenere key must contain only letters A-Z.")
    if len(cleaned) < MIN_KEY_LENGTH:
        raise CipherError(
            f"Vigenere key must have at least {MIN_KEY_LENGTH} letters "
            f"(got {len(cleaned)})."
        )
    return cleaned


def key_warnings(key):
    """Non-fatal warnings about weak Vigenere keys."""
    warnings = []
    if len(set(key)) < 5:
        warnings.append("Key uses fewer than 5 distinct letters (weak).")
    for period in range(1, len(key) // 2 + 1):
        if len(key) % period == 0 and key == key[:period] * (len(key) // period):
            warnings.append(
                f"Key repeats with period {period}; the effective key length is only {period}."
            )
            break
    return warnings


# ---------------------------------------------------------------------------
# Section 3: Stage 1 - Affine cipher
# ---------------------------------------------------------------------------
def affine_encrypt(text, a, b):
    """X_i = (a*P_i + b) mod 26."""
    return "".join(num_to_char(a * char_to_num(ch) + b) for ch in text)


def affine_decrypt(text, a, b):
    """P_i = a^-1 * (X_i - b) mod 26."""
    a_inv = mod_inverse(a)
    return "".join(num_to_char(a_inv * (char_to_num(ch) - b)) for ch in text)


# ---------------------------------------------------------------------------
# Section 4: Stage 2 - Vigenere cipher
# ---------------------------------------------------------------------------
def vigenere_encrypt(text, key):
    """C_i = (X_i + K_(i mod m)) mod 26."""
    m = len(key)
    return "".join(
        num_to_char(char_to_num(ch) + char_to_num(key[i % m]))
        for i, ch in enumerate(text)
    )


def vigenere_decrypt(text, key):
    """X_i = (C_i - K_(i mod m)) mod 26."""
    m = len(key)
    return "".join(
        num_to_char(char_to_num(ch) - char_to_num(key[i % m]))
        for i, ch in enumerate(text)
    )


# ---------------------------------------------------------------------------
# Section 5: the complete two-stage cipher
# ---------------------------------------------------------------------------
def encrypt(plaintext, a, b, key):
    """Normalise + validate, then Stage 1 (Affine), then Stage 2 (Vigenere)."""
    text, _ = normalize_text(plaintext)
    a, b = validate_affine_key(a, b)
    key = validate_vigenere_key(key)
    stage1 = affine_encrypt(text, a, b)
    return vigenere_encrypt(stage1, key)


def decrypt(ciphertext, a, b, key):
    """Undo Stage 2 (Vigenere) first, then Stage 1 (Affine)."""
    text = validate_ciphertext(ciphertext)
    a, b = validate_affine_key(a, b)
    key = validate_vigenere_key(key)
    stage1 = vigenere_decrypt(text, key)
    return affine_decrypt(stage1, a, b)


def encrypt_verbose(plaintext, a, b, key):
    """Like encrypt() but returns every intermediate value (for demos)."""
    text, removed = normalize_text(plaintext)
    a, b = validate_affine_key(a, b)
    key = validate_vigenere_key(key)
    stage1 = affine_encrypt(text, a, b)
    stage2 = vigenere_encrypt(stage1, key)
    return {"normalized": text, "removed": removed, "after_affine": stage1,
            "ciphertext": stage2}


# ---------------------------------------------------------------------------
# Section 6: key helpers
# ---------------------------------------------------------------------------
def generate_random_key(length=12):
    """Random key set using the OS cryptographic RNG (secrets module)."""
    if length < MIN_KEY_LENGTH:
        raise CipherError(f"Key length must be at least {MIN_KEY_LENGTH}.")
    a = secrets.choice(VALID_A)
    b = secrets.randbelow(MODULUS)
    key = "".join(secrets.choice(ALPHABET) for _ in range(length))
    return a, b, key


def effective_shifts(a, b, key):
    """
    Combine both stages into one equivalent description:
        C_i = a*P_i + s_(i mod m)   with   s_j = (b + K_j) mod 26.
    The attacker only ever needs (a, s_0..s_(m-1)); b and K cannot be
    separated from ciphertext (see report, Security Analysis).
    """
    return [(b + char_to_num(k)) % MODULUS for k in key]


def format_blocks(text, size=5):
    """'ABCDEFGHIJ' -> 'ABCDE FGHIJ' for readability."""
    return " ".join(text[i:i + size] for i in range(0, len(text), size))


# ---------------------------------------------------------------------------
# Section 7: single-stage baseline (used only for comparison experiments)
# ---------------------------------------------------------------------------
def caesar_encrypt(text, shift):
    """C_i = (P_i + shift) mod 26."""
    return "".join(num_to_char(char_to_num(ch) + shift) for ch in text)


def caesar_decrypt(text, shift):
    """P_i = (C_i - shift) mod 26."""
    return caesar_encrypt(text, -shift)
