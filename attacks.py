"""
attacks.py - Educational cryptanalysis of the Affine -> Vigenere cipher
======================================================================

Key observation that drives every attack here.  Combining both stages:

    C_i = a * P_i + s_(i mod m)        (mod 26),   s_j = b + K_j

So the cipher behaves like a Vigenere cipher whose "plaintext" has been
multiplied by a.  Consequences:
  * Each ciphertext column  C[j], C[j+m], C[j+2m], ...  is a simple AFFINE
    (monoalphabetic) encryption of English with the same a and its own shift
    s_j  -> every column keeps the *shape* of English letter frequencies.
  * b and the Vigenere key K can never be separated from ciphertext alone;
    only the sums s_j matter.  The attacker does not need them separately.

Attacks implemented:
  A. Ciphertext-only frequency analysis
       1. letter frequencies / Index of Coincidence (shows disguising)
       2. naive single-alphabet frequency attack  (expected to FAIL)
       3. key-length estimation by pooled Index of Coincidence
       4. column-wise chi-squared search over (a, shift)   (real recovery)
  B. Known-plaintext attack
       difference trick  C_(i+m) - C_i = a (P_(i+m) - P_i)  removes the key.
"""

from cipher import (ALPHABET, MODULUS, VALID_A, mod_inverse, char_to_num,
                    num_to_char)

# Typical English letter frequencies (percent), A..Z.
ENGLISH_FREQ = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
]
ENGLISH_IC = 0.0667      # IC of English text
RANDOM_IC = 1.0 / 26     # about 0.0385 for uniformly random letters


# ---------------------------------------------------------------------------
# Section 1: statistics
# ---------------------------------------------------------------------------
def letter_counts(text):
    """List of 26 counts."""
    counts = [0] * MODULUS
    for ch in text:
        counts[char_to_num(ch)] += 1
    return counts


def frequency_percentages(text):
    """Percentage of each letter (0 if text is empty)."""
    n = len(text)
    if n == 0:
        return [0.0] * MODULUS
    return [100.0 * c / n for c in letter_counts(text)]


def index_of_coincidence(text):
    """IC = sum n_i (n_i - 1) / (N (N - 1)). English ~0.067, random ~0.038."""
    n = len(text)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in letter_counts(text)) / (n * (n - 1))


def chi_squared_vs_english(counts):
    """Chi-squared distance between observed counts and English expectation."""
    n = sum(counts)
    if n == 0:
        return float("inf")
    total = 0.0
    for p in range(MODULUS):
        expected = n * ENGLISH_FREQ[p] / 100.0
        total += (counts[p] - expected) ** 2 / expected
    return total


def frequency_distance(text):
    """Sum of absolute differences (percentage points) from English."""
    return sum(abs(o - e) for o, e in zip(frequency_percentages(text), ENGLISH_FREQ))


def frequency_report(text, label="Ciphertext"):
    """Printable table: letter, count, %, English %, difference, bar."""
    counts = letter_counts(text)
    pct = frequency_percentages(text)
    lines = [f"{label}: length={len(text)}  IC={index_of_coincidence(text):.4f} "
             f"(English~{ENGLISH_IC}, random~{RANDOM_IC:.4f})  "
             f"L1-distance from English={frequency_distance(text):.1f} pct-points",
             "Letter  Count     %   English%   Diff   Bar"]
    for i, ch in enumerate(ALPHABET):
        bar = "#" * int(round(pct[i]))
        lines.append(f"  {ch}    {counts[i]:5d}  {pct[i]:5.2f}   {ENGLISH_FREQ[i]:6.2f}  "
                     f"{pct[i] - ENGLISH_FREQ[i]:+6.2f}   {bar}")
    return "\n".join(lines)


def accuracy(recovered, original):
    """Fraction of positions where recovered == original ('?' counts wrong)."""
    if not original:
        return 0.0
    n = min(len(recovered), len(original))
    hits = sum(1 for i in range(n) if recovered[i] == original[i])
    return hits / len(original)


# ---------------------------------------------------------------------------
# Section 2: decrypting with an "effective key" (a, shifts)
# ---------------------------------------------------------------------------
def decrypt_with_effective_key(ciphertext, a, shifts):
    """
    P_i = a^-1 (C_i - s_(i mod m)).   shifts[j] may be None (unknown column),
    in which case the output letter is '?'.
    """
    a_inv = mod_inverse(a)
    m = len(shifts)
    out = []
    for i, ch in enumerate(ciphertext):
        s = shifts[i % m]
        out.append("?" if s is None else num_to_char(a_inv * (char_to_num(ch) - s)))
    return "".join(out)


# ---------------------------------------------------------------------------
# Section 3: ciphertext-only attack
# ---------------------------------------------------------------------------
def naive_rank_attack(ciphertext):
    """
    Treat the ciphertext as ONE monoalphabetic cipher: map the most frequent
    ciphertext letter to E, the next to T, ... (classic textbook attack).
    Included to show that plain frequency analysis does NOT work here.
    """
    order_cipher = sorted(range(MODULUS), key=lambda i: -letter_counts(ciphertext)[i])
    order_english = sorted(range(MODULUS), key=lambda i: -ENGLISH_FREQ[i])
    mapping = {num_to_char(c): num_to_char(e)
               for c, e in zip(order_cipher, order_english)}
    return "".join(mapping[ch] for ch in ciphertext)


def pooled_ic(ciphertext, m):
    """IC pooled over the m columns C[j::m] (higher => m is the key length)."""
    num = den = 0
    for j in range(m):
        col = ciphertext[j::m]
        n = len(col)
        den += n * (n - 1)
        num += sum(c * (c - 1) for c in letter_counts(col))
    return num / den if den else 0.0


def estimate_key_length(ciphertext, max_len=20, rel_threshold=0.93):
    """
    Pick the key length from the pooled-IC scores.
    Multiples of the true length score as high as the true length, so we take
    the SMALLEST m whose score is within `rel_threshold` of the best score.
    (Version 1 used a fixed threshold of 0.055 and was fooled by half-length
    guesses: mixing two shifted English columns can still score ~0.057.)
    If even the best score is below 0.05 the text looks random; return the
    arg-max anyway.  Returns (m, {m: pooled_ic}).
    """
    max_len = max(1, min(max_len, len(ciphertext) // 2))
    scores = {m: pooled_ic(ciphertext, m) for m in range(1, max_len + 1)}
    best = max(scores.values())
    if best >= 0.05:
        for m in range(1, max_len + 1):
            if scores[m] >= rel_threshold * best:
                return m, scores
    return max(scores, key=scores.get), scores


def _best_shift(counts, a):
    """
    For one column with letter counts `counts`, assuming multiplier a, find
    shift s minimising chi-squared of the DECRYPTED letters vs English.
    Plain letter p appears in the column as cipher letter (a*p + s) mod 26.
    Returns (best_s, best_chi).
    """
    n = sum(counts)
    best_s, best_chi = 0, float("inf")
    for s in range(MODULUS):
        chi = 0.0
        for p in range(MODULUS):
            expected = n * ENGLISH_FREQ[p] / 100.0
            observed = counts[(a * p + s) % MODULUS]
            chi += (observed - expected) ** 2 / expected
        if chi < best_chi:
            best_s, best_chi = s, chi
    return best_s, best_chi


def frequency_analysis_attack(ciphertext, max_key_len=20, key_length=None):
    """
    Ciphertext-only recovery.
      1. Estimate m (unless supplied) with pooled IC.
      2. Split into m columns (each is an affine cipher with unknown a, s_j).
      3. For every a in the 12 valid values and every column, find the best
         shift by chi-squared; the a with the smallest total chi-squared wins.
      4. Decrypt with the recovered effective key (a, s_0..s_(m-1)).
    Returns a dict with the recovered values.  Cost is O(n + 12*26*26*m).
    """
    if key_length is None:
        m, ic_scores = estimate_key_length(ciphertext, max_key_len)
    else:
        m, ic_scores = key_length, {}
    col_counts = [letter_counts(ciphertext[j::m]) for j in range(m)]

    best = None
    for a in VALID_A:
        total, shifts = 0.0, []
        for counts in col_counts:
            if sum(counts) == 0:
                shifts.append(0)
                continue
            s, chi = _best_shift(counts, a)
            shifts.append(s)
            total += chi
        if best is None or total < best["score"]:
            best = {"a": a, "shifts": shifts, "score": total}

    recovered = decrypt_with_effective_key(ciphertext, best["a"], best["shifts"])
    return {"key_length": m, "a": best["a"], "shifts": best["shifts"],
            "score": best["score"], "recovered": recovered, "ic_scores": ic_scores}


# ---------------------------------------------------------------------------
# Section 4: known-plaintext attack
# ---------------------------------------------------------------------------
def _shifts_from_fragment(frag_c, frag_p, start, a, m):
    """
    Assuming multiplier a and period m, s_j = C_i - a*P_i for the known
    positions i (absolute index start+k, column (start+k) mod m).
    Returns (shifts list with None for unknown columns, overlap) or
    (None, 0) if two positions in the same column disagree.
    overlap = number of known positions that landed on an already-seen column
    (each one is an independent consistency check).
    """
    shifts = [None] * m
    overlap = 0
    for k, (c, p) in enumerate(zip(frag_c, frag_p)):
        col = (start + k) % m
        s = (char_to_num(c) - a * char_to_num(p)) % MODULUS
        if shifts[col] is None:
            shifts[col] = s
        elif shifts[col] != s:
            return None, 0
        else:
            overlap += 1
    return shifts, overlap


def known_plaintext_attack(ciphertext, known_plain, start=0,
                           max_period=40, min_overlap=4, guess_key_length=None):
    """
    Attacker knows that ciphertext[start : start+L] encrypts `known_plain`
    (normalised A-Z, length L) and knows the algorithm (Kerckhoffs).

    Core idea: for two positions in the same Vigenere column,
        C_(i+m) - C_i = a (P_(i+m) - P_i)  (mod 26)
    so the key cancels out and only a and m are left to find.

    Method
      Stage A (verified): for m = 1,2,3,...: for every valid a compute
        s = C - a*P on the known fragment; if the sequence repeats with
        period m and at least `min_overlap` repeats are checked, accept
        (a, m).  A wrong (a, m) passes by chance with probability about
        26^-min_overlap.
      Stage B (unverified fallback): when the fragment is too short for a
        verified period, take m from the ciphertext IC estimate, discard any
        a that is inconsistent, and pick among survivors by English-likeness
        (chi-squared) of the partial decryption.
    Returns a dict (success flag is decided by the caller, who knows the truth).
    """
    L = len(known_plain)
    frag_c = ciphertext[start:start + L]
    if L == 0 or len(frag_c) != L:
        return {"method": "failed", "reason": "bad fragment", "a": None,
                "m": None, "shifts": [], "recovered": "?" * len(ciphertext),
                "columns_known": 0}

    # --- Stage A ---------------------------------------------------------
    for m in range(1, max_period + 1):
        survivors = []
        for a in VALID_A:
            shifts, overlap = _shifts_from_fragment(frag_c, known_plain, start, a, m)
            if shifts is not None and overlap >= min_overlap:
                survivors.append((a, shifts))
        if survivors:
            a, shifts = survivors[0]
            return _kpa_result("verified-period", a, m, shifts, ciphertext,
                               note=f"{len(survivors)} candidate(s) passed")

    # --- Stage B ---------------------------------------------------------
    m = guess_key_length or estimate_key_length(ciphertext)[0]
    best = None
    for a in VALID_A:
        shifts, _ = _shifts_from_fragment(frag_c, known_plain, start, a, m)
        if shifts is None:
            continue
        partial = decrypt_with_effective_key(ciphertext, a, shifts)
        letters = [ch for ch in partial if ch != "?"]
        score = chi_squared_vs_english(letter_counts("".join(letters)))
        if best is None or score < best[0]:
            best = (score, a, shifts)
    if best is None:
        return {"method": "failed", "reason": "no consistent (a, m)", "a": None,
                "m": m, "shifts": [None] * m, "recovered": "?" * len(ciphertext),
                "columns_known": 0}
    return _kpa_result("scored-fallback", best[1], m, best[2], ciphertext,
                       note="a chosen by English-likeness, not verified")


def _kpa_result(method, a, m, shifts, ciphertext, note=""):
    return {"method": method, "a": a, "m": m, "shifts": shifts,
            "recovered": decrypt_with_effective_key(ciphertext, a, shifts),
            "columns_known": sum(s is not None for s in shifts), "note": note}
