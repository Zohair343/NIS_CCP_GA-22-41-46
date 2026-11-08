"""
main.py - Command-line interface for the Affine -> Vigenere custom cipher.

Run:  python main.py            (interactive menu: you type your own text and keys)
      python main.py --demo     (non-interactive demonstration with fixed sample data)
"""

import sys
import time

import attacks
import cipher
from cipher import CipherError

BANNER = """
=====================================================
  CT-486  Custom Classical Cipher: Affine -> Vigenere
  Educational only - NOT secure for real data
=====================================================
Input rules: lowercase is converted to UPPERCASE; spaces, digits and
punctuation are REMOVED before encryption (only A-Z is encrypted).
Decryption therefore returns the normalised text (letters only).
"""

DEFAULT_KEYS = (7, 3, "NETWORKSEC")
SAMPLE_TEXT = ("Classical ciphers are easy to study, and they teach us "
               "why modern cryptography needs far more than a clever keyword.")


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------
def ask_keys(allow_random=True, default=None):
    """
    Prompt for the key parts a, b, K and validate them.
    Leave 'a' empty to use the default keys (if given) or a random key set.
    Raises CipherError on invalid input.
    """
    hint = "Enter = " + ("default keys" if default else "generate random keys")
    a = int(input(f"Affine key a, one of {cipher.VALID_A}  [{hint}]: ").strip())
    if a == "":
        if default:
            a, b, key = default
        elif allow_random:
            a, b, key = cipher.generate_random_key(12)
            print(f"  Random keys generated -> a={a}, b={b}, Vigenere key={key}")
            print("  (write them down: you need them to decrypt)")
        else:
            raise CipherError("Key 'a' is required.")
    else:
        b = (int(input("Affine key b (0-25): ").strip()) + a) % 26
        key = input(f"Vigenere key (>= {cipher.MIN_KEY_LENGTH} letters): ").strip()
    a, b = cipher.validate_affine_key(a, b)
    key = cipher.validate_vigenere_key(key)
    for w in cipher.key_warnings(key):
        print("  Warning:", w)
    return a, b, key


def ask_known_plaintext(ciphertext):
    """Ask for known plaintext + its starting position; return (text, start)."""
    known = input("Known plaintext fragment (letters only; Enter = skip this attack): ")
    if not known.strip():
        return None, 0
    known, _ = cipher.normalize_text(known)
    start_txt = input("Position in the ciphertext where it starts (0 = beginning) [0]: ").strip()
    start = int(start_txt) if start_txt else 0
    if start < 0 or start + len(known) > len(ciphertext):
        raise CipherError(
            f"The fragment (length {len(known)}) does not fit at position {start} "
            f"in a ciphertext of length {len(ciphertext)}.")
    return known, start


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------
def do_encrypt():
    plaintext = input("Plaintext: ")
    normalized, removed = cipher.normalize_text(plaintext)
    if removed:
        print(f"  Note: {removed} non-letter character(s) were removed.")
    print(f"  Normalised plaintext: {normalized}")
    a, b, key = ask_keys()
    info = cipher.encrypt_verbose(plaintext, a, b, key)
    print(f"  After Stage 1 (Affine)  : {cipher.format_blocks(info['after_affine'])}")
    print(f"  FINAL CIPHERTEXT (Stage 2 Vigenere): {cipher.format_blocks(info['ciphertext'])}")


def do_decrypt():
    ciphertext = input("Ciphertext: ")
    cleaned = cipher.validate_ciphertext(ciphertext)
    a, b, key = ask_keys(allow_random=False)
    stage1 = cipher.vigenere_decrypt(cleaned, key)
    print(f"  After undoing Stage 2 (Vigenere): {cipher.format_blocks(stage1)}")
    print(f"  RECOVERED PLAINTEXT (after undoing Stage 1): "
          f"{cipher.decrypt(cleaned, a, b, key)}")


def do_generate_keys():
    a, b, key = cipher.generate_random_key(12)
    print(f"  Random key set -> a={a}, b={b}, Vigenere key={key}")


def run_attacks(ciphertext, known=None, start=0, truth=None):
    """
    Run both attacks on a ciphertext and print the results.
    `truth` (the real plaintext) is optional; when given, accuracy is reported.
    """
    n = len(ciphertext)
    print(attacks.frequency_report(ciphertext, "Ciphertext"))
    if n < 4:
        print("\n  Ciphertext too short to attack.")
        return
    if n < 2 * cipher.MIN_KEY_LENGTH:
        print(f"\n  *** The message has only {n} letters, shorter than twice the minimum key "
              f"length ({cipher.MIN_KEY_LENGTH}). ***\n"
              "  Every letter is shifted by a DIFFERENT key letter, so the text can be read as\n"
              "  almost any word of the same length. The 'recovered text' below is only the\n"
              "  attack's best statistical guess and is NOT a real recovery. This is not a bug:\n"
              "  nothing in the ciphertext can reveal such a short message without the key.")
    elif n < 250:
        print("\n  Note: with fewer than ~250 letters the frequency attack is unreliable "
              "(see report, Table B).")

    t0 = time.perf_counter()
    res = attacks.frequency_analysis_attack(ciphertext)
    dt = time.perf_counter() - t0
    print(f"\n[Frequency analysis, ciphertext only]  time={dt * 1000:.1f} ms")
    print(f"  Estimated key length : {res['key_length']}")
    print(f"  Recovered multiplier a: {res['a']}")
    print(f"  Recovered shifts (b + key letter): {res['shifts']}")
    print(f"  Recovered text (first 120 letters): {res['recovered'][:120]}")
    if truth is not None:
        print(f"  Accuracy vs real plaintext: {attacks.accuracy(res['recovered'], truth):.1%}")
    else:
        print("  (Check by eye: is the recovered text readable English?)")

    if known:
        t0 = time.perf_counter()
        kp = attacks.known_plaintext_attack(ciphertext, known, start)
        dt = time.perf_counter() - t0
        print(f"\n[Known-plaintext attack, {len(known)} known letters at position {start}]  "
              f"time={dt * 1000:.2f} ms")
        print(f"  Method: {kp['method']}  ({kp.get('note', kp.get('reason', ''))})")
        print(f"  Recovered a={kp['a']}, key length m={kp['m']}")
        print(f"  Recovered shifts (b + key letter): {kp['shifts']}")
        print(f"  Key columns recovered: {kp['columns_known']} of {kp['m']}")
        if kp["method"] == "failed" or kp["columns_known"] < (kp["m"] or 0):
            print("  ('?' = a letter this attack cannot decrypt: each known plaintext letter reveals "
                  "only one key column, so about as many known letters as the key length are needed.)")
        print(f"  Recovered text (first 120 letters; ? = unknown): {kp['recovered'][:120]}")
        if truth is not None:
            print(f"  Accuracy vs real plaintext: {attacks.accuracy(kp['recovered'], truth):.1%}")


def do_attack_ciphertext():
    """Attack a ciphertext the user pastes in (keys unknown)."""
    ciphertext = cipher.validate_ciphertext(input("Ciphertext to attack: "))
    known, start = ask_known_plaintext(ciphertext)
    print()
    run_attacks(ciphertext, known, start)


def do_demo_own():
    """Encrypt the user's own text, then attack the result and score the attacks."""
    text = input("Your plaintext (Enter = built-in sample): ").strip() or SAMPLE_TEXT
    normalized, removed = cipher.normalize_text(text)
    if removed:
        print(f"  Note: {removed} non-letter character(s) were removed.")
    a, b, key = ask_keys(default=DEFAULT_KEYS)
    info = cipher.encrypt_verbose(text, a, b, key)
    print(f"\nNormalised : {info['normalized']}")
    print(f"After Affine: {cipher.format_blocks(info['after_affine'])}")
    print(f"Ciphertext : {cipher.format_blocks(info['ciphertext'])}")
    back = cipher.decrypt(info["ciphertext"], a, b, key)
    print(f"Decrypted  : {back}")
    print(f"Round trip OK: {back == normalized}")

    default_known = min(30, max(1, len(normalized) // 2))
    k_txt = input(f"\nHow many letters at the start should the attacker know? "
                  f"[{default_known}, 0 = none]: ").strip()
    k = int(k_txt) if k_txt else default_known
    k = max(0, min(k, len(normalized)))
    print("\n--- Attacks (the attacker does not know the keys) ---")
    run_attacks(info["ciphertext"], normalized[:k] if k else None, 0, truth=normalized)
    print("\nTrue effective shifts (b + key letter):", cipher.effective_shifts(a, b, key))


def do_custom_experiment():
    """Success rate and running time of both attacks on the USER'S OWN plaintext."""
    import experiments
    import os

    raw = input("Your plaintext (type/paste it, or give the path of a .txt file): ").strip()
    if os.path.isfile(raw):
        with open(raw, encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        print("  (read the text from the file)")
    text, removed = cipher.normalize_text(raw)
    n = len(text)
    print(f"  {n} usable letters ({removed} non-letter characters removed).")
    if n < 50:
        print("  Warning: very short text; results will be only for this one length.")
    t_txt = input("Trials per length (random keys each time) [20]: ").strip()
    trials = int(t_txt) if t_txt else 20
    if not 1 <= trials <= 500:
        raise CipherError("Trials must be between 1 and 500.")
    print("  Running ... (random 10-14 letter keys; known-plaintext attack knows the "
          "first 30 letters or half the message, whichever is smaller)")
    rows = experiments.run_custom_experiment(text, trials=trials)
    print()
    print(experiments.custom_experiment_table(rows))
    path = os.path.join(experiments.RESULTS_DIR, "custom_experiment_results.csv")
    experiments.write_csv(
        "custom_experiment_results.csv",
        ["length", "trials", "mean_IC", "freq_exact_rate", "freq_mean_accuracy", "freq_a_found_rate",
         "freq_mean_ms", "known_letters", "kpa_exact_rate", "kpa_mean_accuracy", "kpa_mean_ms"],
        [[r["length"], r["trials"], round(r["ic"], 5), round(r["fa_ok"], 3), round(r["fa_acc"], 4),
          round(r["a_ok"], 3), round(r["fa_ms"], 4), r["known"], round(r["kp_ok"], 3),
          round(r["kp_acc"], 4), round(r["kp_ms"], 5)] for r in rows])
    print(f"\nSaved to {path}")
    if rows[-1]["length"] == n:
        print(f"Note: the row for length {n} uses your whole text, so only the keys vary there.")
    print("Reading the table: 'exact' = share of trials where the attack recovered the plaintext "
          "perfectly; times are per attack on this machine.")


def do_demo():
    """Non-interactive demo with fixed sample data (used by --demo)."""
    import experiments  # local import: pulls in only the corpus

    a, b, key = DEFAULT_KEYS
    print("--- Encryption / decryption demo ---")
    info = cipher.encrypt_verbose(SAMPLE_TEXT, a, b, key)
    print("Plaintext      :", SAMPLE_TEXT)
    print("Normalised     :", info["normalized"])
    print(f"Keys           : a={a}, b={b}, Vigenere key={key}")
    print("After Affine   :", cipher.format_blocks(info["after_affine"]))
    print("Ciphertext     :", cipher.format_blocks(info["ciphertext"]))
    recovered = cipher.decrypt(info["ciphertext"], a, b, key)
    print("Decrypted      :", recovered)
    print("Round trip OK  :", recovered == info["normalized"])

    print("\n--- Attacks on a 500-letter ciphertext (keys unknown to attacker) ---")
    text = experiments.CORPUS[:500]
    ct = cipher.encrypt(text, a, b, key)
    run_attacks(ct, text[:30], 0, truth=text)
    print("\nTrue effective shifts:", cipher.effective_shifts(a, b, key))


MENU = """
1) Encrypt my own message
2) Decrypt a ciphertext (I know the keys)
3) Generate a random key set
4) Encrypt my own message, then attack it (demo)
5) Attack a ciphertext without the keys
6) Run the built-in demo (fixed sample data)
7) Measure attack success rate & time on MY plaintext
8) Quit
"""


def main():
    if "--demo" in sys.argv:
        do_demo()
        return
    print(BANNER)
    actions = {"1": do_encrypt, "2": do_decrypt, "3": do_generate_keys,
               "4": do_demo_own, "5": do_attack_ciphertext, "6": do_demo,
               "7": do_custom_experiment}
    while True:
        print(MENU)
        try:
            choice = input("Choose an option: ").strip()
            if choice == "8":
                print("Goodbye.")
                return
            if choice not in actions:
                print("  Invalid option, please enter 1-8.")
                continue
            actions[choice]()
        except CipherError as err:
            print(f"  ERROR: {err}")
        except ValueError as err:     # e.g. non-numeric position / count
            print(f"  ERROR: invalid number ({err})")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return


if __name__ == "__main__":
    main()
