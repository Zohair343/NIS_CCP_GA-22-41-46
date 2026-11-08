# Code Walkthrough (for your presentation / viva)

Read in this order: `cipher.py` → `attacks.py` → `experiments.py` → `main.py`.

## The one idea to remember

```
C_i = a * P_i + (b + K_(i mod m))   (mod 26)
```
Stage 1 (Affine) multiplies and shifts; Stage 2 (Vigenère) adds a repeating key. Because both are "multiply/add mod 26", they merge into one formula. Every attack in `attacks.py` uses this formula.

---

## cipher.py

| Section | What it does | Defend this point |
|---|---|---|
| Constants | `VALID_A` = the 12 numbers coprime with 26; `MIN_KEY_LENGTH = 10` | Why coprime? If gcd(a,26) ≠ 1, two letters encrypt to the same letter, so decryption is ambiguous. |
| `char_to_num / num_to_char` | A↔0 … Z↔25. `num_to_char` applies `% 26` itself | Python's `%` always gives a non-negative result, so `(x - k) % 26` is safe for decryption. |
| `mod_inverse(a)` | Tries x = 1…25 until a·x ≡ 1 (mod 26) | Brute force is fine because the modulus is only 26. |
| `normalize_text` | Uppercases, **drops** everything not A–Z, counts removed characters, rejects empty result | Spaces/punctuation are removed, so decryption returns the *normalised* plaintext. |
| `validate_ciphertext` | Accepts letters and whitespace only | Anything else cannot be a valid ciphertext. |
| `validate_affine_key`, `validate_vigenere_key` | Type/range checks; keyword ≥ 10 letters, letters only | Raises `CipherError` with a readable message. |
| `key_warnings` | Warns on keywords with <5 distinct letters or an internal repeat | Such keys have a shorter *effective* period. |
| `affine_encrypt/decrypt` | `(a·P + b) % 26` and `a⁻¹·(X − b) % 26` | Decryption uses the inverse. |
| `vigenere_encrypt/decrypt` | Adds / subtracts `key[i % m]` | `i % m` repeats the keyword along the message. |
| `encrypt` | normalise → validate → Affine → Vigenère | Order matters. |
| `decrypt` | validate → **undo Vigenère first** → undo Affine | Decrypt in reverse order. |
| `encrypt_verbose` | Same as `encrypt` but returns intermediate results | Used for the demo. |
| `generate_random_key` | Uses `secrets` (OS cryptographic RNG) | Simulation code uses seeded `random` instead so experiments are reproducible. |
| `effective_shifts` | `s_j = (b + K_j) % 26` | The combined key an attacker can recover. |
| `caesar_*` | Single-stage baseline for the comparison | Not part of the proposed cipher. |

## attacks.py

| Function | What it does |
|---|---|
| `letter_counts`, `frequency_percentages`, `frequency_report` | Count letters, convert to %, print the table with the English reference. |
| `index_of_coincidence` | IC = Σ n(n−1)/(N(N−1)). English ≈ 0.067; flat ≈ 0.038. |
| `chi_squared_vs_english` | Σ (observed − expected)²/expected. Smaller = more English-like. |
| `naive_rank_attack` | Maps most frequent ciphertext letter → E, etc. A *control*: shows plain frequency analysis fails. |
| `pooled_ic(text, m)` | Splits into m columns, pools coincidences. Peaks at the true key length (and its multiples). |
| `estimate_key_length` | Smallest m whose pooled IC ≥ 93 % of the best. The first version used a fixed 0.055 threshold and was fooled by half-length guesses (see report §15.3). |
| `_best_shift(counts, a)` | For one column and a guessed multiplier a, tries all 26 shifts s; plaintext letter p shows up as cipher letter `(a·p + s) % 26`; keeps the shift with the lowest χ². |
| `frequency_analysis_attack` | Estimate m → split columns → for each of 12 a's sum the best-shift χ² over columns → choose best a → decrypt. |
| `_shifts_from_fragment` | For a guessed (a, m): `s = C − a·P` at each known position; detects contradictions in a column; counts consistent repeats. |
| `known_plaintext_attack` | Stage A: find (a, m) whose s-sequence repeats (verified). Stage B: fallback using the IC estimate and English scoring (unverified). Then decrypt everything. |
| `decrypt_with_effective_key` | Decrypts with (a, s_0…s_{m−1}); unknown columns show `?`. |
| `accuracy` | Fraction of positions that match the truth. |

**Why the difference trick works.** For positions i and i+m (same key column): `C_{i+m} − C_i = a(P_{i+m} − P_i)`. The key cancels, leaving only *a*. With 12 candidates for *a*, the attacker tests which gives a consistent repeating `s`.

## experiments.py

* `CORPUS`: original English text, normalised to A–Z (2 782 letters).
* `random_key_set`: random a, b and a 10–14-letter keyword (seeded `random.Random(486)`).
* `experiment_lengths`: for each length and trial → encrypt, **assert** the round trip, run naive attack, frequency attack and known-plaintext attack, time them with `time.perf_counter()`.
* `representative_runs`: one run per length with fixed keys (a=7, b=3, `NETWORKSEC`) to show recovered key values.
* `experiment_known_length`: known-plaintext attack with 4…50 known letters.
* `experiment_scaling`: running time for n up to 10⁶, custom vs Caesar.
* `make_graphs`, `build_tables`, `write_csv`: output files in `results/`.

## main.py

Menu: 1 encrypt, 2 decrypt, 3 random keys, 4 encrypt then attack (scored against your real plaintext), 5 attack a pasted ciphertext (optionally with a known plaintext fragment), 6 built-in demo, 7 optional extra that repeats the experiment on your own plaintext (`experiments.run_custom_experiment`), 8 quit. All errors are `CipherError`s caught in the loop and shown without a traceback. `python main.py --demo` runs without prompts. `run_attacks()` prints the frequency table, the frequency attack and (if a known fragment is given) the known-plaintext attack.

## Likely viva questions

1. *Why must a be coprime with 26?* Otherwise the map is not one-to-one.
2. *Why is b redundant?* It is added to every position, exactly like adding the same constant to every key letter.
3. *Why does frequency analysis fail on the whole text but succeed per column?* Vigenère mixes m alphabets (flat), but each column uses one alphabet (English-shaped).
4. *Why did short messages resist?* χ² needs enough letters per column; 5 letters per column is too noisy.
5. *Why can't the attack recover b and K separately?* Only b + K_j influences the ciphertext.
6. *What would make it stronger?* Replace Affine with a keyed substitution and/or add transposition (report §22).
7. *Is it secure?* No. Do not claim that.
