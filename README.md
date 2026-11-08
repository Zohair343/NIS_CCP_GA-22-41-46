# Custom-Classical-Cipher

Two-stage **Affine → Vigenère** cipher with a full cryptanalysis toolkit (frequency analysis + known-plaintext attack), experiments, and a project report. Built for **CT-486 Network and Information Security**.

> ⚠️ **Educational only.** This cipher is broken by the attacks in this repository and must never be used to protect real information.

## How the cipher works

For letters A–Z = 0…25 and a key (`a`, `b`, `K`):

| Stage | Encrypt | Decrypt |
|---|---|---|
| 1 – Affine | `X = (a·P + b) mod 26` | `P = a⁻¹ (X − b) mod 26` |
| 2 – Vigenère (`K`, ≥ 10 letters) | `C = (X + K[i mod m]) mod 26` | `X = (C − K[i mod m]) mod 26` |

Keys: `a` ∈ {1,3,5,7,9,11,15,17,19,21,23,25}, `b` ∈ 0…25, `K` = at least 10 letters.
Input: lowercase → uppercase; spaces, digits and punctuation are **removed**, so decryption returns the normalised (letters-only) plaintext.

**Key finding:** the two stages collapse into `C = a·P + (b + K)`; `b` is redundant and the effective key space is 12·26^m, not 12·26·26^m.

## Repository structure

| Path | Purpose |
|---|---|
| `main.py` | Command-line menu: encrypt, decrypt, random keys, demo |
| `cipher.py` | Cipher logic: normalisation, validation, Affine, Vigenère, encrypt/decrypt, key generation |
| `attacks.py` | Frequency statistics, frequency-analysis attack, known-plaintext attack |
| `experiments.py` | Runs all experiments, writes CSV/tables/graphs |
| `tests/test_cipher.py` | Unit tests (known vector, 300 round trips, validation, attacks) |
| `report/project_report.md` | Full academic report (24 sections) |
| `report/code_walkthrough.md` | Section-by-section code explanation for presentations |
| `results/experiment_results.csv` | Summary per message length |
| `results/*.csv`, `results/results_tables.md` | Per-trial, known-length, scaling data and formatted tables |
| `results/performance_graphs/` | PNG graphs |
| `requirements.txt` | `matplotlib` (graphs only; the cipher itself uses only the standard library) |

## Installation

Requires Python 3.8+.

```bash
git clone https://github.com/<your-username>/Custom-Classical-Cipher.git
cd Custom-Classical-Cipher
pip install -r requirements.txt
```

## Usage

```bash
python main.py            # interactive menu
python main.py --demo     # encrypt, decrypt and attack a sample message
python experiments.py     # full experiments (~30 s); writes results/
python experiments.py --quick
python -m unittest discover tests -v
```

### Interactive menu (you type your own text and keys)

| Option | What you enter | What happens |
|---|---|---|
| 1 Encrypt | your plaintext, then `a`, `b`, keyword (or press Enter at `a` to get random keys) | shows both stages and the ciphertext |
| 2 Decrypt | ciphertext and the three keys | shows the recovered plaintext |
| 3 Random keys | nothing | prints a random key set |
| 4 Encrypt then attack | your plaintext, keys (Enter = defaults), how many letters the attacker knows | round-trip check, then both attacks scored against your real plaintext |
| 5 Attack without keys | any ciphertext you paste, optionally a known plaintext fragment and its position | frequency analysis (and known-plaintext attack) with recovered `a`, shifts and text |
| 6 Built-in demo | nothing | fixed sample data |
| 7 Measure attacks on my plaintext | your plaintext (typed, pasted, or a `.txt` file path) and trials per length | success rate, letters correct and time of both attacks at lengths 50/100/250/500/1000 and your full text length (random keys each trial); saved to `results/custom_experiment_results.csv` |

For a reliable ciphertext-only attack use 250+ letters (see report Table B).

### Sample session

```
Choose an option: 1
Plaintext: Meet me at the library at nine!
  Note: 7 non-letter character(s) were removed.
  Normalised plaintext: MEETMEATTHELIBRARYATNINE
Affine key a (one of [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]): 5
Affine key b (0-25): 8
Vigenere key (>= 10 letters): ABCDEFGHIJ
  After Stage 1 (Affine)  : QCCZQ CIZZR CLWNP IPYIZ VWVC
  FINAL CIPHERTEXT (Stage 2 Vigenere): QDECU HOGHA CMYQT NVFQI VXXF

Choose an option: 2
Ciphertext: QDECU HOGHA CMYQT NVFQI VXXF
  RECOVERED PLAINTEXT (after undoing Stage 1): MEETMEATTHELIBRARYATNINE
```

Invalid input is rejected with a message, e.g. `ERROR: Vigenere key must have at least 10 letters (got 5).`

## Results (measured; 50 random key sets per length)

| Msg length | Mean ciphertext IC | Frequency attack (ciphertext only): exact / letters correct | Known-plaintext (30 known letters): exact |
|---|---|---|---|
| 50 | 0.0423 | 0 % / 15.3 % | 100 % |
| 100 | 0.0421 | 0 % / 47.9 % | 100 % |
| 250 | 0.0410 | 46 % / 94.4 % | 100 % |
| 500 | 0.0410 | 90 % / 99.2 % | 100 % |
| 1000 | 0.0412 | 100 % / 100 % | 100 % |

Timings, graphs, limitations and interpretation: see `report/project_report.md` and `results/`. Timings are machine-dependent; rerun `experiments.py` for your own values (success rates are reproducible with the fixed seed).

## Limitations

Results come from one English corpus, keys of 10–14 letters, a known fragment at position 0, and 50 trials per length (≈ ±14 points margin). See report §21.

## Suggested GitHub description

> Educational two-stage classical cipher (Affine → Vigenère) in pure Python with frequency-analysis and known-plaintext attack simulations, experiments, and a full report. CT-486 project. Not secure.

Topics: `cryptography` `classical-ciphers` `cryptanalysis` `vigenere` `affine-cipher` `python` `education`

## Uploading to GitHub

1. Create an empty repository named `Custom-Classical-Cipher` on github.com (no README/licence).
2. In the project folder:

```bash
git init
git add .
git commit -m "Initial commit: Affine-Vigenere cipher, attacks, experiments, report"
git branch -M main
git remote add origin https://github.com/<your-username>/Custom-Classical-Cipher.git
git push -u origin main
```

## Licence / academic integrity

Written for a university assignment. If you submit it, understand and be able to explain every part (see `report/code_walkthrough.md`) and add your own name to the report cover page.
