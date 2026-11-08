"""
experiments.py - Runs every experiment and writes results/ (CSV, tables, graphs)

Run:  python experiments.py            (full run, a few minutes at most)
      python experiments.py --quick    (fewer trials, smaller scaling sizes)

All numbers in the report come from this script.  Randomness is seeded
(SEED) so a run is reproducible, but TIMES depend on the machine.

Experiment 1  Attacks vs message length (50..1000 letters), TRIALS random
              key sets per length.
Experiment 2  Known-plaintext attack vs amount of known plaintext (500-letter msg).
Experiment 3  Running-time scaling (1e3..1e6 letters): custom cipher vs Caesar.
"""

import csv
import os
import random
import statistics
import sys
import time

import attacks
import cipher
from cipher import ALPHABET, VALID_A

SEED = 486
LENGTHS = [50, 100, 250, 500, 1000]
KNOWN_LEN = 30                       # known-plaintext letters in Experiment 1
KNOWN_LENGTHS = [4, 8, 10, 12, 14, 16, 20, 30, 50]
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
GRAPH_DIR = os.path.join(RESULTS_DIR, "performance_graphs")

# Original English prose used as test plaintext (normalised to A-Z below).
_RAW_CORPUS = """
When the first telegraph lines were strung across the countryside, people worried that private
messages would travel in plain view of anyone who cared to listen. Merchants wanted to protect
their prices, generals wanted to hide their plans, and ordinary families simply wanted their
letters to remain their own. The answer, as it had been for centuries, was a secret code that only
the sender and the receiver could understand. Some of these codes were remarkably simple. A clerk
might shift every letter of the alphabet by a fixed number of places, so that an ordinary word
became a meaningless jumble. Others were more careful, using a keyword to change the shift from
one letter to the next, which made the secret message look much more mysterious to a curious
observer. For a long time, such methods were thought to be unbreakable, and they were trusted with
important matters of state and commerce.

Eventually patient scholars noticed something remarkable about language itself. In any long piece
of English writing, the letter e appears far more often than the letter z, and certain pairs of
letters travel together again and again. Counting the letters in a secret message could therefore
reveal the shape of the original text, even when the actual letters had been hidden. A student with
a pencil and a good deal of patience could look at the counts, make a careful guess, test it
against the rest of the message, and slowly uncover the secret. The lesson was clear. A good code
must hide not only the letters but also the habits of the language that produced them.

Modern engineers learned this lesson thoroughly. Today the networks that carry our messages, our
payments, and our medical records depend upon algorithms designed by large teams and tested for
years by thousands of independent experts. Nobody relies on a clever trick that happens to look
confusing. Instead the designers assume that an attacker knows exactly how the system works and
that the only real secret is the key. They measure how many guesses an opponent would need, how
much plain text the opponent might already know, and what happens when the same key is used many
times. A scheme that fails any of these tests is quietly retired, no matter how elegant it once
seemed.

Studying the old ciphers is still worthwhile, because every weakness of the past teaches a
principle that remains true. A repeating key leaves a repeating pattern. A small key space can be
searched by a patient machine in a single afternoon. A transformation that is purely linear can be
solved with a few known pairs of letters, much as an equation can be solved from a few known
points. By combining two simple ideas we can build something that appears stronger, and then we can
measure honestly how much stronger it really is. That honest measurement, rather than a confident
claim, is what separates real security engineering from wishful thinking.

On a quiet evening in the library, a student arranged the letters of a short message in neat
columns and began to count. The first column looked random, but the second column showed a
surprising pattern, with one letter appearing again and again. After a while the whole structure
became visible, and the supposedly mysterious message turned into a plain sentence about the
weather. The student smiled, closed the notebook, and walked home through the rain, already
planning a better cipher for the following week.
"""
CORPUS = "".join(ch for ch in _RAW_CORPUS.upper() if "A" <= ch <= "Z")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def random_key_set(rng):
    """Random (a, b, key) with a key of 10-14 letters. Seeded rng => repeatable."""
    a = rng.choice(VALID_A)
    b = rng.randrange(26)
    key = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(10, 14)))
    return a, b, key


def timed(fn, *args, repeat=1):
    """Return (result, mean seconds per call) using time.perf_counter()."""
    start = time.perf_counter()
    result = None
    for _ in range(repeat):
        result = fn(*args)
    return result, (time.perf_counter() - start) / repeat


def caesar_bruteforce(ciphertext):
    """
    Baseline attack on the single-stage Caesar cipher: try all 26 shifts and
    keep the one whose letter counts fit English best.  O(n + 26*26).
    """
    counts = attacks.letter_counts(ciphertext)
    best_shift, best_chi = 0, float("inf")
    for s in range(26):
        rotated = [counts[(p + s) % 26] for p in range(26)]
        chi = attacks.chi_squared_vs_english(rotated)
        if chi < best_chi:
            best_shift, best_chi = s, chi
    return best_shift


def write_csv(name, header, rows):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, name)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return path


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Experiment 1: attacks vs message length
# ---------------------------------------------------------------------------
def experiment_lengths(trials):
    rng = random.Random(SEED)
    per_trial, summary = [], []
    for L in LENGTHS:
        agg = {k: [] for k in ("ic", "dist", "naive", "fa_ok", "fa_acc", "fa_ms", "m_ok",
                               "fa_a_ok", "kp_ok", "kp_acc_all", "kp_acc_unknown",
                               "kp_ms", "kp_a_ok", "enc_us", "dec_us", "kp_verified")}
        for t in range(trials):
            a, b, key = random_key_set(rng)
            off = rng.randrange(len(CORPUS) - L + 1)
            pt = CORPUS[off:off + L]
            ct, enc_t = timed(cipher.encrypt, pt, a, b, key, repeat=50)
            _, dec_t = timed(cipher.decrypt, ct, a, b, key, repeat=50)
            assert cipher.decrypt(ct, a, b, key) == pt     # round-trip sanity check

            agg["ic"].append(attacks.index_of_coincidence(ct))
            agg["dist"].append(attacks.frequency_distance(ct))
            agg["naive"].append(attacks.accuracy(attacks.naive_rank_attack(ct), pt))

            fa, fa_t = timed(attacks.frequency_analysis_attack, ct)
            agg["fa_ok"].append(fa["recovered"] == pt)
            agg["fa_acc"].append(attacks.accuracy(fa["recovered"], pt))
            agg["fa_ms"].append(fa_t * 1000)
            agg["m_ok"].append(fa["key_length"] % len(key) == 0)
            agg["fa_a_ok"].append(fa["a"] == a)

            known = pt[:KNOWN_LEN]
            kp, kp_t = timed(attacks.known_plaintext_attack, ct, known, 0, repeat=5)
            agg["kp_ok"].append(kp["recovered"] == pt)
            agg["kp_acc_all"].append(attacks.accuracy(kp["recovered"], pt))
            unk = len(pt) - len(known)
            agg["kp_acc_unknown"].append(
                attacks.accuracy(kp["recovered"][KNOWN_LEN:], pt[KNOWN_LEN:]) if unk > 0 else float("nan"))
            agg["kp_ms"].append(kp_t * 1000)
            agg["kp_a_ok"].append(kp["a"] == a)
            agg["kp_verified"].append(kp["method"] == "verified-period")
            agg["enc_us"].append(enc_t * 1e6)
            agg["dec_us"].append(dec_t * 1e6)

            per_trial.append([L, t, a, b, key, len(key), fa["key_length"], fa["a"],
                              int(fa["recovered"] == pt), round(agg["fa_acc"][-1], 4),
                              int(kp["recovered"] == pt), round(agg["kp_acc_all"][-1], 4),
                              kp["method"]])

        def mean(k):
            vals = [v for v in agg[k] if v == v]    # drop NaN
            return statistics.mean(vals) if vals else float("nan")

        summary.append({
            "length": L, "ct_len": L, "ic": mean("ic"), "dist": mean("dist"),
            "naive": mean("naive"), "fa_ok": mean("fa_ok"), "fa_acc": mean("fa_acc"),
            "fa_ms": mean("fa_ms"), "m_ok": mean("m_ok"), "fa_a_ok": mean("fa_a_ok"),
            "kp_ok": mean("kp_ok"), "kp_acc_all": mean("kp_acc_all"),
            "kp_acc_unknown": mean("kp_acc_unknown"), "kp_ms": mean("kp_ms"),
            "kp_a_ok": mean("kp_a_ok"), "kp_verified": mean("kp_verified"),
            "enc_us": mean("enc_us"), "dec_us": mean("dec_us"),
        })
    write_csv("per_trial_results.csv",
              ["length", "trial", "true_a", "true_b", "true_key", "true_key_len", "est_key_len",
               "recovered_a", "freq_exact", "freq_accuracy", "kpa_exact", "kpa_accuracy",
               "kpa_method"], per_trial)
    return summary


def representative_runs():
    """One run per length with the fixed demo keys; shows recovered key info."""
    a, b, key = 7, 3, "NETWORKSEC"
    true_shifts = cipher.effective_shifts(a, b, key)
    rows = []
    for L in LENGTHS:
        pt = CORPUS[:L]
        ct = cipher.encrypt(pt, a, b, key)
        fa, fa_t = timed(attacks.frequency_analysis_attack, ct)
        kp, kp_t = timed(attacks.known_plaintext_attack, ct, pt[:KNOWN_LEN], 0, repeat=5)
        rows.append({
            "length": L, "est_m": fa["key_length"], "a": fa["a"], "shifts": fa["shifts"],
            "fa_acc": attacks.accuracy(fa["recovered"], pt), "fa_exact": fa["recovered"] == pt,
            "fa_ms": fa_t * 1000, "kp_m": kp["m"], "kp_a": kp["a"], "kp_shifts": kp["shifts"],
            "kp_acc": attacks.accuracy(kp["recovered"], pt), "kp_exact": kp["recovered"] == pt,
            "kp_ms": kp_t * 1000, "true_shifts": true_shifts, "wrong_cols":
                sum(1 for x, y in zip(fa["shifts"], true_shifts) if x != y) if len(fa["shifts"]) == len(true_shifts) else None,
        })
    return rows


# ---------------------------------------------------------------------------
# Experiment 2: KPA vs amount of known plaintext
# ---------------------------------------------------------------------------
def experiment_known_length(trials, L=500):
    rng = random.Random(SEED + 1)
    rows = []
    for k in KNOWN_LENGTHS:
        ok, acc_all, acc_unk, verified, a_ok, ms, cols = [], [], [], [], [], [], []
        for _ in range(trials):
            a, b, key = random_key_set(rng)
            off = rng.randrange(len(CORPUS) - L + 1)
            pt = CORPUS[off:off + L]
            ct = cipher.encrypt(pt, a, b, key)
            kp, dt = timed(attacks.known_plaintext_attack, ct, pt[:k], 0, repeat=5)
            ok.append(kp["recovered"] == pt)
            acc_all.append(attacks.accuracy(kp["recovered"], pt))
            acc_unk.append(attacks.accuracy(kp["recovered"][k:], pt[k:]))
            verified.append(kp["method"] == "verified-period")
            a_ok.append(kp["a"] == a)
            ms.append(dt * 1000)
            cols.append(kp.get("columns_known", 0) / len(key))
        rows.append({"known": k, "ok": statistics.mean(ok), "acc": statistics.mean(acc_all),
                     "acc_unknown": statistics.mean(acc_unk), "verified": statistics.mean(verified),
                     "a_ok": statistics.mean(a_ok), "cols": statistics.mean(cols),
                     "ms": statistics.mean(ms)})
    return rows


# ---------------------------------------------------------------------------
# Experiment 3: running-time scaling
# ---------------------------------------------------------------------------
def experiment_scaling(sizes):
    a, b, key = 7, 3, "NETWORKSEC"
    rows = []
    for n in sizes:
        pt = (CORPUS * (n // len(CORPUS) + 1))[:n]
        reps = 20 if n <= 10_000 else (5 if n <= 100_000 else 2)
        ct, t_enc = timed(cipher.encrypt, pt, a, b, key, repeat=reps)
        _, t_dec = timed(cipher.decrypt, ct, a, b, key, repeat=reps)
        cct, t_cenc = timed(cipher.caesar_encrypt, pt, 5, repeat=reps)
        _, t_cdec = timed(cipher.caesar_decrypt, cct, 5, repeat=reps)
        _, t_fa = timed(attacks.frequency_analysis_attack, ct, repeat=reps)
        _, t_kp = timed(attacks.known_plaintext_attack, ct, pt[:KNOWN_LEN], 0, repeat=reps)
        _, t_cb = timed(caesar_bruteforce, cct, repeat=reps)
        rows.append({"n": n, "enc": t_enc, "dec": t_dec, "cenc": t_cenc, "cdec": t_cdec,
                     "fa": t_fa, "kp": t_kp, "cbf": t_cb})
    return rows


# ---------------------------------------------------------------------------
# Custom experiment: the same measurements, but on the USER'S OWN plaintext
# ---------------------------------------------------------------------------
def run_custom_experiment(text, lengths=None, trials=20, known_len=30, seed=None):
    """
    Measure both attacks on prefixes/windows of `text` (any plaintext the user
    supplies).  For every length L <= len(text) (default: 50, 100, 250, 500,
    1000 and the full text length) it runs `trials` trials, each with a fresh
    random key set (a, b, 10-14 letter keyword) and a random window of the
    text.  Known-plaintext attack: the first min(known_len, L//2) letters of
    the window are known.  Returns a list of result rows (dicts).

    Note: when L equals the text length there is only one possible window, so
    only the keys vary between trials.
    """
    text, _ = cipher.normalize_text(text)
    n = len(text)
    if lengths is None:
        lengths = [L for L in LENGTHS if L <= n]
        if n not in lengths:
            lengths.append(n)
    lengths = sorted(set(L for L in lengths if 2 <= L <= n))
    rng = random.Random(seed)
    rows = []
    for L in lengths:
        k = min(known_len, max(1, L // 2))
        acc = {key: [] for key in ("ic", "fa_ok", "fa_acc", "fa_ms", "a_ok",
                                   "kp_ok", "kp_acc", "kp_ms")}
        for _ in range(trials):
            a, b, key = random_key_set(rng)
            off = rng.randrange(n - L + 1)
            pt = text[off:off + L]
            ct = cipher.encrypt(pt, a, b, key)
            acc["ic"].append(attacks.index_of_coincidence(ct))
            fa, t = timed(attacks.frequency_analysis_attack, ct)
            acc["fa_ok"].append(fa["recovered"] == pt)
            acc["fa_acc"].append(attacks.accuracy(fa["recovered"], pt))
            acc["fa_ms"].append(t * 1000)
            acc["a_ok"].append(fa["a"] == a)
            kp, t = timed(attacks.known_plaintext_attack, ct, pt[:k], 0, repeat=3)
            acc["kp_ok"].append(kp["recovered"] == pt)
            acc["kp_acc"].append(attacks.accuracy(kp["recovered"], pt))
            acc["kp_ms"].append(t * 1000)
        row = {"length": L, "trials": trials, "known": k}
        row.update({key: statistics.mean(v) for key, v in acc.items()})
        rows.append(row)
    return rows


def custom_experiment_table(rows):
    """Markdown table for run_custom_experiment() results."""
    return md_table(
        ["Length", "Trials", "Mean IC", "Freq: exact", "Freq: letters correct", "Freq: a found",
         "Freq: time (ms)", "Known letters", "KPA: exact", "KPA: letters correct", "KPA: time (ms)"],
        [[r["length"], r["trials"], f"{r['ic']:.4f}", f"{r['fa_ok']:.0%}", f"{r['fa_acc']:.1%}",
          f"{r['a_ok']:.0%}", f"{r['fa_ms']:.2f}", r["known"], f"{r['kp_ok']:.0%}",
          f"{r['kp_acc']:.1%}", f"{r['kp_ms']:.3f}"] for r in rows])


# ---------------------------------------------------------------------------
# Graphs
# ---------------------------------------------------------------------------
BLUE, ORANGE, GREEN, GRAY = "#0072B2", "#D55E00", "#009E73", "#6b6b6b"   # Okabe-Ito


def _style(ax, xlabel, ylabel, title):
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title, loc="left", fontsize=11)
    ax.grid(True, color="#e5e5e5", linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)


def make_graphs(summary, known_rows, scaling):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    os.makedirs(GRAPH_DIR, exist_ok=True)
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": "#888"})

    def save(fig, name):
        fig.tight_layout()
        fig.savefig(os.path.join(GRAPH_DIR, name), dpi=150)
        plt.close(fig)

    xs = [r["length"] for r in summary]

    # 1. Letter frequencies: English vs plaintext vs ciphertext
    pt = CORPUS[:1000]
    ct = cipher.encrypt(pt, 7, 3, "NETWORKSEC")
    fig, axes = plt.subplots(3, 1, figsize=(8, 6.5), sharex=True, sharey=True)
    series = [("Typical English (reference)", attacks.ENGLISH_FREQ, GRAY),
              (f"Plaintext sample (1000 letters, IC={attacks.index_of_coincidence(pt):.3f})",
               attacks.frequency_percentages(pt), BLUE),
              (f"Ciphertext (1000 letters, IC={attacks.index_of_coincidence(ct):.3f})",
               attacks.frequency_percentages(ct), ORANGE)]
    for ax, (title, vals, color) in zip(axes, series):
        ax.bar(list(ALPHABET), vals, color=color, width=0.7)
        _style(ax, "", "Frequency (%)", title)
    axes[-1].set_xlabel("Letter")
    save(fig, "frequency_comparison.png")

    # 2. Attack success vs length
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    ax1.plot(xs, [100 * r["fa_ok"] for r in summary], "-o", color=BLUE, label="Frequency analysis (ciphertext only)")
    ax1.plot(xs, [100 * r["kp_ok"] for r in summary], "-s", color=ORANGE, label=f"Known-plaintext ({KNOWN_LEN} known letters)")
    _style(ax1, "Message length (letters)", "Exact recovery rate (%)", "Exact plaintext recovery")
    ax1.set_ylim(-5, 105)
    ax1.legend(frameon=False, fontsize=8, loc="center right")
    ax2.plot(xs, [100 * r["fa_acc"] for r in summary], "-o", color=BLUE, label="Frequency analysis")
    ax2.plot(xs, [100 * r["kp_acc_all"] for r in summary], "-s", color=ORANGE, label="Known-plaintext")
    ax2.plot(xs, [100 * r["naive"] for r in summary], "-^", color=GRAY, label="Naive single-alphabet attack")
    _style(ax2, "Message length (letters)", "Mean letters correct (%)", "Mean recovery accuracy")
    ax2.set_ylim(-5, 105)
    ax2.legend(frameon=False, fontsize=8, loc="center right")
    save(fig, "attack_success_vs_length.png")

    # 3. Attack time vs length
    fig, ax = plt.subplots(figsize=(6.5, 4))
    ax.plot(xs, [r["fa_ms"] for r in summary], "-o", color=BLUE, label="Frequency analysis")
    ax.plot(xs, [r["kp_ms"] for r in summary], "-s", color=ORANGE, label="Known-plaintext")
    _style(ax, "Message length (letters)", "Mean attack time (ms)", "Attack time vs message length")
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False)
    save(fig, "attack_time_vs_length.png")

    # 4. Scaling: encryption/decryption
    ns = [r["n"] for r in scaling]
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    ax.loglog(ns, [r["enc"] * 1000 for r in scaling], "-o", color=BLUE, label="Custom encrypt (2 stages)")
    ax.loglog(ns, [r["dec"] * 1000 for r in scaling], "--o", color=GREEN, label="Custom decrypt (2 stages)")
    ax.loglog(ns, [r["cenc"] * 1000 for r in scaling], "-s", color=ORANGE, label="Caesar encrypt (1 stage)")
    _style(ax, "Message length n (letters)", "Mean time (ms)", "Encryption/decryption time (log-log)")
    ax.legend(frameon=False, fontsize=8)
    save(fig, "scaling_encryption.png")

    # 5. Scaling: attacks
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    ax.loglog(ns, [r["fa"] * 1000 for r in scaling], "-o", color=BLUE, label="Custom: frequency analysis")
    ax.loglog(ns, [r["kp"] * 1000 for r in scaling], "-s", color=ORANGE, label=f"Custom: known-plaintext ({KNOWN_LEN} known)")
    ax.loglog(ns, [r["cbf"] * 1000 for r in scaling], "-^", color=GRAY, label="Caesar: brute force")
    _style(ax, "Ciphertext length n (letters)", "Mean time (ms)", "Attack time (log-log)")
    ax.legend(frameon=False, fontsize=8)
    save(fig, "scaling_attacks.png")

    # 6. KPA vs known length
    fig, ax = plt.subplots(figsize=(6.5, 4))
    kx = [r["known"] for r in known_rows]
    ax.plot(kx, [100 * r["ok"] for r in known_rows], "-o", color=ORANGE, label="Exact recovery rate")
    ax.plot(kx, [100 * r["acc"] for r in known_rows], "-s", color=BLUE, label="Mean letters correct")
    _style(ax, "Known plaintext length (letters)", "%", "Known-plaintext attack vs amount known (500-letter message)")
    ax.set_ylim(-5, 105)
    ax.legend(frameon=False)
    save(fig, "kpa_vs_known_length.png")


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def build_tables(summary, reps, known_rows, scaling, trials):
    t = []
    t.append(f"### Table A - Summary per message length ({trials} random key sets per length)\n")
    t.append(md_table(
        ["Msg length", "Ciphertext length", "Mean IC", "L1 dist. from English (pct-pts)",
         "Naive single-alphabet attack: letters correct"],
        [[r["length"], r["ct_len"], f"{r['ic']:.4f}", f"{r['dist']:.1f}", f"{r['naive']:.1%}"] for r in summary]))
    t.append(f"\n### Table B - Frequency-analysis attack (ciphertext only, {trials} trials per length)\n")
    t.append(md_table(
        ["Msg length", "Exact recovery", "Mean letters correct", "Key length found (true or multiple)",
         "Multiplier a found", "Mean time (ms)"],
        [[r["length"], f"{r['fa_ok']:.0%}", f"{r['fa_acc']:.1%}", f"{r['m_ok']:.0%}",
          f"{r['fa_a_ok']:.0%}", f"{r['fa_ms']:.2f}"] for r in summary]))
    t.append(f"\n### Table C - Known-plaintext attack ({KNOWN_LEN} known letters at the start, {trials} trials per length)\n")
    t.append(md_table(
        ["Msg length", "Exact recovery", "Mean letters correct (all)", "Mean letters correct (unknown part)",
         "a found", "Verified period", "Mean time (ms)"],
        [[r["length"], f"{r['kp_ok']:.0%}", f"{r['kp_acc_all']:.1%}",
          "n/a" if r["kp_acc_unknown"] != r["kp_acc_unknown"] else f"{r['kp_acc_unknown']:.1%}",
          f"{r['kp_a_ok']:.0%}", f"{r['kp_verified']:.0%}", f"{r['kp_ms']:.3f}"] for r in summary]))
    t.append("\n### Table D - Representative run (a=7, b=3, key NETWORKSEC; true effective shifts "
             f"s_j = b+K_j = {reps[0]['true_shifts']})\n")
    t.append(md_table(
        ["Msg length", "Freq: est. key len", "Freq: a", "Freq: letters correct", "Freq: exact",
         "Freq: wrong shift columns", "Freq: time (ms)", "KPA: a", "KPA: m", "KPA: letters correct",
         "KPA: exact", "KPA: time (ms)"],
        [[r["length"], r["est_m"], r["a"], f"{r['fa_acc']:.1%}", r["fa_exact"], r["wrong_cols"],
          f"{r['fa_ms']:.2f}", r["kp_a"], r["kp_m"], f"{r['kp_acc']:.1%}", r["kp_exact"],
          f"{r['kp_ms']:.3f}"] for r in reps]))
    t.append("\nRecovered effective shifts in the representative run:\n")
    for r in reps:
        t.append(f"- n={r['length']}: frequency analysis -> {r['shifts']}; known-plaintext -> {r['kp_shifts']}")
    t.append(f"\n### Table E - Known-plaintext attack vs amount of known text (500-letter messages, {trials} trials)\n")
    t.append(md_table(
        ["Known letters", "Exact recovery", "Mean letters correct", "Unknown part correct", "a found",
         "Verified period", "Key columns recovered", "Mean time (ms)"],
        [[r["known"], f"{r['ok']:.0%}", f"{r['acc']:.1%}", f"{r['acc_unknown']:.1%}", f"{r['a_ok']:.0%}",
          f"{r['verified']:.0%}", f"{r['cols']:.0%}", f"{r['ms']:.3f}"] for r in known_rows]))
    t.append("\n### Table F - Mean encryption/decryption time vs length (small messages, microseconds)\n")
    t.append(md_table(["Msg length", "Encrypt (us)", "Decrypt (us)"],
                      [[r["length"], f"{r['enc_us']:.1f}", f"{r['dec_us']:.1f}"] for r in summary]))
    t.append("\n### Table G - Scaling (milliseconds, mean of repeated runs)\n")
    t.append(md_table(
        ["n", "Custom enc", "Custom dec", "Caesar enc", "Caesar dec", "Freq. analysis", "Known-plaintext", "Caesar brute force"],
        [[f"{r['n']:,}"] + [f"{r[k] * 1000:.3f}" for k in ("enc", "dec", "cenc", "cdec", "fa", "kp", "cbf")]
         for r in scaling]))
    ratios = [r["enc"] / r["cenc"] for r in scaling]
    t.append(f"\nCustom/Caesar encryption time ratio per size: {[round(x, 2) for x in ratios]}")
    return "\n".join(t)


def main():
    quick = "--quick" in sys.argv
    trials = 10 if quick else 50
    sizes = [1_000, 10_000, 100_000] if quick else [1_000, 10_000, 100_000, 1_000_000]
    print(f"Corpus: {len(CORPUS)} letters. Trials per length: {trials}. Seed: {SEED}")

    print("Experiment 1: attacks vs message length ...")
    summary = experiment_lengths(trials)
    reps = representative_runs()
    print("Experiment 2: known-plaintext vs known length ...")
    known_rows = experiment_known_length(trials)
    print("Experiment 3: scaling ...")
    scaling = experiment_scaling(sizes)

    write_csv("experiment_results.csv",
              ["message_length", "ciphertext_length", "mean_IC", "L1_dist_from_english", "naive_attack_accuracy",
               "freq_exact_rate", "freq_mean_accuracy", "freq_keylen_ok_rate", "freq_a_ok_rate", "freq_mean_ms",
               "kpa_exact_rate", "kpa_mean_accuracy_all", "kpa_mean_accuracy_unknown", "kpa_a_ok_rate",
               "kpa_verified_rate", "kpa_mean_ms", "encrypt_us", "decrypt_us"],
              [[r["length"], r["ct_len"], round(r["ic"], 5), round(r["dist"], 3), round(r["naive"], 4),
                round(r["fa_ok"], 3), round(r["fa_acc"], 4), round(r["m_ok"], 3), round(r["fa_a_ok"], 3),
                round(r["fa_ms"], 4), round(r["kp_ok"], 3), round(r["kp_acc_all"], 4),
                round(r["kp_acc_unknown"], 4) if r["kp_acc_unknown"] == r["kp_acc_unknown"] else "",
                round(r["kp_a_ok"], 3), round(r["kp_verified"], 3), round(r["kp_ms"], 5),
                round(r["enc_us"], 2), round(r["dec_us"], 2)] for r in summary])
    write_csv("kpa_known_length_results.csv",
              ["known_letters", "exact_rate", "mean_accuracy", "unknown_part_accuracy", "a_ok_rate",
               "verified_rate", "columns_recovered", "mean_ms"],
              [[r["known"], round(r["ok"], 3), round(r["acc"], 4), round(r["acc_unknown"], 4),
                round(r["a_ok"], 3), round(r["verified"], 3), round(r["cols"], 3), round(r["ms"], 5)]
               for r in known_rows])
    write_csv("scaling_results.csv",
              ["n", "custom_encrypt_s", "custom_decrypt_s", "caesar_encrypt_s", "caesar_decrypt_s",
               "freq_analysis_s", "known_plaintext_s", "caesar_bruteforce_s"],
              [[r["n"]] + [f"{r[k]:.6f}" for k in ("enc", "dec", "cenc", "cdec", "fa", "kp", "cbf")]
               for r in scaling])

    tables = build_tables(summary, reps, known_rows, scaling, trials)
    with open(os.path.join(RESULTS_DIR, "results_tables.md"), "w") as f:
        f.write(tables + "\n")
    print(tables)

    try:
        make_graphs(summary, known_rows, scaling)
        print(f"\nGraphs written to {GRAPH_DIR}")
    except ImportError:
        print("\nmatplotlib not installed: graphs skipped (pip install -r requirements.txt)")
    print(f"CSV files and results_tables.md written to {RESULTS_DIR}")


if __name__ == "__main__":
    main()
