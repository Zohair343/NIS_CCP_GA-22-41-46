### Table A - Summary per message length (50 random key sets per length)

| Msg length | Ciphertext length | Mean IC | L1 dist. from English (pct-pts) | Naive single-alphabet attack: letters correct |
|---|---|---|---|---|
| 50 | 50 | 0.0423 | 87.0 | 7.2% |
| 100 | 100 | 0.0421 | 81.6 | 7.2% |
| 250 | 250 | 0.0410 | 75.7 | 6.7% |
| 500 | 500 | 0.0410 | 72.9 | 6.1% |
| 1000 | 1000 | 0.0412 | 73.3 | 6.3% |

### Table B - Frequency-analysis attack (ciphertext only, 50 trials per length)

| Msg length | Exact recovery | Mean letters correct | Key length found (true or multiple) | Multiplier a found | Mean time (ms) |
|---|---|---|---|---|---|
| 50 | 0% | 8.6% | 12% | 18% | 10.85 |
| 100 | 0% | 28.9% | 38% | 42% | 15.02 |
| 250 | 34% | 77.7% | 76% | 90% | 21.78 |
| 500 | 68% | 83.3% | 74% | 96% | 18.48 |
| 1000 | 68% | 82.4% | 68% | 100% | 23.59 |

### Table C - Known-plaintext attack (30 known letters at the start, 50 trials per length)

| Msg length | Exact recovery | Mean letters correct (all) | Mean letters correct (unknown part) | a found | Verified period | Mean time (ms) |
|---|---|---|---|---|---|---|
| 50 | 100% | 100.0% | 100.0% | 100% | 100% | 0.321 |
| 100 | 100% | 100.0% | 100.0% | 100% | 100% | 0.329 |
| 250 | 100% | 100.0% | 100.0% | 100% | 100% | 0.463 |
| 500 | 100% | 100.0% | 100.0% | 100% | 100% | 0.431 |
| 1000 | 100% | 100.0% | 100.0% | 100% | 100% | 0.659 |

### Table D - Representative run (a=7, b=3, key NETWORKSEC; true effective shifts s_j = b+K_j = [16, 7, 22, 25, 17, 20, 13, 21, 7, 5])

| Msg length | Freq: est. key len | Freq: a | Freq: letters correct | Freq: exact | Freq: wrong shift columns | Freq: time (ms) | KPA: a | KPA: m | KPA: letters correct | KPA: exact | KPA: time (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 50 | 10 | 7 | 50.0% | False | 5 | 13.75 | 7 | 10 | 100.0% | True | 0.207 |
| 100 | 10 | 7 | 90.0% | False | 1 | 14.00 | 7 | 10 | 100.0% | True | 0.221 |
| 250 | 10 | 7 | 100.0% | True | 0 | 14.62 | 7 | 10 | 100.0% | True | 0.255 |
| 500 | 10 | 7 | 100.0% | True | 0 | 14.54 | 7 | 10 | 100.0% | True | 0.285 |
| 1000 | 10 | 7 | 100.0% | True | 0 | 15.47 | 7 | 10 | 100.0% | True | 0.369 |

Recovered effective shifts in the representative run:

- n=50: frequency analysis -> [10, 7, 22, 12, 17, 13, 9, 10, 7, 5]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]
- n=100: frequency analysis -> [16, 7, 22, 25, 17, 20, 15, 21, 7, 5]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]
- n=250: frequency analysis -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]
- n=500: frequency analysis -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]
- n=1000: frequency analysis -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]

### Table E - Known-plaintext attack vs amount of known text (500-letter messages, 50 trials)

| Known letters | Exact recovery | Mean letters correct | Unknown part correct | a found | Verified period | Key columns recovered | Mean time (ms) |
|---|---|---|---|---|---|---|---|
| 4 | 0% | 33.4% | 32.9% | 94% | 0% | 34% | 3.724 |
| 8 | 0% | 54.0% | 53.5% | 78% | 0% | 57% | 4.281 |
| 10 | 16% | 66.7% | 66.5% | 78% | 0% | 67% | 5.014 |
| 12 | 36% | 68.2% | 68.1% | 72% | 0% | 68% | 4.343 |
| 14 | 76% | 76.0% | 76.0% | 76% | 20% | 76% | 4.513 |
| 16 | 90% | 90.0% | 90.0% | 90% | 54% | 90% | 1.533 |
| 20 | 100% | 100.0% | 100.0% | 100% | 100% | 100% | 0.381 |
| 30 | 100% | 100.0% | 100.0% | 100% | 100% | 100% | 0.374 |
| 50 | 100% | 100.0% | 100.0% | 100% | 100% | 100% | 0.478 |

### Table F - Mean encryption/decryption time vs length (small messages, microseconds)

| Msg length | Encrypt (us) | Decrypt (us) |
|---|---|---|
| 50 | 25.4 | 25.6 |
| 100 | 46.9 | 48.2 |
| 250 | 144.1 | 149.4 |
| 500 | 254.8 | 253.8 |
| 1000 | 571.6 | 588.2 |

### Table G - Scaling (milliseconds, mean of repeated runs)

| n | Custom enc | Custom dec | Caesar enc | Caesar dec | Freq. analysis | Known-plaintext | Caesar brute force |
|---|---|---|---|---|---|---|---|
| 1,000 | 0.552 | 0.761 | 0.239 | 0.227 | 29.887 | 0.778 | 0.338 |
| 10,000 | 5.950 | 3.943 | 1.244 | 1.289 | 30.537 | 2.019 | 0.947 |
| 100,000 | 48.354 | 58.509 | 18.126 | 15.712 | 230.696 | 19.053 | 8.299 |
| 1,000,000 | 494.593 | 501.265 | 209.282 | 233.317 | 2336.947 | 221.616 | 85.292 |

Custom/Caesar encryption time ratio per size: [2.31, 4.78, 2.67, 2.36]
