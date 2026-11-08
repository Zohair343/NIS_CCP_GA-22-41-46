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
| 50 | 0% | 15.3% | 36% | 26% | 29.56 |
| 100 | 0% | 47.9% | 70% | 70% | 22.23 |
| 250 | 46% | 94.4% | 100% | 100% | 22.23 |
| 500 | 90% | 99.2% | 100% | 100% | 22.08 |
| 1000 | 100% | 100.0% | 100% | 100% | 19.96 |

### Table C - Known-plaintext attack (30 known letters at the start, 50 trials per length)

| Msg length | Exact recovery | Mean letters correct (all) | Mean letters correct (unknown part) | a found | Verified period | Mean time (ms) |
|---|---|---|---|---|---|---|
| 50 | 100% | 100.0% | 100.0% | 100% | 100% | 0.464 |
| 100 | 100% | 100.0% | 100.0% | 100% | 100% | 0.362 |
| 250 | 100% | 100.0% | 100.0% | 100% | 100% | 0.387 |
| 500 | 100% | 100.0% | 100.0% | 100% | 100% | 0.444 |
| 1000 | 100% | 100.0% | 100.0% | 100% | 100% | 0.491 |

### Table D - Representative run (a=7, b=3, key NETWORKSEC; true effective shifts s_j = b+K_j = [16, 7, 22, 25, 17, 20, 13, 21, 7, 5])

| Msg length | Freq: est. key len | Freq: a | Freq: letters correct | Freq: exact | Freq: wrong shift columns | Freq: time (ms) | KPA: a | KPA: m | KPA: letters correct | KPA: exact | KPA: time (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 50 | 20 | 7 | 28.0% | False | None | 27.38 | 7 | 10 | 100.0% | True | 0.206 |
| 100 | 10 | 7 | 90.0% | False | 1 | 13.98 | 7 | 10 | 100.0% | True | 0.217 |
| 250 | 10 | 7 | 100.0% | True | 0 | 14.64 | 7 | 10 | 100.0% | True | 0.239 |
| 500 | 10 | 7 | 100.0% | True | 0 | 14.74 | 7 | 10 | 100.0% | True | 0.283 |
| 1000 | 10 | 7 | 100.0% | True | 0 | 15.81 | 7 | 10 | 100.0% | True | 0.376 |

Recovered effective shifts in the representative run:

- n=50: frequency analysis -> [10, 4, 22, 9, 17, 14, 11, 1, 7, 5, 10, 8, 22, 7, 1, 7, 0, 7, 20, 3]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]
- n=100: frequency analysis -> [16, 7, 22, 25, 17, 20, 15, 21, 7, 5]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]
- n=250: frequency analysis -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]
- n=500: frequency analysis -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]
- n=1000: frequency analysis -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]; known-plaintext -> [16, 7, 22, 25, 17, 20, 13, 21, 7, 5]

### Table E - Known-plaintext attack vs amount of known text (500-letter messages, 50 trials)

| Known letters | Exact recovery | Mean letters correct | Unknown part correct | a found | Verified period | Key columns recovered | Mean time (ms) |
|---|---|---|---|---|---|---|---|
| 4 | 0% | 34.3% | 33.8% | 100% | 0% | 34% | 2.897 |
| 8 | 0% | 66.9% | 66.4% | 100% | 0% | 67% | 3.443 |
| 10 | 22% | 84.9% | 84.6% | 100% | 0% | 85% | 4.891 |
| 12 | 46% | 93.7% | 93.6% | 100% | 0% | 94% | 5.495 |
| 14 | 100% | 100.0% | 100.0% | 100% | 20% | 100% | 3.906 |
| 16 | 100% | 100.0% | 100.0% | 100% | 54% | 100% | 2.568 |
| 20 | 100% | 100.0% | 100.0% | 100% | 100% | 100% | 0.710 |
| 30 | 100% | 100.0% | 100.0% | 100% | 100% | 100% | 0.729 |
| 50 | 100% | 100.0% | 100.0% | 100% | 100% | 100% | 0.684 |

### Table F - Mean encryption/decryption time vs length (small messages, microseconds)

| Msg length | Encrypt (us) | Decrypt (us) |
|---|---|---|
| 50 | 33.8 | 34.6 |
| 100 | 54.4 | 58.5 |
| 250 | 128.6 | 126.8 |
| 500 | 252.1 | 262.5 |
| 1000 | 436.2 | 431.1 |

### Table G - Scaling (milliseconds, mean of repeated runs)

| n | Custom enc | Custom dec | Caesar enc | Caesar dec | Freq. analysis | Known-plaintext | Caesar brute force |
|---|---|---|---|---|---|---|---|
| 1,000 | 0.744 | 0.765 | 0.242 | 0.245 | 25.567 | 0.734 | 0.368 |
| 10,000 | 7.316 | 7.292 | 2.312 | 2.276 | 45.777 | 3.844 | 1.234 |
| 100,000 | 64.075 | 68.414 | 18.271 | 21.356 | 232.930 | 18.266 | 7.653 |
| 1,000,000 | 410.135 | 516.615 | 191.918 | 155.140 | 2372.998 | 296.747 | 127.924 |

Custom/Caesar encryption time ratio per size: [3.07, 3.16, 3.51, 2.14]
