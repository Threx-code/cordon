# Cordon benchmark

Measured inside Docker by `bench/run.py`. Losses are listed, not hidden.

## Malware blocked (higher is better)

| tool | inputs | blocked | passed | no answer | rate |
|---|---|---|---|---|---|
| cordon | 39328 | 37039 | 2289 | 0 | 94.2% |
| guarddog | 498 | 426 | 72 | 0 | 85.5% |
| cordon, content only | 39328 | 31361 | 0 | 0 | 79.7% |
| cordon on guarddog's sample | 498 | 474 | 0 | 0 | 95.2% |

