# Threshold sweep: `promptguard2-86m`

- Benign real pages: 63; attack pages scored: 1932
- promptwall's false-positive rate on the same benign pages: 4.8%

## At promptwall's false-positive rate

Best baseline threshold with benign FPR <= 4.8%: **0.034209** (benign FPR 4.8%).

| | baseline | promptwall (same pages) |
|---|---|---|
| Attack pages flagged (n=1835) | 31.4% | 63.4% |
| Attack text reaching the LLM | 32.8% | 7.8% |

## Full sweep (grid points only)

| threshold | benign pages flagged | attack pages kept | baseline flagged | promptwall flagged | baseline reached LLM | promptwall reached LLM |
|---|---|---|---|---|---|---|
| 0.9 | 1.6% | 1899 | 20.4% | 64.2% | 43.2% | 7.6% |
| 0.7 | 1.6% | 1899 | 21.6% | 64.2% | 42.0% | 7.6% |
| 0.5 | 1.6% | 1899 | 22.3% | 64.2% | 41.3% | 7.6% |
| 0.3 | 1.6% | 1899 | 23.5% | 64.2% | 40.1% | 7.6% |
| 0.2 | 1.6% | 1899 | 25.1% | 64.2% | 38.5% | 7.6% |
| 0.1 | 3.2% | 1867 | 27.2% | 63.8% | 36.6% | 7.7% |
| 0.05 | 3.2% | 1867 | 29.8% | 63.8% | 34.2% | 7.7% |
| 0.02 | 11.1% | 1705 | 33.0% | 64.3% | 31.0% | 8.0% |
| 0.01 | 22.2% | 1479 | 40.2% | 63.5% | 24.9% | 8.3% |
| 0.005 | 58.7% | 805 | 40.9% | 62.2% | 24.8% | 8.7% |
| 0.002 | 79.4% | 389 | 46.3% | 64.0% | 20.3% | 10.3% |
| 0.001 | 88.9% | 194 | 57.2% | 73.2% | 13.4% | 7.7% |
| 0.0005 | 98.4% | 32 | 56.2% | 28.1% | 15.6% | 18.8% |
