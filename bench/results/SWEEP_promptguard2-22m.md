# Threshold sweep: `promptguard2-22m`

- Benign real pages: 63; attack pages scored: 1932
- promptwall's false-positive rate on the same benign pages: 4.8%

## At promptwall's false-positive rate

Best baseline threshold with benign FPR <= 4.8%: **0.154946** (benign FPR 4.8%).

| | baseline | promptwall (same pages) |
|---|---|---|
| Attack pages flagged (n=1835) | 28.0% | 64.5% |
| Attack text reaching the LLM | 35.9% | 7.6% |

## Full sweep (grid points only)

| threshold | benign pages flagged | attack pages kept | baseline flagged | promptwall flagged | baseline reached LLM | promptwall reached LLM |
|---|---|---|---|---|---|---|
| 0.9 | 1.6% | 1899 | 21.8% | 64.2% | 41.8% | 7.6% |
| 0.7 | 1.6% | 1899 | 23.3% | 64.2% | 40.3% | 7.6% |
| 0.5 | 1.6% | 1899 | 24.4% | 64.2% | 39.2% | 7.6% |
| 0.3 | 3.2% | 1867 | 25.8% | 63.8% | 37.8% | 7.8% |
| 0.2 | 4.8% | 1835 | 27.2% | 64.5% | 36.5% | 7.6% |
| 0.1 | 7.9% | 1771 | 28.0% | 64.0% | 35.6% | 7.7% |
| 0.05 | 9.5% | 1739 | 31.3% | 63.6% | 32.5% | 7.8% |
| 0.02 | 19.0% | 1545 | 37.2% | 64.9% | 26.9% | 7.8% |
| 0.01 | 33.3% | 1288 | 40.4% | 66.6% | 23.5% | 7.5% |
| 0.005 | 42.9% | 1126 | 45.9% | 63.8% | 18.9% | 8.4% |
| 0.002 | 85.7% | 258 | 46.5% | 60.1% | 17.4% | 12.0% |
| 0.001 | 98.4% | 32 | 53.1% | 28.1% | 18.8% | 18.8% |
