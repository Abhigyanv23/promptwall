# Baseline: `meta-llama/Llama-Prompt-Guard-2-86M` vs promptwall

- Threshold 0.5; input = extracted page text in 512-token windows, score = max over windows; tokenizer: repo tokenizer.json (DIFFERS from transformers' tokenizer)
- Latency per page: baseline p50 590.0 ms, p95 5193.9 ms | promptwall p50 52.0 ms, p95 302.7 ms
- Host pages the baseline flags on their own (dropped from the attack comparison for both): 1 (33 attack pages skipped)

## attack pages by delivery

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| style_block_class | 172 | 40% | 67% | 100% | 60% | 0% |
| visible_paragraph | 173 | 40% | 53% | 100% | 60% | 43% |
| css_display_none | 173 | 40% | 64% | 100% | 60% | 0% |
| zero_width_split | 172 | 40% | 56% | 100% | 60% | 41% |
| css_same_color | 173 | 39% | 66% | 100% | 61% | 0% |
| css_font_size_zero | 173 | 38% | 65% | 100% | 62% | 0% |
| homoglyph_visible | 172 | 9% | 100% | 100% | 91% | 0% |
| html_comment | 173 | 0% | 67% | 0% | 0% | 0% |
| img_alt_text | 173 | 0% | 69% | 0% | 0% | 0% |
| unicode_tag_smuggling | 173 | 0% | 100% | 0% | 0% | 0% |
| js_injected | 172 | 0% | 0% | 0% | 0% | 0% |

## attack pages by wrapper

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| seen: ignore_previous | 322 | 55% | 90% | 63% | 9% | 2% |
| seen: injecagent_important | 322 | 55% | 91% | 63% | 9% | 0% |
| held-out: agentdojo_important | 322 | 16% | 61% | 64% | 49% | 7% |
| seen: system_message | 322 | 6% | 83% | 63% | 57% | 5% |
| held-out: plain | 322 | 1% | 28% | 63% | 62% | 17% |
| held-out: todo | 289 | 0% | 29% | 64% | 64% | 16% |

## attack pages by goal source

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| bipia (wrapped) | 735 | 27% | 76% | 64% | 36% | 5% |
| injecagent (wrapped) | 607 | 27% | 69% | 64% | 37% | 7% |
| agentdojo (wrapped) | 235 | 24% | 63% | 64% | 40% | 6% |
| bipia (plain goal) | 150 | 3% | 38% | 63% | 61% | 16% |
| injecagent (plain goal) | 124 | 0% | 18% | 63% | 63% | 18% |
| agentdojo (plain goal) | 48 | 0% | 23% | 65% | 65% | 21% |

## text-level attacks

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| InjecAgent tool output (enhanced) | 300 | 100% | 100% |
| Tensor Trust direct attacks (held-out half) | 368 | 82% | 95% |
| InjecAgent tool output (base) | 300 | 0% | 0% |

## benign pages

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| readability test pages (real sites) | 63 | 2% | 5% |

## benign text

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| BIPIA emails (benign) | 50 | 0% | 0% |
| BIPIA tables (benign) | 100 | 0% | 0% |

## hard negatives

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| hand-written hard negatives | 10 | 30% | 60% |
