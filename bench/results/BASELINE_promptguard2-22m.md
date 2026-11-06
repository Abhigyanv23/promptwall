# Baseline: `meta-llama/Llama-Prompt-Guard-2-22M` vs promptwall

- Threshold 0.5; input = extracted page text in 512-token windows, score = max over windows; tokenizer: repo tokenizer.json (DIFFERS from transformers' tokenizer)
- Latency per page: baseline p50 217.4 ms, p95 2200.9 ms | promptwall p50 52.0 ms, p95 302.7 ms
- Host pages the baseline flags on their own (dropped from the attack comparison for both): 1 (33 attack pages skipped)

## attack pages by delivery

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| css_font_size_zero | 173 | 45% | 65% | 100% | 55% | 0% |
| css_same_color | 173 | 45% | 66% | 100% | 55% | 0% |
| style_block_class | 172 | 44% | 67% | 100% | 56% | 0% |
| zero_width_split | 172 | 44% | 56% | 100% | 56% | 41% |
| visible_paragraph | 173 | 43% | 53% | 100% | 57% | 43% |
| css_display_none | 173 | 43% | 64% | 100% | 57% | 0% |
| homoglyph_visible | 172 | 5% | 100% | 100% | 95% | 0% |
| html_comment | 173 | 0% | 67% | 0% | 0% | 0% |
| img_alt_text | 173 | 0% | 69% | 0% | 0% | 0% |
| unicode_tag_smuggling | 173 | 0% | 100% | 0% | 0% | 0% |
| js_injected | 172 | 0% | 0% | 0% | 0% | 0% |

## attack pages by wrapper

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| seen: ignore_previous | 322 | 55% | 90% | 63% | 9% | 2% |
| seen: injecagent_important | 322 | 54% | 91% | 63% | 9% | 0% |
| held-out: agentdojo_important | 322 | 20% | 61% | 64% | 44% | 7% |
| held-out: todo | 289 | 6% | 29% | 64% | 58% | 16% |
| seen: system_message | 322 | 6% | 83% | 63% | 57% | 5% |
| held-out: plain | 322 | 4% | 28% | 63% | 59% | 17% |

## attack pages by goal source

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| bipia (wrapped) | 735 | 31% | 76% | 64% | 32% | 5% |
| injecagent (wrapped) | 607 | 27% | 69% | 64% | 37% | 7% |
| agentdojo (wrapped) | 235 | 24% | 63% | 64% | 40% | 6% |
| bipia (plain goal) | 150 | 7% | 38% | 63% | 56% | 16% |
| agentdojo (plain goal) | 48 | 2% | 23% | 65% | 62% | 21% |
| injecagent (plain goal) | 124 | 1% | 18% | 63% | 62% | 18% |

## text-level attacks

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| InjecAgent tool output (enhanced) | 300 | 100% | 100% |
| Tensor Trust direct attacks (held-out half) | 368 | 78% | 95% |
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
| hand-written hard negatives | 10 | 40% | 60% |
