# Baseline: `protectai/deberta-v3-base-prompt-injection-v2` vs promptwall

- Threshold 0.5; input = extracted page text in 128-token windows, score = max over windows
- Latency per page: baseline p50 360.3 ms, p95 2682.5 ms | promptwall p50 52.0 ms, p95 302.7 ms
- Host pages the baseline flags on their own (dropped from the attack comparison for both): 38 (1224 attack pages skipped)

## attack pages by delivery

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| zero_width_split | 65 | 57% | 55% | 100% | 43% | 35% |
| style_block_class | 62 | 55% | 71% | 100% | 45% | 0% |
| homoglyph_visible | 64 | 52% | 100% | 100% | 48% | 0% |
| visible_paragraph | 66 | 48% | 50% | 100% | 52% | 38% |
| css_display_none | 64 | 48% | 59% | 100% | 52% | 0% |
| css_same_color | 64 | 44% | 62% | 100% | 56% | 0% |
| css_font_size_zero | 65 | 43% | 65% | 100% | 57% | 0% |
| img_alt_text | 64 | 0% | 69% | 0% | 0% | 0% |
| js_injected | 65 | 0% | 0% | 0% | 0% | 0% |
| unicode_tag_smuggling | 64 | 0% | 100% | 0% | 0% | 0% |
| html_comment | 65 | 0% | 69% | 0% | 0% | 0% |

## attack pages by wrapper

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| seen: injecagent_important | 129 | 52% | 91% | 63% | 11% | 0% |
| seen: ignore_previous | 128 | 48% | 91% | 63% | 16% | 0% |
| held-out: agentdojo_important | 96 | 44% | 53% | 65% | 21% | 9% |
| held-out: todo | 64 | 22% | 25% | 64% | 42% | 9% |
| seen: system_message | 129 | 17% | 81% | 64% | 47% | 3% |
| held-out: plain | 162 | 10% | 28% | 64% | 53% | 18% |

## attack pages by goal source

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| injecagent (wrapped) | 211 | 43% | 73% | 64% | 21% | 5% |
| agentdojo (wrapped) | 80 | 35% | 69% | 60% | 25% | 1% |
| bipia (wrapped) | 255 | 34% | 77% | 64% | 30% | 3% |
| agentdojo (plain goal) | 24 | 17% | 21% | 71% | 54% | 17% |
| injecagent (plain goal) | 63 | 14% | 17% | 62% | 48% | 19% |
| bipia (plain goal) | 75 | 5% | 39% | 63% | 57% | 17% |

## text-level attacks

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| InjecAgent tool output (enhanced) | 300 | 100% | 100% |
| Tensor Trust direct attacks (held-out half) | 368 | 98% | 95% |
| InjecAgent tool output (base) | 300 | 72% | 0% |

## benign pages

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| readability test pages (real sites) | 63 | 62% | 5% |

## benign text

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| BIPIA emails (benign) | 50 | 68% | 0% |
| BIPIA tables (benign) | 100 | 61% | 0% |

## hard negatives

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| hand-written hard negatives | 10 | 60% | 60% |
