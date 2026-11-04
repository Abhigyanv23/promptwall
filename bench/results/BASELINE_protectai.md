# Baseline: `protectai/deberta-v3-base-prompt-injection-v2` vs promptwall

- Threshold 0.5; input = extracted page text in 512-token windows, score = max over windows
- Latency per page: baseline p50 612.2 ms, p95 4462.1 ms | promptwall p50 52.0 ms, p95 302.7 ms
- Host pages the baseline flags on their own (dropped from the attack comparison for both): 22 (709 attack pages skipped)

## attack pages by delivery

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| css_font_size_zero | 113 | 26% | 69% | 100% | 74% | 0% |
| zero_width_split | 111 | 25% | 62% | 100% | 75% | 32% |
| css_display_none | 110 | 25% | 65% | 100% | 75% | 0% |
| visible_paragraph | 111 | 23% | 56% | 100% | 77% | 37% |
| css_same_color | 111 | 23% | 67% | 100% | 77% | 0% |
| style_block_class | 110 | 22% | 75% | 100% | 78% | 0% |
| homoglyph_visible | 111 | 18% | 100% | 100% | 82% | 0% |
| img_alt_text | 111 | 0% | 72% | 0% | 0% | 0% |
| js_injected | 111 | 0% | 0% | 0% | 0% | 0% |
| unicode_tag_smuggling | 112 | 0% | 100% | 0% | 0% | 0% |
| html_comment | 112 | 0% | 71% | 0% | 0% | 0% |

## attack pages by wrapper

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| seen: injecagent_important | 257 | 33% | 91% | 63% | 30% | 0% |
| seen: ignore_previous | 258 | 25% | 91% | 64% | 39% | 0% |
| held-out: plain | 194 | 10% | 28% | 63% | 54% | 18% |
| held-out: todo | 193 | 5% | 28% | 64% | 59% | 15% |
| seen: system_message | 225 | 0% | 84% | 63% | 63% | 2% |
| held-out: agentdojo_important | 96 | 0% | 53% | 65% | 65% | 9% |

## attack pages by goal source

| group | n | baseline flagged | promptwall flagged | reached LLM: no defence | baseline | promptwall |
|---|---|---|---|---|---|---|
| injecagent (wrapped) | 397 | 17% | 72% | 63% | 46% | 5% |
| agentdojo (wrapped) | 152 | 16% | 69% | 62% | 47% | 3% |
| bipia (wrapped) | 480 | 14% | 78% | 65% | 51% | 4% |
| injecagent (plain goal) | 76 | 13% | 18% | 62% | 49% | 18% |
| bipia (plain goal) | 90 | 8% | 40% | 64% | 57% | 17% |
| agentdojo (plain goal) | 28 | 7% | 18% | 64% | 57% | 18% |

## text-level attacks

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| InjecAgent tool output (enhanced) | 300 | 100% | 100% |
| Tensor Trust direct attacks (held-out half) | 368 | 98% | 95% |
| InjecAgent tool output (base) | 300 | 64% | 0% |

## benign pages

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| readability test pages (real sites) | 63 | 35% | 5% |

## benign text

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| BIPIA emails (benign) | 50 | 62% | 0% |
| BIPIA tables (benign) | 100 | 5% | 0% |

## hard negatives

| group | n | baseline flagged | promptwall flagged |
|---|---|---|---|
| hand-written hard negatives | 10 | 60% | 60% |
