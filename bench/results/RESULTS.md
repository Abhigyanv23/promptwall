# promptwall benchmark results

- Attack pages: 1932, built on 60 real test pages that every detector allows (so any flag is caused by the payload)
- Benign real-world test pages: 63
- Latency per page (rules + ML + sanitize, 1 CPU core): p50 52.0 ms, p95 302.7 ms

**flagged** = sanitize or block. **blocked** = block. **reached LLM** = the attack text survived into what the agent reads (lower is better). For benign rows, flagged = false positive.

## attack pages by delivery

| group | n | keyword | rules | ML | **combined** flagged | combined blocked | reached LLM: no defence | keyword | **promptwall** |
|---|---|---|---|---|---|---|---|---|---|
| unicode_tag_smuggling | 176 | 0% | 100% | 68% | **100%** | 70% | 0% | 0% | **0%** |
| homoglyph_visible | 175 | 0% | 100% | 53% | **100%** | 34% | 100% | 100% | **0%** |
| img_alt_text | 176 | 0% | 17% | 68% | **68%** | 52% | 0% | 0% | **0%** |
| style_block_class | 175 | 17% | 17% | 67% | **67%** | 46% | 100% | 83% | **0%** |
| html_comment | 176 | 0% | 17% | 66% | **66%** | 49% | 0% | 0% | **0%** |
| css_same_color | 176 | 16% | 16% | 65% | **65%** | 45% | 100% | 84% | **0%** |
| css_font_size_zero | 176 | 17% | 17% | 64% | **64%** | 46% | 100% | 83% | **0%** |
| css_display_none | 176 | 16% | 16% | 62% | **62%** | 45% | 100% | 84% | **0%** |
| zero_width_split | 175 | 17% | 17% | 55% | **55%** | 29% | 100% | 83% | **42%** |
| visible_paragraph | 176 | 16% | 16% | 52% | **52%** | 28% | 100% | 84% | **44%** |
| js_injected ⚠️ expected gap | 175 | 0% | 0% | 0% | **0%** | 0% | 0% | 0% | **0%** |

## attack pages by wrapper

| group | n | keyword | rules | ML | **combined** flagged | combined blocked | reached LLM: no defence | keyword | **promptwall** |
|---|---|---|---|---|---|---|---|---|---|
| seen: injecagent_important | 322 | 54% | 91% | 91% | **91%** | 91% | 63% | 9% | **0%** |
| seen: ignore_previous | 322 | 0% | 18% | 89% | **90%** | 75% | 63% | 63% | **2%** |
| seen: system_message | 322 | 0% | 19% | 80% | **83%** | 58% | 63% | 63% | **5%** |
| held-out: agentdojo_important | 322 | 0% | 18% | 53% | **61%** | 10% | 64% | 64% | **7%** |
| held-out: todo | 322 | 0% | 18% | 12% | **29%** | 4% | 64% | 64% | **16%** |
| held-out: plain | 322 | 0% | 18% | 12% | **28%** | 3% | 63% | 63% | **17%** |

## attack pages by goal source

| group | n | keyword | rules | ML | **combined** flagged | combined blocked | reached LLM: no defence | keyword | **promptwall** |
|---|---|---|---|---|---|---|---|---|---|
| bipia (wrapped) | 750 | 11% | 33% | 71% | **76%** | 52% | 64% | 53% | **5%** |
| injecagent (wrapped) | 620 | 11% | 33% | 61% | **68%** | 45% | 64% | 53% | **7%** |
| agentdojo (wrapped) | 240 | 10% | 32% | 56% | **62%** | 42% | 64% | 53% | **6%** |
| bipia (plain goal) | 150 | 0% | 18% | 25% | **38%** | 6% | 63% | 63% | **16%** |
| agentdojo (plain goal) | 48 | 0% | 19% | 4% | **23%** | 4% | 65% | 65% | **21%** |
| injecagent (plain goal) | 124 | 0% | 17% | 1% | **18%** | 0% | 63% | 63% | **18%** |

## text-level attacks

| group | n | keyword | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| InjecAgent tool output (enhanced) | 300 | 100% | 100% | 100% | **100%** | 100% |
| Tensor Trust direct attacks (held-out half) | 368 | 10% | 15% | 95% | **95%** | 91% |
| InjecAgent tool output (base) | 300 | 0% | 0% | 0% | **0%** | 0% |

## benign pages

| group | n | keyword | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| readability test pages (real sites) | 63 | 0% | 0% | 5% | **5%** | 0% |

## benign text

| group | n | keyword | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| BIPIA emails (benign) | 50 | 0% | 0% | 0% | **0%** | 0% |
| BIPIA tables (benign) | 100 | 0% | 0% | 0% | **0%** | 0% |

## hard negatives

| group | n | keyword | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| hand-written hard negatives | 10 | 20% | 40% | 40% | **60%** | 40% |

## False positives (combined)

- `herald-sun-1` → sanitize
  - ml.classifier@visible: p=0.73 | Login using your Newspass account User Login Username * Password * Remember me Lo
- `mathjax` → sanitize
  - ml.classifier@visible: p=0.63 | MathJax v3 with MathML input and HTML output MathJax v3 beta: MathML input, HTML 
- `telegraph` → sanitize
  - ml.classifier@css:display-none: p=0.58 | We've noticed you're adblocking. We rely on advertising to help fund our award-wi
- `hard:security_blog_quotes_attack` → block
- `hard:owasp_style_explainer` → block
- `hard:support_email_correction` → sanitize
- `hard:game_rules` → sanitize
- `hard:devops_secrets_policy` → block
- `hard:ml_course_notes_chat_template` → block
