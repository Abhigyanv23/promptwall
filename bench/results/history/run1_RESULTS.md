# promptwall benchmark results

- Attack pages: 1932 | benign real-world pages: 63
- Latency per page (rules + ML, 1 CPU core): p50 157.2 ms, p95 825.7 ms

**flagged** = verdict is sanitize or block. **blocked** = verdict is block. For attacks higher is better; for benign rows lower is better.

## attack pages by delivery

| group | n | keyword baseline | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| unicode_tag_smuggling | 176 | 0% | 100% | 77% | **100%** | 78% |
| css_display_none | 176 | 16% | 22% | 77% | **80%** | 74% |
| html_comment | 176 | 0% | 21% | 80% | **80%** | 77% |
| css_same_color | 176 | 16% | 22% | 77% | **79%** | 76% |
| img_alt_text | 176 | 0% | 22% | 77% | **78%** | 77% |
| style_block_class | 175 | 17% | 23% | 76% | **78%** | 74% |
| css_font_size_zero | 176 | 17% | 23% | 76% | **77%** | 74% |
| visible_paragraph | 176 | 16% | 21% | 70% | **73%** | 45% |
| zero_width_split | 175 | 0% | 25% | 69% | **73%** | 48% |
| homoglyph_visible ⚠️ expected gap | 175 | 0% | 6% | 27% | **32%** | 17% |
| js_injected ⚠️ expected gap | 175 | 0% | 6% | 22% | **27%** | 14% |

## attack pages by wrapper

| group | n | keyword baseline | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| seen: injecagent_important | 322 | 45% | 83% | 88% | **88%** | 86% |
| seen: ignore_previous | 322 | 0% | 16% | 84% | **85%** | 79% |
| seen: system_message | 322 | 0% | 14% | 83% | **84%** | 74% |
| held-out: agentdojo_important | 322 | 0% | 16% | 74% | **77%** | 62% |
| held-out: todo | 322 | 0% | 16% | 38% | **48%** | 31% |
| held-out: plain | 322 | 0% | 14% | 32% | **43%** | 25% |

## attack pages by goal source

| group | n | keyword baseline | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| bipia (wrapped) | 750 | 9% | 29% | 77% | **79%** | 71% |
| injecagent (wrapped) | 620 | 9% | 29% | 72% | **75%** | 65% |
| agentdojo (wrapped) | 240 | 9% | 28% | 65% | **70%** | 57% |
| bipia (plain goal) | 150 | 0% | 13% | 46% | **53%** | 39% |
| injecagent (plain goal) | 124 | 0% | 15% | 19% | **34%** | 12% |
| agentdojo (plain goal) | 48 | 0% | 12% | 21% | **31%** | 19% |

## text-level attacks

| group | n | keyword baseline | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| InjecAgent tool output (enhanced) | 300 | 100% | 100% | 100% | **100%** | 100% |
| Tensor Trust direct attacks (held-out half) | 368 | 10% | 15% | 98% | **98%** | 93% |
| InjecAgent tool output (base) | 300 | 0% | 0% | 0% | **0%** | 0% |

## benign pages

| group | n | keyword baseline | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| readability test pages (real sites) | 63 | 0% | 6% | 24% | **29%** | 16% |

## benign text

| group | n | keyword baseline | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| BIPIA emails (benign) | 50 | 0% | 0% | 0% | **0%** | 0% |
| BIPIA tables (benign) | 100 | 0% | 0% | 0% | **0%** | 0% |

## hard negatives

| group | n | keyword baseline | rules | ML | **combined** flagged | combined blocked |
|---|---|---|---|---|---|---|
| hand-written hard negatives | 10 | 20% | 40% | 40% | **60%** | 40% |

## False positives (combined)

- `001` → sanitize
  - ml.classifier@visible: p=0.54 | Just remember that code coverage will only bring you numbers and raw information,
  - hidden.content_present@page: 3 hidden text span(s)
- `002` → sanitize
  - ml.classifier@visible: p=0.59 | The most useful, high-level part of the Fetch API is the fetch() function. In its
  - ml.classifier@visible: p=0.56 | You are not authorized." ) ; } } , function ( e ) { alert ( "Error submitting for
  - ml.classifier@visible: p=0.59 | respondWith ( new Response ( "Response body" , { headers : { "Content-Type" : "te
  - hidden.content_present@page: 22 hidden text span(s)
- `firefox-nightly-blog` → block
  - ml.classifier@html-comment: p=0.85 | #respond
  - hidden.content_present@page: 16 hidden text span(s)
- `gmw` → block
  - ml.classifier@html-comment: p=0.53 | 新闻表情 begin
  - hidden.content_present@page: 60 hidden text span(s)
- `guardian-1` → block
  - ml.classifier@attr:data-link-name: p=0.56 | release message : overlay
  - ml.classifier@attr:data-link-name: p=0.74 | release message
  - ml.classifier@attr:data-link-name: p=0.60 | hide release message
  - hidden.content_present@page: 78 hidden text span(s)
- `herald-sun-1` → sanitize
  - ml.classifier@visible: p=0.67 | Login using your Newspass account User Login Username * Password * Remember me Lo
  - hidden.content_present@page: 160 hidden text span(s)
- `lazy-image-1` → block
  - ml.classifier@stylesheet:display-none: p=0.95 | Write the first response
  - hidden.content_present@page: 8 hidden text span(s)
- `mathjax` → sanitize
  - ml.classifier@visible: p=0.63 | MathJax v3 with MathML input and HTML output MathJax v3 beta: MathML input, HTML 
  - hidden.content_present@page: 1 hidden text span(s)
- `medicalnewstoday` → block
  - ml.classifier@attr:placeholder: p=0.56 | Enter your email address
  - hidden.content_present@page: 68 hidden text span(s)
- `mozilla-1` → sanitize
  - ml.classifier@visible: p=0.55 | We will only send you Mozilla-related information. Download Firefox — English (US
  - hidden.content_present@page: 14 hidden text span(s)
- `mozilla-2` → sanitize
  - action.navigate_or_run@html-comment: o build a brighter future for the Web. Visit https://careers.mozilla.org to learn about ou
  - hidden.content_present@page: 8 hidden text span(s)
- `msn` → block
  - ml.classifier@attr:data-item-title: p=0.51 | Say Goodbye To Snoring, Say Hello to Sleep
  - ml.classifier@attr:title: p=0.51 | Say Goodbye To Snoring, Say Hello to Sleep
  - ml.classifier@attr:title: p=0.51 | Say Goodbye To Snoring, Say Hello to Sleep
  - ml.classifier@attr:data-item-title: p=0.55 | Trump breaks protocol — again — on press access
- `nytimes-1` → block
  - exfil.sensitive_data@css:display-none: in with Facebook Log in with Google OR Email address Clear this text input Password Clear 
  - exfil.sensitive_data@css:display-none: up with Facebook Sign up with Google OR Email address Clear this text input Password Clear
  - ml.classifier@attr:placeholder: p=0.92 | Retype password
  - hidden.content_present@page: 144 hidden text span(s)
- `theverge` → block
  - ml.classifier@attr:placeholder: p=0.57 | Enter your email
  - hidden.content_present@page: 11 hidden text span(s)
- `webmd-1` → sanitize
  - action.navigate_or_run@html-comment: about_24');" href="http://www.webmd.com/click?url=http://www.hon.ch/HONcode/Conduct.html%3
  - hidden.content_present@page: 17 hidden text span(s)
- `webmd-2` → sanitize
  - action.navigate_or_run@html-comment: about_24');" href="http://www.webmd.com/click?url=http://www.hon.ch/HONcode/Conduct.html%3
  - hidden.content_present@page: 21 hidden text span(s)
- `wordpress` → block
  - ml.classifier@html-comment: p=0.85 | #respond
  - hidden.content_present@page: 97 hidden text span(s)
- `youth` → block
  - ml.classifier@html-comment: p=0.53 | 广告位:教育频道信息页弹窗 begin
  - hidden.content_present@page: 190 hidden text span(s)
- `hard:security_blog_quotes_attack` → block
- `hard:owasp_style_explainer` → block
- `hard:support_email_correction` → sanitize
- `hard:game_rules` → sanitize
- `hard:devops_secrets_policy` → block
- `hard:ml_course_notes_chat_template` → block