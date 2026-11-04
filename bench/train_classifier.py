"""Train the ML layer and write promptwall/data/classifier.joblib.

Uses ONLY training splits from bench/sources.py:
  positives: BIPIA-train goals x 3 training wrappers, Tensor Trust (train half)
  negatives: chunks of the 'fit' readability pages + BIPIA-train emails/tables
Thresholds are picked on the 'val' pages + a held-out slice of positives.
Test pages, test goals and held-out wrappers are never touched here.

    python bench/train_classifier.py
"""
from __future__ import annotations

import random
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
import sources  # noqa: E402
from promptwall.extract import extract_html  # noqa: E402
from promptwall.ml import DEFAULT_MODEL_PATH, chunk_text, eligible  # noqa: E402
from promptwall.scanner import normalize  # noqa: E402

RNG = random.Random(13)
# Chunk-level FPR target. A page has ~100-200 chunks, so page-level FPR is far
# higher than chunk-level: run 1 used 0.2% per chunk and flagged ~26% of pages.
VAL_FPR_TARGET = 0.0003


def page_chunks(html: str) -> list[str]:
    ext = extract_html(html)
    chunks = chunk_text(normalize(ext.visible_text))
    for span in ext.hidden_spans:
        chunks.extend(chunk_text(normalize(span.text)))
    return [c for c in chunks if eligible(c)]


def build():
    pages = sources.readability_pages()
    neg_fit = [c for _, h in pages["fit"] for c in page_chunks(h)]
    ctx = sources.bipia_contexts("train")
    emails = [t for k, t in ctx if k == "email"]
    tables = RNG.sample([t for k, t in ctx if k == "table"], 300)
    neg_fit += [c for t in emails + tables for c in chunk_text(normalize(t)) if eligible(c)]
    val_pages = [page_chunks(h) for _, h in pages["val"]]
    neg_val = [c for p in val_pages for c in p]

    pos_fit, pos_val = [], []
    for g in sources.train_goals():
        texts = ([g.text] if g.source == "tensortrust"
                 else [sources.wrap(w, g.text) for w in sources.TRAIN_WRAPPERS])
        for t in texts:
            t = normalize(t)
            # Augment: payload often lands next to ordinary page text.
            if RNG.random() < 0.5:
                ctx_sent = RNG.choice(neg_fit)[:200]
                t = f"{ctx_sent} {t}" if RNG.random() < 0.5 else f"{t} {ctx_sent}"
            target = pos_val if sources.bucket("val:" + g.text) < 20 else pos_fit
            target.extend(c for c in chunk_text(t) if eligible(c))
    return neg_fit, pos_fit, neg_val, pos_val, val_pages


def make_pipeline() -> Pipeline:
    feats = FeatureUnion([
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2,
                                 sublinear_tf=True, max_features=60000, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                 sublinear_tf=True, max_features=120000, lowercase=True)),
    ])
    clf = LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced")
    return Pipeline([("features", feats), ("clf", clf)])


def main():
    t0 = time.time()
    neg_fit, pos_fit, neg_val, pos_val, val_pages = build()
    print(f"fit: {len(pos_fit)} pos / {len(neg_fit)} neg chunks | "
          f"val: {len(pos_val)} pos / {len(neg_val)} neg chunks")

    X = pos_fit + neg_fit
    y = np.array([1] * len(pos_fit) + [0] * len(neg_fit))
    pipe = make_pipeline().fit(X, y)

    pv = pipe.predict_proba(pos_val)[:, 1]
    nv = pipe.predict_proba(neg_val)[:, 1]
    auc = roc_auc_score([1] * len(pv) + [0] * len(nv), np.concatenate([pv, nv]))
    # strictly above the quantile (ties: the same ad text repeats on a page)
    threshold = float(max(0.5, np.quantile(nv, 1 - VAL_FPR_TARGET) + 1e-6))
    high = float(max(threshold, nv.max() + 1e-6, 0.9))
    print(f"val AUC={auc:.4f}  threshold={threshold:.3f}  high={high:.3f}")
    page_max = [max(pipe.predict_proba(p)[:, 1], default=0.0) for p in val_pages if p]
    print(f"val recall@threshold={np.mean(pv >= threshold):.3f}  "
          f"recall@high={np.mean(pv >= high):.3f}  "
          f"val chunk FPR={np.mean(nv >= threshold):.4f}  "
          f"val PAGE FPR={np.mean(np.array(page_max) >= threshold):.3f} (n={len(page_max)})")
    print("top benign val chunks:")
    for i in np.argsort(-nv)[:5]:
        print(f"  {nv[i]:.3f}  {neg_val[i][:110]!r}")

    DEFAULT_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "pipeline": pipe, "threshold": threshold, "high_threshold": high,
        "meta": {"val_auc": auc, "n_pos": len(pos_fit), "n_neg": len(neg_fit),
                 "trained": time.strftime("%Y-%m-%d"),
                 "sklearn_version": sklearn.__version__},
    }, DEFAULT_MODEL_PATH, compress=3)
    size = DEFAULT_MODEL_PATH.stat().st_size / 1e6
    print(f"saved {DEFAULT_MODEL_PATH} ({size:.1f} MB) in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()