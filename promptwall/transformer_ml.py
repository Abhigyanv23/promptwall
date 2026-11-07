"""Transformer classifier: a fine-tuned small transformer in place of TF-IDF.

Same interface as ml.InjectionClassifier (threshold, high_threshold, meta,
predict_proba, score_text, score_many), so Scanner, the sanitizer and the
benchmark use it unchanged:

    from promptwall import Scanner
    from promptwall.transformer_ml import TransformerClassifier
    scanner = Scanner(classifier=TransformerClassifier("path/or/hf-repo-id"))

The model directory is what bench/train_transformer.py writes: a Hugging Face
model + tokenizer, plus promptwall_meta.json holding the thresholds that were
calibrated on validation pages.

Optional cascade (prefilter=...): score every chunk with the cheap TF-IDF model
first and send only chunks above `prefilter_threshold` to the transformer.
Chunks below it keep their TF-IDF score, which is far below the transformer's
threshold, so they cannot raise a finding. This trades a little recall for a
large CPU speed-up; the benchmark measures both settings.

    pip install "promptwall-agent[transformer]"
"""
from __future__ import annotations

import json
from pathlib import Path

from .ml import ChunkScore, chunk_text, eligible

META_FILE = "promptwall_meta.json"
MAX_TOKENS = 128   # chunks are <= 400 characters, about 100 tokens


class TransformerClassifier:
    def __init__(self, model: str | Path, *, device: str | None = None, batch_size: int = 64,
                 prefilter=None, prefilter_threshold: float = 0.02,
                 cache_size: int = 200_000):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.batch_size = batch_size
        self.tok = AutoTokenizer.from_pretrained(str(model))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(model))
        self.model.to(self.device).eval()

        meta_path = Path(model) / META_FILE
        if meta_path.exists():
            bundle = json.loads(meta_path.read_text(encoding="utf-8"))
        else:  # a Hugging Face repo id: fetch the metadata file from the repo
            from huggingface_hub import hf_hub_download
            bundle = json.loads(Path(hf_hub_download(str(model), META_FILE)).read_text(
                encoding="utf-8"))
        self.threshold: float = bundle["threshold"]
        self.high_threshold: float = bundle["high_threshold"]
        self.meta: dict = bundle.get("meta", {}) | {"kind": "transformer", "model": str(model)}
        self.prefilter = prefilter
        self.prefilter_threshold = prefilter_threshold
        if prefilter is not None:
            self.meta |= {"cascade_prefilter_threshold": prefilter_threshold}
        # Score cache: identical text always gets the identical score, and pages
        # repeat a lot of text (navigation, footers, boilerplate). cache_size=0
        # disables it, e.g. to measure cold per-page latency.
        self.cache_size = cache_size
        self._cache: dict[str, float] = {}
        self.stats = {"chunks": 0, "cache_hits": 0, "sent_to_transformer": 0}

    # -- scoring
    def _transformer_proba(self, texts: list[str]) -> list[float]:
        out: list[float] = []
        T = self.torch
        for i in range(0, len(texts), self.batch_size):
            batch = texts[i:i + self.batch_size]
            enc = self.tok(batch, truncation=True, max_length=MAX_TOKENS, padding=True,
                           return_tensors="pt").to(self.device)
            with T.no_grad():
                logits = self.model(**enc).logits
            out.extend(T.softmax(logits.float(), dim=-1)[:, 1].tolist())
        return out

    def _score_uncached(self, texts: list[str]) -> list[float]:
        if self.prefilter is None:
            self.stats["sent_to_transformer"] += len(texts)
            return self._transformer_proba(texts)
        cheap = self.prefilter.predict_proba(texts)
        hard = [i for i, p in enumerate(cheap) if p >= self.prefilter_threshold]
        self.stats["sent_to_transformer"] += len(hard)
        probs = list(cheap)
        for i, p in zip(hard, self._transformer_proba([texts[i] for i in hard])):
            probs[i] = p
        return probs

    def _lookup(self, texts: list[str], count: bool) -> list[float]:
        if count:
            self.stats["chunks"] += len(texts)
        if self.cache_size <= 0:
            return self._score_uncached(texts)
        cached = [t in self._cache for t in texts]
        if count:
            self.stats["cache_hits"] += sum(cached)
        todo = list(dict.fromkeys(t for t, c in zip(texts, cached) if not c))  # unique, in order
        if todo:
            if len(self._cache) + len(todo) > self.cache_size:
                self._cache.clear()               # simple bound; refills from the next pages
            self._cache.update(zip(todo, self._score_uncached(todo)))
        return [self._cache[t] for t in texts]

    def predict_proba(self, texts: list[str]) -> list[float]:
        return self._lookup(texts, count=True) if texts else []

    def prefetch(self, texts: list[str]) -> None:
        """Score many texts in ONE batched call, so later single-text calls hit the cache."""
        if texts and self.cache_size > 0:
            self._lookup(texts, count=False)

    def score_text(self, text: str) -> list[ChunkScore]:
        return self.score_many([text])[0]

    def score_many(self, texts: list[str]) -> list[list[ChunkScore]]:
        per_text = [[c for c in chunk_text(t) if eligible(c)] for t in texts]
        flat = [c for cs in per_text for c in cs]
        probs = iter(self.predict_proba(flat))
        return [[ChunkScore(next(probs), c) for c in cs] for cs in per_text]