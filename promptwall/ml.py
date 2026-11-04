"""Learned detector: TF-IDF (word + char n-grams) + logistic regression.

Small and CPU-only on purpose (~ms per page). It complements the regex rules
by catching paraphrases and template variants the rules don't list. It is
trained by bench/train_classifier.py; see the README for what it was trained
on and its measured limits.

Security note: the model file is a joblib pickle. Only load the file shipped
with the package or one you trained yourself - never one from an untrusted
source.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MODEL_PATH = Path(__file__).parent / "data" / "classifier.joblib"
MAX_CHUNK_CHARS = 400
# Chunks shorter than this are UI fragments ("Retype password", "#respond").
# Scoring them produced most of the benchmark's false positives in run 1.
MIN_WORDS = 6
_WORD = re.compile(r"\w+")


def eligible(chunk: str) -> bool:
    return len(_WORD.findall(chunk)) >= MIN_WORDS

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


def chunk_text(text: str, max_chars: int = MAX_CHUNK_CHARS) -> list[str]:
    """Pack sentences/lines into windows of <= max_chars.

    Injections usually span a few short lines (e.g. AgentDojo's <INFORMATION>
    block), so packing neighbours keeps them in one window.
    """
    parts = [p.strip() for p in _SENT_SPLIT.split(text) if p and p.strip()]
    chunks: list[str] = []
    cur = ""
    for p in parts:
        while len(p) > max_chars:  # very long run-on segment
            if cur:
                chunks.append(cur)
                cur = ""
            chunks.append(p[:max_chars])
            p = p[max_chars:]
        if not cur:
            cur = p
        elif len(cur) + 1 + len(p) <= max_chars:
            cur = f"{cur} {p}"
        else:
            chunks.append(cur)
            cur = p
    if cur:
        chunks.append(cur)
    return chunks


@dataclass
class ChunkScore:
    prob: float
    text: str


class ModelLoadError(RuntimeError):
    """The model file can't be used with the installed scikit-learn."""


class InjectionClassifier:
    def __init__(self, path: str | Path = DEFAULT_MODEL_PATH):
        import warnings

        import joblib  # optional dependency
        import sklearn

        with warnings.catch_warnings():
            # sklearn warns on version mismatch; we check explicitly below.
            warnings.simplefilter("ignore")
            bundle = joblib.load(path)
        self.pipeline = bundle["pipeline"]
        self.threshold: float = bundle["threshold"]
        self.high_threshold: float = bundle["high_threshold"]
        self.meta: dict = bundle.get("meta", {})

        trained_with = self.meta.get("sklearn_version")
        installed = sklearn.__version__
        try:
            self.pipeline.predict_proba(["smoke test sentence for the classifier"])
        except Exception as e:  # noqa: BLE001 - any failure means unusable
            raise ModelLoadError(
                f"{path} was trained with scikit-learn {trained_with or 'unknown'} but "
                f"{installed} is installed ({type(e).__name__}: {e}). Fix: "
                f"pip install -U \"scikit-learn>={trained_with or '1.9'}\" or retrain "
                f"with bench/train_classifier.py") from e
        if trained_with and trained_with.split(".")[:2] != installed.split(".")[:2]:
            warnings.warn(f"promptwall model trained with scikit-learn {trained_with}, "
                          f"running {installed}; scores may differ slightly.", stacklevel=2)

    @classmethod
    def load_default(cls) -> "InjectionClassifier | None":
        """Load the bundled model, or return None (rules-only) with a warning."""
        import warnings

        if not DEFAULT_MODEL_PATH.exists():
            return None
        try:
            return cls(DEFAULT_MODEL_PATH)
        except ImportError:
            return None
        except ModelLoadError as e:
            warnings.warn(f"promptwall ML layer disabled: {e}", stacklevel=2)
            return None

    def predict_proba(self, texts: list[str]) -> list[float]:
        if not texts:
            return []
        return [float(p) for p in self.pipeline.predict_proba(texts)[:, 1]]

    def score_text(self, text: str) -> list[ChunkScore]:
        return self.score_many([text])[0]

    def score_many(self, texts: list[str]) -> list[list[ChunkScore]]:
        """Score several texts in ONE model call (pages have 100s of hidden spans)."""
        per_text = [[c for c in chunk_text(t) if eligible(c)] for t in texts]
        flat = [c for cs in per_text for c in cs]
        probs = iter(self.predict_proba(flat))
        return [[ChunkScore(next(probs), c) for c in cs] for cs in per_text]