"""The baseline must scan EVERY token of a page: a window bug that dropped the
tail would hide attacks placed near the end and make the baseline look worse."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))
from baselines import HFDetector  # noqa: E402


class FakeTok:
    def __call__(self, text, **kw):
        return {"input_ids": list(range(len(text.split())))}

    def decode(self, ids, **kw):
        return " ".join(f"w{i}" for i in ids)


@pytest.mark.parametrize("n", [5, 510, 511, 956, 957, 1200, 5000])
def test_windows_cover_every_token_within_512(n):
    d = HFDetector.__new__(HFDetector)
    d.tok = FakeTok()
    wins = d._windows(" ".join(["x"] * n))
    if n <= HFDetector.WINDOW:
        assert len(wins) == 1
        return
    seen = set().union(*({int(t[1:]) for t in w.split()} for w in wins))
    assert seen == set(range(n))
    assert max(len(w.split()) for w in wins) <= HFDetector.WINDOW