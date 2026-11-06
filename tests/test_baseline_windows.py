"""The baseline must scan EVERY token of a page: a window bug that dropped the
tail would hide attacks placed near the end and make the baseline look worse."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))
from baselines import HFDetector  # noqa: E402


def _detector(window: int = 512) -> HFDetector:
    d = HFDetector.__new__(HFDetector)          # no model download
    d.WINDOW = max(16, min(window, 512) - 2)
    d.STRIDE = max(1, d.WINDOW - max(8, d.WINDOW // 8))
    return d


@pytest.mark.parametrize("window", [512, 128, 64])
@pytest.mark.parametrize("n", [0, 5, 510, 511, 956, 957, 1200, 5000])
def test_windows_cover_every_token_within_limit(window, n):
    d = _detector(window)
    ids = list(range(n))
    wins = d._windows(ids)
    seen = set().union(*map(set, wins)) if wins else set()
    assert seen == set(ids)
    assert max((len(w) for w in wins), default=0) <= d.WINDOW
    # Windows keep token order and are contiguous slices of the page.
    for w in wins:
        assert w == ids[w[0]:w[0] + len(w)] if w else True


def test_window_keys_differ_for_different_ids():
    assert HFDetector._key([1, 2, 3]) != HFDetector._key([1, 23])