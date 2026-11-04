"""Invisible / control Unicode used to hide or split injected instructions."""
import re

# Zero-width chars. Note: ZWJ/ZWNJ are legitimate in Devanagari and emoji,
# so they are only flagged above a count threshold - but always stripped
# before pattern matching (attackers use them to split keywords).
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")

# Bidirectional overrides/isolates (text that renders differently than it reads).
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")

# Unicode "tag" block - invisible copies of ASCII ("ASCII smuggling").
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")


def decode_tag_smuggling(text: str) -> str:
    """Recover the ASCII hidden in Unicode tag characters."""
    out = []
    for ch in TAG_CHARS.findall(text):
        cp = ord(ch) - 0xE0000
        if 0x20 <= cp < 0x7F:
            out.append(chr(cp))
    return "".join(out)


def strip_invisible(text: str) -> str:
    return TAG_CHARS.sub("", BIDI.sub("", ZERO_WIDTH.sub("", text)))


def invisible_counts(text: str) -> dict[str, int]:
    return {
        "zero_width": len(ZERO_WIDTH.findall(text)),
        "bidi": len(BIDI.findall(text)),
        "tag": len(TAG_CHARS.findall(text)),
    }