"""Rule-based instruction patterns. Severity here is the base severity for
visible text; the scanner escalates one level when a match is in hidden content."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    pattern: re.Pattern


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


RULES: list[Rule] = [
    Rule(
        "override.ignore_previous", "instruction_override", Severity.HIGH,
        _r(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}"
           r"\b(previous|prior|above|earlier|all|any|your)\b[^.\n]{0,40}"
           r"\b(instructions?|prompts?|rules?|directions?|guidelines?|context)\b"),
    ),
    Rule(
        "override.new_instructions", "instruction_override", Severity.MEDIUM,
        _r(r"\b(new|updated|real|actual)\s+(system\s+)?(instructions?|task|objective)\s*:"),
    ),
    Rule(
        "role.chat_template_token", "role_hijack", Severity.HIGH,
        _r(r"<\|?\s*(system|im_start|im_end|endoftext)\s*\|?>|\[/?INST\]"),
    ),
    Rule(
        # LOW on purpose: "System: Windows 11" is common on product pages.
        "role.fake_system_label", "role_hijack", Severity.LOW,
        _r(r"(^|\n)\s*\[?\s*(system|developer)\s*\]?\s*:"),
    ),
    Rule(
        "role.persona_switch", "role_hijack", Severity.MEDIUM,
        _r(r"\byou are now\b|\bfrom now on,? you\b"
           r"|\b(enter|switch to|enable)\s+(developer|dan|god|jailbreak)\s+mode\b"),
    ),
    Rule(
        "target.addresses_agent", "agent_targeting", Severity.LOW,
        _r(r"\b(ai|assistant|agent|llm|language model|chatbot)s?\b[^.\n]{0,30}"
           r"\b(must|should|are instructed to|need to|will now)\b"),
    ),
    Rule(
        "secrecy.hide_from_user", "concealment", Severity.HIGH,
        _r(r"\b(do not|don't|never|without)\b[^.\n]{0,25}"
           r"\b(tell|telling|inform|informing|mention|mentioning|reveal|revealing|alert|alerting)\b"
           r"[^.\n]{0,25}\b(the )?(user|human|operator)\b"),
    ),
    Rule(
        "exfil.sensitive_data", "exfiltration", Severity.HIGH,
        # "email" only as a verb ("email the/all/your ..."): login forms that say
        # "Email address ... Password" were false positives in benchmark run 1.
        _r(r"\b(send|forward|post|upload|leak|exfiltrate|transmit"
           r"|e-?mail\s+(?:me|us|the|all|your|my|their|its|any|these|those))\b[^.\n]{0,40}"
           r"\b(passwords?|api[ _-]?keys?|tokens?|credentials?|cookies?"
           r"|chat history|conversation|system prompt|private data)\b"),
    ),
    Rule(
        "exfil.markdown_image", "exfiltration", Severity.MEDIUM,
        _r(r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*=[^)]*\)"),
    ),
    Rule(
        "action.navigate_or_run", "tool_abuse", Severity.LOW,
        _r(r"\b(click|navigate to|go to|visit|open|download|execute|run)\b[^.\n]{0,30}https?://"),
    ),
]