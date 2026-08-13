from __future__ import annotations

import re
from typing import Dict, Iterable, List, Set

from .models import LanguageFeatures


URGENCY_PATTERNS: Dict[str, re.Pattern[str]] = {
    "urgent": re.compile(r"\burgent\b", re.IGNORECASE),
    "immediately": re.compile(r"\bimmediately\b", re.IGNORECASE),
    "act now": re.compile(r"\bact\s+now\b", re.IGNORECASE),
    "as soon as possible": re.compile(
        r"\bas\s+soon\s+as\s+possible\b",
        re.IGNORECASE,
    ),
    "within 24 hours": re.compile(
        r"\bwithin\s+24\s+hours?\b",
        re.IGNORECASE,
    ),
    "limited time": re.compile(
        r"\blimited\s+time\b",
        re.IGNORECASE,
    ),
    "final notice": re.compile(
        r"\bfinal\s+notice\b",
        re.IGNORECASE,
    ),
}


CREDENTIAL_PATTERNS: Dict[str, re.Pattern[str]] = {
    "password": re.compile(
        r"\bpassword\b",
        re.IGNORECASE,
    ),
    "username": re.compile(
        r"\buser\s*name\b|\busername\b",
        re.IGNORECASE,
    ),
    "credentials": re.compile(
        r"\bcredentials?\b",
        re.IGNORECASE,
    ),
    "login": re.compile(
        r"\blog\s*in\b|\blogin\b",
        re.IGNORECASE,
    ),
    "sign in": re.compile(
        r"\bsign\s*in\b",
        re.IGNORECASE,
    ),
    "verify your password": re.compile(
        r"\bverify\s+your\s+password\b",
        re.IGNORECASE,
    ),
    "confirm your password": re.compile(
        r"\bconfirm\s+your\s+password\b",
        re.IGNORECASE,
    ),
}


FINANCIAL_PATTERNS: Dict[str, re.Pattern[str]] = {
    "bank account": re.compile(
        r"\bbank\s+account\b",
        re.IGNORECASE,
    ),
    "credit card": re.compile(
        r"\bcredit\s+card\b",
        re.IGNORECASE,
    ),
    "debit card": re.compile(
        r"\bdebit\s+card\b",
        re.IGNORECASE,
    ),
    "payment": re.compile(
        r"\bpayment\b",
        re.IGNORECASE,
    ),
    "wire transfer": re.compile(
        r"\bwire\s+transfer\b",
        re.IGNORECASE,
    ),
    "invoice": re.compile(
        r"\binvoice\b",
        re.IGNORECASE,
    ),
    "refund": re.compile(
        r"\brefund\b",
        re.IGNORECASE,
    ),
    "billing": re.compile(
        r"\bbilling\b",
        re.IGNORECASE,
    ),
}


VERIFICATION_PATTERNS: Dict[str, re.Pattern[str]] = {
    "verify": re.compile(
        r"\bverify\b",
        re.IGNORECASE,
    ),
    "verification": re.compile(
        r"\bverification\b",
        re.IGNORECASE,
    ),
    "confirm your identity": re.compile(
        r"\bconfirm\s+your\s+identity\b",
        re.IGNORECASE,
    ),
    "verify your identity": re.compile(
        r"\bverify\s+your\s+identity\b",
        re.IGNORECASE,
    ),
    "confirm account": re.compile(
        r"\bconfirm\s+(?:your\s+)?account\b",
        re.IGNORECASE,
    ),
    "verify account": re.compile(
        r"\bverify\s+(?:your\s+)?account\b",
        re.IGNORECASE,
    ),
}


SUSPENSION_PATTERNS: Dict[str, re.Pattern[str]] = {
    "account suspended": re.compile(
        r"\baccount\s+(?:(?:is|has\s+been|will\s+be)\s+)?suspended\b",
        re.IGNORECASE,
    ),

    "account locked": re.compile(
        r"\baccount\s+(?:(?:is|has\s+been|will\s+be)\s+)?locked\b",
        re.IGNORECASE,
    ),

    "account disabled": re.compile(
        r"\baccount\s+(?:(?:is|has\s+been|will\s+be)\s+)?disabled\b",
        re.IGNORECASE,
    ),

    "access restricted": re.compile(
        r"\baccess\s+(?:(?:is|has\s+been|will\s+be)\s+)?restricted\b",
        re.IGNORECASE,
    ),

    "account terminated": re.compile(
        r"\baccount\s+(?:(?:is|has\s+been|will\s+be)\s+)?terminated\b",
        re.IGNORECASE,
    ),
}


PASSWORD_RESET_PATTERNS: Dict[str, re.Pattern[str]] = {
    "reset your password": re.compile(
        r"\breset\s+your\s+password\b",
        re.IGNORECASE,
    ),
    "password reset": re.compile(
        r"\bpassword\s+reset\b",
        re.IGNORECASE,
    ),
    "change your password": re.compile(
        r"\bchange\s+your\s+password\b",
        re.IGNORECASE,
    ),
    "update your password": re.compile(
        r"\bupdate\s+your\s+password\b",
        re.IGNORECASE,
    ),
}


def analyze_language(
    subject: str | None,
    body: str | None,
) -> LanguageFeatures:
    """
    Extract deterministic linguistic and social-engineering evidence.

    The analyzer identifies observable language patterns only.

    It does not:
        - classify the email,
        - assign a risk score,
        - make a triage decision,
        - call external services,
        - use an LLM.
    """

    text = _combine_text(
        subject=subject,
        body=body,
    )

    urgency_terms = _find_matches(
        text,
        URGENCY_PATTERNS,
    )

    credential_terms = _find_matches(
        text,
        CREDENTIAL_PATTERNS,
    )

    financial_terms = _find_matches(
        text,
        FINANCIAL_PATTERNS,
    )

    verification_terms = _find_matches(
        text,
        VERIFICATION_PATTERNS,
    )

    suspension_terms = _find_matches(
        text,
        SUSPENSION_PATTERNS,
    )

    password_terms = _find_matches(
        text,
        PASSWORD_RESET_PATTERNS,
    )

    return LanguageFeatures(
        urgency_language=bool(
            urgency_terms
        ),
        credential_request=bool(
            credential_terms
        ),
        financial_request=bool(
            financial_terms
        ),
        verification_request=bool(
            verification_terms
        ),
        account_suspension_language=bool(
            suspension_terms
        ),
        password_reset_language=bool(
            password_terms
        ),
        matched_urgency_terms=urgency_terms,
        matched_credential_terms=credential_terms,
        matched_financial_terms=financial_terms,
        matched_verification_terms=verification_terms,
        matched_suspension_terms=suspension_terms,
        matched_password_terms=password_terms,
    )


def _find_matches(
    text: str,
    patterns: Dict[str, re.Pattern[str]],
) -> List[str]:
    """
    Return sorted, deduplicated semantic labels for patterns
    matched in the text.
    """

    if not text:
        return []

    matched: Set[str] = set()

    for label, pattern in patterns.items():
        if pattern.search(text):
            matched.add(label)

    return sorted(matched)


def _combine_text(
    subject: str | None,
    body: str | None,
) -> str:
    """
    Combine nullable subject and body for linguistic analysis.
    """

    values: Iterable[str] = (
        value.strip()
        for value in (
            subject or "",
            body or "",
        )
        if value and value.strip()
    )

    return "\n".join(values)