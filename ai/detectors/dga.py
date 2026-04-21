"""
Cerberix AI — DGA (Domain Generation Algorithm) Detector

Detects algorithmically generated domain names commonly used by malware
for C2 communication. Uses character-level entropy analysis and
consonant ratio scoring — no external model files needed.
"""

import math
import re
from dataclasses import dataclass
from typing import Optional

# Known benign high-entropy domains (CDNs, cloud services)
WHITELIST_PATTERNS = [
    r".*\.amazonaws\.com$",
    r".*\.cloudfront\.net$",
    r".*\.akamaihd\.net$",
    r".*\.cloudflare\.com$",
    r".*\.googleapis\.com$",
    r".*\.gstatic\.com$",
    r".*\.azure\.com$",
    r".*\.microsoft\.com$",
    r".*\.windows\.net$",
    r".*\.github\.com$",
    r".*\.docker\.com$",
    r".*\.docker\.io$",
]

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


@dataclass
class DGAAlert:
    domain: str
    entropy: float
    consonant_ratio: float
    score: float
    client_ip: str
    severity: str = "high"
    description: str = ""


class DGADetector:
    """
    Scores domains based on:
    1. Shannon entropy of the subdomain label
    2. Consonant-to-vowel ratio
    3. Digit density
    4. Label length
    5. Bigram frequency deviation

    No ML model files — pure statistical analysis.
    """

    def __init__(self, entropy_threshold: float = 3.5):
        self.entropy_threshold = entropy_threshold
        self._whitelist_re = [re.compile(p) for p in WHITELIST_PATTERNS]
        # Track recently flagged to avoid duplicates
        self._flagged: set[str] = set()
        self._max_flagged = 10000

        # English bigram frequency (common bigrams score low)
        self._common_bigrams = {
            "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
            "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
            "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
            "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
        }

    def analyze(self, domain: str, client_ip: str = "") -> Optional[DGAAlert]:
        """Analyze a domain name for DGA characteristics."""
        domain = domain.lower().strip().rstrip(".")

        # Skip whitelisted
        for pattern in self._whitelist_re:
            if pattern.match(domain):
                return None

        # Skip already flagged
        if domain in self._flagged:
            return None

        # Extract the registerable domain label (2nd-level)
        parts = domain.split(".")
        if len(parts) < 2:
            return None

        # Use the longest non-TLD label for analysis
        labels = [p for p in parts[:-1] if len(p) > 1]  # skip TLD
        if not labels:
            return None

        label = max(labels, key=len)

        # Skip very short labels (not enough signal)
        if len(label) < 6:
            return None

        # ── Scoring ─────────────────────────────────────────
        entropy = self._shannon_entropy(label)
        consonant_ratio = self._consonant_ratio(label)
        digit_ratio = sum(1 for c in label if c.isdigit()) / len(label)
        bigram_score = self._bigram_score(label)
        length_score = min(len(label) / 30.0, 1.0)

        # Weighted composite score (0-1 scale, higher = more suspicious)
        score = (
            (entropy / 5.0) * 0.30
            + consonant_ratio * 0.25
            + digit_ratio * 0.20
            + (1.0 - bigram_score) * 0.15
            + length_score * 0.10
        )

        # Threshold check
        if entropy >= self.entropy_threshold and score >= 0.55:
            if len(self._flagged) >= self._max_flagged:
                self._flagged.clear()
            self._flagged.add(domain)

            return DGAAlert(
                domain=domain,
                entropy=round(entropy, 3),
                consonant_ratio=round(consonant_ratio, 3),
                score=round(score, 3),
                client_ip=client_ip,
                severity="high" if score > 0.75 else "medium",
                description=(
                    f"Suspected DGA domain: {domain} "
                    f"(entropy={entropy:.2f}, score={score:.2f})"
                ),
            )

        return None

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    @staticmethod
    def _consonant_ratio(text: str) -> float:
        """Ratio of consonants to total alphabetic characters."""
        alpha = [c for c in text.lower() if c.isalpha()]
        if not alpha:
            return 0.0
        return sum(1 for c in alpha if c in CONSONANTS) / len(alpha)

    def _bigram_score(self, text: str) -> float:
        """Score based on how many bigrams are common English bigrams."""
        if len(text) < 2:
            return 0.0
        bigrams = [text[i:i + 2] for i in range(len(text) - 1)]
        alpha_bigrams = [b for b in bigrams if b.isalpha()]
        if not alpha_bigrams:
            return 0.0
        common_count = sum(1 for b in alpha_bigrams if b in self._common_bigrams)
        return common_count / len(alpha_bigrams)
