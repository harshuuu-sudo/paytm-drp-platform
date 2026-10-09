"""
Look-Alike & Homoglyph Detection Engine
Unicode / Leetspeak normalization, token padding detection, Levenshtein distance,
and Benign vs Malicious spoofing differentiation.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple
from config.brand_config import (
    BRAND_STEM,
    LEETSPEAK_MAP,
    UNICODE_HOMOGLYPH_MAP,
    HIGH_RISK_PADDING_TOKENS,
)

# Optional fast C-accelerated Levenshtein/RapidFuzz with pure-Python fallback
try:
    import Levenshtein as lev_mod

    def _levenshtein_distance(s1: str, s2: str) -> int:
        return lev_mod.distance(s1, s2)

    def _levenshtein_ratio(s1: str, s2: str) -> float:
        return lev_mod.ratio(s1, s2)

except ImportError:
    try:
        from rapidfuzz.distance import Levenshtein as rf_lev

        def _levenshtein_distance(s1: str, s2: str) -> int:
            return rf_lev.distance(s1, s2)

        def _levenshtein_ratio(s1: str, s2: str) -> float:
            return rf_lev.normalized_similarity(s1, s2)
    except ImportError:
        # Pure-python fallback
        def _levenshtein_distance(s1: str, s2: str) -> int:
            if len(s1) < len(s2):
                return _levenshtein_distance(s2, s1)
            if len(s2) == 0:
                return len(s1)
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            return previous_row[-1]

        def _levenshtein_ratio(s1: str, s2: str) -> float:
            dist = _levenshtein_distance(s1, s2)
            lens = len(s1) + len(s2)
            return (lens - dist) / lens if lens > 0 else 1.0


@dataclass
class HomoglyphAnalysisResult:
    original_text: str
    normalized_clean: str
    de_leeted_text: str
    detected_homoglyphs: List[Dict[str, str]] = field(default_factory=list)
    detected_leetspeak: List[Dict[str, str]] = field(default_factory=list)
    has_homoglyphs: bool = False
    has_leetspeak: bool = False
    stem_detected: bool = False
    exact_stem_match: bool = False
    padding_tokens_found: List[str] = field(default_factory=list)
    levenshtein_distance_to_stem: int = 999
    similarity_ratio_to_stem: float = 0.0
    is_likely_benign: bool = False
    benign_rationale: str = ""
    identity_risk_score: float = 0.0
    flags: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "original_text": self.original_text,
            "normalized_clean": self.normalized_clean,
            "de_leeted_text": self.de_leeted_text,
            "detected_homoglyphs": self.detected_homoglyphs,
            "detected_leetspeak": self.detected_leetspeak,
            "has_homoglyphs": self.has_homoglyphs,
            "has_leetspeak": self.has_leetspeak,
            "stem_detected": self.stem_detected,
            "exact_stem_match": self.exact_stem_match,
            "padding_tokens_found": self.padding_tokens_found,
            "levenshtein_distance_to_stem": self.levenshtein_distance_to_stem,
            "similarity_ratio_to_stem": round(self.similarity_ratio_to_stem, 4),
            "is_likely_benign": self.is_likely_benign,
            "benign_rationale": self.benign_rationale,
            "identity_risk_score": round(self.identity_risk_score, 2),
            "flags": self.flags,
        }


class LookAlikeHomoglyphEngine:
    """
    Advanced Look-Alike, Homoglyph, and Identity Impersonation Detection Engine.
    Handles Unicode scripts, Leetspeak, Token Padding, and Benign Filtering.
    """

    def __init__(
        self,
        brand_stem: str = BRAND_STEM,
        padding_tokens: Set[str] = HIGH_RISK_PADDING_TOKENS,
    ):
        self.brand_stem = brand_stem.lower()
        self.padding_tokens = {p.lower() for p in padding_tokens}

    def normalize_text(self, text: str) -> Tuple[str, str, List[Dict[str, str]], List[Dict[str, str]]]:
        """
        Performs dual-stage normalization:
        1. Unicode homoglyph transformation (Cyrillic, Greek, fullwidth -> ASCII)
        2. Leetspeak substitution ('0'->'o', '4'->'a', '1'->'l', '$'->'s', '@'->'a')
        Returns (clean_text, de_leeted_text, homoglyphs_found, leetspeak_found)
        """
        if not text:
            return "", "", [], []

        homoglyphs_found: List[Dict[str, str]] = []
        leetspeak_found: List[Dict[str, str]] = []
        # Strip leading '@' handle prefix if present
        raw_target = text
        if raw_target.startswith("@"):
            raw_target = raw_target[1:]

        # Step A: Strip combining accents via NFKD
        nfkd_form = unicodedata.normalize("NFKD", raw_target)

        # Step B: Scan and replace Unicode Homoglyphs
        stage1_chars = []
        for i, ch in enumerate(nfkd_form):
            if ch in UNICODE_HOMOGLYPH_MAP:
                mapped = UNICODE_HOMOGLYPH_MAP[ch]
                homoglyphs_found.append({
                    "char": ch,
                    "mapped": mapped,
                    "pos": i,
                    "type": "Unicode Homoglyph"
                })
                stage1_chars.append(mapped)
            else:
                stage1_chars.append(ch)

        stage1_text = "".join(stage1_chars).lower()

        # Step C: Scan and replace Leetspeak characters
        stage2_chars = []
        for i, ch in enumerate(stage1_text):
            if ch in LEETSPEAK_MAP:
                mapped = LEETSPEAK_MAP[ch]
                leetspeak_found.append({
                    "char": ch,
                    "mapped": mapped,
                    "pos": i,
                    "type": "Leetspeak Substitution"
                })
                stage2_chars.append(mapped)
            else:
                stage2_chars.append(ch)

        de_leeted_text = "".join(stage2_chars)

        # Clean text removes separators for compact stem comparison
        clean_text = re.sub(r"[^a-zA-Z0-9]", "", de_leeted_text)

        return clean_text, de_leeted_text, homoglyphs_found, leetspeak_found

    def analyze(
        self,
        candidate_text: str,
        display_name: str = "",
        bio: str = "",
    ) -> HomoglyphAnalysisResult:
        """
        Evaluates candidate text (handle, title, or name) for impersonation, homoglyphs,
        leetspeak, token padding, and differentiates benign entities.
        """
        clean_text, de_leeted, homoglyphs, leets = self.normalize_text(candidate_text)
        flags: List[str] = []

        # Tokenization of de-leeted text (split by non-alphanumeric)
        raw_tokens = [t for t in re.split(r"[^a-zA-Z0-9]+", de_leeted.lower()) if t]
        clean_tokens = [re.sub(r"[^a-z0-9]", "", t) for t in raw_tokens if t]

        # 1. Stem Matching
        exact_stem_match = self.brand_stem in clean_tokens
        stem_detected = (self.brand_stem in clean_text) or exact_stem_match

        # 2. Token Padding Detection (e.g. "care", "refund", "upi", "support")
        padding_found = []
        for t in clean_tokens:
            if t in self.padding_tokens and t != self.brand_stem:
                padding_found.append(t)
        # Check sub-strings within tokens if concatenated (e.g. "paytmcare")
        for pad in self.padding_tokens:
            if pad in clean_text and pad not in padding_found and pad != self.brand_stem:
                padding_found.append(pad)

        # 3. Levenshtein Metrics to Brand Stem
        # Compare first token or closest token to brand stem
        min_dist = 999
        max_ratio = 0.0

        candidates_to_compare = clean_tokens if clean_tokens else [clean_text]
        for token in candidates_to_compare:
            d = _levenshtein_distance(token, self.brand_stem)
            r = _levenshtein_ratio(token, self.brand_stem)
            if d < min_dist:
                min_dist = d
            if r > max_ratio:
                max_ratio = r

        # Also compare entire clean string if short
        if len(clean_text) <= 12:
            d_full = _levenshtein_distance(clean_text, self.brand_stem)
            r_full = _levenshtein_ratio(clean_text, self.brand_stem)
            if d_full < min_dist:
                min_dist = d_full
            if r_full > max_ratio:
                max_ratio = r_full

        # 4. Homoglyph / Leetspeak Flags
        if homoglyphs:
            flags.append(f"FLAG_UNICODE_HOMOGLYPH: Found {len(homoglyphs)} lookalike character(s)")
        if leets:
            flags.append(f"FLAG_LEETSPEAK_SUBSTITUTION: Found {len(leets)} obfuscation character(s)")
        if padding_found:
            flags.append(f"FLAG_HIGH_RISK_PADDING: Brand hijacked with {padding_found}")
        if stem_detected:
            flags.append(f"FLAG_BRAND_STEM_DETECTED: Target brand '{self.brand_stem}' identified in payload")

        # 5. Differentiate Benign Third Parties (e.g., "Payton Miller", "Payment Gateway")
        is_benign = False
        benign_rationale = ""

        # Benign check:
        # If the word is a known natural word/name and does NOT have homoglyphs or leetspeak,
        # and does NOT contain financial scam padding, and similarity is modest.
        combined_context = f"{candidate_text} {display_name} {bio}".lower()
        has_any_scam_keyword = any(pad in combined_context for pad in self.padding_tokens)

        # Common benign names or terms containing "pay" or similar:
        # e.g., "payton", "payne", "payment", "paypal", "payday"
        benign_stems = {"payton", "payne", "patty", "payday", "payroll", "payer", "payout"}
        has_benign_token = any(b in clean_tokens for b in benign_stems)

        if not homoglyphs and not leets and not stem_detected:
            if has_benign_token and not has_any_scam_keyword:
                is_benign = True
                benign_rationale = (
                    f"Candidate contains benign linguistic/personal identifier (e.g., '{has_benign_token}') "
                    "with 0 homoglyphs/leetspeak and no financial phishing or support triggers."
                )
            elif min_dist >= 2 and max_ratio < 0.75 and not has_any_scam_keyword:
                is_benign = True
                benign_rationale = (
                    "Low lexical correlation to brand stem (Levenshtein distance >= 2) "
                    "and zero brand hijacking padding detected."
                )

        # 6. Compute Identity Risk Score (0 - 100)
        identity_score = 0.0

        if is_benign:
            identity_score = max(0.0, (max_ratio * 20.0))  # Max 15-20% for benign
        else:
            # Component A: Stem presence & Obfuscation
            if stem_detected or exact_stem_match:
                identity_score += 45.0
            elif min_dist == 1:
                # 1 char typo-squatting or swap (e.g. patym, pyatm)
                identity_score += 35.0
                flags.append("FLAG_TYPOSQUATTING: Character swap / 1-edit distance to brand stem")
            elif min_dist == 2 and max_ratio >= 0.70:
                identity_score += 20.0

            # Component B: Homoglyph / Leetspeak penalties
            if homoglyphs:
                identity_score += min(30.0, len(homoglyphs) * 15.0)
            if leets:
                identity_score += min(25.0, len(leets) * 10.0)

            # Component C: Padding Hijacking
            if padding_found:
                identity_score += min(30.0, len(padding_found) * 15.0)

            # Cap identity score at 100
            identity_score = min(100.0, identity_score)

        return HomoglyphAnalysisResult(
            original_text=candidate_text,
            normalized_clean=clean_text,
            de_leeted_text=de_leeted,
            detected_homoglyphs=homoglyphs,
            detected_leetspeak=leets,
            has_homoglyphs=bool(homoglyphs),
            has_leetspeak=bool(leets),
            stem_detected=stem_detected,
            exact_stem_match=exact_stem_match,
            padding_tokens_found=padding_found,
            levenshtein_distance_to_stem=min_dist,
            similarity_ratio_to_stem=max_ratio,
            is_likely_benign=is_benign,
            benign_rationale=benign_rationale,
            identity_risk_score=identity_score,
            flags=flags,
        )
