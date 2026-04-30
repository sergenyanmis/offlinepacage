import base64
import re
from dataclasses import dataclass, field
from typing import List
from lxml import etree


# ---------------------------------------------------------------------------
# Puan agirliklari
# ---------------------------------------------------------------------------
WEIGHTS = {
    "regex_test":              30,   # PropertyRegex, RegexTest vb. — en pahali test
    "regex_alternation":        3,   # Regex icindeki her | icin ek puan
    "regex_wildcard":           5,   # .* veya .+ kullanimi
    "regex_catastrophic":      20,   # ic ice quantifier — catastrophic backtracking
    "condition_count":          4,   # Her test kosulu icin
    "rule_reference":           8,   # Baska kurala referans (RuleMatch_Test)
    "multi_rule_reference":    10,   # Ayni testte 2+ kural referansi
    "reference_set_multi":      6,   # 3+ reference set kullanimi
    "ip_list_long":             5,   # 10+ IP/CIDR listesi
    "ariel_filter":             8,   # ArielFilterTest — AQL filtre
    "ariel_matches":           15,   # AQL icinde MATCHES/IMATCHES
    "negate":                   5,   # NOT koşulu
    "cross_field":              6,   # sourceOrDestination gibi cift alan
}

# Regex iceren test sinifları
REGEX_TEST_NAMES = {
    "com.q1labs.semsources.cre.tests.PropertyRegex",
    "com.q1labs.semsources.cre.tests.RegexTest",
    "com.q1labs.semsources.cre.tests.EventStringRegex_Test",
    "com.q1labs.semsources.cre.tests.PayloadTest",
    "com.q1labs.semsources.cre.tests.CustomPropertyRegex_Test",
    "com.q1labs.semsources.cre.tests.StringPropertyRegex_Test",
}

ARIEL_REGEX_KEYWORDS = {"IMATCHES", "MATCHES", "MATCHESREGEX"}


# ---------------------------------------------------------------------------
# Veri modelleri
# ---------------------------------------------------------------------------
@dataclass
class ComplexityBreakdown:
    condition_count: int = 0
    regex_test_count: int = 0
    regex_alternation_count: int = 0
    regex_wildcard_count: int = 0
    regex_catastrophic: bool = False
    rule_reference_count: int = 0
    multi_rule_reference: bool = False
    reference_set_count: int = 0
    ip_list_long: bool = False
    ariel_filter_count: int = 0
    ariel_matches: bool = False
    negate_count: int = 0
    cross_field: bool = False
    issues: List[str] = field(default_factory=list)


@dataclass
class ComplexityResult:
    rule_id: str
    rule_name: str
    score: int
    classification: str   # LOW / MEDIUM / HIGH / CRITICAL
    breakdown: ComplexityBreakdown
    recommendations: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar
# ---------------------------------------------------------------------------
def _clean(data: bytes) -> bytes:
    return re.sub(rb'[\x00-\x08\x0b\x0c\x0e-\x1f]', b'', data)


def _classify(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    return "LOW"


def _analyze_regex_pattern(pattern: str) -> dict:
    """Regex pattern'ini analiz et, risk faktörlerini dondur."""
    result = {
        "alternation_count": pattern.count("|"),
        "has_wildcard": bool(re.search(r'\.\*|\.\+', pattern)),
        "is_catastrophic": bool(re.search(r'(\.\*|\.\+).{0,20}(\.\*|\.\+)', pattern)),
    }
    return result


def _count_items(val: str) -> int:
    """Virgülle ayrılmış liste eleman sayısını döndür."""
    if not val:
        return 0
    return len([x for x in val.split(",") if x.strip()])


# ---------------------------------------------------------------------------
# Ana puanlama fonksiyonu
# ---------------------------------------------------------------------------
def score_rule_from_b64(rule_id: str, rule_data_b64: str) -> ComplexityResult:
    """
    Base64 encode edilmis rule_data XML'ini alir,
    karmasiklik puani hesaplar ve ComplexityResult dondurur.
    """
    bd = ComplexityBreakdown()
    raw_score = 0
    rule_name = rule_id

    try:
        raw = _clean(base64.b64decode(rule_data_b64 + "=="))
        inner = etree.fromstring(raw)
        rule_name = inner.findtext("name") or rule_id
        tests = inner.findall(".//test")

        # --- 1. Kosul sayisi ---
        bd.condition_count = len(tests)
        raw_score += bd.condition_count * WEIGHTS["condition_count"]

        for test in tests:
            tname = test.get("name", "")
            negate = test.get("negate", "false") == "true"
            user_selections = [
                (us.text or "") for us in test.findall(".//userSelection")
            ]
            all_vals = " ".join(user_selections)

            # --- 2. NOT kosulu ---
            if negate:
                bd.negate_count += 1
                raw_score += WEIGHTS["negate"]
                bd.issues.append(f"NOT kosulu kullanilmis: {tname}")

            # --- 3. Regex test ---
            if tname in REGEX_TEST_NAMES:
                bd.regex_test_count += 1
                raw_score += WEIGHTS["regex_test"]

                # Regex pattern analizi (ikinci userSelection genelde pattern)
                pattern = user_selections[1] if len(user_selections) > 1 else ""
                regex_info = _analyze_regex_pattern(pattern)

                alt_count = regex_info["alternation_count"]
                if alt_count > 0:
                    bd.regex_alternation_count += alt_count
                    raw_score += alt_count * WEIGHTS["regex_alternation"]
                    bd.issues.append(
                        f"Regex icinde {alt_count} alternation (|) var"
                    )

                if regex_info["has_wildcard"]:
                    bd.regex_wildcard_count += 1
                    raw_score += WEIGHTS["regex_wildcard"]
                    bd.issues.append("Regex icinde .* veya .+ kullanimi var")

                if regex_info["is_catastrophic"]:
                    bd.regex_catastrophic = True
                    raw_score += WEIGHTS["regex_catastrophic"]
                    bd.issues.append(
                        "KRITIK: Catastrophic backtracking riski — ic ice wildcard"
                    )

            # --- 4. Kural referansi (RuleMatch_Test) ---
            elif "RuleMatch_Test" in tname:
                # Kac kurala referans veriliyor?
                # UUID listesi virgülle ayrılır
                ref_count = _count_items(
                    next((v for v in user_selections if "-" in v), "")
                )
                bd.rule_reference_count += max(ref_count, 1)
                raw_score += WEIGHTS["rule_reference"]

                if ref_count > 1:
                    bd.multi_rule_reference = True
                    raw_score += WEIGHTS["multi_rule_reference"]
                    bd.issues.append(
                        f"Tek testte {ref_count} farkli kurala referans"
                    )

            # --- 5. Reference Set ---
            elif "ReferenceSetTest" in tname:
                # Set ID'leri virgülle ayrılır
                set_val = next(
                    (v for v in user_selections if re.search(r'\d+', v) and "," in v),
                    ""
                )
                set_count = _count_items(set_val)
                bd.reference_set_count += set_count
                if set_count >= 3:
                    raw_score += WEIGHTS["reference_set_multi"]
                    bd.issues.append(
                        f"{set_count} reference set kullaniliyor — bellek okuma yuku"
                    )

                # Cift alan (sourceOrDestination vb.)
                if "sourceOrDestination" in all_vals or "SourceOrDest" in all_vals:
                    bd.cross_field = True
                    raw_score += WEIGHTS["cross_field"]
                    bd.issues.append(
                        "sourceOrDestination gibi cift alan kullanimi var"
                    )

            # --- 6. IP listesi ---
            elif "SrcHost_Test" in tname or "DstHost_Test" in tname:
                ip_val = next(
                    (v for v in user_selections if "." in v or "/" in v), ""
                )
                ip_count = _count_items(ip_val)
                if ip_count >= 10:
                    bd.ip_list_long = True
                    raw_score += WEIGHTS["ip_list_long"]
                    bd.issues.append(
                        f"{ip_count} IP/CIDR listesi — Reference Set kullanilmasi onerilir"
                    )

            # --- 7. ArielFilterTest ---
            elif "ArielFilterTest" in tname:
                bd.ariel_filter_count += 1
                raw_score += WEIGHTS["ariel_filter"]

                upper_val = all_vals.upper()
                if any(kw in upper_val for kw in ARIEL_REGEX_KEYWORDS):
                    bd.ariel_matches = True
                    raw_score += WEIGHTS["ariel_matches"]
                    bd.issues.append(
                        "AQL filtresi icinde MATCHES/IMATCHES kullanimi"
                    )

    except Exception as e:
        bd.issues.append(f"Parse hatasi: {e}")

    # Normalize 0-100
    score = min(int(raw_score * 100 / 150), 100)
    classification = _classify(score)

    # Oneri uret
    recommendations = _build_recommendations(bd, classification)

    return ComplexityResult(
        rule_id=rule_id,
        rule_name=rule_name,
        score=score,
        classification=classification,
        breakdown=bd,
        recommendations=recommendations,
    )


def _build_recommendations(bd: ComplexityBreakdown, cls: str) -> List[str]:
    recs = []

    if bd.regex_catastrophic:
        recs.append(
            "KRITIK: Regex pattern catastrophic backtracking riski tasiyor. "
            "Ic ice .* veya .+ kullanimi kaldirin."
        )
    if bd.regex_test_count > 0 and bd.regex_alternation_count > 5:
        recs.append(
            f"Regex icinde {bd.regex_alternation_count} alternation var. "
            "IS ONE OF veya Reference Set ile degistirmeyi dusunun."
        )
    if bd.regex_wildcard_count > 0:
        recs.append(
            ".* veya .+ kullanimi CPU yukunu arttirir. "
            "Mumkunse sabit string eslesme kullanin."
        )
    if bd.multi_rule_reference:
        recs.append(
            "Tek testte birden fazla kural referansi var. "
            "Kurali daha kucuk parcalara bolmeyi dusunun."
        )
    if bd.reference_set_count >= 3:
        recs.append(
            f"{bd.reference_set_count} reference set sorgulanıyor. "
            "Setleri birlestirip tek sette toplamak performansi arttirir."
        )
    if bd.ip_list_long:
        recs.append(
            "Uzun IP listesi yerine Reference Set kullanin — O(1) arama saglar."
        )
    if bd.ariel_matches:
        recs.append(
            "AQL filtresinde MATCHES kullanimi pahalidir. "
            "Mumkunse QID veya kategori bazli filtreleme tercih edin."
        )
    if bd.negate_count > 1:
        recs.append(
            f"{bd.negate_count} NOT kosulu var. "
            "NOT kosullari her olay icin ek islem yapar, azaltilmasi onerilir."
        )
    if not recs and cls in ("LOW", "MEDIUM"):
        recs.append("Kural genel olarak iyi yazilmis, buyuk bir sorun tespit edilmedi.")

    return recs


# ---------------------------------------------------------------------------
# Export XML'inden tum kurallari skorla
# ---------------------------------------------------------------------------
def score_all_rules_from_export(export_path: str) -> List[ComplexityResult]:
    import os
    if not os.path.exists(export_path):
        return []

    results = []
    try:
        with open(export_path, "rb") as f:
            data = _clean(f.read())
        root = etree.fromstring(data)

        for r in root.findall("custom_rule"):
            rule_id = r.findtext("id") or "unknown"
            rule_data_b64 = r.findtext("rule_data") or ""
            if not rule_data_b64:
                continue
            result = score_rule_from_b64(rule_id, rule_data_b64)
            results.append(result)

    except Exception:
        pass

    return sorted(results, key=lambda x: x.score, reverse=True)
