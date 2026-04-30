import base64
import re
import asyncio
from fastapi import APIRouter
from lxml import etree
from services.qradar_client import QRadarClient

router = APIRouter()

# Regex içeren test class'ları
REGEX_TEST_NAMES = {
    "com.q1labs.semsources.cre.tests.RegexTest",
    "com.q1labs.semsources.cre.tests.EventStringRegex_Test",
    "com.q1labs.semsources.cre.tests.PayloadTest",
    "com.q1labs.semsources.cre.tests.CustomPropertyRegex_Test",
}

# ArielFilterTest içindeki userSelection'da regex operatör belirteçleri
ARIEL_REGEX_KEYWORDS = [
    "IMATCHES", "MATCHES", "ILIKE", "~", "REGEX",
    "matchesregex", "MATCHESREGEX"
]

# QRadar test name'lerinden regex içerdiği bilinen genel pattern
REGEX_NAME_PATTERN = re.compile(r'[Rr]egex|REGEX|[Mm]atches|MATCHES', re.IGNORECASE)


def _clean_xml(data: bytes) -> bytes:
    """Geçersiz XML kontrol karakterlerini temizle."""
    return re.sub(rb'[\x00-\x08\x0b\x0c\x0e-\x1f]', b'', data)


def _rule_has_regex(rule_data_b64: str) -> bool:
    """
    rule_data (Base64 encoded XML) içinde regex kullanımı var mı?
    """
    if not rule_data_b64:
        return False
    try:
        raw = base64.b64decode(rule_data_b64 + '==')
        raw = _clean_xml(raw)
        inner = etree.fromstring(raw)

        for test in inner.findall('.//test'):
            test_name = test.get('name', '')

            # 1. Bilinen regex test class'ları
            if test_name in REGEX_TEST_NAMES:
                return True

            # 2. Test adında regex geçiyor mu
            if REGEX_NAME_PATTERN.search(test_name):
                return True

            # 3. ArielFilterTest içinde MATCHES/REGEX operatörü var mı
            if 'ArielFilterTest' in test_name:
                for param in test.findall('.//userSelection'):
                    val = (param.text or '').upper()
                    if any(kw.upper() in val for kw in ARIEL_REGEX_KEYWORDS):
                        return True

            # 4. Herhangi bir userSelection içinde regex pattern'ı var mı
            for param in test.findall('.//userSelection'):
                val = param.text or ''
                if any(kw in val for kw in ARIEL_REGEX_KEYWORDS):
                    return True

    except Exception:
        pass

    return False


@router.get("/api/dashboard/summary")
async def dashboard_summary():
    client = QRadarClient()

    # Tüm kuralları çek
    result = await client.get_all_rules(page=1, page_size=500)
    rules_raw = result.get("rules", [])
    total = result.get("total", len(rules_raw))
    enabled = sum(1 for r in rules_raw if r.get("enabled", True))

    # Kapasite sıralaması — en pahalı 5 kural
    sorted_by_capacity = sorted(
        rules_raw,
        key=lambda r: r.get("average_capacity") or 0,
        reverse=True
    )
    top_expensive = [
        {
            "id": str(r.get("id", "")),
            "name": r.get("name", ""),
            "avg_test_time_ms": round((r.get("average_capacity") or 0) / 1_000_000, 2),
        }
        for r in sorted_by_capacity[:5]
        if (r.get("average_capacity") or 0) > 0
    ]

    # Yüksek karmaşıklık: average_capacity > 500ms (500_000_000 ns)
    high_complexity_threshold = 500_000_000
    high_complexity_rules = sum(
        1 for r in rules_raw
        if (r.get("average_capacity") or 0) > high_complexity_threshold
    )

    # --- Regex tespiti ---
    # QRadar API'si rule_data döndürmüyor; contentManagement export XML'ini
    # periyodik olarak parse edip bir cache/dosyaya yazmanız önerilir.
    # Alternatif: export XML'ini backend'e yükleyip burada okumak.
    rules_with_regex = _count_regex_rules_from_export()

    # Bugün alarmların sayısı (son 24 saat)
    alerts_today = await client.get_sgm_alert_count(hours=24)

    return {
        "total_rules": total,
        "enabled_rules": enabled,
        "rules_with_regex": rules_with_regex,
        "high_complexity_rules": high_complexity_rules,
        "top_expensive_rules": top_expensive,
        "never_triggered": 0,       # Sonraki adımda eklenecek
        "alerts_today": alerts_today,
        "false_positive_rate_pct": 0.0  # Sonraki adımda eklenecek
    }


def _count_regex_rules_from_export(
    export_path: str = "/opt/qradar-analyzer/data/latest_export.xml"
) -> int:
    """
    contentManagement.pl ile üretilen export XML'ini okur,
    her kuralın rule_data'sını decode ederek regex içerenleri sayar.

    Export XML'ini güncel tutmak için QRadar'da şu komutu çalıştırın:
      /opt/qradar/bin/contentManagement.pl --action export \
          --content-type custom_rule \
          --outputfile /opt/qradar-analyzer/data/latest_export.xml
    """
    import os
    if not os.path.exists(export_path):
        return 0

    try:
        with open(export_path, 'rb') as f:
            raw = f.read()
        raw = _clean_xml(raw)
        root = etree.fromstring(raw)

        count = 0
        for rule_el in root.findall('custom_rule'):
            rule_data_b64 = rule_el.findtext('rule_data') or ''
            if _rule_has_regex(rule_data_b64):
                count += 1
        return count
    except Exception:
        return 0
