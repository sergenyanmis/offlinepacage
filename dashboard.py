from fastapi import APIRouter
from services.qradar_client import QRadarClient
from datetime import datetime, timezone

router = APIRouter()


@router.get("/api/dashboard/summary")
async def dashboard_summary():
    client = QRadarClient()

    # Tum kurallari cek
    result = await client.get_all_rules(page=1, page_size=500)
    rules_raw = result.get("rules", [])
    total = result.get("total", len(rules_raw))
    enabled = sum(1 for r in rules_raw if r.get("enabled", True))

    # Kapasiteye gore en pahali 5 kural
    sorted_by_capacity = sorted(
        rules_raw,
        key=lambda r: r.get("average_capacity") or 0,
        reverse=True
    )
    top_expensive = [
        {
            "id": str(r.get("id", "")),
            "name": r.get("name", ""),
            "avg_test_time_ms": round((r.get("average_capacity") or 0) / 1000000, 2),
        }
        for r in sorted_by_capacity[:5]
        if (r.get("average_capacity") or 0) > 0
    ]

    # Yuksek karmasiklikli kurallar: average_capacity > 500ms (500_000_000 ns)
    high_complexity_threshold = 500_000_000
    high_complexity_rules = sum(
        1 for r in rules_raw
        if (r.get("average_capacity") or 0) > high_complexity_threshold
    )

    # Bugunun baslangici (epoch ms)
    now = datetime.now(timezone.utc)
    today_start_ms = int(datetime(now.year, now.month, now.day, tzinfo=timezone.utc).timestamp() * 1000)

    # Bugün açılan offense sayisi
    alerts_today = await client.get_offense_count_since(today_start_ms)

    return {
        "total_rules": total,
        "enabled_rules": enabled,
        "rules_with_regex": 0,
        "high_complexity_rules": high_complexity_rules,
        "top_expensive_rules": top_expensive,
        "never_triggered": 0,
        "alerts_today": alerts_today,
        "false_positive_rate_pct": 0.0
    }
