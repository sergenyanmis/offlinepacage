from fastapi import APIRouter
from services.qradar_client import QRadarClient

router = APIRouter()


@router.get("/api/dashboard/summary")
async def dashboard_summary():
    client = QRadarClient()

    # Tum kurallari ve grup haritasini paralel cek
    result = await client.get_all_rules(page=1, page_size=500)
    rules_raw = result.get("rules", [])
    total = result.get("total", len(rules_raw))

    enabled = sum(1 for r in rules_raw if r.get("enabled", True))

    # Kapasiteye gore en pahali 5 kural (average_capacity yuksek = pahali)
    sorted_by_capacity = sorted(
        rules_raw,
        key=lambda r: r.get("average_capacity") or 0,
        reverse=True
    )
    top_expensive = [
        {
            "id": str(r.get("id", "")),
            "name": r.get("name", ""),
            "avg_test_time_ms": round(r.get("average_capacity", 0) / 1000000, 2),
        }
        for r in sorted_by_capacity[:5]
        if r.get("average_capacity", 0) > 0
    ]

    return {
        "total_rules": total,
        "enabled_rules": enabled,
        "rules_with_regex": 0,
        "high_complexity_rules": 0,
        "top_expensive_rules": top_expensive,
        "never_triggered": 0,
        "alerts_today": 0,
        "false_positive_rate_pct": 0.0
    }
