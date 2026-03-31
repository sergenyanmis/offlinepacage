import httpx
import logging
from typing import Optional
from config import settings

logger = logging.getLogger(__name__)


class QRadarClient:
    def __init__(self):
        self.base_url = f"https://{settings.qradar_host}:{settings.qradar_port}"
        self.headers = {
            "SEC": settings.qradar_api_token,
            "Version": "18.0",
            "Accept": "application/json",
        }
        self.verify_ssl = settings.qradar_verify_ssl

    async def _get(self, path: str, params: dict = None):
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=60) as client:
            response = await client.get(
                f"{self.base_url}{path}",
                headers=self.headers,
                params=params or {}
            )
            response.raise_for_status()
            return response.json()

    async def health_check(self) -> dict:
        try:
            await self._get("/api/system/servers")
            return {"qradar_reachable": True, "version": "unknown", "jmx_reachable": False}
        except Exception as e:
            logger.warning(f"QRadar health check failed: {e}")
            return {"qradar_reachable": False, "version": None, "jmx_reachable": False}

    async def get_version(self) -> Optional[str]:
        try:
            data = await self._get("/api/system/servers")
            if isinstance(data, list) and data:
                return data[0].get("version")
            return None
        except Exception:
            return None

    async def get_all_rules(self, page: int = 1, page_size: int = 50,
                             enabled: Optional[bool] = None,
                             group: Optional[str] = None) -> dict:
        params = {
            "fields": "id,name,enabled,type,origin,owner,creation_date,modification_date,average_capacity",
            "Range": f"items={((page - 1) * page_size)}-{(page * page_size) - 1}",
        }
        filters = ["type='EVENT'"]
        if enabled is not None:
            filters.append(f"enabled={str(enabled).lower()}")
        params["filter"] = " AND ".join(filters)

        try:
            data = await self._get("/api/analytics/rules", params)
            rules = data if isinstance(data, list) else []
            return {"rules": rules, "total": len(rules)}
        except Exception as e:
            logger.error(f"get_all_rules error: {e}")
            return {"rules": [], "total": 0}

    async def get_all_rules_count(self) -> int:
        """Toplam kural sayisini dondurur."""
        params = {
            "fields": "id",
            "filter": "type='EVENT'",
            "Range": "items=0-499",
        }
        try:
            data = await self._get("/api/analytics/rules", params)
            return len(data) if isinstance(data, list) else 0
        except Exception:
            return 0

    async def get_rule_detail(self, rule_id: str) -> Optional[dict]:
        try:
            return await self._get(f"/api/analytics/rules/{rule_id}")
        except Exception as e:
            logger.error(f"get_rule_detail error for {rule_id}: {e}")
            return None

    async def get_rule_groups(self) -> list:
        try:
            return await self._get("/api/analytics/rule_groups")
        except Exception:
            return []

    async def build_rule_group_map(self) -> dict[str, str]:
        """Kural ID -> Grup adi eslesmesi olusturur."""
        groups = await self.get_rule_groups()
        rule_group_map = {}
        for group in groups:
            group_name = group.get("name", "")
            for rule_id in group.get("child_items", []):
                rule_group_map[str(rule_id)] = group_name
        return rule_group_map

    async def _run_aql(self, aql: str, poll_timeout: int = 25) -> list:
        """AQL sorgusu calistirir, tamamlanana kadar bekler ve sonuclari dondurur."""
        import asyncio
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/api/ariel/searches",
                headers=self.headers,
                params={"query_expression": aql},
            )
            resp.raise_for_status()
            search_id = resp.json().get("search_id")
        if not search_id:
            return []

        deadline = asyncio.get_event_loop().time() + poll_timeout
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10) as client:
            while asyncio.get_event_loop().time() < deadline:
                sr = await client.get(
                    f"{self.base_url}/api/ariel/searches/{search_id}",
                    headers=self.headers,
                )
                status = sr.json().get("status", "")
                if status == "COMPLETED":
                    break
                if status in ("ERROR", "CANCELLED"):
                    logger.error(f"AQL search {search_id} status: {status}")
                    return []
                await asyncio.sleep(1)
            else:
                logger.warning(f"AQL search {search_id} timed out after {poll_timeout}s")
                return []

            rr = await client.get(
                f"{self.base_url}/api/ariel/searches/{search_id}/results",
                headers=self.headers,
            )
            rr.raise_for_status()
            body = rr.json()
        # Sonuclar events/flows/offenses anahtari altinda gelir
        for key in ("events", "offenses", "flows"):
            if key in body:
                return body[key]
        return []

    async def get_offense_count_since(self, since_ms: int) -> int:
        """Belirtilen epoch ms'den bu yana acilan offense sayisini AQL ile dondurur."""
        aql = f"SELECT COUNT(*) AS count FROM offenses WHERE starttime > {since_ms}"
        try:
            rows = await self._run_aql(aql, poll_timeout=25)
            if rows:
                return int(rows[0].get("count", 0))
            return 0
        except Exception as e:
            logger.error(f"get_offense_count_since AQL error: {e}")
            return 0

    async def get_trigger_stats(self, rule_id: str) -> dict:
        return {
            "daily_triggers": [],
            "hourly_heatmap": [],
            "performance_over_time": [],
            "top_source_ips": [],
        }
