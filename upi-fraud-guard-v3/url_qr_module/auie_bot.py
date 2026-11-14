"""
Controlled Background Intelligence Bot for AUIE.

Monitors, validates, normalizes, deduplicates, and ingests multi-source threat intelligence feeds
with feed health tracking, transaction safety, and graceful error recovery.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cti_collector import cti_collector_worker
from cti_connectors import ALL_CONNECTORS, BaseSourceConnector
from cti_database import cti_db

logger = logging.getLogger("upi_fraud_guard.auie.bot")


class AUIEBackgroundBot:
    """Background threat intelligence worker and status tracker."""

    def __init__(self) -> None:
        self.interval_seconds = float(os.environ.get("CTI_COLLECTION_INTERVAL_MINUTES", "30")) * 60.0
        self.connectors: List[BaseSourceConnector] = ALL_CONNECTORS

    async def trigger_sync_now(self) -> List[Dict[str, Any]]:
        """Triggers an immediate collection pass across all threat intelligence connectors."""
        logger.info("AUIE Bot triggering intelligence sync pass...")
        results = await cti_collector_worker.run_now()
        for res in results:
            feed_name = res.get("source_name", "Unknown Feed")
            status = res.get("status", "Unknown")
            records = res.get("inserted_indicators", 0)
            err = res.get("error_details", "")
            now_iso = datetime.now(timezone.utc).isoformat()
            with cti_db._get_connection() as conn:
                conn.execute(
                    """INSERT INTO auie_feed_sync
                       (feed_id, feed_name, last_sync_attempt, last_sync_success, records_ingested, status, error_message)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(feed_id) DO UPDATE SET
                           last_sync_attempt=excluded.last_sync_attempt,
                           last_sync_success=CASE WHEN excluded.status='Success' THEN excluded.last_sync_attempt ELSE auie_feed_sync.last_sync_success END,
                           records_ingested=auie_feed_sync.records_ingested + excluded.records_ingested,
                           status=excluded.status,
                           error_message=excluded.error_message""",
                    (f"FEED-{hash(feed_name) & 0xFFFFFFFF:08x}", feed_name, now_iso, now_iso if status == "Success" else None, records, status, err),
                )
                conn.commit()
        return results

    def get_feed_health(self) -> List[Dict[str, Any]]:
        """Returns feed synchronization status, health state, and last successful update times."""
        sources = cti_db.get_sources()
        with cti_db._get_connection() as conn:
            sync_rows = conn.execute("SELECT * FROM auie_feed_sync").fetchall()
            cols = [c[1] for c in conn.execute("PRAGMA table_info(auie_feed_sync)").fetchall()]
            sync_map = {r[1]: dict(zip(cols, r)) for r in sync_rows}

        health_list: List[Dict[str, Any]] = []
        for src in sources:
            name = src["name"]
            sync_info = sync_map.get(name, {})
            health_list.append({
                "source_id": src["source_id"],
                "source_name": name,
                "source_type": src["source_type"],
                "url": src["url"],
                "status": src["status"],
                "last_attempt": src.get("last_attempt") or src.get("last_sync"),
                "last_success": src.get("last_success") or sync_info.get("last_sync_success"),
                "records_fetched": src.get("records_fetched", 0),
                "error_count": src.get("error_count", 0),
                "last_error": src.get("rate_limit_info", "") or sync_info.get("error_message", ""),
                "records_ingested": sync_info.get("records_ingested", 0),
            })
        return health_list


auie_bot = AUIEBackgroundBot()
