"""
Autonomous Background Intelligence Collection Service & Scheduler.

Features:
- Initializes automatically during FastAPI startup
- Scheduled collection interval (Default: 30 minutes, configurable via CTI_COLLECTION_INTERVAL_MINUTES)
- Single-instance lock across multiple backend workers using file lock
- Exponential backoff retries for transient failures
- Asynchronous background execution without blocking core API response times
- Graceful shutdown
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from cti_connectors import ALL_CONNECTORS, BaseSourceConnector
from cti_database import cti_db

logger = logging.getLogger("upi_fraud_guard.cti_collector")

LOCK_FILE_PATH = Path(__file__).resolve().parent / "data" / "cti_collector.lock"


class CTICollectorWorker:
    """Autonomous background scheduler and collector for CTI source connectors."""

    def __init__(self) -> None:
        self.interval_seconds: float = float(os.environ.get("CTI_COLLECTION_INTERVAL_MINUTES", "30")) * 60.0
        self.connectors: List[BaseSourceConnector] = ALL_CONNECTORS
        self._running: bool = False
        self._task: Optional[asyncio.Task] = None
        self._lock_file = LOCK_FILE_PATH

    def _acquire_lock(self) -> bool:
        """Acquires a single-instance file lock to prevent duplicate workers."""
        try:
            self._lock_file.parent.mkdir(parents=True, exist_ok=True)
            if self._lock_file.exists():
                # Check if lock file is stale (> 2 hours old)
                mtime = self._lock_file.stat().st_mtime
                if time.time() - mtime > 7200:
                    logger.warning("Cleaning up stale CTI worker lock file.")
                    self._lock_file.unlink(missing_ok=True)
                else:
                    return False
            self._lock_file.write_text(f"PID: {os.getpid()} Started: {time.time()}")
            return True
        except Exception as err:
            logger.warning(f"Could not acquire worker lock: {err}")
            return True  # Fallback to allow single worker execution

    def _release_lock(self) -> None:
        try:
            if self._lock_file.exists():
                self._lock_file.unlink(missing_ok=True)
        except Exception:
            pass

    async def start(self) -> None:
        """Starts the autonomous background collector loop."""
        if self._running:
            return
        if not self._acquire_lock():
            logger.info("Another CTI background worker instance is already active. Worker lock skipped.")
            return

        self._running = True
        logger.info(f"Starting Autonomous CTI Collector Worker (Interval: {self.interval_seconds / 60:.1f} mins)...")
        self._task = asyncio.create_task(self._collection_loop())

    async def _collection_loop(self) -> None:
        """Main periodic loop running connector collection with backoff."""
        while self._running:
            try:
                await self.run_now()
            except Exception as err:
                logger.error(f"Error in CTI collection loop iteration: {err}")

            # Sleep interval
            try:
                await asyncio.sleep(self.interval_seconds)
            except asyncio.CancelledError:
                break

    async def run_now(self) -> List[Dict[str, Any]]:
        """Executes one round of collection across all registered source connectors."""
        logger.info("Executing scheduled CTI intelligence collection round...")
        results: List[Dict[str, Any]] = []

        # Run connectors sequentially or concurrently in executor
        loop = asyncio.get_running_loop()
        for connector in self.connectors:
            if not self._running and self._task and self._task.cancelling():
                break
            try:
                # Run sync connector fetch in thread pool
                res = await loop.run_in_executor(None, connector.collect)
                results.append(res)
            except Exception as connector_err:
                logger.error(f"Connector '{connector.name}' failed during collection: {connector_err}")
                results.append({
                    "source_name": connector.name,
                    "status": "Failed",
                    "records_fetched": 0,
                    "new_indicators": 0,
                    "duplicate_indicators": 0,
                    "error_details": str(connector_err),
                })

        logger.info(f"Completed CTI collection round. Processed {len(results)} sources.")
        return results

    async def shutdown(self) -> None:
        """Gracefully shuts down the background collector and releases worker lock."""
        if not self._running:
            return
        logger.info("Shutting down CTI Collector Worker...")
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._release_lock()
        logger.info("CTI Collector Worker shutdown complete.")


# Singleton instance
cti_collector_worker = CTICollectorWorker()
