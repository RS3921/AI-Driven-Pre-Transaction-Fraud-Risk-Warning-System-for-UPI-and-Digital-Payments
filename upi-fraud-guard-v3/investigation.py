"""
Fraud Investigation Centre and Case Management System for UPI Fraud Guard.

Manages the lifecycle of suspicious transaction cases:
- Statuses: New, Under Investigation, Escalated, Resolved, False Positive
- Evidence Collection, Analyst Notes, Case Assignment, Audit Timelines
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_DB_PATH = Path(__file__).resolve().parent / "data" / "risk_checks.db"


class InvestigationManager:
    """Manages central investigation queue, evidence collection, and status workflows."""

    def __init__(self, db_path: Path = _DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    case_id TEXT PRIMARY KEY,
                    check_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'New',
                    assigned_to TEXT DEFAULT 'Unassigned',
                    priority TEXT NOT NULL DEFAULT 'Medium',
                    verdict TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    message TEXT DEFAULT '',
                    url_or_qr TEXT DEFAULT '',
                    amount REAL,
                    recipient TEXT DEFAULT '',
                    evidence TEXT DEFAULT '[]',
                    notes TEXT DEFAULT '[]',
                    history_timeline TEXT DEFAULT '[]'
                )
                """
            )
            conn.commit()

    def create_case_from_check(
        self,
        check_id: int,
        verdict: str,
        risk_score: float,
        message: str,
        url_or_qr: str,
        amount: Optional[float],
        recipient: str,
        reasons: List[str],
    ) -> str:
        """Creates a new investigation case if the transaction is suspicious or high risk."""
        case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{check_id}"
        now = datetime.now(timezone.utc).isoformat()
        priority = "Critical" if risk_score >= 0.85 else "High" if risk_score >= 0.65 else "Medium"

        timeline = [
            {
                "timestamp": now,
                "action": "Case Created",
                "actor": "System Alert",
                "details": f"Flagged with verdict '{verdict}' and risk score {round(risk_score * 100)}%",
            }
        ]

        evidence = [
            {"type": "Risk Reasons", "data": reasons},
            {"type": "Message Text", "data": message},
            {"type": "Link or QR Payload", "data": url_or_qr},
        ]

        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO investigations
                (case_id, check_id, created_at, updated_at, status, assigned_to, priority, verdict, risk_score, message, url_or_qr, amount, recipient, evidence, notes, history_timeline)
                VALUES (?, ?, ?, ?, 'New', 'Unassigned', ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?)
                """,
                (
                    case_id,
                    check_id,
                    now,
                    now,
                    priority,
                    verdict,
                    risk_score,
                    message,
                    url_or_qr,
                    amount,
                    recipient,
                    json.dumps(evidence),
                    json.dumps(timeline),
                ),
            )
            conn.commit()
        return case_id

    def list_cases(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Lists cases from the queue with optional filtering."""
        query = "SELECT case_id, check_id, created_at, updated_at, status, assigned_to, priority, verdict, risk_score, message, amount, recipient FROM investigations WHERE 1=1"
        params: List[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if priority:
            query += " AND priority = ?"
            params.append(priority)

        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(query, params).fetchall()

        keys = ["case_id", "check_id", "created_at", "updated_at", "status", "assigned_to", "priority", "verdict", "risk_score", "message", "amount", "recipient"]
        return [dict(zip(keys, row)) for row in rows]

    def get_case_details(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Gets full investigation record including evidence and notes."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute("SELECT * FROM investigations WHERE case_id = ?", (case_id,)).fetchone()
            if not row:
                return None
            keys = [col[1] for col in conn.execute("PRAGMA table_info(investigations)").fetchall()]
            data = dict(zip(keys, row))
            data["evidence"] = json.loads(data["evidence"])
            data["notes"] = json.loads(data["notes"])
            data["history_timeline"] = json.loads(data["history_timeline"])
            return data

    def update_case(
        self,
        case_id: str,
        actor: str,
        new_status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        add_note: Optional[str] = None,
    ) -> bool:
        """Updates case status, assignee, and appends notes & timeline actions."""
        record = self.get_case_details(case_id)
        if not record:
            return False

        now = datetime.now(timezone.utc).isoformat()
        notes = record["notes"]
        timeline = record["history_timeline"]

        if add_note:
            notes.append({"timestamp": now, "author": actor, "note": add_note})

        if new_status and new_status != record["status"]:
            timeline.append({"timestamp": now, "action": "Status Change", "actor": actor, "details": f"Status updated from '{record['status']}' to '{new_status}'"})
            status_val = new_status
        else:
            status_val = record["status"]

        if assigned_to and assigned_to != record["assigned_to"]:
            timeline.append({"timestamp": now, "action": "Case Assigned", "actor": actor, "details": f"Assigned to {assigned_to}"})
            assignee_val = assigned_to
        else:
            assignee_val = record["assigned_to"]

        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                UPDATE investigations
                SET status = ?, assigned_to = ?, updated_at = ?, notes = ?, history_timeline = ?
                WHERE case_id = ?
                """,
                (status_val, assignee_val, now, json.dumps(notes), json.dumps(timeline), case_id),
            )
            conn.commit()
        return True


# Singleton instance
investigation_manager = InvestigationManager()
