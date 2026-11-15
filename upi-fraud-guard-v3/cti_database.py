"""
Persistent SQLite database layer for the Autonomous Cyber Threat Intelligence (CTI) Engine.

Manages persistent tables for:
- cti_sources
- cti_indicators
- cti_collection_logs
- cti_fraud_patterns
- cti_indicator_reviews
- cti_model_registry
"""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("upi_fraud_guard.cti_database")

_DB_PATH = Path(__file__).resolve().parent / "data" / "risk_checks.db"


class CTIDatabase:
    """SQLite Database manager for Threat Intelligence records, logs, and registry."""

    def __init__(self, db_path: Path = _DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _init_db(self) -> None:
        with closing(self._get_connection()) as conn:
            # 1. cti_sources
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cti_sources (
                    source_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    source_type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    last_sync TEXT,
                    status TEXT NOT NULL DEFAULT 'Initialized',
                    records_fetched INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    checkpoint TEXT DEFAULT '',
                    api_key_required INTEGER DEFAULT 0,
                    rate_limit_info TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )

            # 2. cti_indicators
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cti_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    indicator_value TEXT NOT NULL UNIQUE,
                    indicator_type TEXT NOT NULL,
                    threat_category TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    source_name TEXT NOT NULL,
                    source_reference TEXT DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    confidence_score INTEGER DEFAULT 50,
                    verification_status TEXT NOT NULL DEFAULT 'Reported Unverified',
                    evidence TEXT DEFAULT '[]',
                    associated_mitre_tactics TEXT DEFAULT '[]',
                    expires_at TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cti_ind_val ON cti_indicators(indicator_value);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cti_ind_type ON cti_indicators(indicator_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cti_ind_status ON cti_indicators(verification_status);")
            self._ensure_column(conn, "cti_indicators", "source_names", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(conn, "cti_indicators", "source_count", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column(conn, "cti_indicators", "quarantined", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "cti_sources", "last_attempt", "TEXT")
            self._ensure_column(conn, "cti_sources", "last_success", "TEXT")
            conn.execute("UPDATE cti_indicators SET source_names=json_array(source_name) WHERE source_names='[]' OR source_names IS NULL")
            conn.execute("""CREATE TABLE IF NOT EXISTS cti_indicator_quarantine (
                quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                quarantined_by TEXT NOT NULL,
                quarantined_at TEXT NOT NULL,
                resolution TEXT DEFAULT '',
                resolved_by TEXT DEFAULT '',
                resolved_at TEXT,
                FOREIGN KEY(indicator_id) REFERENCES cti_indicators(indicator_id)
            )""")

            # 3. cti_collection_logs
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cti_collection_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    records_fetched INTEGER DEFAULT 0,
                    new_indicators INTEGER DEFAULT 0,
                    duplicate_indicators INTEGER DEFAULT 0,
                    error_details TEXT DEFAULT ''
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cti_logs_ts ON cti_collection_logs(timestamp);")
            self._ensure_column(conn, "cti_collection_logs", "extracted_indicators", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "cti_collection_logs", "inserted_indicators", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "cti_collection_logs", "rejected_records", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "cti_collection_logs", "failed_records", "INTEGER NOT NULL DEFAULT 0")

            # 4. cti_fraud_patterns
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cti_fraud_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    pattern_name TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    extracted_keywords TEXT DEFAULT '[]',
                    mitre_mapping TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )

            # 5. cti_indicator_reviews
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cti_indicator_reviews (
                    review_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_id TEXT NOT NULL,
                    reviewer_id TEXT NOT NULL,
                    previous_status TEXT NOT NULL,
                    new_status TEXT NOT NULL,
                    review_notes TEXT DEFAULT '',
                    reviewed_at TEXT NOT NULL,
                    FOREIGN KEY(indicator_id) REFERENCES cti_indicators(indicator_id) ON DELETE CASCADE
                )
                """
            )

            # 6. cti_model_registry
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cti_model_registry (
                    model_id TEXT PRIMARY KEY,
                    model_name TEXT NOT NULL,
                    version TEXT NOT NULL UNIQUE,
                    trained_at TEXT NOT NULL,
                    dataset_version TEXT NOT NULL,
                    training_config TEXT DEFAULT '{}',
                    metrics TEXT DEFAULT '{}',
                    approval_status TEXT NOT NULL DEFAULT 'Pending Approval',
                    is_active INTEGER DEFAULT 0
                )
                """
            )
            conn.execute("""CREATE TABLE IF NOT EXISTS cti_model_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT, model_id TEXT NOT NULL, actor TEXT NOT NULL,
                action TEXT NOT NULL, created_at TEXT NOT NULL, details TEXT DEFAULT '{}')""")
            conn.execute("""CREATE TABLE IF NOT EXISTS cti_model_deployments (
                deployment_id INTEGER PRIMARY KEY AUTOINCREMENT, model_id TEXT NOT NULL, actor TEXT NOT NULL,
                deployed_at TEXT NOT NULL, action TEXT NOT NULL, previous_model_id TEXT,
                previous_artifact TEXT NOT NULL, previous_checksum TEXT NOT NULL,
                artifact TEXT NOT NULL, checksum TEXT NOT NULL)""")

            # 7. AUIE Schema Tables
            conn.execute("""CREATE TABLE IF NOT EXISTS auie_url_reputation (
                url_hash TEXT PRIMARY KEY,
                canonical_url TEXT NOT NULL,
                domain TEXT NOT NULL,
                reputation_state TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                reasons TEXT DEFAULT '[]',
                sources_evidence TEXT DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                expires_at TEXT,
                updated_at TEXT NOT NULL
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_auie_rep_domain ON auie_url_reputation(domain);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_auie_rep_state ON auie_url_reputation(reputation_state);")

            conn.execute("""CREATE TABLE IF NOT EXISTS auie_trusted_domains (
                domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL DEFAULT 'Legitimate Domain',
                allow_subdomains INTEGER DEFAULT 1,
                requires_path_check INTEGER DEFAULT 0,
                added_by TEXT NOT NULL DEFAULT 'system',
                added_at TEXT NOT NULL,
                expires_at TEXT,
                review_notes TEXT DEFAULT ''
            )""")

            conn.execute("""CREATE TABLE IF NOT EXISTS auie_provider_status (
                provider_id TEXT PRIMARY KEY,
                provider_name TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'UNCONFIGURED',
                last_successful_lookup TEXT,
                error_count INTEGER DEFAULT 0,
                last_error TEXT DEFAULT '',
                quota_remaining INTEGER,
                updated_at TEXT NOT NULL
            )""")

            conn.execute("""CREATE TABLE IF NOT EXISTS auie_feed_sync (
                feed_id TEXT PRIMARY KEY,
                feed_name TEXT NOT NULL UNIQUE,
                last_sync_attempt TEXT,
                last_sync_success TEXT,
                records_ingested INTEGER DEFAULT 0,
                records_withdrawn INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'INITIALIZED',
                error_message TEXT DEFAULT ''
            )""")

            conn.execute("""CREATE TABLE IF NOT EXISTS auie_analysis_history (
                analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_url TEXT NOT NULL,
                canonical_url TEXT NOT NULL,
                domain TEXT NOT NULL,
                reputation_state TEXT NOT NULL,
                risk_score REAL NOT NULL,
                reasons TEXT DEFAULT '[]',
                providers_consulted TEXT DEFAULT '[]',
                cache_hit INTEGER DEFAULT 0,
                latency_ms REAL DEFAULT 0.0,
                analyzed_at TEXT NOT NULL,
                user_id TEXT DEFAULT 'system'
            )""")

            conn.execute("""CREATE TABLE IF NOT EXISTS auie_false_positive_feedback (
                feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_or_domain TEXT NOT NULL,
                reported_verdict TEXT NOT NULL,
                claimed_verdict TEXT NOT NULL,
                reporter_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
                reported_at TEXT NOT NULL,
                reviewed_by TEXT,
                reviewed_at TEXT,
                review_notes TEXT DEFAULT ''
            )""")

            conn.execute("""CREATE TABLE IF NOT EXISTS auie_analyst_reviews (
                review_id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                previous_state TEXT NOT NULL,
                new_state TEXT NOT NULL,
                analyst_id TEXT NOT NULL,
                notes TEXT DEFAULT '',
                reviewed_at TEXT NOT NULL
            )""")

            # Seed default verified trusted domains if table is empty
            count = conn.execute("SELECT COUNT(*) FROM auie_trusted_domains").fetchone()[0]
            if count == 0:
                now_iso = datetime.now(timezone.utc).isoformat()
                default_trusted = [
                    ("google.com", "Search / Portal", 1, 0),
                    ("paytm.com", "Payment Gateway", 1, 0),
                    ("phonepe.com", "Payment Gateway", 1, 0),
                    ("npci.org.in", "Financial Body", 1, 0),
                    ("bhimupi.org.in", "Financial Body", 1, 0),
                    ("sbi.co.in", "Bank", 1, 0),
                    ("hdfcbank.com", "Bank", 1, 0),
                    ("icicibank.com", "Bank", 1, 0),
                    ("axisbank.com", "Bank", 1, 0),
                    ("amazon.in", "E-Commerce", 1, 0),
                    ("amazon.com", "E-Commerce", 1, 0),
                    ("flipkart.com", "E-Commerce", 1, 0),
                    ("github.com", "Developer Platform", 1, 1),
                    ("medium.com", "Publishing Platform", 1, 1),
                    ("swiggy.com", "Merchant", 1, 0),
                    ("zomato.com", "Merchant", 1, 0),
                    ("cert-in.org.in", "Government Advisory", 1, 0),
                    ("rbi.org.in", "Regulatory Body", 1, 0),
                    ("cisa.gov", "Government Advisory", 1, 0),
                    ("microsoft.com", "Technology Platform", 1, 0),
                    ("gpay.app", "Payment Gateway", 1, 0),
                ]
                for d_name, d_cat, sub_ok, path_check in default_trusted:
                    conn.execute(
                        """INSERT OR IGNORE INTO auie_trusted_domains
                           (domain, category, allow_subdomains, requires_path_check, added_by, added_at)
                           VALUES (?, ?, ?, ?, 'system_baseline', ?)""",
                        (d_name, d_cat, sub_ok, path_check, now_iso),
                    )

            conn.commit()

    # --- SOURCE CRUD ---
    def upsert_source(self, source_id: str, name: str, source_type: str, url: str, api_key_required: bool = False) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            conn.execute(
                """
                INSERT INTO cti_sources (source_id, name, source_type, url, api_key_required, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    url=excluded.url,
                    source_type=excluded.source_type,
                    api_key_required=excluded.api_key_required
                """,
                (source_id, name, source_type, url, 1 if api_key_required else 0, now),
            )
            conn.commit()

    def update_source_sync(self, name: str, status: str, records_fetched: int, checkpoint: str = "", error_msg: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            if status == "Success":
                conn.execute(
                    """UPDATE cti_sources SET last_attempt=?, last_success=?, last_sync=?, status=?,
                       records_fetched=records_fetched+?, checkpoint=?, error_count=0, rate_limit_info=''
                       WHERE name=?""",
                    (now, now, now, status, records_fetched, checkpoint, name),
                )
            else:
                conn.execute(
                    """UPDATE cti_sources SET last_attempt=?, status=?, error_count=error_count+1,
                       rate_limit_info=? WHERE name=?""",
                    (now, status, error_msg[:500], name),
                )
            conn.commit()

    def get_sources(self) -> List[Dict[str, Any]]:
        with closing(self._get_connection()) as conn:
            rows = conn.execute("SELECT * FROM cti_sources ORDER BY name").fetchall()
            cols = [c[1] for c in conn.execute("PRAGMA table_info(cti_sources)").fetchall()]
            return [dict(zip(cols, r)) for r in rows]

    # --- INDICATORS CRUD ---
    def add_indicator(
        self,
        indicator_value: str,
        indicator_type: str,
        threat_category: str,
        source_name: str,
        description: str = "",
        source_reference: str = "",
        confidence_score: int = 50,
        verification_status: str = "Reported Unverified",
        evidence: Optional[List[Any]] = None,
        mitre_tactics: Optional[List[str]] = None,
        expires_at: Optional[str] = None,
        source_verified: bool = False,
    ) -> bool:
        val = indicator_value.strip().lower()
        if not val:
            return False

        now = datetime.now(timezone.utc).isoformat()
        indicator_id = f"IND-{hash(val) & 0xFFFFFFFF:08x}"
        evidence_json = evidence or []
        mitre_json = json.dumps(mitre_tactics or [])

        with closing(self._get_connection()) as conn:
            existing = conn.execute(
                "SELECT indicator_id, confidence_score, evidence, source_names, source_count, verification_status FROM cti_indicators WHERE indicator_value = ?",
                (val,),
            ).fetchone()
            source_entry = {"source": source_name, "reference": source_reference, "collected_at": now, "evidence": evidence_json}
            if existing:
                names = set(json.loads(existing[3] or "[]"))
                is_new_source = source_name not in names
                names.add(source_name)
                evidence_rows = json.loads(existing[2] or "[]")
                if source_entry not in evidence_rows:
                    evidence_rows.append(source_entry)
                new_conf = max(existing[1], confidence_score)
                status = existing[5]
                if status not in {"Allowlisted", "Expired"} and source_verified:
                    status = "Verified Malicious"
                conn.execute(
                    """UPDATE cti_indicators SET last_seen=?, confidence_score=?, evidence=?,
                       source_names=?, source_count=?, verification_status=? WHERE indicator_value=?""",
                    (now, new_conf, json.dumps(evidence_rows), json.dumps(sorted(names)), len(names), status, val),
                )
                conn.commit()
                return False

            evidence_rows = [source_entry]
            conn.execute(
                """INSERT INTO cti_indicators (
                    indicator_id, indicator_value, indicator_type, threat_category, description,
                    source_name, source_reference, first_seen, last_seen, collected_at,
                    confidence_score, verification_status, evidence, associated_mitre_tactics,
                    expires_at, source_names, source_count, quarantined
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)""",
                (indicator_id, val, indicator_type, threat_category, description, source_name,
                 source_reference, now, now, now, confidence_score,
                 "Verified Malicious" if source_verified and verification_status == "Verified Malicious" else verification_status,
                 json.dumps(evidence_rows), mitre_json, expires_at, json.dumps([source_name])),
            )
            conn.commit()
            return True

    def query_indicators(
        self,
        indicator_type: Optional[str] = None,
        verification_status: Optional[str] = None,
        source_name: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM cti_indicators WHERE 1=1"
        params: List[Any] = []

        if indicator_type:
            query += " AND indicator_type = ?"
            params.append(indicator_type)
        if verification_status:
            query += " AND verification_status = ?"
            params.append(verification_status)
        if source_name:
            query += " AND source_name = ?"
            params.append(source_name)
        if search_query:
            query += " AND (indicator_value LIKE ? OR description LIKE ?)"
            params.extend([f"%{search_query}%", f"%{search_query}%"])

        query += " ORDER BY collected_at DESC LIMIT ?"
        params.append(max(1, limit))

        with closing(self._get_connection()) as conn:
            rows = conn.execute(query, params).fetchall()
            cols = [c[1] for c in conn.execute("PRAGMA table_info(cti_indicators)").fetchall()]
            results = []
            for r in rows:
                item = dict(zip(cols, r))
                item["evidence"] = json.loads(item["evidence"])
                item["associated_mitre_tactics"] = json.loads(item["associated_mitre_tactics"])
                item["source_names"] = json.loads(item.get("source_names") or "[]")
                results.append(item)
            return results

    def quarantine_indicator(self, indicator_id: str, reason: str, actor: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            row = conn.execute("SELECT 1 FROM cti_indicators WHERE indicator_id=?", (indicator_id,)).fetchone()
            if not row:
                return False
            conn.execute("UPDATE cti_indicators SET quarantined=1 WHERE indicator_id=?", (indicator_id,))
            conn.execute(
                "INSERT INTO cti_indicator_quarantine(indicator_id,reason,quarantined_by,quarantined_at) VALUES(?,?,?,?)",
                (indicator_id, reason[:1000], actor, now),
            )
            conn.commit()
            return True

    def get_quarantine_candidates(self, limit: int = 500) -> List[Dict[str, Any]]:
        with closing(self._get_connection()) as conn:
            rows = conn.execute(
                """SELECT indicator_id,indicator_value,source_name,description,verification_status
                   FROM cti_indicators WHERE quarantined=0 AND
                   (lower(description) LIKE '%sample%' OR lower(description) LIKE '%fallback%'
                    OR lower(description) LIKE '%demo%' OR lower(indicator_value) LIKE '%sample%')
                   ORDER BY collected_at DESC LIMIT ?""", (max(1, min(limit, 1000)),)
            ).fetchall()
            return [dict(zip(("indicator_id","indicator_value","source_name","description","verification_status"), r)) for r in rows]

    # --- LOGS & AUDIT ---
    def add_collection_log(
        self,
        source_name: str,
        status: str,
        records_fetched: int,
        new_indicators: int,
        duplicate_indicators: int,
        error_details: str = "",
        extracted_indicators: int = 0,
        rejected_records: int = 0,
        failed_records: int = 0,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            conn.execute(
                """
                INSERT INTO cti_collection_logs
                (source_name, timestamp, status, records_fetched, new_indicators, duplicate_indicators,
                 error_details, extracted_indicators, inserted_indicators, rejected_records, failed_records)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (source_name, now, status, records_fetched, new_indicators, duplicate_indicators,
                 error_details, extracted_indicators, new_indicators, rejected_records, failed_records),
            )
            conn.commit()

    def get_collection_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with closing(self._get_connection()) as conn:
            rows = conn.execute("SELECT * FROM cti_collection_logs ORDER BY log_id DESC LIMIT ?", (limit,)).fetchall()
            cols = [c[1] for c in conn.execute("PRAGMA table_info(cti_collection_logs)").fetchall()]
            return [dict(zip(cols, r)) for r in rows]

    # --- INDICATOR REVIEW ---
    def get_indicator_reviews(self, indicator_id: str) -> Optional[List[Dict[str, Any]]]:
        with closing(self._get_connection()) as conn:
            exists = conn.execute("SELECT 1 FROM cti_indicators WHERE indicator_id=?", (indicator_id,)).fetchone()
            if not exists:
                return None
            rows = conn.execute(
                """SELECT review_id,reviewer_id,previous_status,new_status,review_notes,reviewed_at
                   FROM cti_indicator_reviews WHERE indicator_id=? ORDER BY reviewed_at DESC""",
                (indicator_id,),
            ).fetchall()
            cols = ("review_id","reviewer_id","previous_status","new_status","review_notes","reviewed_at")
            return [dict(zip(cols, row)) for row in rows]

    def review_indicator(self, indicator_id: str, reviewer_id: str, new_status: str, notes: str = "") -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            row = conn.execute("SELECT verification_status FROM cti_indicators WHERE indicator_id = ?", (indicator_id,)).fetchone()
            if not row:
                return False
            prev_status = row[0]
            conn.execute("UPDATE cti_indicators SET verification_status = ? WHERE indicator_id = ?", (new_status, indicator_id))
            conn.execute(
                """
                INSERT INTO cti_indicator_reviews (indicator_id, reviewer_id, previous_status, new_status, review_notes, reviewed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (indicator_id, reviewer_id, prev_status, new_status, notes, now),
            )
            conn.commit()
            return True

    # --- AUIE SPECIFIC CRUD METHODS ---
    def get_trusted_domains(self) -> List[Dict[str, Any]]:
        with closing(self._get_connection()) as conn:
            rows = conn.execute("SELECT * FROM auie_trusted_domains ORDER BY domain ASC").fetchall()
            cols = [c[1] for c in conn.execute("PRAGMA table_info(auie_trusted_domains)").fetchall()]
            return [dict(zip(cols, r)) for r in rows]

    def add_trusted_domain(
        self, domain: str, category: str = "Legitimate Domain", allow_subdomains: bool = True,
        requires_path_check: bool = False, added_by: str = "analyst", notes: str = ""
    ) -> bool:
        clean = domain.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            conn.execute(
                """INSERT INTO auie_trusted_domains (domain, category, allow_subdomains, requires_path_check, added_by, added_at, review_notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(domain) DO UPDATE SET
                       category=excluded.category, allow_subdomains=excluded.allow_subdomains,
                       requires_path_check=excluded.requires_path_check, review_notes=excluded.review_notes""",
                (clean, category, 1 if allow_subdomains else 0, 1 if requires_path_check else 0, added_by, now_iso, notes),
            )
            conn.commit()
            return True

    def remove_trusted_domain(self, domain: str) -> bool:
        clean = domain.strip().lower()
        with closing(self._get_connection()) as conn:
            cur = conn.execute("DELETE FROM auie_trusted_domains WHERE domain=?", (clean,))
            conn.commit()
            return cur.rowcount > 0

    def get_url_reputation(self, url_hash: str) -> Optional[Dict[str, Any]]:
        with closing(self._get_connection()) as conn:
            row = conn.execute("SELECT * FROM auie_url_reputation WHERE url_hash=?", (url_hash,)).fetchone()
            if not row:
                return None
            cols = [c[1] for c in conn.execute("PRAGMA table_info(auie_url_reputation)").fetchall()]
            item = dict(zip(cols, row))
            item["reasons"] = json.loads(item.get("reasons") or "[]")
            item["sources_evidence"] = json.loads(item.get("sources_evidence") or "[]")
            return item

    def upsert_url_reputation(
        self, url_hash: str, canonical_url: str, domain: str, reputation_state: str,
        confidence_score: float, reasons: List[str], sources_evidence: List[Any],
        expires_at: Optional[str] = None
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        reasons_json = json.dumps(reasons)
        evidence_json = json.dumps(sources_evidence)
        with closing(self._get_connection()) as conn:
            existing = conn.execute("SELECT first_seen FROM auie_url_reputation WHERE url_hash=?", (url_hash,)).fetchone()
            first_seen = existing[0] if existing else now_iso
            conn.execute(
                """INSERT INTO auie_url_reputation
                   (url_hash, canonical_url, domain, reputation_state, confidence_score, reasons, sources_evidence, first_seen, last_seen, expires_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(url_hash) DO UPDATE SET
                       reputation_state=excluded.reputation_state,
                       confidence_score=excluded.confidence_score,
                       reasons=excluded.reasons,
                       sources_evidence=excluded.sources_evidence,
                       last_seen=excluded.last_seen,
                       expires_at=excluded.expires_at,
                       updated_at=excluded.updated_at""",
                (url_hash, canonical_url, domain, reputation_state, confidence_score, reasons_json, evidence_json, first_seen, now_iso, expires_at, now_iso),
            )
            conn.commit()

    def update_provider_status(self, provider_id: str, provider_name: str, status: str, error_msg: str = "", quota_remaining: Optional[int] = None) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            if status == "ACTIVE":
                conn.execute(
                    """INSERT INTO auie_provider_status (provider_id, provider_name, status, last_successful_lookup, error_count, last_error, quota_remaining, updated_at)
                       VALUES (?, ?, ?, ?, 0, '', ?, ?)
                       ON CONFLICT(provider_id) DO UPDATE SET
                           status=excluded.status, last_successful_lookup=excluded.last_successful_lookup,
                           error_count=0, last_error='', quota_remaining=excluded.quota_remaining, updated_at=excluded.updated_at""",
                    (provider_id, provider_name, status, now_iso, quota_remaining, now_iso),
                )
            else:
                conn.execute(
                    """INSERT INTO auie_provider_status (provider_id, provider_name, status, error_count, last_error, updated_at)
                       VALUES (?, ?, ?, 1, ?, ?)
                       ON CONFLICT(provider_id) DO UPDATE SET
                           status=excluded.status, error_count=error_count+1,
                           last_error=excluded.last_error, updated_at=excluded.updated_at""",
                    (provider_id, provider_name, status, error_msg[:500], now_iso),
                )
            conn.commit()

    def get_provider_statuses(self) -> List[Dict[str, Any]]:
        with closing(self._get_connection()) as conn:
            rows = conn.execute("SELECT * FROM auie_provider_status ORDER BY provider_name ASC").fetchall()
            cols = [c[1] for c in conn.execute("PRAGMA table_info(auie_provider_status)").fetchall()]
            return [dict(zip(cols, r)) for r in rows]

    def add_auie_analysis_history(
        self, raw_url: str, canonical_url: str, domain: str, state: str, risk_score: float,
        reasons: List[str], providers_consulted: List[str], cache_hit: bool, latency_ms: float, user_id: str = "system"
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            conn.execute(
                """INSERT INTO auie_analysis_history
                   (raw_url, canonical_url, domain, reputation_state, risk_score, reasons, providers_consulted, cache_hit, latency_ms, analyzed_at, user_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (raw_url[:1000], canonical_url[:1000], domain[:250], state, risk_score, json.dumps(reasons), json.dumps(providers_consulted), 1 if cache_hit else 0, round(latency_ms, 2), now_iso, user_id),
            )
            conn.commit()

    def add_false_positive_feedback(
        self, url_or_domain: str, reported_verdict: str, claimed_verdict: str, reporter_id: str, reason: str
    ) -> int:
        now_iso = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            cur = conn.execute(
                """INSERT INTO auie_false_positive_feedback
                   (url_or_domain, reported_verdict, claimed_verdict, reporter_id, reason, status, reported_at)
                   VALUES (?, ?, ?, ?, ?, 'PENDING_REVIEW', ?)""",
                (url_or_domain[:1000], reported_verdict, claimed_verdict, reporter_id, reason[:1000], now_iso),
            )
            conn.commit()
            return cur.lastrowid

    def get_false_positive_feedback(self, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        query = "SELECT * FROM auie_false_positive_feedback WHERE 1=1"
        params: list = []
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY feedback_id DESC LIMIT ?"
        params.append(max(1, limit))
        with closing(self._get_connection()) as conn:
            rows = conn.execute(query, params).fetchall()
            cols = [c[1] for c in conn.execute("PRAGMA table_info(auie_false_positive_feedback)").fetchall()]
            return [dict(zip(cols, r)) for r in rows]

    def review_false_positive_feedback(self, feedback_id: int, reviewer_id: str, new_status: str, notes: str = "") -> bool:
        now_iso = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            row = conn.execute("SELECT status FROM auie_false_positive_feedback WHERE feedback_id=?", (feedback_id,)).fetchone()
            if not row:
                return False
            conn.execute(
                """UPDATE auie_false_positive_feedback
                   SET status=?, reviewed_by=?, reviewed_at=?, review_notes=? WHERE feedback_id=?""",
                (new_status, reviewer_id, now_iso, notes, feedback_id),
            )
            conn.commit()
            return True

    def purge_expired_indicators(self) -> int:
        """Purges or updates status of indicators whose expiration timestamp has passed."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            cur = conn.execute(
                "UPDATE cti_indicators SET verification_status='Expired' WHERE expires_at IS NOT NULL AND expires_at < ? AND verification_status != 'Expired'",
                (now_iso,),
            )
            conn.commit()
            return cur.rowcount

    def get_cti_database_stats(self) -> Dict[str, Any]:
        """Returns summary statistics of active, verified, expired, and category-level CTI indicators."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with closing(self._get_connection()) as conn:
            total = conn.execute("SELECT COUNT(*) FROM cti_indicators").fetchone()[0]
            verified = conn.execute("SELECT COUNT(*) FROM cti_indicators WHERE verification_status='Verified Malicious' AND quarantined=0").fetchone()[0]
            expired = conn.execute("SELECT COUNT(*) FROM cti_indicators WHERE verification_status='Expired' OR (expires_at IS NOT NULL AND expires_at < ?)", (now_iso,)).fetchone()[0]
            quarantined = conn.execute("SELECT COUNT(*) FROM cti_indicators WHERE quarantined=1").fetchone()[0]

            by_source_rows = conn.execute("SELECT source_name, COUNT(*) FROM cti_indicators GROUP BY source_name").fetchall()
            by_category_rows = conn.execute("SELECT threat_category, COUNT(*) FROM cti_indicators GROUP BY threat_category").fetchall()

            return {
                "total_indicators": total,
                "verified_malicious": verified,
                "expired_indicators": expired,
                "quarantined_indicators": quarantined,
                "by_source": dict(by_source_rows),
                "by_category": dict(by_category_rows),
            }

    def get_auie_analysis_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with closing(self._get_connection()) as conn:
            rows = conn.execute("SELECT * FROM auie_analysis_history ORDER BY analysis_id DESC LIMIT ?", (limit,)).fetchall()
            cols = [c[1] for c in conn.execute("PRAGMA table_info(auie_analysis_history)").fetchall()]
            results = []
            for r in rows:
                item = dict(zip(cols, r))
                item["reasons"] = json.loads(item.get("reasons") or "[]")
                item["providers_consulted"] = json.loads(item.get("providers_consulted") or "[]")
                results.append(item)
            return results

    def get_approved_learning_dataset(self) -> List[Dict[str, Any]]:
        """Returns approved analyst feedback records eligible to enter training datasets."""
        with closing(self._get_connection()) as conn:
            rows = conn.execute(
                "SELECT * FROM auie_false_positive_feedback WHERE status='APPROVED' ORDER BY feedback_id ASC"
            ).fetchall()
            cols = [c[1] for c in conn.execute("PRAGMA table_info(auie_false_positive_feedback)").fetchall()]
            return [dict(zip(cols, r)) for r in rows]


# Global database instance
cti_db = CTIDatabase()

