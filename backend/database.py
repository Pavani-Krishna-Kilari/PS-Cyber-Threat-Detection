"""
SQLite Persistence Layer for AI-SIEM Threat Detection History and Analysis Sessions.

Provides lightweight, robust, zero-dependency persistence for actual inference records,
historical queries, filtering, and context retrieval for the AI Assistant.
"""

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional

from src.config import PROJECT_ROOT

DB_PATH = PROJECT_ROOT / "data" / "detection_history.db"


def get_connection() -> sqlite3.Connection:
    """Returns a thread-safe connection to the SQLite database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes database tables if they do not already exist, with safe schema migrations."""
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                session_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_name TEXT NOT NULL,
                input_type TEXT NOT NULL,
                total_records INTEGER NOT NULL,
                normal_events INTEGER NOT NULL,
                threats_detected INTEGER NOT NULL,
                known_threats INTEGER NOT NULL DEFAULT 0,
                unknown_anomalous INTEGER NOT NULL DEFAULT 0,
                invalid_records INTEGER NOT NULL,
                threat_ratio REAL NOT NULL,
                attack_categories TEXT NOT NULL,
                severity_distribution TEXT NOT NULL,
                model_summary TEXT NOT NULL
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                input_type TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                destination_port INTEGER,
                protocol TEXT,
                verdict TEXT NOT NULL,
                prediction_status TEXT NOT NULL DEFAULT 'NORMAL',
                predicted_class TEXT NOT NULL DEFAULT 'Benign Network Traffic',
                confidence REAL NOT NULL DEFAULT 0.0,
                threat_confidence REAL NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                dominant_basepoint TEXT,
                dominant_similarity REAL,
                profile_vector TEXT,
                model_breakdown TEXT,
                anomaly_verdict TEXT,
                anomaly_status TEXT NOT NULL DEFAULT 'NORMAL',
                anomaly_score REAL,
                detection_reason TEXT NOT NULL DEFAULT '',
                requires_investigation INTEGER NOT NULL DEFAULT 0,
                flow_metadata TEXT,
                FOREIGN KEY(session_id) REFERENCES analysis_sessions(session_id)
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                start_time TEXT,
                end_time TEXT,
                verdict TEXT NOT NULL,
                max_confidence REAL NOT NULL,
                window_count INTEGER NOT NULL,
                attributed_flow_count INTEGER NOT NULL,
                constituent_windows TEXT,
                PRIMARY KEY (session_id, campaign_id),
                FOREIGN KEY(session_id) REFERENCES analysis_sessions(session_id)
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                name TEXT NOT NULL,
                callsign TEXT NOT NULL,
                role TEXT NOT NULL,
                clearance TEXT NOT NULL,
                department TEXT NOT NULL,
                avatar TEXT NOT NULL,
                remember_me INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                auth_method TEXT NOT NULL
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS access_clearance_tickets (
                ticket_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                clearance_level TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS password_recovery_requests (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL DEFAULT '',
                used INTEGER NOT NULL DEFAULT 0
            );
            """)

            # Resumable Chunked Upload & Processing Infrastructure
            conn.execute("""
            CREATE TABLE IF NOT EXISTS upload_sessions (
                upload_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL UNIQUE,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                total_chunks INTEGER NOT NULL,
                uploaded_chunks_count INTEGER DEFAULT 0,
                upload_status TEXT NOT NULL DEFAULT 'UPLOADING',
                sort_status TEXT NOT NULL DEFAULT 'PENDING',
                processing_status TEXT NOT NULL DEFAULT 'PENDING',
                total_rows INTEGER DEFAULT 0,
                processed_rows INTEGER DEFAULT 0,
                total_batches INTEGER DEFAULT 0,
                completed_batches INTEGER DEFAULT 0,
                global_t0 TEXT DEFAULT '',
                last_finalized_k INTEGER DEFAULT -1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                error_message TEXT DEFAULT ''
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS upload_chunks (
                upload_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_size INTEGER NOT NULL,
                received_at TEXT NOT NULL,
                PRIMARY KEY (upload_id, chunk_index),
                FOREIGN KEY(upload_id) REFERENCES upload_sessions(upload_id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS batch_checkpoints (
                upload_id TEXT NOT NULL,
                batch_index INTEGER NOT NULL,
                row_start INTEGER NOT NULL,
                row_end INTEGER NOT NULL,
                n_flows INTEGER NOT NULL,
                n_event_sets INTEGER NOT NULL,
                last_finalized_k INTEGER NOT NULL,
                boundary_state TEXT DEFAULT '',
                metrics_snapshot TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'COMPLETED',
                checkpoint_time TEXT NOT NULL,
                PRIMARY KEY (upload_id, batch_index),
                FOREIGN KEY(upload_id) REFERENCES upload_sessions(upload_id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS batch_intermediate_detections (
                id TEXT PRIMARY KEY,
                upload_id TEXT NOT NULL,
                batch_index INTEGER NOT NULL,
                detection_json TEXT NOT NULL,
                FOREIGN KEY(upload_id) REFERENCES upload_sessions(upload_id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS batch_pending_alert_windows (
                event_set_id TEXT NOT NULL,
                upload_id TEXT NOT NULL,
                batch_index INTEGER NOT NULL,
                window_json TEXT NOT NULL,
                flow_indices_json TEXT NOT NULL,
                PRIMARY KEY (upload_id, event_set_id),
                FOREIGN KEY(upload_id) REFERENCES upload_sessions(upload_id) ON DELETE CASCADE
            );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_upload_chunks_uid ON upload_chunks(upload_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_batch_checkpoints_uid ON batch_checkpoints(upload_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_batch_intermediate_uid ON batch_intermediate_detections(upload_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_batch_pending_alert_uid ON batch_pending_alert_windows(upload_id);")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_verdict ON detections(verdict);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_session ON detections(session_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_session ON campaigns(session_id);")

            # Safe schema migrations for existing databases
            existing_sess_cols = [c[1] for c in conn.execute("PRAGMA table_info(analysis_sessions);").fetchall()]
            if "known_threats" not in existing_sess_cols:
                conn.execute("ALTER TABLE analysis_sessions ADD COLUMN known_threats INTEGER NOT NULL DEFAULT 0;")
            if "unknown_anomalous" not in existing_sess_cols:
                conn.execute("ALTER TABLE analysis_sessions ADD COLUMN unknown_anomalous INTEGER NOT NULL DEFAULT 0;")
            if "report_data" not in existing_sess_cols:
                conn.execute("ALTER TABLE analysis_sessions ADD COLUMN report_data TEXT;")

            existing_det_cols = [c[1] for c in conn.execute("PRAGMA table_info(detections);").fetchall()]
            cols_to_add = [
                ("prediction_status", "TEXT NOT NULL DEFAULT 'NORMAL'"),
                ("predicted_class", "TEXT NOT NULL DEFAULT 'Benign Network Traffic'"),
                ("confidence", "REAL NOT NULL DEFAULT 0.0"),
                ("anomaly_status", "TEXT NOT NULL DEFAULT 'NORMAL'"),
                ("detection_reason", "TEXT NOT NULL DEFAULT ''"),
                ("requires_investigation", "INTEGER NOT NULL DEFAULT 0"),
                ("campaign_id", "TEXT NOT NULL DEFAULT '-'")
            ]
            for col_name, col_type in cols_to_add:
                if col_name not in existing_det_cols:
                    conn.execute(f"ALTER TABLE detections ADD COLUMN {col_name} {col_type};")

            existing_rec_cols = [c[1] for c in conn.execute("PRAGMA table_info(password_recovery_requests);").fetchall()]
            if "expires_at" not in existing_rec_cols:
                conn.execute("ALTER TABLE password_recovery_requests ADD COLUMN expires_at TEXT NOT NULL DEFAULT '';")
            if "used" not in existing_rec_cols:
                conn.execute("ALTER TABLE password_recovery_requests ADD COLUMN used INTEGER NOT NULL DEFAULT 0;")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(prediction_status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_campaign ON detections(campaign_id);")

            # Dual-Layer Data Drift Reports Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS drift_reports (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                upload_id TEXT,
                timestamp TEXT NOT NULL,
                reference_experiment TEXT NOT NULL DEFAULT 'exp_b',
                reference_population TEXT NOT NULL DEFAULT 'full',
                overall_drift_score REAL NOT NULL,
                overall_drift_percentage REAL NOT NULL,
                drift_status TEXT NOT NULL,
                recommendation_alert INTEGER NOT NULL DEFAULT 0,
                recommendation_message TEXT NOT NULL,
                is_partial INTEGER NOT NULL DEFAULT 0,
                omitted_layer TEXT DEFAULT '',
                layer1_score REAL,
                layer2_score REAL,
                report_json TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES analysis_sessions(session_id)
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_drift_reports_session ON drift_reports(session_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_drift_reports_timestamp ON drift_reports(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_drift_reports_status ON drift_reports(drift_status);")

            # Candidate Datasets Table (Head of SOC Training Studio)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS candidate_datasets (
                dataset_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                row_count INTEGER NOT NULL,
                dataset_type TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                validation_report_json TEXT NOT NULL
            );
            """)

            # Candidate Models Table (Isolated Experiments)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS candidate_models (
                candidate_id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL,
                model_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'TRAINED',
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                approved_by TEXT DEFAULT '',
                approved_at TEXT DEFAULT '',
                approval_note TEXT DEFAULT ''
            );
            """)

            # Model Backups & Rollback Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS model_backups (
                backup_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                previous_model_type TEXT NOT NULL,
                previous_candidate_id TEXT,
                backup_path TEXT NOT NULL,
                created_by TEXT NOT NULL
            );
            """)

            # Model Activation Audit Trail
            conn.execute("""
            CREATE TABLE IF NOT EXISTS model_activation_audit (
                activation_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL,
                dataset_id TEXT DEFAULT '',
                action TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                approval_note TEXT DEFAULT '',
                timestamp TEXT NOT NULL,
                backup_id TEXT DEFAULT '',
                metrics_json TEXT DEFAULT '',
                activation_result TEXT DEFAULT 'SUCCESS'
            );
            """)
            for col_name, col_type in [
                ("dataset_id", "TEXT DEFAULT ''"),
                ("metrics_json", "TEXT DEFAULT ''"),
                ("activation_result", "TEXT DEFAULT 'SUCCESS'")
            ]:
                try:
                    conn.execute(f"ALTER TABLE model_activation_audit ADD COLUMN {col_name} {col_type};")
                except Exception:
                    pass
            conn.execute("CREATE INDEX IF NOT EXISTS idx_candidate_models_status ON candidate_models(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_candidate_datasets_time ON candidate_datasets(uploaded_at);")
    finally:
        conn.close()


def insert_session(session_data: Dict[str, Any]) -> str:
    """Persists an analysis session summary into the database."""
    init_db()
    session_id = session_data.get("session_id") or f"SESS-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO analysis_sessions (
                session_id, timestamp, source_name, input_type,
                total_records, normal_events, threats_detected, known_threats, unknown_anomalous, invalid_records,
                threat_ratio, attack_categories, severity_distribution, model_summary, report_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                session_data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
                session_data.get("source_name", "Unknown Source"),
                session_data.get("input_type", "unknown"),
                int(session_data.get("total_records", 0)),
                int(session_data.get("normal_events", 0)),
                int(session_data.get("threats_detected", session_data.get("known_threats", 0))),
                int(session_data.get("known_threats", session_data.get("threats_detected", 0))),
                int(session_data.get("unknown_anomalous", 0)),
                int(session_data.get("invalid_records", 0)),
                float(session_data.get("threat_ratio", 0.0)),
                json.dumps(session_data.get("attack_categories", {})),
                json.dumps(session_data.get("severity_distribution", {})),
                json.dumps(session_data.get("model_summary", {})),
                json.dumps(session_data)
            ))

        if "drift_analysis" in session_data and isinstance(session_data["drift_analysis"], dict):
            try:
                da = session_data["drift_analysis"]
                da["session_id"] = session_id
                save_drift_report(da)
            except Exception as e_dr:
                import logging
                logging.getLogger(__name__).warning(f"Error persisting drift analysis from insert_session: {e_dr}")

        return session_id
    finally:
        conn.close()


def insert_detections(records: List[Dict[str, Any]], session_id: Optional[str] = None):
    """Batch-persists individual detection inference records."""
    if not records:
        return
    init_db()
    conn = get_connection()
    try:
        with conn:
            for r in records:
                det_id = r.get("id") or f"DET-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
                verdict = r.get("verdict", "NORMAL")
                status = r.get("prediction_status", verdict)
                conn.execute("""
                INSERT OR REPLACE INTO detections (
                    id, session_id, timestamp, source, input_type,
                    source_ip, destination_ip, destination_port, protocol,
                    verdict, prediction_status, predicted_class, confidence,
                    threat_confidence, threat_type, severity,
                    dominant_basepoint, dominant_similarity, profile_vector,
                    model_breakdown, anomaly_verdict, anomaly_status, anomaly_score,
                    detection_reason, requires_investigation, flow_metadata, campaign_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    det_id,
                    session_id or r.get("session_id"),
                    r.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
                    r.get("source", "Threat Analyzer"),
                    r.get("input_type", "flow"),
                    str(r.get("source_ip", "N/A")),
                    str(r.get("destination_ip", "N/A")),
                    int(r.get("destination_port", 0)),
                    str(r.get("protocol", "TCP")),
                    verdict,
                    status,
                    str(r.get("predicted_class", r.get("threat_type", "Benign Communication"))),
                    float(r.get("confidence", r.get("threat_confidence", 0.0))),
                    float(r.get("threat_confidence", 0.0)),
                    str(r.get("threat_type", r.get("predicted_class", "Benign Communication"))),
                    str(r.get("severity", "LOW")),
                    str(r.get("dominant_basepoint", "bp_01")),
                    float(r.get("dominant_similarity", 0.0)),
                    json.dumps(r.get("profile_vector", [])),
                    json.dumps(r.get("model_breakdown", {})),
                    str(r.get("anomaly_verdict", "NORMAL")),
                    str(r.get("anomaly_status", "NORMAL")),
                    float(r.get("anomaly_score", 0.0)),
                    str(r.get("detection_reason", "")),
                    1 if r.get("requires_investigation") else 0,
                    json.dumps(r.get("flow_metadata", {})),
                    str(r.get("campaign_id", "-"))
                ))
    finally:
        conn.close()


def get_latest_session() -> Optional[Dict[str, Any]]:
    """Retrieves the most recent analysis session from SQLite."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
        SELECT * FROM analysis_sessions ORDER BY timestamp DESC LIMIT 1
        """)
        row = cur.fetchone()
        if not row:
            return None
        keys = row.keys()
        return {
            "session_id": row["session_id"],
            "timestamp": row["timestamp"],
            "source_name": row["source_name"],
            "input_type": row["input_type"],
            "total_records": row["total_records"],
            "normal_events": row["normal_events"],
            "threats_detected": row["threats_detected"],
            "known_threats": row["known_threats"] if "known_threats" in keys else row["threats_detected"],
            "unknown_anomalous": row["unknown_anomalous"] if "unknown_anomalous" in keys else 0,
            "invalid_records": row["invalid_records"],
            "threat_ratio": row["threat_ratio"],
            "attack_categories": json.loads(row["attack_categories"]),
            "severity_distribution": json.loads(row["severity_distribution"]),
            "model_summary": json.loads(row["model_summary"])
        }
    finally:
        conn.close()


def get_detections(
    limit: int = 50,
    offset: int = 0,
    verdict: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Fetches paginated and filtered actual detection records."""
    init_db()
    conn = get_connection()
    try:
        query = "SELECT * FROM detections WHERE 1=1"
        params: List[Any] = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        if verdict and verdict.upper() != "ALL":
            v_up = verdict.upper()
            if v_up == "THREAT":
                query += " AND (verdict = 'THREAT' OR verdict = 'KNOWN_THREAT' OR prediction_status = 'KNOWN_THREAT' OR verdict = 'UNKNOWN_ANOMALOUS' OR prediction_status = 'UNKNOWN_ANOMALOUS' OR requires_investigation = 1)"
            elif v_up in ["KNOWN_THREAT", "UNKNOWN_ANOMALOUS", "NORMAL"]:
                query += " AND (verdict = ? OR prediction_status = ?)"
                params.extend([v_up, v_up])
            else:
                query += " AND (verdict = ? OR prediction_status = ?)"
                params.extend([v_up, v_up])

        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            query += " AND (LOWER(source_ip) LIKE ? OR LOWER(destination_ip) LIKE ? OR LOWER(threat_type) LIKE ? OR LOWER(predicted_class) LIKE ?)"
            params.extend([term, term, term, term])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = conn.execute(query, params)
        rows = cur.fetchall()

        results = []
        for r in rows:
            keys = r.keys()
            camp_id = r["campaign_id"] if "campaign_id" in keys and r["campaign_id"] else "-"
            results.append({
                "id": r["id"],
                "session_id": r["session_id"],
                "campaign_id": camp_id,
                "timestamp": r["timestamp"],
                "source": r["source"],
                "input_type": r["input_type"],
                "source_ip": r["source_ip"],
                "destination_ip": r["destination_ip"],
                "destination_port": r["destination_port"],
                "protocol": r["protocol"],
                "verdict": r["verdict"],
                "prediction_status": r["prediction_status"] if "prediction_status" in keys else r["verdict"],
                "predicted_class": r["predicted_class"] if "predicted_class" in keys else r["threat_type"],
                "confidence": r["confidence"] if "confidence" in keys else r["threat_confidence"],
                "threat_confidence": r["threat_confidence"],
                "threat_type": r["threat_type"],
                "severity": r["severity"],
                "dominant_basepoint": r["dominant_basepoint"],
                "dominant_similarity": r["dominant_similarity"],
                "profile_vector": json.loads(r["profile_vector"]) if r["profile_vector"] else [],
                "model_breakdown": json.loads(r["model_breakdown"]) if r["model_breakdown"] else {},
                "anomaly_verdict": r["anomaly_verdict"],
                "anomaly_status": r["anomaly_status"] if "anomaly_status" in keys else r.get("anomaly_verdict", "NORMAL"),
                "anomaly_score": r["anomaly_score"],
                "detection_reason": r["detection_reason"] if "detection_reason" in keys else "",
                "requires_investigation": bool(r["requires_investigation"]) if "requires_investigation" in keys else (r["verdict"] in ["THREAT", "KNOWN_THREAT", "UNKNOWN_ANOMALOUS"]),
                "flow_metadata": json.loads(r["flow_metadata"]) if "flow_metadata" in keys and r["flow_metadata"] else {}
            })
        return results
    finally:
        conn.close()


def get_detections_count(
    verdict: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    session_id: Optional[str] = None
) -> int:
    """Returns the total number of detections matching filters."""
    init_db()
    conn = get_connection()
    try:
        query = "SELECT COUNT(*) FROM detections WHERE 1=1"
        params: List[Any] = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        if verdict and verdict.upper() != "ALL":
            v_up = verdict.upper()
            if v_up == "THREAT":
                query += " AND (verdict = 'THREAT' OR verdict = 'KNOWN_THREAT' OR prediction_status = 'KNOWN_THREAT' OR verdict = 'UNKNOWN_ANOMALOUS' OR prediction_status = 'UNKNOWN_ANOMALOUS' OR requires_investigation = 1)"
            elif v_up in ["KNOWN_THREAT", "UNKNOWN_ANOMALOUS", "NORMAL"]:
                query += " AND (verdict = ? OR prediction_status = ?)"
                params.extend([v_up, v_up])
            else:
                query += " AND (verdict = ? OR prediction_status = ?)"
                params.extend([v_up, v_up])

        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            query += " AND (LOWER(source_ip) LIKE ? OR LOWER(destination_ip) LIKE ? OR LOWER(threat_type) LIKE ? OR LOWER(predicted_class) LIKE ?)"
            params.extend([term, term, term, term])

        cur = conn.execute(query, params)
        return int(cur.fetchone()[0])
    finally:
        conn.close()


def get_recent_threats(limit: int = 5, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves the most recent actual threat detections."""
    return get_detections(limit=limit, verdict="THREAT", session_id=session_id)


def get_recent_unknown_anomalous(limit: int = 5, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves the most recent unknown / anomalous detections."""
    return get_detections(limit=limit, verdict="UNKNOWN_ANOMALOUS", session_id=session_id)


def get_session_stream(session_id: str) -> List[Dict[str, Any]]:
    """
    Retrieves all sliding-window detection records for a specific upload session ordered
    chronologically (by rowid ASC) for sliding-window stream display and telemetry analysis.
    """
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
            SELECT id, session_id, timestamp, source, input_type,
                   source_ip, destination_ip, destination_port, protocol,
                   verdict, prediction_status, predicted_class,
                   confidence, threat_confidence, threat_type, severity,
                   dominant_basepoint, dominant_similarity,
                   anomaly_verdict, anomaly_status, anomaly_score,
                   detection_reason, requires_investigation,
                   flow_metadata, campaign_id
            FROM detections
            WHERE session_id = ?
            ORDER BY rowid ASC
        """, (session_id,))
        rows = cur.fetchall()
        stream = []
        for r in rows:
            meta = {}
            if r["flow_metadata"]:
                try:
                    meta = json.loads(r["flow_metadata"])
                except Exception:
                    meta = {}

            window_id = meta.get("window_id") or r["id"]
            event_set_id = meta.get("event_set_id") or "-"
            n_flows = meta.get("n_flows", 1)
            window_start = meta.get("window_start") or r["timestamp"]
            window_end = meta.get("window_end") or r["timestamp"]

            camp_id = r["campaign_id"] if (r["campaign_id"] and r["campaign_id"] != "-") else "-"

            verdict = r["verdict"]
            status = r["prediction_status"] or verdict
            conf = float(r["threat_confidence"] if r["threat_confidence"] is not None else r["confidence"])

            stream.append({
                "id": r["id"],
                "session_id": r["session_id"],
                "timestamp": window_start,
                "window_time": window_start,
                "window_start": window_start,
                "window_end": window_end,
                "window_id": str(window_id),
                "event_set_id": str(event_set_id),
                "n_flows": int(n_flows),
                "source_ip": r["source_ip"] or "N/A",
                "destination_ip": r["destination_ip"] or "N/A",
                "destination_port": int(r["destination_port"] or 0),
                "protocol": r["protocol"] or "TCP",
                "verdict": verdict,
                "prediction_status": status,
                "predicted_class": r["predicted_class"],
                "threat_type": r["threat_type"],
                "confidence": conf,
                "threat_confidence": conf,
                "severity": r["severity"],
                "campaign_id": camp_id,
                "dominant_basepoint": r["dominant_basepoint"] or "bp_01",
                "dominant_similarity": float(r["dominant_similarity"] or 0.0),
                "anomaly_verdict": r["anomaly_verdict"] or "NORMAL",
                "anomaly_status": r["anomaly_status"] or "NORMAL",
                "anomaly_score": float(r["anomaly_score"] or 0.0),
                "detection_reason": r["detection_reason"] or "",
                "requires_investigation": bool(r["requires_investigation"])
            })
        return stream
    finally:
        conn.close()


def insert_campaigns(campaigns: List[Dict[str, Any]], session_id: str):
    """Batch-persists logical security campaigns into SQLite."""
    if not campaigns:
        return
    init_db()
    conn = get_connection()
    try:
        with conn:
            for c in campaigns:
                conn.execute("""
                INSERT OR REPLACE INTO campaigns (
                    campaign_id, session_id, source_ip, destination_ip,
                    start_time, end_time, verdict, max_confidence,
                    window_count, attributed_flow_count, constituent_windows
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    c["campaign_id"],
                    session_id,
                    str(c.get("source_ip", "")),
                    str(c.get("destination_ip", "")),
                    str(c.get("start_time", "")),
                    str(c.get("end_time", "")),
                    c.get("verdict", "UNKNOWN_ANOMALOUS"),
                    float(c.get("max_confidence", 0.0)),
                    int(c.get("window_count", 1)),
                    int(c.get("attributed_flow_count", 0)),
                    json.dumps(c.get("constituent_windows", []))
                ))
    finally:
        conn.close()


def get_campaigns(limit: int = 50, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves security campaigns, optionally filtered by session_id."""
    init_db()
    conn = get_connection()
    try:
        query = "SELECT * FROM campaigns WHERE 1=1"
        params: List[Any] = []
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        query += " ORDER BY start_time DESC LIMIT ?"
        params.append(limit)
        cur = conn.execute(query, params)
        rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({
                "campaign_id": r["campaign_id"],
                "session_id": r["session_id"],
                "source_ip": r["source_ip"],
                "destination_ip": r["destination_ip"],
                "start_time": r["start_time"],
                "end_time": r["end_time"],
                "verdict": r["verdict"],
                "max_confidence": r["max_confidence"],
                "window_count": r["window_count"],
                "attributed_flow_count": r["attributed_flow_count"],
                "constituent_windows": json.loads(r["constituent_windows"]) if r["constituent_windows"] else []
            })
        return out
    finally:
        conn.close()


def get_sessions(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Retrieves paginated analysis sessions sorted chronologically descending."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
            SELECT session_id, timestamp, source_name, input_type,
                   total_records, normal_events, threats_detected,
                   known_threats, unknown_anomalous, invalid_records,
                   threat_ratio, attack_categories, severity_distribution, model_summary
            FROM analysis_sessions
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        rows = cur.fetchall()
        out = []
        for r in rows:
            keys = r.keys()
            sid = r["session_id"]

            camp_cur = conn.execute("SELECT COUNT(*) FROM campaigns WHERE session_id = ?", (sid,))
            camp_count = int(camp_cur.fetchone()[0])

            det_cur = conn.execute("SELECT COUNT(*) FROM detections WHERE session_id = ?", (sid,))
            det_count = int(det_cur.fetchone()[0])

            out.append({
                "session_id": sid,
                "timestamp": r["timestamp"],
                "filename": r["source_name"],
                "source_name": r["source_name"],
                "input_type": r["input_type"],
                "total_records": r["total_records"],
                "uploaded_flows": r["total_records"],
                "event_sets": det_count if det_count > 0 else r["total_records"],
                "normal_events": r["normal_events"],
                "known_threats": r["known_threats"] if "known_threats" in keys else r["threats_detected"],
                "unknown_anomalous": r["unknown_anomalous"] if "unknown_anomalous" in keys else 0,
                "threats_detected": r["threats_detected"],
                "campaigns_count": camp_count,
                "status": "Completed"
            })
        return out
    finally:
        conn.close()


def get_sessions_count() -> int:
    """Returns the total number of recorded analysis sessions."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT COUNT(*) FROM analysis_sessions")
        return int(cur.fetchone()[0])
    finally:
        conn.close()


def get_session_by_id(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single analysis session summary by its ID."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
            SELECT * FROM analysis_sessions WHERE session_id = ?
        """, (session_id,))
        row = cur.fetchone()
        if not row:
            return None
        keys = row.keys()
        return {
            "session_id": row["session_id"],
            "timestamp": row["timestamp"],
            "source_name": row["source_name"],
            "filename": row["source_name"],
            "input_type": row["input_type"],
            "total_records": row["total_records"],
            "normal_events": row["normal_events"],
            "threats_detected": row["threats_detected"],
            "known_threats": row["known_threats"] if "known_threats" in keys else row["threats_detected"],
            "unknown_anomalous": row["unknown_anomalous"] if "unknown_anomalous" in keys else 0,
            "invalid_records": row["invalid_records"],
            "threat_ratio": row["threat_ratio"],
            "attack_categories": json.loads(row["attack_categories"]) if row["attack_categories"] else {},
            "severity_distribution": json.loads(row["severity_distribution"]) if row["severity_distribution"] else {},
            "model_summary": json.loads(row["model_summary"]) if row["model_summary"] else {},
            "status": "Completed"
        }
    finally:
        conn.close()


def get_session_report(session_id: str, include_drift: bool = True) -> Optional[Dict[str, Any]]:
    """
    Retrieves the complete, immutable persistent classification report for a session.
    If report_data is cached, loads and enriches it; otherwise synthesizes the report
    from session columns, actual detections, and campaigns.
    """
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM analysis_sessions WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        if not row:
            return None
        keys = row.keys()

        report: Dict[str, Any] = {}
        if "report_data" in keys and row["report_data"]:
            try:
                report = json.loads(row["report_data"])
            except Exception:
                report = {}

        report["session_id"] = row["session_id"]
        report["filename"] = report.get("filename") or row["source_name"]
        report["source_name"] = report.get("source_name") or row["source_name"]
        report["input_type"] = report.get("input_type") or row["input_type"]
        report["timestamp"] = report.get("timestamp") or row["timestamp"]
        report["status"] = "Completed"
        report["has_data"] = True

        report["total_records"] = report.get("total_records") or row["total_records"]
        report["normal_events"] = report.get("normal_events") or row["normal_events"]
        report["threats_detected"] = report.get("threats_detected") or row["threats_detected"]
        report["known_threats"] = report.get("known_threats", row["known_threats"] if "known_threats" in keys else row["threats_detected"])
        report["unknown_anomalous"] = report.get("unknown_anomalous", row["unknown_anomalous"] if "unknown_anomalous" in keys else 0)
        report["invalid_records"] = report.get("invalid_records") or row["invalid_records"]
        report["threat_ratio"] = report.get("threat_ratio", row["threat_ratio"])

        if "attack_categories" not in report or not report["attack_categories"]:
            report["attack_categories"] = json.loads(row["attack_categories"]) if row["attack_categories"] else {}
        if "severity_distribution" not in report or not report["severity_distribution"]:
            report["severity_distribution"] = json.loads(row["severity_distribution"]) if row["severity_distribution"] else {}
        if "model_summary" not in report or not report["model_summary"]:
            report["model_summary"] = json.loads(row["model_summary"]) if row["model_summary"] else {}

        ms = report.get("model_summary") or {}
        if "fcnn_avg" not in ms or ms.get("fcnn_avg") is None:
            try:
                cur_ms = conn.execute("""
                    SELECT 
                        AVG(json_extract(model_breakdown, '$.fcnn')),
                        AVG(json_extract(model_breakdown, '$.cnn')),
                        AVG(json_extract(model_breakdown, '$.lstm')),
                        AVG(confidence),
                        COUNT(*)
                    FROM detections
                    WHERE session_id = ? AND model_breakdown IS NOT NULL
                """, (session_id,))
                ms_row = cur_ms.fetchone()
                if ms_row and ms_row[4] > 0 and ms_row[0] is not None:
                    ms["fcnn_avg"] = round(float(ms_row[0]), 4)
                    ms["cnn_avg"] = round(float(ms_row[1]), 4)
                    ms["lstm_avg"] = round(float(ms_row[2]), 4)
                    ms["ensemble_avg"] = round(float(ms_row[3]), 4)
                else:
                    ms["fcnn_avg"] = None
                    ms["cnn_avg"] = None
                    ms["lstm_avg"] = None
                    ms["ensemble_avg"] = None
            except Exception:
                pass
            report["model_summary"] = ms

        # Enrich drift analysis from drift_reports table (omitted for Regular Security Analysts)
        if include_drift:
            if not report.get("drift_analysis"):
                try:
                    report["drift_analysis"] = get_drift_report_by_session(session_id)
                except Exception:
                    report["drift_analysis"] = None
        else:
            report["drift_analysis"] = None

        # Enrich campaigns, known_threats_list, and unknown_anomalies_list
        if not report.get("campaigns"):
            report["campaigns"] = get_campaigns(session_id=session_id, limit=500)
        if not report.get("known_threats_list"):
            report["known_threats_list"] = get_detections(session_id=session_id, verdict="KNOWN_THREAT", limit=1000)
        if not report.get("unknown_anomalies_list"):
            report["unknown_anomalies_list"] = get_detections(session_id=session_id, verdict="UNKNOWN_ANOMALOUS", limit=1000)

        # Ensure structured statistics
        if not report.get("flow_statistics"):
            report["flow_statistics"] = {
                "total_raw_flows": report["total_records"],
                "unique_flows_analysed": report["total_records"],
                "benign_flows": report["normal_events"],
                "known_threat_flows": report["known_threats"],
                "unknown_anomalous_flows": report["unknown_anomalous"],
                "invalid_flows": report["invalid_records"]
            }
        if not report.get("event_set_statistics"):
            det_count = len(report.get("known_threats_list", [])) + len(report.get("unknown_anomalies_list", [])) + report["normal_events"]
            report["event_set_statistics"] = {
                "total_event_sets": det_count if det_count > 0 else report["total_records"],
                "normal_event_sets": report["normal_events"],
                "ann_alert_sets": report["known_threats"],
                "unknown_anomalous_sets": report["unknown_anomalous"]
            }
        if not report.get("campaign_statistics"):
            camps = report.get("campaigns", [])
            report["campaign_statistics"] = {
                "total_campaigns": len(camps),
                "known_threat_campaigns": sum(1 for c in camps if c.get("verdict") == "KNOWN_THREAT"),
                "unknown_anomalous_campaigns": sum(1 for c in camps if c.get("verdict") == "UNKNOWN_ANOMALOUS")
            }

        return report
    finally:
        conn.close()


def delete_session(session_id: str) -> bool:
    """
    Transactionally deletes a single session and its associated detections and campaigns.
    Does NOT affect any other sessions or call clear_all_history().
    Returns True if the session existed and was deleted, False if not found.
    """
    init_db()
    conn = get_connection()
    try:
        with conn:
            cur = conn.execute("SELECT session_id FROM analysis_sessions WHERE session_id = ?", (session_id,))
            if not cur.fetchone():
                return False

            conn.execute("DELETE FROM detections WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM campaigns WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM drift_reports WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM analysis_sessions WHERE session_id = ?", (session_id,))
            return True
    finally:
        conn.close()


def clear_all_history():
    """Wipes all sessions, campaigns, and detection records for a clean test state."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            conn.execute("DELETE FROM detections;")
            conn.execute("DELETE FROM campaigns;")
            conn.execute("DELETE FROM drift_reports;")
            conn.execute("DELETE FROM analysis_sessions;")
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Dual-Layer Data Drift Reports Persistence
# -----------------------------------------------------------------------------

def save_drift_report(report_dict: Dict[str, Any]) -> str:
    """Persists a dual-layer drift report into SQLite."""
    init_db()
    conn = get_connection()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    report_id = report_dict.get("id") or f"DRIFT-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    session_id = report_dict.get("session_id")
    upload_id = report_dict.get("upload_id")

    l1 = report_dict.get("layer1_network_features")
    l1_score = float(l1["score"]) if (l1 and "score" in l1 and l1["score"] is not None) else None
    l2 = report_dict.get("layer2_event_profiles")
    l2_score = float(l2["score"]) if (l2 and "score" in l2 and l2["score"] is not None) else None

    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO drift_reports (
                id, session_id, upload_id, timestamp, reference_experiment, reference_population,
                overall_drift_score, overall_drift_percentage, drift_status, recommendation_alert,
                recommendation_message, is_partial, omitted_layer, layer1_score, layer2_score, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                session_id,
                upload_id,
                report_dict.get("timestamp") or now_str,
                report_dict.get("reference_experiment", "exp_b"),
                report_dict.get("reference_population", "full"),
                float(report_dict.get("overall_drift_score", 0.0)),
                float(report_dict.get("overall_drift_percentage", 0.0)),
                report_dict.get("drift_status", "LOW"),
                1 if report_dict.get("recommendation_alert") else 0,
                report_dict.get("recommendation_message", ""),
                1 if report_dict.get("is_partial") else 0,
                report_dict.get("omitted_layer") or "",
                l1_score,
                l2_score,
                json.dumps(report_dict)
            ))
        return report_id
    finally:
        conn.close()


def get_latest_drift_report() -> Optional[Dict[str, Any]]:
    """Retrieves the most recent data drift evaluation report."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
        SELECT report_json FROM drift_reports
        ORDER BY timestamp DESC, rowid DESC
        LIMIT 1
        """)
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row["report_json"])
    finally:
        conn.close()


def get_drift_report_by_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves drift report for a specific session."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
        SELECT report_json FROM drift_reports
        WHERE session_id = ?
        ORDER BY timestamp DESC
        LIMIT 1
        """, (session_id,))
        row = cur.fetchone()
        if row:
            return json.loads(row["report_json"])

        cur_sess = conn.execute("SELECT report_data FROM analysis_sessions WHERE session_id = ?", (session_id,))
        row_sess = cur_sess.fetchone()
        if row_sess and row_sess["report_data"]:
            try:
                sess_data = json.loads(row_sess["report_data"])
                if "drift_analysis" in sess_data:
                    return sess_data["drift_analysis"]
            except Exception:
                pass
        return None
    finally:
        conn.close()


def get_drift_reports_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves summarized historical data drift reports for trend visualization."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
        SELECT id, session_id, upload_id, timestamp, reference_experiment, reference_population,
               overall_drift_score, overall_drift_percentage, drift_status, recommendation_alert,
               recommendation_message, is_partial, omitted_layer, layer1_score, layer2_score
        FROM drift_reports
        ORDER BY timestamp DESC, rowid DESC
        LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        return [
            {
                "id": r["id"],
                "session_id": r["session_id"],
                "upload_id": r["upload_id"],
                "timestamp": r["timestamp"],
                "reference_experiment": r["reference_experiment"],
                "reference_population": r["reference_population"],
                "overall_drift_score": float(r["overall_drift_score"]),
                "overall_drift_percentage": float(r["overall_drift_percentage"]),
                "drift_status": r["drift_status"],
                "recommendation_alert": bool(r["recommendation_alert"]),
                "recommendation_message": r["recommendation_message"],
                "is_partial": bool(r["is_partial"]),
                "omitted_layer": r["omitted_layer"],
                "layer1_score": float(r["layer1_score"]) if r["layer1_score"] is not None else None,
                "layer2_score": float(r["layer2_score"]) if r["layer2_score"] is not None else None,
            }
            for r in rows
        ]
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# User Sessions & Access Control Persistence
# -----------------------------------------------------------------------------

def save_user_session(session_dict: Dict[str, Any]):
    """Persists an active authenticated user session into SQLite."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO user_sessions (
                token, email, name, callsign, role, clearance,
                department, avatar, remember_me, created_at, expires_at, auth_method
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_dict["token"],
                session_dict["email"],
                session_dict.get("name", "SOC Operator"),
                session_dict.get("callsign", "Sentinel"),
                session_dict.get("role", "Security Analyst"),
                session_dict.get("clearance", "Level 3"),
                session_dict.get("department", "SOC"),
                session_dict.get("avatar", "SO"),
                1 if session_dict.get("remember_me") else 0,
                session_dict["created_at"],
                session_dict["expires_at"],
                session_dict.get("auth_method", "SOC_CREDENTIALS")
            ))
    finally:
        conn.close()


def get_user_session(token: str) -> Optional[Dict[str, Any]]:
    """Retrieves an active user session by token from SQLite."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM user_sessions WHERE token = ?", (token,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "token": row["token"],
            "email": row["email"],
            "name": row["name"],
            "callsign": row["callsign"],
            "role": row["role"],
            "clearance": row["clearance"],
            "department": row["department"],
            "avatar": row["avatar"],
            "remember_me": bool(row["remember_me"]),
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "auth_method": row["auth_method"]
        }
    finally:
        conn.close()


def delete_user_session(token: str) -> bool:
    """Deletes and revokes a user session token from SQLite."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            cur = conn.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
            return cur.rowcount > 0
    finally:
        conn.close()


def save_clearance_ticket(ticket_dict: Dict[str, Any]):
    """Persists an access clearance ticket into SQLite."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO access_clearance_tickets (
                ticket_id, name, email, clearance_level, reason, status, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ticket_dict["ticket_id"],
                ticket_dict["name"],
                ticket_dict["email"],
                ticket_dict["clearance_level"],
                ticket_dict["reason"],
                ticket_dict["status"],
                ticket_dict["timestamp"]
            ))
    finally:
        conn.close()


def save_recovery_token(token: str, email: str, created_at: str, expires_at: str = ""):
    """Persists a password recovery token into SQLite with expiry tracking."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO password_recovery_requests (
                token, email, created_at, expires_at, used
            ) VALUES (?, ?, ?, ?, 0)
            """, (token, email, created_at, expires_at))
    finally:
        conn.close()


def get_recovery_token(token: str) -> Optional[Dict[str, Any]]:
    """Retrieves a recovery token record from SQLite."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM password_recovery_requests WHERE token = ?", (token,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "token": row["token"],
            "email": row["email"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"] if "expires_at" in row.keys() else "",
            "used": bool(row["used"]) if "used" in row.keys() else False
        }
    finally:
        conn.close()


def mark_recovery_token_used(token: str) -> bool:
    """Marks a recovery token as consumed in SQLite (single-use enforcement)."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            cur = conn.execute("UPDATE password_recovery_requests SET used = 1 WHERE token = ?", (token,))
            return cur.rowcount > 0
    finally:
        conn.close()


# =====================================================================
# Resumable Chunked Upload & Processing Helper Functions
# =====================================================================

def create_upload_session(
    upload_id: str,
    session_id: str,
    filename: str,
    file_size: int,
    file_hash: str,
    total_chunks: int
) -> Dict[str, Any]:
    """Creates a new tracking session for a chunked upload."""
    init_db()
    conn = get_connection()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO upload_sessions (
                upload_id, session_id, filename, file_size, file_hash, total_chunks,
                uploaded_chunks_count, upload_status, sort_status, processing_status,
                total_rows, processed_rows, total_batches, completed_batches,
                global_t0, last_finalized_k, created_at, updated_at, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, 0, 'UPLOADING', 'PENDING', 'PENDING', 0, 0, 0, 0, '', -1, ?, ?, '')
            """, (upload_id, session_id, filename, file_size, file_hash, total_chunks, now_str, now_str))
        return get_upload_session(upload_id) or {}
    finally:
        conn.close()


def get_upload_session(upload_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an upload session record by upload_id."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM upload_sessions WHERE upload_id = ?", (upload_id,))
        row = cur.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


get_upload = get_upload_session


def find_upload_session_by_hash(file_hash: str, file_size: int) -> Optional[Dict[str, Any]]:
    """Finds an existing upload session by file hash and size for resume matching."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT * FROM upload_sessions WHERE file_hash = ? AND file_size = ? ORDER BY created_at DESC LIMIT 1",
            (file_hash, file_size)
        )
        row = cur.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def record_upload_chunk(upload_id: str, chunk_index: int, chunk_size: int) -> int:
    """Records receipt of a file chunk and updates uploaded count atomically."""
    init_db()
    conn = get_connection()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO upload_chunks (upload_id, chunk_index, chunk_size, received_at)
            VALUES (?, ?, ?, ?)
            """, (upload_id, chunk_index, chunk_size, now_str))

            cur = conn.execute("SELECT COUNT(*) FROM upload_chunks WHERE upload_id = ?", (upload_id,))
            count = cur.fetchone()[0]

            conn.execute("""
            UPDATE upload_sessions
            SET uploaded_chunks_count = ?, updated_at = ?
            WHERE upload_id = ?
            """, (count, now_str, upload_id))
            return count
    finally:
        conn.close()


def get_completed_chunks(upload_id: str) -> List[int]:
    """Returns sorted list of chunk indices already uploaded for this session."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT chunk_index FROM upload_chunks WHERE upload_id = ? ORDER BY chunk_index ASC",
            (upload_id,)
        )
        return [row[0] for row in cur.fetchall()]
    finally:
        conn.close()


def update_upload_status(
    upload_id: str,
    upload_status: Optional[str] = None,
    sort_status: Optional[str] = None,
    processing_status: Optional[str] = None,
    error_message: Optional[str] = None
) -> None:
    """Updates status indicators for an upload session."""
    init_db()
    conn = get_connection()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    updates = ["updated_at = ?"]
    params = [now_str]

    if upload_status is not None:
        updates.append("upload_status = ?")
        params.append(upload_status)
    if sort_status is not None:
        updates.append("sort_status = ?")
        params.append(sort_status)
    if processing_status is not None:
        updates.append("processing_status = ?")
        params.append(processing_status)
    if error_message is not None:
        updates.append("error_message = ?")
        params.append(error_message)

    params.append(upload_id)
    sql = f"UPDATE upload_sessions SET {', '.join(updates)} WHERE upload_id = ?"
    try:
        with conn:
            conn.execute(sql, tuple(params))
    finally:
        conn.close()


def update_upload_progress(
    upload_id: str,
    total_rows: Optional[int] = None,
    total_batches: Optional[int] = None,
    processed_rows: Optional[int] = None,
    completed_batches: Optional[int] = None,
    global_t0: Optional[str] = None,
    last_finalized_k: Optional[int] = None
) -> None:
    """Updates row, batch, and window progress counters for an upload session."""
    init_db()
    conn = get_connection()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    updates = ["updated_at = ?"]
    params = [now_str]

    if total_rows is not None:
        updates.append("total_rows = ?")
        params.append(total_rows)
    if total_batches is not None:
        updates.append("total_batches = ?")
        params.append(total_batches)
    if processed_rows is not None:
        updates.append("processed_rows = ?")
        params.append(processed_rows)
    if completed_batches is not None:
        updates.append("completed_batches = ?")
        params.append(completed_batches)
    if global_t0 is not None:
        updates.append("global_t0 = ?")
        params.append(global_t0)
    if last_finalized_k is not None:
        updates.append("last_finalized_k = ?")
        params.append(last_finalized_k)

    params.append(upload_id)
    sql = f"UPDATE upload_sessions SET {', '.join(updates)} WHERE upload_id = ?"
    try:
        with conn:
            conn.execute(sql, tuple(params))
    finally:
        conn.close()


def save_batch_checkpoint(
    upload_id: str,
    batch_index: int,
    row_start: int,
    row_end: int,
    n_flows: int,
    n_event_sets: int,
    last_finalized_k: int,
    boundary_state: str,
    metrics_snapshot: str,
    detections_list: List[Dict[str, Any]],
    alert_windows_list: List[Dict[str, Any]]
) -> None:
    """
    Atomically saves batch checkpoint, intermediate detections, and pending alert windows.
    If an error occurs, the entire batch's state is rolled back.
    """
    init_db()
    conn = get_connection()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with conn:
            # 1. Insert intermediate detection records
            det_rows = [
                (
                    d["id"],
                    upload_id,
                    batch_index,
                    json.dumps(d)
                )
                for d in detections_list
            ]
            conn.executemany("""
            INSERT OR REPLACE INTO batch_intermediate_detections (id, upload_id, batch_index, detection_json)
            VALUES (?, ?, ?, ?)
            """, det_rows)

            # 2. Insert pending alert windows
            win_rows = [
                (
                    w["event_set_id"],
                    upload_id,
                    batch_index,
                    json.dumps(w["window_dict"]),
                    json.dumps(w["flow_indices"])
                )
                for w in alert_windows_list
            ]
            conn.executemany("""
            INSERT OR REPLACE INTO batch_pending_alert_windows (event_set_id, upload_id, batch_index, window_json, flow_indices_json)
            VALUES (?, ?, ?, ?, ?)
            """, win_rows)

            # 3. Insert checkpoint record
            conn.execute("""
            INSERT OR REPLACE INTO batch_checkpoints (
                upload_id, batch_index, row_start, row_end, n_flows, n_event_sets,
                last_finalized_k, boundary_state, metrics_snapshot, status, checkpoint_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'COMPLETED', ?)
            """, (
                upload_id, batch_index, row_start, row_end, n_flows, n_event_sets,
                last_finalized_k, boundary_state, metrics_snapshot, now_str
            ))

            # 4. Update upload_sessions progress counters
            conn.execute("""
            UPDATE upload_sessions
            SET completed_batches = ?, processed_rows = ?, last_finalized_k = ?, updated_at = ?
            WHERE upload_id = ?
            """, (batch_index + 1, row_end, last_finalized_k, now_str, upload_id))
    finally:
        conn.close()


def get_latest_checkpoint(upload_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves the most recent completed batch checkpoint for an upload session."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT * FROM batch_checkpoints WHERE upload_id = ? AND status = 'COMPLETED' ORDER BY batch_index DESC LIMIT 1",
            (upload_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def get_all_checkpoints(upload_id: str) -> List[Dict[str, Any]]:
    """Retrieves all completed checkpoints for an upload session."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT * FROM batch_checkpoints WHERE upload_id = ? ORDER BY batch_index ASC",
            (upload_id,)
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_pending_alert_windows(upload_id: str) -> List[Dict[str, Any]]:
    """Retrieves all accumulated alert windows across all batches for global campaign coalescence."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT * FROM batch_pending_alert_windows WHERE upload_id = ? ORDER BY batch_index ASC, event_set_id ASC",
            (upload_id,)
        )
        out = []
        for row in cur.fetchall():
            out.append({
                "event_set_id": row["event_set_id"],
                "batch_index": row["batch_index"],
                "window": json.loads(row["window_json"]),
                "flow_indices": json.loads(row["flow_indices_json"])
            })
        return out
    finally:
        conn.close()


def get_intermediate_detections(upload_id: str) -> List[Dict[str, Any]]:
    """Retrieves all staged intermediate detection records for an upload session."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT detection_json FROM batch_intermediate_detections WHERE upload_id = ? ORDER BY batch_index ASC, id ASC",
            (upload_id,)
        )
        return [json.loads(row[0]) for row in cur.fetchall()]
    finally:
        conn.close()


def finalize_upload_session(
    upload_id: str,
    session_summary: Dict[str, Any],
    coalesced_campaigns: List[Dict[str, Any]],
    final_detections: List[Dict[str, Any]]
) -> None:
    """
    Atomically commits the final analysis session, moves staged detections to production,
    inserts coalesced campaigns, and cleans up staging tables in ONE transaction.
    """
    init_db()
    conn = get_connection()
    session_id = session_summary["session_id"]
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with conn:
            # 1. Insert master analysis session
            conn.execute("""
            INSERT OR REPLACE INTO analysis_sessions (
                session_id, timestamp, source_name, input_type, total_records,
                normal_events, threats_detected, known_threats, unknown_anomalous,
                invalid_records, threat_ratio, attack_categories, severity_distribution,
                model_summary, report_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                session_summary.get("timestamp", now_str),
                session_summary.get("source_name", "uploaded_file.csv"),
                session_summary.get("input_type", "flow"),
                session_summary.get("total_records", 0),
                session_summary.get("normal_events", 0),
                session_summary.get("threats_detected", 0),
                session_summary.get("known_threats", 0),
                session_summary.get("unknown_anomalous", 0),
                session_summary.get("invalid_records", 0),
                session_summary.get("threat_ratio", 0.0),
                json.dumps(session_summary.get("attack_categories", {})),
                json.dumps(session_summary.get("severity_distribution", {})),
                json.dumps(session_summary.get("model_summary", {})),
                json.dumps(session_summary.get("report_data", session_summary))
            ))

            # 2. Insert final detections into production table
            det_rows = [
                (
                    d.get("id", f"DET-{session_id}-{i:04d}"),
                    session_id,
                    d.get("timestamp", now_str),
                    d.get("source", session_summary.get("source_name", "flow")),
                    d.get("input_type", "flow"),
                    d.get("source_ip", "-"),
                    d.get("destination_ip", "-"),
                    d.get("destination_port", 0),
                    d.get("protocol", "TCP"),
                    d.get("verdict", "NORMAL"),
                    d.get("prediction_status", d.get("verdict", "NORMAL")),
                    d.get("predicted_class", "Benign Network Traffic"),
                    d.get("confidence", 0.0),
                    d.get("threat_confidence", d.get("confidence", 0.0)),
                    d.get("threat_type", d.get("predicted_class", "Benign Network Traffic")),
                    d.get("severity", "LOW"),
                    d.get("dominant_basepoint", "bp_01"),
                    d.get("dominant_similarity", 0.0),
                    json.dumps(d.get("profile_vector", d.get("basepoint_profile", []))),
                    json.dumps(d.get("model_breakdown", {})),
                    d.get("anomaly_verdict", "NORMAL"),
                    d.get("anomaly_status", "NORMAL"),
                    d.get("anomaly_score", 0.0),
                    d.get("detection_reason", ""),
                    1 if d.get("requires_investigation") else 0,
                    json.dumps(d.get("flow_metadata", {})),
                    d.get("campaign_id", "-")
                )
                for i, d in enumerate(final_detections)
            ]
            conn.executemany("""
            INSERT OR REPLACE INTO detections (
                id, session_id, timestamp, source, input_type, source_ip, destination_ip,
                destination_port, protocol, verdict, prediction_status, predicted_class,
                confidence, threat_confidence, threat_type, severity, dominant_basepoint,
                dominant_similarity, profile_vector, model_breakdown, anomaly_verdict,
                anomaly_status, anomaly_score, detection_reason, requires_investigation,
                flow_metadata, campaign_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, det_rows)

            # 3. Insert coalesced campaigns
            camp_rows = [
                (
                    c["campaign_id"],
                    session_id,
                    c.get("source_ip", "-"),
                    c.get("destination_ip", "-"),
                    c.get("start_time", now_str),
                    c.get("end_time", now_str),
                    c.get("verdict", "KNOWN_THREAT"),
                    c.get("max_confidence", 0.0),
                    c.get("window_count", 0),
                    c.get("attributed_flow_count", 0),
                    json.dumps(c.get("constituent_windows", []))
                )
                for c in coalesced_campaigns
            ]
            conn.executemany("""
            INSERT OR REPLACE INTO campaigns (
                campaign_id, session_id, source_ip, destination_ip, start_time, end_time,
                verdict, max_confidence, window_count, attributed_flow_count, constituent_windows
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, camp_rows)

            # 4. Insert drift report if present
            if "drift_analysis" in session_summary and isinstance(session_summary["drift_analysis"], dict):
                da = session_summary["drift_analysis"]
                drift_id = da.get("id") or f"DRIFT-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
                l1 = da.get("layer1_network_features")
                l1_score = float(l1["score"]) if (l1 and "score" in l1 and l1["score"] is not None) else None
                l2 = da.get("layer2_event_profiles")
                l2_score = float(l2["score"]) if (l2 and "score" in l2 and l2["score"] is not None) else None

                conn.execute("""
                INSERT OR REPLACE INTO drift_reports (
                    id, session_id, upload_id, timestamp, reference_experiment, reference_population,
                    overall_drift_score, overall_drift_percentage, drift_status, recommendation_alert,
                    recommendation_message, is_partial, omitted_layer, layer1_score, layer2_score, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    drift_id,
                    session_id,
                    upload_id,
                    da.get("timestamp") or now_str,
                    da.get("reference_experiment", "exp_b"),
                    da.get("reference_population", "full"),
                    float(da.get("overall_drift_score", 0.0)),
                    float(da.get("overall_drift_percentage", 0.0)),
                    da.get("drift_status", "LOW"),
                    1 if da.get("recommendation_alert") else 0,
                    da.get("recommendation_message", ""),
                    1 if da.get("is_partial") else 0,
                    da.get("omitted_layer") or "",
                    l1_score,
                    l2_score,
                    json.dumps(da)
                ))

            # 5. Mark upload session completed
            conn.execute("""
            UPDATE upload_sessions
            SET processing_status = 'COMPLETED', updated_at = ?
            WHERE upload_id = ?
            """, (now_str, upload_id))

            # 6. Clean up temporary staging tables
            conn.execute("DELETE FROM batch_intermediate_detections WHERE upload_id = ?", (upload_id,))
            conn.execute("DELETE FROM batch_pending_alert_windows WHERE upload_id = ?", (upload_id,))
    finally:
        conn.close()


PROTECTED_INCIDENT_UPLOADS = {"UPL-20261118220457-b41aa8a7"}


def cancel_and_cleanup_upload(upload_id: str) -> bool:
    """Cancels an upload session and drops all associated staging records."""
    if upload_id in PROTECTED_INCIDENT_UPLOADS:
        raise ValueError(
            f"Upload session '{upload_id}' is protected for forensic diagnostic audit and cannot be purged."
        )
    init_db()
    conn = get_connection()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with conn:
            conn.execute("""
            UPDATE upload_sessions
            SET upload_status = 'CANCELLED', processing_status = 'CANCELLED', updated_at = ?
            WHERE upload_id = ?
            """, (now_str, upload_id))
            conn.execute("DELETE FROM upload_chunks WHERE upload_id = ?", (upload_id,))
            conn.execute("DELETE FROM batch_checkpoints WHERE upload_id = ?", (upload_id,))
            conn.execute("DELETE FROM batch_intermediate_detections WHERE upload_id = ?", (upload_id,))
            conn.execute("DELETE FROM batch_pending_alert_windows WHERE upload_id = ?", (upload_id,))
            return True
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Training Dataset Management & Candidate Model Studio Persistence
# -----------------------------------------------------------------------------

def save_candidate_dataset(dataset_data: Dict[str, Any]) -> str:
    """Persists a validated candidate dataset entry into SQLite."""
    init_db()
    dataset_id = dataset_data.get("dataset_id") or f"DS-CAND-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO candidate_datasets (
                dataset_id, filename, file_path, row_count, dataset_type,
                uploaded_by, uploaded_at, validation_report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                dataset_id,
                dataset_data["filename"],
                str(dataset_data["file_path"]),
                int(dataset_data["row_count"]),
                dataset_data.get("dataset_type", "EVENT_PROFILES"),
                dataset_data.get("uploaded_by", "admin@soc.ai"),
                dataset_data.get("uploaded_at") or time.strftime("%Y-%m-%d %H:%M:%S"),
                json.dumps(dataset_data.get("validation_report", {}))
            ))
        return dataset_id
    finally:
        conn.close()


def get_candidate_dataset(dataset_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a candidate dataset entry by ID."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM candidate_datasets WHERE dataset_id = ?", (dataset_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["validation_report"] = json.loads(d.get("validation_report_json") or "{}")
        except Exception:
            d["validation_report"] = {}
        return d
    finally:
        conn.close()


def list_candidate_datasets(limit: int = 50) -> List[Dict[str, Any]]:
    """Lists recent candidate datasets sorted by upload time descending."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM candidate_datasets ORDER BY uploaded_at DESC LIMIT ?", (limit,))
        results = []
        for row in cur.fetchall():
            d = dict(row)
            try:
                d["validation_report"] = json.loads(d.get("validation_report_json") or "{}")
            except Exception:
                d["validation_report"] = {}
            results.append(d)
        return results
    finally:
        conn.close()


def save_candidate_model(model_data: Dict[str, Any]) -> str:
    """Persists a trained candidate model entry into SQLite."""
    init_db()
    candidate_id = model_data.get("candidate_id") or f"MDL-CAND-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO candidate_models (
                candidate_id, dataset_id, model_name, status, created_at,
                created_by, metrics_json, artifact_path, approved_by, approved_at, approval_note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                candidate_id,
                model_data.get("dataset_id", "UNKNOWN"),
                model_data.get("model_name", "FCNN_Candidate_Ensemble"),
                model_data.get("status", "TRAINED"),
                model_data.get("created_at") or time.strftime("%Y-%m-%d %H:%M:%S"),
                model_data.get("created_by", "admin@soc.ai"),
                json.dumps(model_data.get("metrics", {})),
                str(model_data.get("artifact_path", "")),
                model_data.get("approved_by", ""),
                model_data.get("approved_at", ""),
                model_data.get("approval_note", "")
            ))
        return candidate_id
    finally:
        conn.close()


def get_candidate_model(candidate_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a candidate model entry by ID."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM candidate_models WHERE candidate_id = ?", (candidate_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["metrics"] = json.loads(d.get("metrics_json") or "{}")
        except Exception:
            d["metrics"] = {}
        return d
    finally:
        conn.close()


def get_active_candidate_model() -> Optional[Dict[str, Any]]:
    """Retrieves the currently ACTIVE candidate model if one was activated."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM candidate_models WHERE status = 'ACTIVE' ORDER BY approved_at DESC LIMIT 1")
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["metrics"] = json.loads(d.get("metrics_json") or "{}")
        except Exception:
            d["metrics"] = {}
        return d
    finally:
        conn.close()


def update_candidate_model_status(
    candidate_id: str,
    status: str,
    approved_by: str = "",
    approval_note: str = ""
) -> bool:
    """Updates candidate model status (e.g. TRAINED, ACTIVE, ARCHIVED, ROLLED_BACK)."""
    init_db()
    conn = get_connection()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with conn:
            conn.execute("""
            UPDATE candidate_models
            SET status = ?, approved_by = ?, approved_at = ?, approval_note = ?
            WHERE candidate_id = ?
            """, (status, approved_by, now_str if approved_by else "", approval_note, candidate_id))
            return True
    finally:
        conn.close()


def list_candidate_models(limit: int = 50) -> List[Dict[str, Any]]:
    """Lists candidate models sorted by creation time descending."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM candidate_models ORDER BY created_at DESC LIMIT ?", (limit,))
        results = []
        for row in cur.fetchall():
            d = dict(row)
            try:
                d["metrics"] = json.loads(d.get("metrics_json") or "{}")
            except Exception:
                d["metrics"] = {}
            results.append(d)
        return results
    finally:
        conn.close()


def save_model_backup(backup_data: Dict[str, Any]) -> str:
    """Records a pre-activation rollback backup snapshot in SQLite."""
    init_db()
    backup_id = backup_data.get("backup_id") or f"BKP-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO model_backups (
                backup_id, timestamp, previous_model_type, previous_candidate_id, backup_path, created_by
            ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                backup_id,
                backup_data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
                backup_data.get("previous_model_type", "EXPERIMENT_B_BASELINE"),
                backup_data.get("previous_candidate_id"),
                str(backup_data.get("backup_path", "")),
                backup_data.get("created_by", "admin@soc.ai")
            ))
        return backup_id
    finally:
        conn.close()


def list_model_backups(limit: int = 20) -> List[Dict[str, Any]]:
    """Lists available model backups."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM model_backups ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def save_activation_audit(audit_data: Dict[str, Any]) -> str:
    """Records an authorized activation or rollback action in the audit trail."""
    init_db()
    act_id = audit_data.get("activation_id") or f"ACT-AUDIT-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    metrics_str = json.dumps(audit_data.get("metrics", {})) if isinstance(audit_data.get("metrics"), dict) else str(audit_data.get("metrics", ""))
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO model_activation_audit (
                activation_id, candidate_id, dataset_id, action, approved_by, approval_note, timestamp, backup_id, metrics_json, activation_result
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                act_id,
                audit_data.get("candidate_id", ""),
                audit_data.get("dataset_id", ""),
                audit_data.get("action", "ACTIVATE"),
                audit_data.get("approved_by", "admin@soc.ai"),
                audit_data.get("approval_note", ""),
                audit_data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
                audit_data.get("backup_id", ""),
                metrics_str,
                audit_data.get("activation_result", "SUCCESS")
            ))
        return act_id
    finally:
        conn.close()


def list_activation_audits(limit: int = 50) -> List[Dict[str, Any]]:
    """Lists activation audit records."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM model_activation_audit ORDER BY timestamp DESC LIMIT ?", (limit,))
        results = []
        for r in cur.fetchall():
            d = dict(r)
            if "metrics_json" in d:
                try:
                    d["metrics"] = json.loads(d["metrics_json"] or "{}")
                except Exception:
                    d["metrics"] = {}
            results.append(d)
        return results
    finally:
        conn.close()

