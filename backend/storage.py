"""
Stockage persistant pour les événements de cybersécurité FIRE AGENT.
Utilise SQLite (intégré à la bibliothèque standard Python) pour garantir
une persistance robuste, sans dépendance externe.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from models import SecurityEventInput, AnalysisResult, TriggeredRule

DB_FILE_PATH = os.path.join(os.path.dirname(__file__), "fire_agent.db")

class EventStorage:
    def __init__(self, db_path: str = DB_FILE_PATH):
        self.db_path = db_path
        self._shared_conn = None
        if self.db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:")
            self._shared_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_conn:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source_host TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    technical_data_json TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    analysis_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_risk_level ON events(risk_level)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)
            """)
            conn.commit()

    def save_event_with_analysis(self, event: SecurityEventInput, analysis: AnalysisResult) -> Dict[str, Any]:
        """Enregistre un événement et son analyse dans la base de données."""
        created_at = datetime.utcnow().isoformat() + "Z"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO events (
                    event_id, timestamp, source_host, event_type, description,
                    technical_data_json, risk_level, risk_score, analysis_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.timestamp,
                event.source_host,
                event.event_type,
                event.description,
                json.dumps(event.technical_data, ensure_ascii=False),
                analysis.risk_level,
                analysis.risk_score,
                json.dumps(analysis.to_dict(), ensure_ascii=False),
                created_at
            ))
            conn.commit()

        return {
            "event": event.to_dict(),
            "analysis": analysis.to_dict(),
            "stored_at": created_at
        }

    def get_events(
        self, 
        limit: int = 50, 
        offset: int = 0, 
        risk_level: Optional[str] = None, 
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Récupère l'historique des événements analysés avec filtres optionnels."""
        query = "SELECT * FROM events"
        params: List[Any] = []
        clauses: List[str] = []

        if risk_level:
            clauses.append("risk_level = ?")
            params.append(risk_level)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)

        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            results = []
            for row in rows:
                results.append({
                    "event_id": row["event_id"],
                    "timestamp": row["timestamp"],
                    "source_host": row["source_host"],
                    "event_type": row["event_type"],
                    "description": row["description"],
                    "technical_data": json.loads(row["technical_data_json"]),
                    "risk_level": row["risk_level"],
                    "risk_score": row["risk_score"],
                    "analysis": json.loads(row["analysis_json"]),
                    "created_at": row["created_at"]
                })
            return results

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Récupère le détail complet d'un événement par son identifiant unique."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "event_id": row["event_id"],
                "timestamp": row["timestamp"],
                "source_host": row["source_host"],
                "event_type": row["event_type"],
                "description": row["description"],
                "technical_data": json.loads(row["technical_data_json"]),
                "risk_level": row["risk_level"],
                "risk_score": row["risk_score"],
                "analysis": json.loads(row["analysis_json"]),
                "created_at": row["created_at"]
            }

    def get_statistics(self) -> Dict[str, Any]:
        """Calcule les statistiques globales pour le tableau de bord SOC."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM events")
            total = cursor.fetchone()["total"]

            cursor.execute("SELECT risk_level, COUNT(*) as count FROM events GROUP BY risk_level")
            by_risk = {row["risk_level"]: row["count"] for row in cursor.fetchall()}

            cursor.execute("SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type")
            by_type = {row["event_type"]: row["count"] for row in cursor.fetchall()}

            return {
                "total_events": total,
                "by_risk_level": {
                    "Faible": by_risk.get("Faible", 0),
                    "Élevé": by_risk.get("Élevé", 0),
                    "Critique": by_risk.get("Critique", 0)
                },
                "by_event_type": by_type
            }

    def clear(self) -> None:
        """Nettoie la base de données (utilisé pour les tests)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM events")
            conn.commit()
