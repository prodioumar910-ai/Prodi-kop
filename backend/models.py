"""
Modèles de données pour le moteur d'analyse de cybersécurité FIRE AGENT.
Définit le format standard des événements informatiques et les résultats d'analyse.
Conforme aux principes de minimisation des données et de rejet des secrets.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional
import json
import re

# Liste des clés proscrites pour protéger la confidentialité
FORBIDDEN_SENSITIVE_KEYS = {
    'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
    'private_key', 'token', 'auth_token', 'access_token', 'bearer',
    'mot_de_passe', 'cle_secrete', 'credit_card', 'ssn'
}

class ValidationError(Exception):
    """Exception levée lorsqu'un événement est malformé ou non conforme."""
    pass

class SensitiveDataRejectedError(Exception):
    """Exception levée lorsqu'un événement contient des identifiants ou données secrètes."""
    pass

@dataclass
class TriggeredRule:
    rule_id: str
    rule_name: str
    category: str
    severity: str  # 'Faible' | 'Élevé' | 'Critique'
    description: str
    condition_matched: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AnalysisResult:
    event_id: str
    analyzed_at: str
    risk_level: str  # 'Faible' | 'Élevé' | 'Critique'
    risk_score: int  # 0 à 100
    triggered_rules: List[TriggeredRule] = field(default_factory=list)
    decision_reasons: List[str] = field(default_factory=list)
    analysis_limits: List[str] = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "analyzed_at": self.analyzed_at,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "triggered_rules": [r.to_dict() for r in self.triggered_rules],
            "decision_reasons": self.decision_reasons,
            "analysis_limits": self.analysis_limits,
            "recommended_action": self.recommended_action
        }

@dataclass
class SecurityEventInput:
    event_id: str
    timestamp: str
    source_host: str
    event_type: str
    description: str
    technical_data: Dict[str, Any] = field(default_factory=dict)

    ALLOWED_EVENT_TYPES = {
        'failed_logins',
        'unusual_connection',
        'suspicious_file',
        'phishing_simulation',
        'telemetry_scan',
        'generic_event'
    }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEventInput":
        if not isinstance(data, dict):
            raise ValidationError("Le corps de la requête doit être un objet JSON valide.")

        # Vérification des champs obligatoires
        required_fields = ['event_id', 'timestamp', 'source_host', 'event_type', 'description']
        missing_fields = [f for f in required_fields if f not in data or data[f] is None or data[f] == ""]
        if missing_fields:
            raise ValidationError(f"Champs obligatoires manquants : {', '.join(missing_fields)}")

        event_id = str(data['event_id']).strip()
        timestamp = str(data['timestamp']).strip()
        source_host = str(data['source_host']).strip()
        event_type = str(data['event_type']).strip().lower()
        description = str(data['description']).strip()

        if len(event_id) < 3:
            raise ValidationError("L'identifiant unique 'event_id' doit comporter au moins 3 caractères.")

        # Vérification du format de timestamp ISO ou standard
        if not cls._is_valid_timestamp(timestamp):
            raise ValidationError(f"Format de date/heure 'timestamp' invalide : '{timestamp}'. Utilisez le format ISO 8601 (ex: 2026-10-10T08:30:00Z).")

        if event_type not in cls.ALLOWED_EVENT_TYPES:
            raise ValidationError(
                f"Type d'événement '{event_type}' non reconnu. Types autorisés : {', '.join(cls.ALLOWED_EVENT_TYPES)}"
            )

        # Vérification de technical_data
        tech_data = data.get('technical_data', {})
        if tech_data is not None and not isinstance(tech_data, dict):
            raise ValidationError("Le champ 'technical_data' doit être un dictionnaire d'attributs techniques.")

        # Vérification de sécurité : rejet absolu des mots de passe et secrets
        cls._check_no_sensitive_data(data)
        if tech_data:
            cls._check_no_sensitive_data(tech_data)

        return cls(
            event_id=event_id,
            timestamp=timestamp,
            source_host=source_host,
            event_type=event_type,
            description=description,
            technical_data=tech_data or {}
        )

    @classmethod
    def _is_valid_timestamp(cls, ts: str) -> bool:
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d"
        ]
        # Essai de parsing
        for fmt in formats:
            try:
                datetime.strptime(ts.split('.')[0].replace('Z', ''), "%Y-%m-%dT%H:%M:%S")
                return True
            except ValueError:
                pass
            try:
                datetime.strptime(ts, fmt)
                return True
            except ValueError:
                pass
        return bool(re.match(r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', ts))

    @classmethod
    def _check_no_sensitive_data(cls, data_dict: Dict[str, Any]) -> None:
        """Contrôle déontologique : interdit la collecte de secrets, mots de passe et jetons."""
        for key in data_dict.keys():
            k_lower = key.lower()
            if any(forbidden in k_lower for forbidden in FORBIDDEN_SENSITIVE_KEYS):
                raise SensitiveDataRejectedError(
                    f"Donnée sensible interdite détectée (clé : '{key}'). "
                    "FIRE AGENT applique le principe de minimisation : aucun mot de passe ou clé secrète ne doit être transmis."
                )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
