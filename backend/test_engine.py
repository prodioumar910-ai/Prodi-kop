"""
Suite de tests automatisés pour le moteur d'analyse, l'architecture multi-agents
et la persistance SQLite de FIRE AGENT.
Exécutable directement avec : python3 backend/test_engine.py
"""

import unittest
import sys
import os

# Ajout du chemin backend
sys.path.insert(0, os.path.dirname(__file__))

from models import SecurityEventInput, ValidationError, SensitiveDataRejectedError
from agents import (
    FireAgentPipeline,
    DetectorAgent,
    AnalystAgent,
    RiskAgent,
    ProtectionAgent,
    VerificationAgent,
    ChiefAgent
)
from rule_engine import SecurityRuleEngine
from storage import EventStorage

class TestFireAgentEngine(unittest.TestCase):
    def setUp(self):
        # Base de données en mémoire pour isoler chaque test
        self.storage = EventStorage(db_path=":memory:")

    def test_01_well_formed_event_validation(self):
        """Vérifie qu'un événement conforme au format est accepté sans erreur."""
        payload = {
            "event_id": "EVT-TEST-001",
            "timestamp": "2026-10-10T08:30:00Z",
            "source_host": "SRV-FILE-01",
            "event_type": "suspicious_file",
            "description": "Fichier avec macro détecté dans le répertoire utilisateur.",
            "technical_data": {
                "file_name": "facture_octobre.xlsm",
                "file_extension": ".xlsm",
                "has_macros": True,
                "spawned_process": "powershell.exe"
            }
        }
        event = SecurityEventInput.from_dict(payload)
        self.assertEqual(event.event_id, "EVT-TEST-001")
        self.assertEqual(event.source_host, "SRV-FILE-01")
        self.assertTrue(event.technical_data["has_macros"])

    def test_02_malformed_event_rejection(self):
        """Vérifie que les événements incomplets ou invalides sont rejetés avec des erreurs explicites."""
        # 1. Manque event_id
        bad_payload_1 = {
            "timestamp": "2026-10-10T08:30:00Z",
            "source_host": "SRV-01",
            "event_type": "suspicious_file",
            "description": "Test"
        }
        with self.assertRaises(ValidationError) as ctx:
            SecurityEventInput.from_dict(bad_payload_1)
        self.assertIn("event_id", str(ctx.exception))

        # 2. Type d'événement non autorisé
        bad_payload_2 = {
            "event_id": "EVT-002",
            "timestamp": "2026-10-10T08:30:00Z",
            "source_host": "SRV-01",
            "event_type": "invalid_unknown_type",
            "description": "Test"
        }
        with self.assertRaises(ValidationError) as ctx:
            SecurityEventInput.from_dict(bad_payload_2)
        self.assertIn("non reconnu", str(ctx.exception))

        # 3. Timestamp invalide
        bad_payload_3 = {
            "event_id": "EVT-003",
            "timestamp": "hier_apres_midi",
            "source_host": "SRV-01",
            "event_type": "failed_logins",
            "description": "Test"
        }
        with self.assertRaises(ValidationError) as ctx:
            SecurityEventInput.from_dict(bad_payload_3)
        self.assertIn("timestamp", str(ctx.exception))

    def test_03_sensitive_data_strict_rejection(self):
        """Vérifie le respect de la déontologie : rejet immédiat des mots de passe et clés secrètes."""
        forbidden_payload = {
            "event_id": "EVT-SECRET-001",
            "timestamp": "2026-10-10T08:30:00Z",
            "source_host": "WKSTN-ADMIN",
            "event_type": "failed_logins",
            "description": "Tentative de connexion avec capture de mot de passe",
            "technical_data": {
                "source_ip": "194.26.29.110",
                "password": "SuperSecretPassword123!"  # INTERDIT
            }
        }
        with self.assertRaises(SensitiveDataRejectedError) as ctx:
            SecurityEventInput.from_dict(forbidden_payload)
        self.assertIn("Donnée sensible interdite", str(ctx.exception))

    def test_04_persistent_storage_and_history(self):
        """Vérifie l'enregistrement en base SQLite et la restitution filtrée de l'historique."""
        payload = {
            "event_id": "EVT-STORE-01",
            "timestamp": "2026-10-10T10:00:00Z",
            "source_host": "SRV-TEST",
            "event_type": "failed_logins",
            "description": "Test de persistance SQLite",
            "technical_data": {"failed_attempts": 18}
        }
        event = SecurityEventInput.from_dict(payload)
        analysis = SecurityRuleEngine.evaluate(event)

        self.storage.save_event_with_analysis(event, analysis)

        # Récupération
        stored = self.storage.get_event_by_id("EVT-STORE-01")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["risk_level"], "Critique")
        self.assertEqual(stored["source_host"], "SRV-TEST")

        # Vérification des stats
        stats = self.storage.get_statistics()
        self.assertEqual(stats["total_events"], 1)
        self.assertEqual(stats["by_risk_level"]["Critique"], 1)

    # ==========================================================================
    # TESTS SPÉCIFIQUES DES SIX AGENTS LOGICIELS (PRIORITÉ 2)
    # ==========================================================================

    def test_05_detector_agent(self):
        """Vérifie que DetectorAgent identifie correctement les signatures heuristiques."""
        evt = SecurityEventInput.from_dict({
            "event_id": "EVT-AG-DET",
            "timestamp": "2026-10-10T11:00:00Z",
            "source_host": "WKSTN-FIN-01",
            "event_type": "suspicious_file",
            "description": "Document avec macro",
            "technical_data": {
                "has_macros": True,
                "spawned_process": "powershell.exe -Enc QwA="
            }
        })
        det_out = DetectorAgent.run(evt)
        self.assertTrue(det_out.anomaly_detected)
        self.assertIn("HOST_OFFICE_SPAWNED_SHELL", det_out.anomaly_signatures)
        self.assertGreaterEqual(det_out.anomaly_confidence, 0.95)

    def test_06_analyst_agent(self):
        """Vérifie que AnalystAgent extrait les IoCs et effectue la corrélation MITRE ATT&CK."""
        evt = SecurityEventInput.from_dict({
            "event_id": "EVT-AG-ANA",
            "timestamp": "2026-10-10T11:05:00Z",
            "source_host": "SRV-DC-01",
            "event_type": "failed_logins",
            "description": "Brute-force",
            "technical_data": {
                "source_ip": "185.220.101.44",
                "failed_attempts": 20
            }
        })
        det_out = DetectorAgent.run(evt)
        ana_out = AnalystAgent.run(det_out)

        self.assertIn("185.220.101.44", ana_out.extracted_iocs["ips"])
        self.assertEqual(ana_out.mitre_technique["id"], "T1110.003")
        self.assertEqual(ana_out.mitre_technique["name"], "Brute Force: Password Spraying")

    def test_07_risk_agent_three_tier_scoring(self):
        """Vérifie que RiskAgent calcule le score et affecte les 3 paliers stricts."""
        # Cas Critique (macro powershell)
        evt_crit = SecurityEventInput.from_dict({
            "event_id": "EVT-RISK-CRIT",
            "timestamp": "2026-10-10T11:10:00Z",
            "source_host": "PC-01",
            "event_type": "suspicious_file",
            "description": "Macro",
            "technical_data": {"has_macros": True, "spawned_process": "powershell.exe"}
        })
        det_crit = DetectorAgent.run(evt_crit)
        ana_crit = AnalystAgent.run(det_crit)
        risk_crit = RiskAgent.run(ana_crit)
        self.assertEqual(risk_crit.risk_level, "Critique")
        self.assertEqual(risk_crit.required_policy, "CRITICAL_ISOLATION_AND_ESCALATE")
        self.assertGreaterEqual(risk_crit.calculated_score, 85)

        # Cas Élevé (vitesse de déplacement > 900 km/h)
        evt_high = SecurityEventInput.from_dict({
            "event_id": "EVT-RISK-HIGH",
            "timestamp": "2026-10-10T11:10:00Z",
            "source_host": "VPN-01",
            "event_type": "unusual_connection",
            "description": "Voyage impossible",
            "technical_data": {"travel_speed_kmh": 2500}
        })
        det_high = DetectorAgent.run(evt_high)
        ana_high = AnalystAgent.run(det_high)
        risk_high = RiskAgent.run(ana_high)
        self.assertEqual(risk_high.risk_level, "Élevé")
        self.assertEqual(risk_high.required_policy, "SIMULATE_CONTAINMENT")

        # Cas Faible (monitoring nominal)
        evt_low = SecurityEventInput.from_dict({
            "event_id": "EVT-RISK-LOW",
            "timestamp": "2026-10-10T11:10:00Z",
            "source_host": "MON-01",
            "event_type": "telemetry_scan",
            "description": "Monitoring",
            "technical_data": {"cpu": "12%"}
        })
        det_low = DetectorAgent.run(evt_low)
        ana_low = AnalystAgent.run(det_low)
        risk_low = RiskAgent.run(ana_low)
        self.assertEqual(risk_low.risk_level, "Faible")
        self.assertEqual(risk_low.required_policy, "PASSIVE_LOG")

    def test_08_protection_agent_safety_guarantee(self):
        """Vérifie la garantie absolue : real_system_touched = False (aucune action réelle destructive)."""
        evt = SecurityEventInput.from_dict({
            "event_id": "EVT-PROT-SAFE",
            "timestamp": "2026-10-10T11:15:00Z",
            "source_host": "PC-TEST",
            "event_type": "suspicious_file",
            "description": "Test sécurité hôte",
            "technical_data": {"has_macros": True, "spawned_process": "powershell.exe", "source_ip": "1.2.3.4"}
        })
        det = DetectorAgent.run(evt)
        ana = AnalystAgent.run(det)
        risk = RiskAgent.run(ana)
        prot = ProtectionAgent.run(risk)

        self.assertTrue(len(prot.executed_sandbox_actions) > 0)
        for act in prot.executed_sandbox_actions:
            self.assertFalse(act["real_system_touched"], "Viol de sécurité : l'action défensive n'est pas isolée !")

    def test_09_verification_agent(self):
        """Vérifie que VerificationAgent confirme l'endiguement et le risque résiduel nul."""
        evt = SecurityEventInput.from_dict({
            "event_id": "EVT-VERIF-TEST",
            "timestamp": "2026-10-10T11:20:00Z",
            "source_host": "PC-TEST",
            "event_type": "suspicious_file",
            "description": "Test vérification",
            "technical_data": {"has_macros": True, "spawned_process": "powershell.exe"}
        })
        det = DetectorAgent.run(evt)
        ana = AnalystAgent.run(det)
        risk = RiskAgent.run(ana)
        prot = ProtectionAgent.run(risk)
        verif = VerificationAgent.run(prot)

        self.assertTrue(verif.containment_verified)
        self.assertEqual(verif.residual_risk_score, 0)
        self.assertTrue(len(verif.integrity_checks) > 0)

    def test_10_chief_agent_and_full_pipeline(self):
        """Vérifie l'orchestration complète par les 6 agents et le rapport du Chef Agent."""
        evt = SecurityEventInput.from_dict({
            "event_id": "EVT-FULL-PIPE",
            "timestamp": "2026-10-10T11:25:00Z",
            "source_host": "SRV-DC-01",
            "event_type": "failed_logins",
            "description": "Attaque par pulvérisation d'identifiants",
            "technical_data": {"source_ip": "194.26.29.99", "failed_attempts": 32}
        })

        chief_out = FireAgentPipeline.execute(evt)

        self.assertEqual(chief_out.consensus_score, 100)
        self.assertEqual(chief_out.alert_priority, "RSSI_URGENT")
        self.assertTrue(len(chief_out.hardening_recommendations) > 0)
        self.assertIn("SRV-DC-01", chief_out.executive_summary)
        self.assertIn("CRITIQUE", chief_out.executive_summary)

if __name__ == '__main__':
    unittest.main(verbosity=2)
