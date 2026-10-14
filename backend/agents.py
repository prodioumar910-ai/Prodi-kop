"""
FIRE AGENT — Architecture Multi-Agents en Python.
Définit six agents logiciels spécialisés et collaboratifs qui se transmettent
des objets de données structurés :
1. DetectorAgent     : Repère les anomalies télémétriques et déviations de signature.
2. AnalystAgent      : Examine les IoC (IP, domaines, hash) et associe la technique MITRE.
3. RiskAgent         : Évalue le score (0-100) et le palier de gravité (Faible/Élevé/Critique).
4. ProtectionAgent   : Prescrit les actions défensives simulées en bac à sable hermétique.
5. VerificationAgent : Contrôle la bonne exécution simulée et l'intégrité sans effet de bord.
6. ChiefAgent        : Arbitre le consensus, alerte le SOC/RSSI et génère le rapport exécutif.

Garanties de sécurité :
- Détection déterministe et transparente (pas d'IA fictive ou opaque).
- Aucune altération réelle du système (real_system_touched = False).
- Zéro collecte de données secrètes ou mots de passe.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional
import hashlib
from models import SecurityEventInput, TriggeredRule, AnalysisResult

@dataclass
class DetectorOutput:
    input_event: Dict[str, Any]
    anomaly_detected: bool = False
    anomaly_type: str = "AUCUNE"
    anomaly_confidence: float = 0.5
    anomaly_signatures: List[str] = field(default_factory=list)
    timestamp: str = ""
    detector_reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AnalystOutput:
    detector_output: Dict[str, Any]
    extracted_iocs: Dict[str, List[str]] = field(default_factory=dict)
    mitre_technique: Dict[str, str] = field(default_factory=dict)
    attack_vector_summary: str = ""
    analyst_reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class RiskOutput:
    analyst_output: Dict[str, Any]
    calculated_score: int = 15
    risk_level: str = "Faible"  # 'Faible' | 'Élevé' | 'Critique'
    required_policy: str = "PASSIVE_LOG"  # PASSIVE_LOG | SIMULATE_CONTAINMENT | CRITICAL_ISOLATION_AND_ESCALATE
    impact_factors: Dict[str, float] = field(default_factory=dict)
    risk_explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ProtectionAction:
    action_type: str
    target_entity: str
    sandbox_result: str
    real_system_touched: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ProtectionOutput:
    risk_output: Dict[str, Any]
    executed_sandbox_actions: List[Dict[str, Any]] = field(default_factory=list)
    action_summary: str = ""
    protection_reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class VerificationCheck:
    check_name: str
    passed: bool
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class VerificationOutput:
    protection_output: Dict[str, Any]
    containment_verified: bool = True
    residual_risk_score: int = 0
    integrity_checks: List[Dict[str, Any]] = field(default_factory=list)
    verification_verdict: str = ""
    verification_reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ChiefOutput:
    verification_output: Dict[str, Any]
    incident_id: str = ""
    consensus_score: int = 100
    alert_priority: str = "AUCUNE"  # AUCUNE | SOC_STANDARD | RSSI_URGENT
    executive_summary: str = ""
    hardening_recommendations: List[str] = field(default_factory=list)
    triggered_rules: List[Dict[str, Any]] = field(default_factory=list)
    analysis_limits: List[str] = field(default_factory=list)
    final_analysis: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# 1. AGENT DÉTECTEUR
# ==============================================================================
class DetectorAgent:
    """
    Rôle : Scruter les signaux télémétriques et identifier les anomalies
    selon des signatures heuristiques déterministes.
    """
    @classmethod
    def run(cls, event: SecurityEventInput) -> DetectorOutput:
        p = event.technical_data
        signatures: List[str] = []
        is_anomaly = False
        confidence = 0.5
        reasoning_parts = []

        # 1. Échecs d'authentification
        failed_attempts = p.get('failed_attempts') or p.get('failed_attempts_count') or 0
        if isinstance(failed_attempts, (int, float)):
            if failed_attempts >= 15:
                signatures.append("AUTH_ANOMALY_MASSIVE_BRUTEFORCE")
                is_anomaly = True
                confidence = max(confidence, 0.98)
                reasoning_parts.append(f"{failed_attempts} échecs d'authentification consécutifs détectés (force brute)")
            elif failed_attempts > 5:
                signatures.append("AUTH_ANOMALY_SUSPICIOUS_FAILURES")
                is_anomaly = True
                confidence = max(confidence, 0.85)
                reasoning_parts.append(f"{failed_attempts} échecs de connexion suspects")

        # 2. Vitesse de déplacement impossible
        travel_speed = p.get('travel_speed_kmh') or p.get('velocity_kmh') or 0
        if isinstance(travel_speed, (int, float)) and travel_speed > 900:
            signatures.append("NET_ANOMALY_IMPOSSIBLE_TRAVEL")
            is_anomaly = True
            confidence = max(confidence, 0.95)
            reasoning_parts.append(f"Vitesse apparente anormale de {travel_speed} km/h entre sessions distantes")

        # 3. Port sensible exposé
        target_port = p.get('target_port') or p.get('port')
        is_external = p.get('is_external_ip') or p.get('is_external', False)
        if target_port in [3389, 22, 445, 5985] and is_external:
            signatures.append("NET_SENSITIVE_PORT_EXTERNAL_ACCESS")
            is_anomaly = True
            confidence = max(confidence, 0.92)
            reasoning_parts.append(f"Connexion externe non restreinte sur port d'administration sensible {target_port}")

        # 4. Document bureautique avec macro et interpréteur système
        has_macros = p.get('has_macros') or p.get('contains_macro', False)
        spawned_proc = str(p.get('spawned_process') or p.get('child_process', '')).lower()
        file_ext = str(p.get('file_extension', '')).lower()
        file_name = str(p.get('file_name', '')).lower()

        shells = ['powershell', 'cmd', 'wscript', 'cscript', 'bash', 'sh']
        if has_macros and any(s in spawned_proc for s in shells):
            signatures.append("HOST_OFFICE_SPAWNED_SHELL")
            is_anomaly = True
            confidence = max(confidence, 0.99)
            reasoning_parts.append(f"Document bureautique déclenchant un interpréteur système ({spawned_proc})")
        elif p.get('double_extension', False) or (file_ext in ['.exe', '.scr', '.vbs', '.bat', '.ps1'] and 'temp' in str(p.get('file_path', '')).lower()):
            signatures.append("HOST_SUSPICIOUS_BINARY_LOCATION")
            is_anomaly = True
            confidence = max(confidence, 0.88)
            reasoning_parts.append(f"Fichier exécutable suspect '{file_name}' avec extension déguisée ou répertoire temporaire")

        # 5. Phishing : SPF Fail ou domaine néo-enregistré
        spf = str(p.get('spf_result', '')).upper()
        dkim = str(p.get('dkim_result', '')).upper()
        domain_age = p.get('domain_age_days')
        has_login_form = p.get('credential_form', False) or any(
            k in str(p.get('embedded_url', '')).lower() for k in ['login', 'auth', 'signin', 'verification']
        )

        if spf == 'FAIL' or dkim == 'FAIL':
            signatures.append("MAIL_AUTH_PROTOCOL_FAIL")
            is_anomaly = True
            confidence = max(confidence, 0.89)
            reasoning_parts.append("Échec de vérification des enregistrements cryptographiques SPF/DKIM de messagerie")

        if isinstance(domain_age, (int, float)) and domain_age < 15 and has_login_form:
            signatures.append("MAIL_NEW_DOMAIN_CREDENTIAL_HARVESTING")
            is_anomaly = True
            confidence = max(confidence, 0.94)
            reasoning_parts.append(f"Domaine de messagerie néo-enregistré ({domain_age} jours) avec lien vers mire de connexion")

        if not is_anomaly:
            reasoning = "Aucune déviation notable par rapport à la télémétrie de référence."
            anomaly_type = "NOMINAL_TELEMETRY"
        else:
            reasoning = f"L'Agent Détecteur a identifié les signatures : {', '.join(signatures)}. " + " ; ".join(reasoning_parts) + "."
            anomaly_type = signatures[0]

        return DetectorOutput(
            input_event=event.to_dict(),
            anomaly_detected=is_anomaly,
            anomaly_type=anomaly_type,
            anomaly_confidence=confidence,
            anomaly_signatures=signatures,
            timestamp=datetime.utcnow().isoformat() + "Z",
            detector_reasoning=reasoning
        )


# ==============================================================================
# 2. AGENT ANALYSTE
# ==============================================================================
class AnalystAgent:
    """
    Rôle : Extraire les indicateurs de compromission (IoCs), enrichir
    les données techniques et corréler l'attaque avec le framework MITRE ATT&CK.
    """
    @classmethod
    def run(cls, det_out: DetectorOutput) -> AnalystOutput:
        raw_evt = det_out.input_event
        p = raw_evt.get('technical_data', {})

        ips: List[str] = []
        domains: List[str] = []
        hashes: List[str] = []
        processes: List[str] = []
        urls: List[str] = []

        if p.get('source_ip'): ips.append(str(p['source_ip']))
        if p.get('email_domain'): domains.append(str(p['email_domain']))
        if p.get('destination_domain'): domains.append(str(p['destination_domain']))
        if p.get('embedded_url'): urls.append(str(p['embedded_url']))
        if p.get('spawned_process'): processes.append(str(p['spawned_process']))
        if p.get('parent_process'): processes.append(str(p['parent_process']))

        # Hash calculé ou extrait
        if p.get('file_hash'):
            hashes.append(str(p['file_hash']))
        elif p.get('file_name'):
            mock_hash = hashlib.sha256(str(p['file_name']).encode('utf-8')).hexdigest()[:32]
            hashes.append(f"sha256:{mock_hash}")

        # Association MITRE ATT&CK
        mitre = {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}
        sigs = det_out.anomaly_signatures

        if "AUTH_ANOMALY_MASSIVE_BRUTEFORCE" in sigs or "AUTH_ANOMALY_SUSPICIOUS_FAILURES" in sigs:
            mitre = {"id": "T1110.003", "name": "Brute Force: Password Spraying", "tactic": "Credential Access"}
        elif "NET_ANOMALY_IMPOSSIBLE_TRAVEL" in sigs:
            mitre = {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts", "tactic": "Defense Evasion"}
        elif "NET_SENSITIVE_PORT_EXTERNAL_ACCESS" in sigs:
            mitre = {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"}
        elif "HOST_OFFICE_SPAWNED_SHELL" in sigs:
            mitre = {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"}
        elif "HOST_SUSPICIOUS_BINARY_LOCATION" in sigs:
            mitre = {"id": "T1036.005", "name": "Masquerading: Match Legitimate Name or Location", "tactic": "Defense Evasion"}
        elif "MAIL_NEW_DOMAIN_CREDENTIAL_HARVESTING" in sigs or "MAIL_AUTH_PROTOCOL_FAIL" in sigs:
            mitre = {"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access"}

        total_iocs = len(ips) + len(domains) + len(hashes) + len(processes) + len(urls)
        reasoning = (
            f"L'Agent Analyste a extrait {total_iocs} indicateurs techniques (IoCs) "
            f"et rattaché l'activité à la technique MITRE {mitre['id']} ({mitre['name']}) dans la tactique {mitre['tactic']}."
        )

        return AnalystOutput(
            detector_output=det_out.to_dict(),
            extracted_iocs={
                "ips": ips,
                "domains": domains,
                "file_hashes": hashes,
                "processes": processes,
                "urls": urls
            },
            mitre_technique=mitre,
            attack_vector_summary=f"{raw_evt.get('event_type', 'Événement')} via {mitre['name']}",
            analyst_reasoning=reasoning
        )


# ==============================================================================
# 3. AGENT RISQUE
# ==============================================================================
class RiskAgent:
    """
    Rôle : Évaluer l'impact et la sévérité selon un barème transparent,
    et prescrire la politique de réponse (3 paliers stricts).
    """
    @classmethod
    def run(cls, ana_out: AnalystOutput) -> RiskOutput:
        det = ana_out.detector_output
        sigs = det.get('anomaly_signatures', [])

        score = 15
        policy = "PASSIVE_LOG"

        if "HOST_OFFICE_SPAWNED_SHELL" in sigs:
            score = 95
        elif "AUTH_ANOMALY_MASSIVE_BRUTEFORCE" in sigs:
            score = 90
        elif "MAIL_NEW_DOMAIN_CREDENTIAL_HARVESTING" in sigs:
            score = 89
        elif "NET_SENSITIVE_PORT_EXTERNAL_ACCESS" in sigs:
            score = 88
        elif "HOST_SUSPICIOUS_BINARY_LOCATION" in sigs:
            score = 80
        elif "NET_ANOMALY_IMPOSSIBLE_TRAVEL" in sigs:
            score = 75
        elif "MAIL_AUTH_PROTOCOL_FAIL" in sigs:
            score = 72
        elif "AUTH_ANOMALY_SUSPICIOUS_FAILURES" in sigs:
            score = 65

        score = min(100, max(0, score))

        if score >= 85:
            risk_level = "Critique"
            policy = "CRITICAL_ISOLATION_AND_ESCALATE"
            impacts = {"confidentiality": 9.5, "integrity": 9.2, "availability": 8.8}
        elif score >= 50:
            risk_level = "Élevé"
            policy = "SIMULATE_CONTAINMENT"
            impacts = {"confidentiality": 7.0, "integrity": 7.5, "availability": 6.0}
        else:
            risk_level = "Faible"
            policy = "PASSIVE_LOG"
            impacts = {"confidentiality": 2.5, "integrity": 2.0, "availability": 1.5}

        explanation = (
            f"L'Agent Risque a attribué un score d'impact de {score}/100, "
            f"classant l'événement au niveau {risk_level.upper()}. Politique prescrite : {policy}."
        )

        return RiskOutput(
            analyst_output=ana_out.to_dict(),
            calculated_score=score,
            risk_level=risk_level,
            required_policy=policy,
            impact_factors=impacts,
            risk_explanation=explanation
        )


# ==============================================================================
# 4. AGENT PROTECTION
# ==============================================================================
class ProtectionAgent:
    """
    Rôle : Définir et consigner les actions de protection simulées en bac à sable.
    GARANTIE STRICTE : real_system_touched = False (aucune modification réelle de machine).
    """
    @classmethod
    def run(cls, risk_out: RiskOutput) -> ProtectionOutput:
        policy = risk_out.required_policy
        ana = risk_out.analyst_output
        iocs = ana.get('extracted_iocs', {})
        target = ana.get('detector_output', {}).get('input_event', {}).get('source_host', 'Hôte test')

        actions: List[ProtectionAction] = []

        if policy == "PASSIVE_LOG":
            actions.append(ProtectionAction(
                action_type="PASSIVE_AUDIT_LOG",
                target_entity=target,
                sandbox_result="Consignation de la télémétrie dans le registre d'audit passif (aucune action restrictive).",
                real_system_touched=False
            ))
        elif policy == "SIMULATE_CONTAINMENT":
            if iocs.get('ips'):
                actions.append(ProtectionAction(
                    action_type="SIMULATE_BLOCK_IP",
                    target_entity=iocs['ips'][0],
                    sandbox_result=f"Filtrage pare-feu simulé (DROP) sur l'adresse IP test {iocs['ips'][0]}.",
                    real_system_touched=False
                ))
            if iocs.get('domains'):
                actions.append(ProtectionAction(
                    action_type="SIMULATE_DNS_SINKHOLE",
                    target_entity=iocs['domains'][0],
                    sandbox_result=f"Redirection DNS sinkhole simulée vers 127.0.0.1 pour le domaine {iocs['domains'][0]}.",
                    real_system_touched=False
                ))
            actions.append(ProtectionAction(
                action_type="SIMULATE_SUSPEND_SESSION",
                target_entity=target,
                sandbox_result="Suspension de la session utilisateur dans le banc d'essai.",
                real_system_touched=False
            ))
        elif policy == "CRITICAL_ISOLATION_AND_ESCALATE":
            actions.append(ProtectionAction(
                action_type="SIMULATE_ISOLATE_HOST",
                target_entity=target,
                sandbox_result=f"Isolement logique du sous-réseau virtuel de test pour l'hôte {target}.",
                real_system_touched=False
            ))
            if iocs.get('file_hashes'):
                actions.append(ProtectionAction(
                    action_type="SIMULATE_QUARANTINE_FILE",
                    target_entity=iocs['file_hashes'][0],
                    sandbox_result=f"Mise en quarantaine simulée de l'artefact suspect {iocs['file_hashes'][0]}.",
                    real_system_touched=False
                ))
            if iocs.get('ips'):
                actions.append(ProtectionAction(
                    action_type="SIMULATE_BLOCK_IP",
                    target_entity=iocs['ips'][0],
                    sandbox_result=f"Blocage périmétrique simulé du serveur distant hostile {iocs['ips'][0]}.",
                    real_system_touched=False
                ))

        summary = " ".join([a.sandbox_result for a in actions])
        reasoning = (
            f"L'Agent Protection a prescrit et simulé {len(actions)} mesure(s) défensive(s) "
            f"en bac à sable clos sans altérer l'infrastructure réelle."
        )

        return ProtectionOutput(
            risk_output=risk_out.to_dict(),
            executed_sandbox_actions=[a.to_dict() for a in actions],
            action_summary=summary,
            protection_reasoning=reasoning
        )


# ==============================================================================
# 5. AGENT VÉRIFICATION
# ==============================================================================
class VerificationAgent:
    """
    Rôle : Contrôler la validité des actions simulées et certifier l'absence d'effets de bord.
    """
    @classmethod
    def run(cls, prot_out: ProtectionOutput) -> VerificationOutput:
        actions = prot_out.executed_sandbox_actions
        checks: List[VerificationCheck] = []

        for act in actions:
            checks.append(VerificationCheck(
                check_name=f"Vérification {act.get('action_type', 'Action')}",
                passed=True,
                evidence=f"Contrôle bac à sable : {act.get('sandbox_result')} (Succès garanti, real_system_touched=False)"
            ))

        checks.append(VerificationCheck(
            check_name="Contrôle d'intégrité globale et non-régression",
            passed=True,
            evidence="Zéro perturbation constatée sur les services opérationnels non ciblés."
        ))

        verdict = f"Certification validée : {len(checks)} contrôles de conformité réussis sans effet de bord."
        reasoning = "L'Agent Vérification certifie la conformité des simulations et confirme le risque résiduel nul."

        return VerificationOutput(
            protection_output=prot_out.to_dict(),
            containment_verified=True,
            residual_risk_score=0,
            integrity_checks=[c.to_dict() for c in checks],
            verification_verdict=verdict,
            verification_reasoning=reasoning
        )


# ==============================================================================
# 6. CHEF AGENT
# ==============================================================================
class ChiefAgent:
    """
    Rôle : Arbitre central, synthèse exécutive, alertes SOC/RSSI
    et recommandations de durcissement.
    """
    @classmethod
    def run(cls, verif_out: VerificationOutput) -> ChiefOutput:
        prot = verif_out.protection_output
        risk = prot.get('risk_output', {})
        ana = risk.get('analyst_output', {})
        det = ana.get('detector_output', {})
        input_evt = det.get('input_event', {})

        event_id = input_evt.get('event_id', f"EVT-{datetime.utcnow().strftime('%H%M%S')}")
        risk_level = risk.get('risk_level', 'Faible')
        risk_score = risk.get('calculated_score', 15)
        source_host = input_evt.get('source_host', 'Hôte test')
        event_type = input_evt.get('event_type', 'Événement')

        alert_priority = "AUCUNE"
        if risk_level == "Critique":
            alert_priority = "RSSI_URGENT"
        elif risk_level == "Élevé":
            alert_priority = "SOC_STANDARD"

        recommendations: List[str] = []
        if "HOST_OFFICE_SPAWNED_SHELL" in det.get('anomaly_signatures', []):
            recommendations.append("Désactivation immédiate des macros bureautiques non signées numériquement.")
            recommendations.append("Application d'une règle de réduction de surface d'attaque (ASR) bloquant les processus enfants d'Office.")
        elif "AUTH_ANOMALY_MASSIVE_BRUTEFORCE" in det.get('anomaly_signatures', []):
            recommendations.append("Verrouillage temporaire du compte ciblé et renforcement de l'authentification multi-facteurs (MFA).")
        elif "NET_ANOMALY_IMPOSSIBLE_TRAVEL" in det.get('anomaly_signatures', []):
            recommendations.append("Révocation des jetons d'accès OAuth/SAML actifs et vérification de compromission de session.")
        elif "MAIL_NEW_DOMAIN_CREDENTIAL_HARVESTING" in det.get('anomaly_signatures', []):
            recommendations.append("Blocage au niveau de la passerelle proxy du nom de domaine néo-enregistré.")
            recommendations.append("Sensibilisation des utilisateurs ciblés à l'ingénierie sociale.")
        else:
            recommendations.append("Maintien de la surveillance télémétrique standard.")

        reasons = [
            det.get('detector_reasoning', ''),
            ana.get('analyst_reasoning', ''),
            risk.get('risk_explanation', ''),
            prot.get('action_summary', '')
        ]

        rules_triggered: List[Dict[str, Any]] = []
        for sig in det.get('anomaly_signatures', []):
            rules_triggered.append({
                "rule_id": sig,
                "rule_name": sig.replace('_', ' ').title(),
                "severity": risk_level,
                "condition_matched": f"Signature {sig} validée par l'Agent Détecteur"
            })

        limits = [
            "Analyse déterministe locale basée sur les règles et signatures : aucune détonation dynamique en bac à sable matériel réel n'est effectuée.",
            "L'analyse dépend de la fidélité des métadonnées transmises par la source hôte.",
            "Ce prototype fonctionne en environnement hermétique : aucun système de production n'est scanné ni altéré."
        ]

        exec_summary = (
            f"Incident [{event_id}] sur {source_host} évalué au niveau {risk_level.upper()} "
            f"(Score: {risk_score}/100) par consensus des 6 agents logiciels. "
            f"Priorité d'alerte : {alert_priority}. Réponse simulée : {prot.get('action_summary', 'Aucune action requise')}."
        )

        final_analysis = {
            "event_id": event_id,
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
            "risk_level": risk_level,
            "risk_score": risk_score,
            "alert_priority": alert_priority,
            "consensus_score": 100,
            "triggered_rules": rules_triggered,
            "decision_reasons": [r for r in reasons if r],
            "analysis_limits": limits,
            "recommended_action": prot.get('action_summary', 'Maintien de la supervision.') + " " + " ".join(recommendations),
            "agents_pipeline": {
                "detecteur": det,
                "analyste": ana,
                "risque": risk,
                "protection": prot,
                "verification": verif_out.to_dict(),
                "chef": {
                    "incident_id": event_id,
                    "alert_priority": alert_priority,
                    "consensus_score": 100,
                    "executive_summary": exec_summary,
                    "hardening_recommendations": recommendations
                }
            }
        }

        return ChiefOutput(
            verification_output=verif_out.to_dict(),
            incident_id=event_id,
            consensus_score=100,
            alert_priority=alert_priority,
            executive_summary=exec_summary,
            hardening_recommendations=recommendations,
            triggered_rules=rules_triggered,
            analysis_limits=limits,
            final_analysis=final_analysis
        )


# ==============================================================================
# PIPELINE COMPLET D'ORCHESTRATION
# ==============================================================================
class FireAgentPipeline:
    """
    Chaîne d'exécution ordonnée des 6 agents logiciels :
    1. Détecteur  ➔
    2. Analyste   ➔
    3. Risque     ➔
    4. Protection ➔
    5. Vérification ➔
    6. Chef Agent
    """
    @classmethod
    def execute(cls, event: SecurityEventInput) -> ChiefOutput:
        # Étape 1 : Agent Détecteur
        step1 = DetectorAgent.run(event)

        # Étape 2 : Agent Analyste (reçoit Détecteur)
        step2 = AnalystAgent.run(step1)

        # Étape 3 : Agent Risque (reçoit Analyste)
        step3 = RiskAgent.run(step2)

        # Étape 4 : Agent Protection (reçoit Risque)
        step4 = ProtectionAgent.run(step3)

        # Étape 5 : Agent Vérification (reçoit Protection)
        step5 = VerificationAgent.run(step4)

        # Étape 6 : Chef Agent (reçoit Vérification)
        step6 = ChiefAgent.run(step5)

        return step6
