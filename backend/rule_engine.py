"""
Moteur de règles d'analyse de cybersécurité pour FIRE AGENT.
Analyse les événements informatiques de manière déterministe et transparente.
Identifie :
- Les échecs de connexion répétés (force brute / password spraying)
- Les connexions inhabituelles (déplacement impossible, ports sensibles)
- Les fichiers suspects (macros malveillantes, extensions déguisées, invocation de shell)
- Les emails de phishing simulé (usurpation de domaine, SPF en échec, liens piégés)
"""

from datetime import datetime
from typing import List, Dict, Any, Tuple
from models import SecurityEventInput, AnalysisResult, TriggeredRule
from agents import (
    FireAgentPipeline,
    DetectorAgent,
    AnalystAgent,
    RiskAgent,
    ProtectionAgent,
    VerificationAgent,
    ChiefAgent
)

# Catalogue des règles prédéfinies
RULES_CATALOG = [
    {
        "id": "R-AUTH-01",
        "name": "Échecs d'authentification suspects répétés",
        "category": "Authentification & Accès",
        "severity": "Élevé",
        "threshold": "failed_attempts > 5",
        "description": "Détecte un nombre anormal d'échecs de connexion consécutifs sur un compte ou une IP source."
    },
    {
        "id": "R-AUTH-02",
        "name": "Attaque par force brute massive avérée",
        "category": "Authentification & Accès",
        "severity": "Critique",
        "threshold": "failed_attempts >= 15",
        "description": "Détecte une saturation d'authentification caractéristique d'un dictionnaire ou password spray automatisé."
    },
    {
        "id": "R-CONN-01",
        "name": "Anomalie géolocale - Déplacement impossible",
        "category": "Réseau & Périmètre",
        "severity": "Élevé",
        "threshold": "travel_speed_kmh > 900 km/h",
        "description": "Détecte deux connexions successives à une distance géographique incompatible avec les moyens de transport conventionnels."
    },
    {
        "id": "R-CONN-02",
        "name": "Connexion externe sur port d'administration sensible",
        "category": "Réseau & Périmètre",
        "severity": "Critique",
        "threshold": "target_port in [3389, 22, 445, 5985] && is_external_ip == true",
        "description": "Repère une exposition non chiffrée ou une tentative d'accès distant aux ports RDP, SSH ou SMB depuis Internet."
    },
    {
        "id": "R-FILE-01",
        "name": "Fichier bureautique avec déclenchement de script système",
        "category": "Système de fichiers & Endpoint",
        "severity": "Critique",
        "threshold": "has_macros == true && spawned_process in ['powershell', 'cmd', 'wscript', 'cscript', 'bash']",
        "description": "Indique l'exécution d'un payload de commande par un document bureautique suspect."
    },
    {
        "id": "R-FILE-02",
        "name": "Extension de fichier double ou exécutable déguisé",
        "category": "Système de fichiers & Endpoint",
        "severity": "Élevé",
        "threshold": "double_extension == true || extension in ['.exe', '.scr', '.vbs', '.ps1'] dans répertoire temporaire",
        "description": "Repère les techniques d'obfuscation de nom de fichier utilisées pour tromper l'utilisateur."
    },
    {
        "id": "R-PHISH-01",
        "name": "Courriel externe avec échec d'authentification de domaine SPF/DKIM",
        "category": "Messagerie & Ingénierie Sociale",
        "severity": "Élevé",
        "threshold": "spf_result == 'FAIL' || dkim_result == 'FAIL'",
        "description": "Signale un courriel usurpant une identité d'expéditeur avec rupture des protocoles de confiance de messagerie."
    },
    {
        "id": "R-PHISH-02",
        "name": "Lien de phishing ciblant des identifiants avec domaine récent",
        "category": "Messagerie & Ingénierie Sociale",
        "severity": "Critique",
        "threshold": "domain_age_days < 15 && (credential_form == true || contains_login_keywords)",
        "description": "Détecte un lien vers une page web enregistrée récemment simulant un portail de connexion institutionnel."
    },
    {
        "id": "R-INFO-01",
        "name": "Activité télémétrique de routine conforme",
        "category": "Supervision Générale",
        "severity": "Faible",
        "threshold": "baseline_activity == true",
        "description": "Événement de diagnostic ou de sonde de routine ne présentant aucune caractéristique hostile."
    }
]

class SecurityRuleEngine:
    """
    Moteur d'évaluation transparent de cybersécurité.
    Chaque décision est documentée avec ses motifs mathématiques et ses limites opérationnelles.
    """

    @classmethod
    def evaluate(cls, event: SecurityEventInput) -> AnalysisResult:
        triggered_rules: List[TriggeredRule] = []
        reasons: List[str] = []
        limits: List[str] = []
        recommended_action: str = ""

        p = event.technical_data
        event_type = event.event_type

        # Score cumulatif de base
        calculated_score = 15

        # ------------------------------------------------------------------
        # 1. RÈGLES : Échecs de connexion répétés (Brute-Force)
        # ------------------------------------------------------------------
        failed_attempts = p.get('failed_attempts') or p.get('failed_attempts_count') or p.get('attempts')
        if failed_attempts is not None and isinstance(failed_attempts, (int, float)):
            if failed_attempts >= 15:
                triggered_rules.append(TriggeredRule(
                    rule_id="R-AUTH-02",
                    rule_name="Attaque par force brute massive avérée",
                    category="Authentification & Accès",
                    severity="Critique",
                    description="Détection de tentatives répétitives massives d'authentification.",
                    condition_matched=f"Échecs consécutifs enregistrés : {failed_attempts} (seuil critique : >= 15)"
                ))
                reasons.append(
                    f"Volume extrême d'échecs de connexion ({failed_attempts} tentatives) sur la machine {event.source_host}, caractéristique d'un déverrouillage automatisé."
                )
                calculated_score = max(calculated_score, 90)
            elif failed_attempts > 5:
                triggered_rules.append(TriggeredRule(
                    rule_id="R-AUTH-01",
                    rule_name="Échecs d'authentification suspects répétés",
                    category="Authentification & Accès",
                    severity="Élevé",
                    description="Dépassement du seuil d'échecs de connexion autorisés.",
                    condition_matched=f"Échecs consécutifs enregistrés : {failed_attempts} (seuil : > 5)"
                ))
                reasons.append(
                    f"{failed_attempts} tentatives d'authentification infructueuses détectées, excédant la marge d'erreur de saisie humaine habituelle."
                )
                calculated_score = max(calculated_score, 65)

        # ------------------------------------------------------------------
        # 2. RÈGLES : Connexions inhabituelles & Anomalies de voyage
        # ------------------------------------------------------------------
        travel_speed = p.get('travel_speed_kmh') or p.get('velocity_kmh')
        if travel_speed is not None and isinstance(travel_speed, (int, float)) and travel_speed > 900:
            triggered_rules.append(TriggeredRule(
                rule_id="R-CONN-01",
                rule_name="Anomalie géolocale - Déplacement impossible",
                category="Réseau & Périmètre",
                severity="Élevé",
                description="Deux sessions ouvertes à une distance physique impossible à franchir en temps réel.",
                condition_matched=f"Vitesse apparente calculée : {travel_speed} km/h (seuil maximal physique : 900 km/h)"
            ))
            reasons.append(
                f"La vitesse apparente entre les deux adresses IP ({travel_speed} km/h) dépasse la vitesse commerciale aérienne, suggérant un partage d'identifiants ou un accès via proxy/VPN malveillant."
            )
            calculated_score = max(calculated_score, 75)

        target_port = p.get('target_port') or p.get('port')
        is_external = p.get('is_external_ip') or p.get('is_external', False)
        if target_port in [3389, 22, 445, 5985] and is_external:
            triggered_rules.append(TriggeredRule(
                rule_id="R-CONN-02",
                rule_name="Connexion externe sur port d'administration sensible",
                category="Réseau & Périmètre",
                severity="Critique",
                description="Tentative de connexion distante directe sur port d'administration critique depuis Internet.",
                condition_matched=f"Port cible : {target_port} exposé publiquement"
            ))
            reasons.append(
                f"Accès direct non restreint au port d'administration {target_port} détecté depuis une adresse publique."
            )
            calculated_score = max(calculated_score, 88)

        # ------------------------------------------------------------------
        # 3. RÈGLES : Fichiers suspects & Exécution anormale
        # ------------------------------------------------------------------
        has_macros = p.get('has_macros') or p.get('contains_macro', False)
        spawned_proc = str(p.get('spawned_process') or p.get('child_process', '')).lower()
        parent_proc = str(p.get('parent_process', '')).lower()
        file_name = str(p.get('file_name', '')).lower()
        file_ext = str(p.get('file_extension', '')).lower()

        shell_processes = ['powershell', 'cmd', 'wscript', 'cscript', 'bash', 'sh']
        is_shell_spawned = any(shell in spawned_proc for shell in shell_processes)

        if has_macros and is_shell_spawned:
            triggered_rules.append(TriggeredRule(
                rule_id="R-FILE-01",
                rule_name="Fichier bureautique avec déclenchement de script système",
                category="Système de fichiers & Endpoint",
                severity="Critique",
                description="Document bureautique ayant instancié un shell système non interactif.",
                condition_matched=f"Macro active + processus enfant interpréteur : '{spawned_proc}'"
            ))
            reasons.append(
                f"Le fichier '{file_name or 'document'}' contient des macros ayant tenté d'exécuter un terminal système ('{spawned_proc}'), un schéma classique de vecteur d'infection ransomware/trojan."
            )
            calculated_score = max(calculated_score, 95)
        elif (file_ext in ['.exe', '.scr', '.vbs', '.bat', '.ps1'] and 'temp' in str(p.get('file_path', '')).lower()) or p.get('double_extension', False):
            triggered_rules.append(TriggeredRule(
                rule_id="R-FILE-02",
                rule_name="Extension de fichier double ou exécutable déguisé",
                category="Système de fichiers & Endpoint",
                severity="Élevé",
                description="Fichier exécutable logé dans un répertoire transitoire ou masqué par double extension.",
                condition_matched=f"Fichier : '{file_name}' avec extension à risque '{file_ext}'"
            ))
            reasons.append(
                f"Présence d'un binaire ou script autonome '{file_name}' déposé dans un dossier temporaire ou présentant une signature trompeuse."
            )
            calculated_score = max(calculated_score, 80)

        # ------------------------------------------------------------------
        # 4. RÈGLES : Phishing simulé & Usurpation
        # ------------------------------------------------------------------
        spf_result = str(p.get('spf_result', '')).upper()
        dkim_result = str(p.get('dkim_result', '')).upper()
        domain_age = p.get('domain_age_days')
        has_login_target = p.get('credential_form', False) or any(
            k in str(p.get('embedded_url', '')).lower() for k in ['login', 'auth', 'signin', 'verification', 'banque']
        )

        if spf_result == 'FAIL' or dkim_result == 'FAIL':
            triggered_rules.append(TriggeredRule(
                rule_id="R-PHISH-01",
                rule_name="Courriel externe avec échec d'authentification de domaine SPF/DKIM",
                category="Messagerie & Ingénierie Sociale",
                severity="Élevé",
                description="Défaut d'alignement cryptographique de l'expéditeur indiquant une usurpation d'identité.",
                condition_matched=f"Résultat SPF: {spf_result or 'N/A'}, DKIM: {dkim_result or 'N/A'}"
            ))
            reasons.append(
                f"Le serveur émetteur n'est pas autorisé par les enregistrements DNS du domaine revendiqué (SPF: {spf_result})."
            )
            calculated_score = max(calculated_score, 72)

        if domain_age is not None and isinstance(domain_age, (int, float)) and domain_age < 15 and has_login_target:
            triggered_rules.append(TriggeredRule(
                rule_id="R-PHISH-02",
                rule_name="Lien de phishing ciblant des identifiants avec domaine récent",
                category="Messagerie & Ingénierie Sociale",
                severity="Critique",
                description="Nom de domaine créé il y a moins de 15 jours hébergeant un formulaire de capture d'identifiants.",
                condition_matched=f"Âge du domaine : {domain_age} jours (< 15) et formulaire d'authentification détecté"
            ))
            reasons.append(
                f"Le lien embarqué pointe vers un nom de domaine néo-enregistré ({domain_age} jours d'existence) imitant une page de connexion légitime."
            )
            calculated_score = max(calculated_score, 89)

        # ------------------------------------------------------------------
        # CAS PAR DÉFAUT : Aucune règle agressive déclenchée
        # ------------------------------------------------------------------
        if not triggered_rules:
            triggered_rules.append(TriggeredRule(
                rule_id="R-INFO-01",
                rule_name="Activité télémétrique de routine conforme",
                category="Supervision Générale",
                severity="Faible",
                description="Aucun marqueur malveillant ni dépassement de seuil constaté.",
                condition_matched="Toutes les métriques se situent dans la plage nominale."
            ))
            reasons.append(
                f"L'événement de type '{event_type}' sur l'hôte {event.source_host} ne présente aucune anomalie détectable par le catalogue de règles actuel."
            )
            calculated_score = 15

        # ------------------------------------------------------------------
        # Paliers stricts de risque
        # ------------------------------------------------------------------
        calculated_score = min(100, max(0, calculated_score))

        if calculated_score >= 85:
            risk_level = "Critique"
            recommended_action = (
                f"Isoler immédiatement la machine source ({event.source_host}) du réseau d'entreprise, "
                "révoquer les jetons de session actifs et déclencher l'astreinte d'urgence du RSSI."
            )
        elif calculated_score >= 50:
            risk_level = "Élevé"
            recommended_action = (
                "Bloquer temporairement l'entité source (adresse IP ou expéditeur), "
                "suspendre le compte utilisateur ciblé et notifier l'analyste SOC de garde."
            )
        else:
            risk_level = "Faible"
            recommended_action = (
                "Consigner l'événement dans le journal d'audit passif pour historique "
                "sans interruption de service ni intervention requise."
            )

        # ------------------------------------------------------------------
        # Transparence absolue : Définition explicite des limites d'analyse
        # ------------------------------------------------------------------
        limits = [
            "Analyse heuristique locale basée sur les règles statiques : aucune détonation dynamique en bac à sable matériel n'a été réalisée.",
            "L'analyse dépend de l'exactitude des métadonnées fournies dans la télémétrie technique (horodatage, adresse IP, hash).",
            "Ce moteur d'analyse fournit une aide à la décision pour le SOC et n'altère en aucun cas les machines réelles de production."
        ]

        return AnalysisResult(
            event_id=event.event_id,
            analyzed_at=datetime.utcnow().isoformat() + "Z",
            risk_level=risk_level,
            risk_score=calculated_score,
            triggered_rules=triggered_rules,
            decision_reasons=reasons,
            analysis_limits=limits,
            recommended_action=recommended_action
        )
