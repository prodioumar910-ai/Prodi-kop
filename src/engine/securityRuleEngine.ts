/**
 * Moteur de règles d'analyse de cybersécurité FIRE AGENT (Implémentation TypeScript).
 * Aligné avec l'architecture backend FastAPI / Python.
 * Assure la validation, le rejet des événements malformés,
 * l'interdiction des secrets et l'analyse déterministe.
 */

export interface TechnicalData {
  source_ip?: string;
  failed_attempts?: number;
  failed_attempts_count?: number;
  targeted_account?: string;
  travel_speed_kmh?: number;
  target_port?: number;
  is_external_ip?: boolean;
  file_name?: string;
  file_extension?: string;
  has_macros?: boolean;
  spawned_process?: string;
  parent_process?: string;
  file_path?: string;
  double_extension?: boolean;
  email_sender?: string;
  email_subject?: string;
  spf_result?: 'PASS' | 'FAIL' | 'NONE';
  dkim_result?: 'PASS' | 'FAIL' | 'NONE';
  domain_age_days?: number;
  embedded_url?: string;
  credential_form?: boolean;
  [key: string]: any;
}

export interface SecurityEventInput {
  event_id: string;
  timestamp: string;
  source_host: string;
  event_type: 'failed_logins' | 'unusual_connection' | 'suspicious_file' | 'phishing_simulation' | 'telemetry_scan' | 'generic_event';
  description: string;
  technical_data: TechnicalData;
}

export interface TriggeredRule {
  rule_id: string;
  rule_name: string;
  category: string;
  severity: 'Faible' | 'Élevé' | 'Critique';
  description: string;
  condition_matched: string;
}

export interface AnalysisResult {
  event_id: string;
  analyzed_at: string;
  risk_level: 'Faible' | 'Élevé' | 'Critique';
  risk_score: number;
  triggered_rules: TriggeredRule[];
  decision_reasons: string[];
  analysis_limits: string[];
  recommended_action: string;
}

export interface RuleDefinition {
  id: string;
  name: string;
  category: string;
  severity: 'Faible' | 'Élevé' | 'Critique';
  threshold: string;
  description: string;
}

export const RULES_CATALOG: RuleDefinition[] = [
  {
    id: 'R-AUTH-01',
    name: "Échecs d'authentification suspects répétés",
    category: 'Authentification & Accès',
    severity: 'Élevé',
    threshold: 'failed_attempts > 5',
    description: "Détecte un nombre anormal d'échecs de connexion consécutifs sur un compte ou une IP source."
  },
  {
    id: 'R-AUTH-02',
    name: 'Attaque par force brute massive avérée',
    category: 'Authentification & Accès',
    severity: 'Critique',
    threshold: 'failed_attempts >= 15',
    description: "Détecte une saturation d'authentification caractéristique d'un dictionnaire ou password spray automatisé."
  },
  {
    id: 'R-CONN-01',
    name: 'Anomalie géolocale - Déplacement impossible',
    category: 'Réseau & Périmètre',
    severity: 'Élevé',
    threshold: 'travel_speed_kmh > 900 km/h',
    description: 'Détecte deux connexions successives à une distance géographique incompatible avec les moyens de transport conventionnels.'
  },
  {
    id: 'R-CONN-02',
    name: "Connexion externe sur port d'administration sensible",
    category: 'Réseau & Périmètre',
    severity: 'Critique',
    threshold: 'target_port in [3389, 22, 445, 5985] && is_external_ip == true',
    description: "Repère une exposition non chiffrée ou une tentative d'accès distant aux ports RDP, SSH ou SMB depuis Internet."
  },
  {
    id: 'R-FILE-01',
    name: 'Fichier bureautique avec déclenchement de script système',
    category: 'Système de fichiers & Endpoint',
    severity: 'Critique',
    threshold: "has_macros == true && spawned_process in ['powershell', 'cmd', 'wscript', 'cscript', 'bash']",
    description: "Indique l'exécution d'un payload de commande par un document bureautique suspect."
  },
  {
    id: 'R-FILE-02',
    name: 'Extension de fichier double ou exécutable déguisé',
    category: 'Système de fichiers & Endpoint',
    severity: 'Élevé',
    threshold: "double_extension == true || extension in ['.exe', '.scr', '.vbs', '.ps1'] dans répertoire temporaire",
    description: "Repère les techniques d'obfuscation de nom de fichier utilisées pour tromper l'utilisateur."
  },
  {
    id: 'R-PHISH-01',
    name: "Courriel externe avec échec d'authentification de domaine SPF/DKIM",
    category: 'Messagerie & Ingénierie Sociale',
    severity: 'Élevé',
    threshold: "spf_result == 'FAIL' || dkim_result == 'FAIL'",
    description: "Signale un courriel usurpant une identité d'expéditeur avec rupture des protocoles de confiance de messagerie."
  },
  {
    id: 'R-PHISH-02',
    name: "Lien de phishing ciblant des identifiants avec domaine récent",
    category: 'Messagerie & Ingénierie Sociale',
    severity: 'Critique',
    threshold: 'domain_age_days < 15 && (credential_form == true || contains_login_keywords)',
    description: "Détecte un lien vers une page web enregistrée récemment simulant un portail de connexion institutionnel."
  },
  {
    id: 'R-INFO-01',
    name: 'Activité télémétrique de routine conforme',
    category: 'Supervision Générale',
    severity: 'Faible',
    threshold: 'baseline_activity == true',
    description: 'Événement de diagnostic ou de sonde de routine ne présentant aucune caractéristique hostile.'
  }
];

const FORBIDDEN_KEYS = [
  'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
  'private_key', 'token', 'auth_token', 'access_token', 'bearer',
  'mot_de_passe', 'cle_secrete'
];

export class SecurityEventValidator {
  public static validate(raw: any): { valid: boolean; errors: string[]; event?: SecurityEventInput } {
    const errors: string[] = [];

    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return { valid: false, errors: ['Le corps de la requête doit être un objet JSON valide.'] };
    }

    // 1. Détection des secrets interdits (Déontologie & Confidentialité)
    for (const key of Object.keys(raw)) {
      const k = key.toLowerCase();
      if (FORBIDDEN_KEYS.some(f => k.includes(f))) {
        return {
          valid: false,
          errors: [`Donnée sensible interdite détectée (clé : '${key}'). Le système interdit la collecte de mots de passe ou secrets.`]
        };
      }
    }

    if (raw.technical_data && typeof raw.technical_data === 'object') {
      for (const key of Object.keys(raw.technical_data)) {
        const k = key.toLowerCase();
        if (FORBIDDEN_KEYS.some(f => k.includes(f))) {
          return {
            valid: false,
            errors: [`Donnée sensible interdite détectée dans technical_data (clé : '${key}').`]
          };
        }
      }
    }

    // 2. Champs obligatoires
    if (!raw.event_id || typeof raw.event_id !== 'string' || raw.event_id.trim().length < 3) {
      errors.push("Le champ 'event_id' est obligatoire et doit comporter au moins 3 caractères.");
    }

    if (!raw.timestamp || typeof raw.timestamp !== 'string') {
      errors.push("Le champ 'timestamp' est obligatoire (format ISO 8601 recommandé).");
    } else {
      const parsedDate = Date.parse(raw.timestamp);
      if (isNaN(parsedDate) && !/^\d{4}-\d{2}-\d{2}/.test(raw.timestamp)) {
        errors.push(`Format d'horodatage invalide : '${raw.timestamp}'.`);
      }
    }

    if (!raw.source_host || typeof raw.source_host !== 'string' || raw.source_host.trim().length === 0) {
      errors.push("Le champ 'source_host' (identifiant de la machine) est obligatoire.");
    }

    const allowedTypes = [
      'failed_logins',
      'unusual_connection',
      'suspicious_file',
      'phishing_simulation',
      'telemetry_scan',
      'generic_event'
    ];
    if (!raw.event_type || !allowedTypes.includes(raw.event_type)) {
      errors.push(`Type d'événement invalide : '${raw.event_type}'. Types autorisés : ${allowedTypes.join(', ')}.`);
    }

    if (!raw.description || typeof raw.description !== 'string') {
      errors.push("Le champ 'description' est obligatoire.");
    }

    if (raw.technical_data && typeof raw.technical_data !== 'object') {
      errors.push("Le champ 'technical_data' doit être un objet clé-valeur.");
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return {
      valid: true,
      errors: [],
      event: {
        event_id: raw.event_id.trim(),
        timestamp: raw.timestamp.trim(),
        source_host: raw.source_host.trim(),
        event_type: raw.event_type,
        description: raw.description.trim(),
        technical_data: raw.technical_data || {}
      }
    };
  }
}

export class SecurityAnalysisEngine {
  public static evaluate(event: SecurityEventInput): AnalysisResult {
    const triggered_rules: TriggeredRule[] = [];
    const reasons: string[] = [];
    const p = event.technical_data || {};
    let calculated_score = 15;

    // 1. Échecs de connexion répétés
    const attempts = p.failed_attempts ?? p.failed_attempts_count;
    if (typeof attempts === 'number') {
      if (attempts >= 15) {
        triggered_rules.push({
          rule_id: 'R-AUTH-02',
          rule_name: 'Attaque par force brute massive avérée',
          category: 'Authentification & Accès',
          severity: 'Critique',
          description: "Détection de tentatives répétitives massives d'authentification.",
          condition_matched: `Échecs consécutifs enregistrés : ${attempts} (seuil critique : >= 15)`
        });
        reasons.push(
          `Volume extrême d'échecs de connexion (${attempts} tentatives) sur la machine ${event.source_host}, caractéristique d'un déverrouillage automatisé.`
        );
        calculated_score = Math.max(calculated_score, 90);
      } else if (attempts > 5) {
        triggered_rules.push({
          rule_id: 'R-AUTH-01',
          rule_name: "Échecs d'authentification suspects répétés",
          category: 'Authentification & Accès',
          severity: 'Élevé',
          description: "Dépassement du seuil d'échecs de connexion autorisés.",
          condition_matched: `Échecs consécutifs enregistrés : ${attempts} (seuil : > 5)`
        });
        reasons.push(
          `${attempts} tentatives d'authentification infructueuses détectées, excédant la marge d'erreur humaine.`
        );
        calculated_score = Math.max(calculated_score, 65);
      }
    }

    // 2. Connexions inhabituelles & vitesse physique
    const travel = p.travel_speed_kmh;
    if (typeof travel === 'number' && travel > 900) {
      triggered_rules.push({
        rule_id: 'R-CONN-01',
        rule_name: 'Anomalie géolocale - Déplacement impossible',
        category: 'Réseau & Périmètre',
        severity: 'Élevé',
        description: 'Deux sessions ouvertes à une distance physique impossible à franchir en temps réel.',
        condition_matched: `Vitesse apparente calculée : ${travel} km/h (seuil maximal : 900 km/h)`
      });
      reasons.push(
        `La vitesse apparente entre les deux sessions (${travel} km/h) dépasse la vitesse commerciale aérienne.`
      );
      calculated_score = Math.max(calculated_score, 75);
    }

    const port = p.target_port;
    const isExternal = p.is_external_ip;
    if (port && [3389, 22, 445, 5985].includes(port) && isExternal) {
      triggered_rules.push({
        rule_id: 'R-CONN-02',
        rule_name: "Connexion externe sur port d'administration sensible",
        category: 'Réseau & Périmètre',
        severity: 'Critique',
        description: "Tentative de connexion distante directe sur port d'administration critique depuis Internet.",
        condition_matched: `Port cible : ${port} exposé publiquement`
      });
      reasons.push(`Accès direct non restreint au port d'administration ${port} détecté depuis une adresse publique.`);
      calculated_score = Math.max(calculated_score, 88);
    }

    // 3. Fichier suspect & exécution anormale
    const hasMacros = Boolean(p.has_macros);
    const spawned = String(p.spawned_process || '').toLowerCase();
    const fileName = String(p.file_name || '').toLowerCase();
    const fileExt = String(p.file_extension || '').toLowerCase();
    const shells = ['powershell', 'cmd', 'wscript', 'cscript', 'bash'];

    if (hasMacros && shells.some(s => spawned.includes(s))) {
      triggered_rules.push({
        rule_id: 'R-FILE-01',
        rule_name: 'Fichier bureautique avec déclenchement de script système',
        category: 'Système de fichiers & Endpoint',
        severity: 'Critique',
        description: 'Document bureautique ayant instancié un shell système non interactif.',
        condition_matched: `Macro active + processus enfant interpréteur : '${spawned}'`
      });
      reasons.push(
        `Le document '${fileName || 'fichier'}' a exécuté un terminal système ('${spawned}'), signature caractéristique de dropper.`
      );
      calculated_score = Math.max(calculated_score, 95);
    } else if (p.double_extension || (['.exe', '.scr', '.vbs', '.bat', '.ps1'].includes(fileExt) && String(p.file_path || '').toLowerCase().includes('temp'))) {
      triggered_rules.push({
        rule_id: 'R-FILE-02',
        rule_name: 'Extension de fichier double ou exécutable déguisé',
        category: 'Système de fichiers & Endpoint',
        severity: 'Élevé',
        description: 'Fichier exécutable logé dans un répertoire transitoire ou masqué par double extension.',
        condition_matched: `Fichier : '${fileName}' avec extension à risque '${fileExt}'`
      });
      reasons.push(`Présence d'un binaire ou script autonome '${fileName}' logé dans un dossier temporaire.`);
      calculated_score = Math.max(calculated_score, 80);
    }

    // 4. Phishing simulé
    const spf = String(p.spf_result || '').toUpperCase();
    const dkim = String(p.dkim_result || '').toUpperCase();
    const domainAge = p.domain_age_days;
    const url = String(p.embedded_url || '').toLowerCase();
    const hasLoginForm = Boolean(p.credential_form) || ['login', 'auth', 'signin', 'verification'].some(k => url.includes(k));

    if (spf === 'FAIL' || dkim === 'FAIL') {
      triggered_rules.push({
        rule_id: 'R-PHISH-01',
        rule_name: "Courriel externe avec échec d'authentification de domaine SPF/DKIM",
        category: 'Messagerie & Ingénierie Sociale',
        severity: 'Élevé',
        description: "Défaut d'alignement cryptographique de l'expéditeur indiquant une usurpation d'identité.",
        condition_matched: `SPF: ${spf}, DKIM: ${dkim}`
      });
      reasons.push("Le serveur émetteur n'est pas autorisé par les enregistrements DNS du domaine revendiqué.");
      calculated_score = Math.max(calculated_score, 72);
    }

    if (typeof domainAge === 'number' && domainAge < 15 && hasLoginForm) {
      triggered_rules.push({
        rule_id: 'R-PHISH-02',
        rule_name: 'Lien de phishing ciblant des identifiants avec domaine récent',
        category: 'Messagerie & Ingénierie Sociale',
        severity: 'Critique',
        description: 'Nom de domaine créé il y a moins de 15 jours hébergeant un formulaire de capture.',
        condition_matched: `Âge du domaine : ${domainAge} jours (< 15) et formulaire d'authentification détecté`
      });
      reasons.push(`Le lien pointe vers un domaine néo-enregistré (${domainAge} jours) simulant une mire d'authentification.`);
      calculated_score = Math.max(calculated_score, 89);
    }

    // Cas par défaut
    if (triggered_rules.length === 0) {
      triggered_rules.push({
        rule_id: 'R-INFO-01',
        rule_name: 'Activité télémétrique de routine conforme',
        category: 'Supervision Générale',
        severity: 'Faible',
        description: 'Aucun marqueur malveillant ni dépassement de seuil constaté.',
        condition_matched: 'Toutes les métriques se situent dans la plage nominale.'
      });
      reasons.push(
        `L'événement de type '${event.event_type}' sur l'hôte ${event.source_host} ne présente aucune anomalie détectable.`
      );
      calculated_score = 15;
    }

    calculated_score = Math.min(100, Math.max(0, calculated_score));

    let risk_level: 'Faible' | 'Élevé' | 'Critique';
    let recommended_action: string;

    if (calculated_score >= 85) {
      risk_level = 'Critique';
      recommended_action = `Isoler immédiatement la machine source (${event.source_host}) du réseau, révoquer les sessions actives et déclencher l'astreinte d'urgence RSSI.`;
    } else if (calculated_score >= 50) {
      risk_level = 'Élevé';
      recommended_action = "Bloquer temporairement l'entité source (IP ou expéditeur), suspendre le compte utilisateur ciblé et notifier l'analyste SOC.";
    } else {
      risk_level = 'Faible';
      recommended_action = "Consigner l'événement dans le journal d'audit passif sans interruption de service ni intervention requise.";
    }

    const limits = [
      "Analyse heuristique locale basée sur les règles statiques : aucune détonation dynamique en bac à sable matériel n'a été réalisée.",
      "L'analyse dépend de l'exactitude des métadonnées fournies dans la télémétrie technique (horodatage, adresse IP, hash).",
      "Ce moteur d'analyse fournit une aide à la décision pour le SOC et n'altère en aucun cas les machines réelles de production."
    ];

    return {
      event_id: event.event_id,
      analyzed_at: new Date().toISOString(),
      risk_level,
      risk_score: calculated_score,
      triggered_rules,
      decision_reasons: reasons,
      analysis_limits: limits,
      recommended_action
    };
  }
}
