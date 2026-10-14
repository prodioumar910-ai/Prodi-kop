import { 
  FireAgentPipeline, 
  DetectorAgent, 
  AnalystAgent, 
  RiskAgent, 
  ProtectionAgent, 
  VerificationAgent, 
  ChiefAgent,
  RawSecurityEventInput
} from '../engine/agentPipeline';
import { 
  SecurityEventValidator, 
  SecurityAnalysisEngine 
} from '../engine/securityRuleEngine';
import { INITIAL_EVENTS, INITIAL_CHEF_REPORT } from '../data/initialData';

export interface TestResult {
  name: string;
  category: string;
  passed: boolean;
  message: string;
  durationMs: number;
  details?: Record<string, any>;
}

export interface TestSuiteSummary {
  total: number;
  passed: number;
  failed: number;
  durationMs: number;
  results: TestResult[];
}

export class FireAgentTestEngine {

  /**
   * Test 1: Exécution réelle de la chaîne multi-agents sur un fichier suspect synthétique
   */
  public static testRealPipelineExecution(): TestResult {
    const startTime = performance.now();
    try {
      const syntheticInput: RawSecurityEventInput = {
        eventId: 'TEST-FILE-001',
        timestamp: new Date().toISOString(),
        source: 'Poste Comptabilité [V-DESK-09]',
        target: 'Dossier Partagé Finance',
        category: 'Fichier suspect',
        payload: {
          fileName: 'Facture_Mars_2026.xlsm',
          fileExtension: '.xlsm',
          hasMacros: true,
          parentProcess: 'EXCEL.EXE',
          spawnedProcess: 'powershell.exe',
          commandLineArgs: '-enc aQB3AHIAIAAtAHUAcgBpACAA...',
          sourceIp: '185.220.101.5'
        }
      };

      const result = FireAgentPipeline.execute(syntheticInput);

      if (!result.incidentId || !result.generatedSecurityEvent) {
        throw new Error('Le Chef Agent n\'a pas produit d\'événement de sécurité');
      }

      if (result.consensusScore !== 100) {
        throw new Error(`Le score de consensus attendu est de 100%, reçu : ${result.consensusScore}%`);
      }

      if (result.verificationOutput.containmentVerified !== true) {
        throw new Error('L\'Agent Vérification n\'a pas certifié l\'endiguement');
      }

      return {
        name: 'Exécution réelle de la chaîne multi-agents',
        category: 'Orchestration Réelle',
        passed: true,
        message: `Pipeline exécuté avec succès : 6 agents ont échangé leurs objets de données. Incident ${result.incidentId} clos par consensus.`,
        durationMs: performance.now() - startTime,
        details: {
          incidentId: result.incidentId,
          riskLevel: result.generatedSecurityEvent.riskLevel,
          score: result.generatedSecurityEvent.riskScore
        }
      };
    } catch (err: any) {
      return {
        name: 'Exécution réelle de la chaîne multi-agents',
        category: 'Orchestration Réelle',
        passed: false,
        message: err.message || 'Erreur inattendue',
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Test 2: Vérification de la transmission des véritables objets de données inter-agents
   */
  public static testDataTransmissionContract(): TestResult {
    const startTime = performance.now();
    try {
      const input: RawSecurityEventInput = {
        eventId: 'TEST-AUTH-002',
        timestamp: new Date().toISOString(),
        source: 'Passerelle SSO / IAM',
        target: 'Compte Admin Secops',
        category: 'Tentative de connexion',
        payload: {
          sourceIp: '194.26.29.114',
          failedAttemptsCount: 28,
          travelVelocityKmH: 14200
        }
      };

      // Étape 1 : Détecteur
      const step1 = DetectorAgent.run(input);
      if (!step1.anomalyDetected || step1.anomalyConfidence < 0.9) {
        throw new Error('Agent Détecteur n\'a pas qualifié l\'anomalie de saut géographique');
      }

      // Étape 2 : Analyste
      const step2 = AnalystAgent.run(step1);
      if (step2.detectorOutput !== step1) {
        throw new Error('Rupture de contrat : l\'Analyste n\'a pas reçu l\'objet exact du Détecteur');
      }
      if (!step2.extractedIoCs.ips.includes('194.26.29.114')) {
        throw new Error('L\'Analyste n\'a pas extrait l\'adresse IP de l\'événement');
      }

      // Étape 3 : Risque
      const step3 = RiskAgent.run(step2);
      if (step3.analystOutput !== step2) {
        throw new Error('Rupture de contrat : l\'Agent Risque n\'a pas reçu l\'objet de l\'Analyste');
      }
      if (step3.calculatedScore < 50 || step3.riskLevel !== 'Élevé') {
        throw new Error(`Incohérence Risque : attendu 'Élevé', obtenu ${step3.riskLevel}`);
      }

      // Étape 4 : Protection
      const step4 = ProtectionAgent.run(step3);
      if (step4.riskOutput !== step3) {
        throw new Error('Rupture de contrat : l\'Agent Protection n\'a pas reçu l\'objet de Risque');
      }
      if (step4.executedSandboxActions.length === 0) {
        throw new Error('L\'Agent Protection n\'a produit aucune action défensive simulée');
      }

      // Étape 5 : Vérification
      const step5 = VerificationAgent.run(step4);
      if (step5.protectionOutput !== step4) {
        throw new Error('Rupture de contrat : l\'Agent Vérification n\'a pas reçu l\'objet de Protection');
      }

      // Étape 6 : Chef
      const step6 = ChiefAgent.run(step5);
      if (step6.verificationOutput !== step5) {
        throw new Error('Rupture de contrat : le Chef Agent n\'a pas reçu l\'objet de Vérification');
      }

      return {
        name: 'Contrat d\'échange d\'objets typés inter-agents',
        category: 'Communication',
        passed: true,
        message: 'Intégrité des 5 liaisons de données vérifiée : chaque agent enrichit et propage le contrat.',
        durationMs: performance.now() - startTime
      };
    } catch (err: any) {
      return {
        name: 'Contrat d\'échange d\'objets typés inter-agents',
        category: 'Communication',
        passed: false,
        message: err.message,
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Test 3: Règle d'évaluation du risque à 3 paliers stricts
   */
  public static testThreeTierRiskRule(): TestResult {
    const startTime = performance.now();
    try {
      // 1. Cas Faible : sonde de port simple
      const lowInput: RawSecurityEventInput = {
        eventId: 'CASE-LOW',
        timestamp: new Date().toISOString(),
        source: 'Serveur Web Intranet',
        target: 'Contrôleur de Domaine',
        category: 'Activité malveillante',
        payload: { sourceIp: '10.0.4.15' }
      };
      const lowRes = FireAgentPipeline.execute(lowInput);
      if (lowRes.verificationOutput.protectionOutput.riskOutput.riskLevel !== 'Faible') {
        throw new Error(`Échec palier Faible : attendu Faible, reçu ${lowRes.verificationOutput.protectionOutput.riskOutput.riskLevel}`);
      }
      if (lowRes.verificationOutput.protectionOutput.executedSandboxActions[0].actionType !== 'PASSIVE_LOG') {
        throw new Error('Le palier Faible ne doit pas déclencher de blocage de service');
      }

      // 2. Cas Élevé : Brute-force & saut géo
      const highInput: RawSecurityEventInput = {
        eventId: 'CASE-HIGH',
        timestamp: new Date().toISOString(),
        source: 'Passerelle Auth',
        target: 'Compte Admin',
        category: 'Tentative de connexion',
        payload: { failedAttemptsCount: 30, sourceIp: '194.26.29.114', travelVelocityKmH: 5000 }
      };
      const highRes = FireAgentPipeline.execute(highInput);
      if (highRes.verificationOutput.protectionOutput.riskOutput.riskLevel !== 'Élevé') {
        throw new Error(`Échec palier Élevé : attendu Élevé, reçu ${highRes.verificationOutput.protectionOutput.riskOutput.riskLevel}`);
      }

      // 3. Cas Critique : Dropper Office exécutant PowerShell
      const criticalInput: RawSecurityEventInput = {
        eventId: 'CASE-CRITICAL',
        timestamp: new Date().toISOString(),
        source: 'Poste Comptabilité',
        target: 'Serveur Fichiers',
        category: 'Fichier suspect',
        payload: { parentProcess: 'excel.exe', spawnedProcess: 'powershell.exe', sourceIp: '185.220.101.5' }
      };
      const criticalRes = FireAgentPipeline.execute(criticalInput);
      if (criticalRes.verificationOutput.protectionOutput.riskOutput.riskLevel !== 'Critique') {
        throw new Error(`Échec palier Critique : attendu Critique, reçu ${criticalRes.verificationOutput.protectionOutput.riskOutput.riskLevel}`);
      }
      if (criticalRes.alertPriority !== 'RSSI_URGENT') {
        throw new Error('Le palier Critique doit déclencher une alerte prioritaire pour le RSSI');
      }

      return {
        name: 'Cohérence mathématique des 3 paliers de risque',
        category: 'Évaluation',
        passed: true,
        message: 'Barème strict validé : Faible (Log passif), Élevé (Protection simulée + SOC), Critique (Alerte prioritaire RSSI).',
        durationMs: performance.now() - startTime
      };
    } catch (err: any) {
      return {
        name: 'Cohérence mathématique des 3 paliers de risque',
        category: 'Évaluation',
        passed: false,
        message: err.message,
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Test 4: Garantie formelle de non-altération du système hôte
   */
  public static testSafetyAndTransparencyGuarantee(): TestResult {
    const startTime = performance.now();
    try {
      const criticalInput: RawSecurityEventInput = {
        eventId: 'TEST-SAFETY',
        timestamp: new Date().toISOString(),
        source: 'Station R&D',
        target: 'Résolveur DNS',
        category: 'Activité malveillante',
        payload: { dnsQueriesPerMin: 450, shannonEntropy: 4.85, exfiltrationTargetDomain: 'c2-test.xyz' }
      };

      const result = FireAgentPipeline.execute(criticalInput);
      const actions = result.verificationOutput.protectionOutput.executedSandboxActions;

      for (const action of actions) {
        if (action.realSystemTouched !== false) {
          throw new Error('Viol de sécurité : action de protection non isolée du système réel');
        }
      }

      return {
        name: 'Garantie de non-altération du système hôte',
        category: 'Sécurité & Déontologie',
        passed: true,
        message: 'Toutes les actions défensives sont vérifiées avec le drapeau strict realSystemTouched: false.',
        durationMs: performance.now() - startTime
      };
    } catch (err: any) {
      return {
        name: 'Garantie de non-altération du système hôte',
        category: 'Sécurité & Déontologie',
        passed: false,
        message: err.message,
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Test 5: Synthèse décisionnelle et génération de rapport par le Chef Agent
   */
  public static testChiefAgentReportGeneration(): TestResult {
    const startTime = performance.now();
    try {
      const input: RawSecurityEventInput = {
        eventId: 'TEST-CHIEF',
        timestamp: new Date().toISOString(),
        source: 'Passerelle Mail',
        target: 'Direction Financière',
        category: 'Email de phishing',
        payload: {
          emailSender: 'support@rh-portal.xyz',
          spfResult: 'FAIL',
          domainAgeDays: 1,
          embeddedUrl: 'https://login-sso-fake.net'
        }
      };

      const output = FireAgentPipeline.execute(input);

      if (!output.executiveSummary || output.executiveSummary.length < 20) {
        throw new Error('La synthèse exécutive du Chef Agent est vide ou trop courte');
      }

      if (output.hardeningRecommendations.length === 0) {
        throw new Error('Le Chef Agent doit formuler au moins une recommandation de durcissement');
      }

      if (!output.generatedSecurityEvent.mitre?.id) {
        throw new Error('L\'événement de sécurité généré n\'a pas de technique MITRE associée');
      }

      return {
        name: 'Génération du rapport et synthèse par le Chef Agent',
        category: 'Supervision',
        passed: true,
        message: `Synthèse exécutive générée avec succès (${output.executiveSummary.length} caractères) et recommandations de durcissement valides.`,
        durationMs: performance.now() - startTime
      };
    } catch (err: any) {
      return {
        name: 'Génération du rapport et synthèse par le Chef Agent',
        category: 'Supervision',
        passed: false,
        message: err.message,
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Test 6: Résilience aux entrées vides, incomplètes ou erratiques
   */
  public static testInputSanitizationAndRobustness(): TestResult {
    const startTime = performance.now();
    try {
      // Événement volontairement minimaliste sans payload technique
      const emptyInput: RawSecurityEventInput = {
        eventId: 'EMPTY-001',
        timestamp: new Date().toISOString(),
        source: 'Inconnue',
        target: 'Inconnue',
        category: 'Activité malveillante',
        payload: {}
      };

      const output = FireAgentPipeline.execute(emptyInput);

      if (!output.incidentId || !output.generatedSecurityEvent) {
        throw new Error('Le pipeline n\'a pas pu traiter une entrée partielle');
      }

      return {
        name: 'Résilience et traitement des cas limites',
        category: 'Robustesse',
        passed: true,
        message: 'Le moteur multi-agents traite les flux minimaux sans lever d\'exception non gérée.',
        durationMs: performance.now() - startTime
      };
    } catch (err: any) {
      return {
        name: 'Résilience et traitement des cas limites',
        category: 'Robustesse',
        passed: false,
        message: err.message,
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Test 7: Validation stricte du format d'événements et rejet des données malformées (Phase 3)
   */
  public static testEventFormatValidationAndRejection(): TestResult {
    const startTime = performance.now();
    try {
      // 1. Événement valide
      const validPayload = {
        event_id: 'EVT-TEST-VALID-01',
        timestamp: new Date().toISOString(),
        source_host: 'SRV-TEST',
        event_type: 'suspicious_file',
        description: 'Test de conformité valide',
        technical_data: { file_name: 'test.exe' }
      };
      const val1 = SecurityEventValidator.validate(validPayload);
      if (!val1.valid || !val1.event) {
        throw new Error(`Événement valide incorrectement rejeté : ${val1.errors.join(', ')}`);
      }

      // 2. Événement malformé sans event_id
      const badPayload1 = {
        timestamp: new Date().toISOString(),
        source_host: 'SRV-TEST',
        event_type: 'suspicious_file',
        description: 'Incomplet'
      };
      const val2 = SecurityEventValidator.validate(badPayload1);
      if (val2.valid) {
        throw new Error('Un événement sans event_id aurait dû être rejeté');
      }

      // 3. Événement avec type inconnu
      const badPayload2 = {
        event_id: 'EVT-BAD-TYPE',
        timestamp: new Date().toISOString(),
        source_host: 'SRV-TEST',
        event_type: 'unknown_unsupported_type',
        description: 'Type inconnu'
      };
      const val3 = SecurityEventValidator.validate(badPayload2);
      if (val3.valid) {
        throw new Error('Un événement avec type non autorisé aurait dû être rejeté');
      }

      return {
        name: 'Validation du format d\'événements et rejet des données malformées',
        category: 'Validation & Spécification',
        passed: true,
        message: 'Contrats validés : structure JSON vérifiée, champs obligatoires requis et rejets explicites conformes.',
        durationMs: performance.now() - startTime
      };
    } catch (err: any) {
      return {
        name: 'Validation du format d\'événements et rejet des données malformées',
        category: 'Validation & Spécification',
        passed: false,
        message: err.message,
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Test 8: Déontologie et rejet strict des mots de passe et secrets (Phase 3)
   */
  public static testSensitiveDataStrictRejection(): TestResult {
    const startTime = performance.now();
    try {
      const sensitivePayload = {
        event_id: 'EVT-SECRET-01',
        timestamp: new Date().toISOString(),
        source_host: 'WKSTN-ADMIN',
        event_type: 'failed_logins',
        description: 'Capture contenant des identifiants',
        technical_data: {
          failed_attempts: 12,
          password: 'SecretClearTextPassword!' // INTERDIT
        }
      };

      const val = SecurityEventValidator.validate(sensitivePayload);
      if (val.valid) {
        throw new Error('Viol de sécurité : un payload contenant un mot de passe a été accepté !');
      }

      if (!val.errors.some(e => e.includes('Donnée sensible'))) {
        throw new Error('Le message d\'erreur doit explicitement mentionner le rejet de données sensibles');
      }

      return {
        name: 'Déontologie et rejet strict des mots de passe et données secrètes',
        category: 'Sécurité & Déontologie',
        passed: true,
        message: 'Principe de minimisation validé : interdiction absolue de collecte de mots de passe ou tokens secrets.',
        durationMs: performance.now() - startTime
      };
    } catch (err: any) {
      return {
        name: 'Déontologie et rejet strict des mots de passe et données secrètes',
        category: 'Sécurité & Déontologie',
        passed: false,
        message: err.message,
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Test 9: Détection déterministe des 4 familles de règles de cybersécurité (Phase 3)
   */
  public static testFourRuleFamiliesDetection(): TestResult {
    const startTime = performance.now();
    try {
      // 1. Force brute
      const resBrute = SecurityAnalysisEngine.evaluate({
        event_id: 'TEST-BRUTE',
        timestamp: new Date().toISOString(),
        source_host: 'SRV-AD',
        event_type: 'failed_logins',
        description: 'Brute force',
        technical_data: { failed_attempts: 20 }
      });
      if (resBrute.risk_level !== 'Critique' || !resBrute.triggered_rules.some(r => r.rule_id === 'R-AUTH-02')) {
        throw new Error('Règle R-AUTH-02 non déclenchée pour 20 échecs de connexion');
      }

      // 2. Déplacement impossible
      const resTravel = SecurityAnalysisEngine.evaluate({
        event_id: 'TEST-TRAVEL',
        timestamp: new Date().toISOString(),
        source_host: 'VPN',
        event_type: 'unusual_connection',
        description: 'Déplacement impossible',
        technical_data: { travel_speed_kmh: 3500 }
      });
      if (resTravel.risk_level !== 'Élevé' || !resTravel.triggered_rules.some(r => r.rule_id === 'R-CONN-01')) {
        throw new Error('Règle R-CONN-01 non déclenchée pour vitesse > 900 km/h');
      }

      // 3. Macro suspecte PowerShell
      const resMacro = SecurityAnalysisEngine.evaluate({
        event_id: 'TEST-MACRO',
        timestamp: new Date().toISOString(),
        source_host: 'PC-FIN',
        event_type: 'suspicious_file',
        description: 'Macro',
        technical_data: { has_macros: true, spawned_process: 'powershell.exe' }
      });
      if (resMacro.risk_level !== 'Critique' || !resMacro.triggered_rules.some(r => r.rule_id === 'R-FILE-01')) {
        throw new Error('Règle R-FILE-01 non déclenchée pour macro PowerShell');
      }

      // 4. Phishing simulé
      const resPhish = SecurityAnalysisEngine.evaluate({
        event_id: 'TEST-PHISH',
        timestamp: new Date().toISOString(),
        source_host: 'RELAY',
        event_type: 'phishing_simulation',
        description: 'Phishing',
        technical_data: { spf_result: 'FAIL', domain_age_days: 2, credential_form: true }
      });
      if (resPhish.risk_level !== 'Critique' || !resPhish.triggered_rules.some(r => r.rule_id === 'R-PHISH-01')) {
        throw new Error('Règles R-PHISH non déclenchées pour SPF FAIL et domaine récent');
      }

      return {
        name: 'Moteur de règles : Couverture des 4 familles de menaces',
        category: 'Moteur de Règles',
        passed: true,
        message: 'Toutes les 4 familles (Force brute, Saut géographique, Fichier suspect, Phishing) détectées avec précision.',
        durationMs: performance.now() - startTime
      };
    } catch (err: any) {
      return {
        name: 'Moteur de règles : Couverture des 4 familles de menaces',
        category: 'Moteur de Règles',
        passed: false,
        message: err.message,
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Test 10: Transparence totale des décisions, limites et recommandations (Phase 3)
   */
  public static testDecisionTransparencyAndLimits(): TestResult {
    const startTime = performance.now();
    try {
      const res = SecurityAnalysisEngine.evaluate({
        event_id: 'TEST-TRANS',
        timestamp: new Date().toISOString(),
        source_host: 'SRV-APP',
        event_type: 'suspicious_file',
        description: 'Document à risque',
        technical_data: { has_macros: true, spawned_process: 'cmd.exe' }
      });

      if (!res.risk_level || res.risk_score <= 0) {
        throw new Error('Le score et le niveau de risque doivent être renseignés');
      }
      if (!res.triggered_rules || res.triggered_rules.length === 0) {
        throw new Error('Les règles déclenchées doivent être listées');
      }
      if (!res.decision_reasons || res.decision_reasons.length === 0) {
        throw new Error('Les raisons explicites de la décision doivent être formulées');
      }
      if (!res.analysis_limits || res.analysis_limits.length === 0) {
        throw new Error('Les limites opérationnelles de l\'analyse doivent être déclarées');
      }
      if (!res.recommended_action || res.recommended_action.length < 10) {
        throw new Error('Une recommandation d\'action concrète doit être fournie');
      }

      return {
        name: 'Transparence décisionnelle : Raisons, limites et recommandations',
        category: 'Transparence & Audit',
        passed: true,
        message: 'Contrat de transparence 100% respecté : score, règles, raisons, limites déontologiques et recommandation.',
        durationMs: performance.now() - startTime
      };
    } catch (err: any) {
      return {
        name: 'Transparence décisionnelle : Raisons, limites et recommandations',
        category: 'Transparence & Audit',
        passed: false,
        message: err.message,
        durationMs: performance.now() - startTime
      };
    }
  }

  /**
   * Exécute l'ensemble de la suite de tests et retourne le résumé
   */
  public static runAllTests(): TestSuiteSummary {
    const startTime = performance.now();
    const results: TestResult[] = [
      this.testRealPipelineExecution(),
      this.testDataTransmissionContract(),
      this.testThreeTierRiskRule(),
      this.testSafetyAndTransparencyGuarantee(),
      this.testChiefAgentReportGeneration(),
      this.testInputSanitizationAndRobustness(),
      this.testEventFormatValidationAndRejection(),
      this.testSensitiveDataStrictRejection(),
      this.testFourRuleFamiliesDetection(),
      this.testDecisionTransparencyAndLimits()
    ];

    const passed = results.filter(r => r.passed).length;
    const failed = results.filter(r => !r.passed).length;

    return {
      total: results.length,
      passed,
      failed,
      durationMs: performance.now() - startTime,
      results
    };
  }
}
