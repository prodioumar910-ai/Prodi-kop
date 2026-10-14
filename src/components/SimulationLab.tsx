import React, { useState, useEffect, useRef, useMemo } from 'react';
import { 
  SimulationScenario, 
  SimulationStep, 
  SecurityEvent, 
  AgentId, 
  RiskLevel 
} from '../types/security';
import { PRESET_SCENARIOS } from '../data/initialData';
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
  Play, 
  Pause, 
  RotateCcw, 
  SkipForward, 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  Cpu, 
  Gauge, 
  Crown, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal, 
  FileCode, 
  Network, 
  Mail, 
  Activity, 
  Sliders, 
  Sparkles,
  Lock,
  ArrowRight,
  Shield,
  Laptop,
  Code2
} from 'lucide-react';

interface SimulationLabProps {
  initialScenarioId?: string;
  onEventCreated: (event: SecurityEvent) => void;
  onCriticalAlertTriggered: (scenario: SimulationScenario, step: SimulationStep) => void;
  onNavigateToChief: () => void;
}

export const SimulationLab: React.FC<SimulationLabProps> = ({
  initialScenarioId,
  onEventCreated,
  onCriticalAlertTriggered,
  onNavigateToChief
}) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(
    initialScenarioId || PRESET_SCENARIOS[0].id
  );
  const [isCustomMode, setIsCustomMode] = useState<boolean>(false);

  // Custom scenario builder state
  const [customTitle, setCustomTitle] = useState('Attaque par injection et exfiltration');
  const [customTarget, setCustomTarget] = useState('Serveur Web Démonstration [API-SRV-02]');
  const [customCategory, setCustomCategory] = useState<'Fichier suspect' | 'Tentative de connexion' | 'Email de phishing' | 'Activité malveillante'>('Activité malveillante');
  const [customRisk, setCustomRisk] = useState<RiskLevel>('Critique');
  const [customIp, setCustomIp] = useState('198.51.100.42');

  // Simulation execution state
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(-1);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);
  const [isFinished, setIsFinished] = useState<boolean>(false);
  const [agentLogs, setAgentLogs] = useState<{ id: string; time: string; agent: string; text: string; type: string }[]>([]);

  const activeScenario = PRESET_SCENARIOS.find(s => s.id === selectedScenarioId) || PRESET_SCENARIOS[0];
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const currentStepIndexRef = useRef<number>(-1);

  useEffect(() => {
    if (initialScenarioId && initialScenarioId !== selectedScenarioId) {
      setSelectedScenarioId(initialScenarioId);
      resetSimulation();
    }
  }, [initialScenarioId]);

  const agentIcons: Record<AgentId, React.ReactNode> = {
    detecteur: <Search className="w-4 h-4 text-[#38A8FF]" />,
    analyste: <Cpu className="w-4 h-4 text-[#38A8FF]" />,
    risque: <Gauge className="w-4 h-4 text-[#38A8FF]" />,
    protection: <Shield className="w-4 h-4 text-[#38A8FF]" />,
    verification: <ShieldCheck className="w-4 h-4 text-[#38A8FF]" />,
    chef: <Crown className="w-4 h-4 text-[#38A8FF]" />
  };

  const scenarioIcons: Record<string, React.ReactNode> = {
    'scenario-macro-excel': <FileCode className="w-5 h-5 text-[#38A8FF]" />,
    'scenario-connexion-bruteforce': <Network className="w-5 h-5 text-[#38A8FF]" />,
    'scenario-email-phishing': <Mail className="w-5 h-5 text-[#38A8FF]" />,
    'scenario-activite-malveillante': <Activity className="w-5 h-5 text-[#38A8FF]" />
  };

  const buildCurrentScenario = (): SimulationScenario => {
    if (!isCustomMode) return activeScenario;

    return {
      id: 'custom-scenario',
      title: customTitle,
      category: customCategory,
      difficulty: 'Standard',
      description: `Scénario de test personnalisé injectant un flux simulé de type ${customCategory} vers ${customTarget}.`,
      targetSystem: customTarget,
      sourceEntity: `Adresse IP source de test : ${customIp}`,
      initialPayload: `INJECTION_TEST_PAYLOAD [Vecteur: ${customCategory}]`,
      expectedRisk: customRisk,
      steps: [
        {
          stepNumber: 1,
          agentId: 'detecteur',
          agentName: 'Agent Détecteur',
          phase: 'Détection d\'anomalie',
          summary: `Repérage d'un flux inhabituel ciblant ${customTarget}`,
          reasoning: `La sonde heuristique a identifié un comportement divergent provenant de ${customIp} dépassant les seuils statistiques standards.`,
          details: [
            `Cible scrutée : ${customTarget}`,
            `Source suspecte : ${customIp}`,
            'Déviation par rapport à la baseline : +320%',
            'Paquet transmis à l\'Agent Analyste'
          ],
          technicalData: { sourceIp: customIp, target: customTarget, confidence: '96%' },
          durationMs: 800
        },
        {
          stepNumber: 2,
          agentId: 'analyste',
          agentName: 'Agent Analyste',
          phase: 'Analyse et extraction IoC',
          summary: 'Extraction des marqueurs techniques et corrélation de la tactique',
          reasoning: `L'inspection des journaux de test confirme la présence de signatures de test correspondant à la catégorie ${customCategory}.`,
          details: [
            `Adresse IP : ${customIp}`,
            `Vecteur : ${customCategory}`,
            'Correspondance MITRE simulée : T1190 (Exploit Public-Facing Application)',
            'Génération de l\'empreinte d\'incident'
          ],
          technicalData: { extractedIoC: customIp, attackType: customCategory },
          durationMs: 1100
        },
        {
          stepNumber: 3,
          agentId: 'risque',
          agentName: 'Agent Risque',
          phase: 'Calcul de criticité et impact',
          summary: `Attribution du niveau de gravité : ${customRisk.toUpperCase()}`,
          reasoning: `L'évaluation d'impact conclut à une sévérité ${customRisk} en raison de la nature critique de la ressource ${customTarget}.`,
          details: [
            `Gravité formelle : ${customRisk}`,
            `Score composite : ${customRisk === 'Critique' ? '92/100' : customRisk === 'Élevé' ? '75/100' : '32/100'}`,
            'Impact potentiel sur le service évalué',
            'Proposition de la directive défensive'
          ],
          technicalData: { riskLevel: customRisk, impactScore: customRisk === 'Critique' ? 9.2 : 7.5 },
          durationMs: 850
        },
        {
          stepNumber: 4,
          agentId: 'protection',
          agentName: 'Agent Protection',
          phase: 'Riposte simulée contrôlée',
          summary: customRisk === 'Faible' ? 'Consignation passive dans le journal d\'audit' : 'Application des contre-mesures de bac à sable autorisées',
          reasoning: customRisk === 'Faible' 
            ? 'Pour un niveau Faible, aucune mesure invasive n\'est requise conformément à la politique.'
            : `Application immédiate du blocage simulé de l'IP ${customIp} et isolement test du service.`,
          details: [
            `[SIMULATION] Règle défensive sandbox injectée pour ${customIp}`,
            '[SIMULATION] Isolation logique de la ressource de test',
            '[SIMULATION] Aucune machine physique hôte n\'est affectée',
            '[SIMULATION] Validation des contraintes de sécurité'
          ],
          technicalData: { mitigation: 'SIMULATION SÉCURISÉE', bannedIp: customIp },
          actionTakenSimulated: customRisk === 'Faible' ? 'Événement consigné dans l\'audit sans interruption de service.' : `Blocage virtuel de l'IP ${customIp} et isolement de la cible test.`,
          durationMs: 1000
        },
        {
          stepNumber: 5,
          agentId: 'verification',
          agentName: 'Agent Vérification',
          phase: 'Audit et contrôle d\'intégrité',
          summary: 'Vérification de l\'étanchéité et audit de l\'absence d\'effets de bord',
          reasoning: 'Le banc d\'essai confirme l\'arrêt complet des requêtes malveillantes sans dégradation des services légitimes.',
          details: [
            'Test de conformité : 100% Validé',
            'Contrôle de persistance résiduelle : 0%',
            'Vérification d\'intégrité sandbox : OK',
            'Rapport d\'intégrité transmis au Chef Agent'
          ],
          technicalData: { residualRisk: '0%', auditStatus: 'CONFORME' },
          verificationCheck: 'Audit terminé : Menace neutralisée en environnement bac à sable avec succès.',
          durationMs: 800
        },
        {
          stepNumber: 6,
          agentId: 'chef',
          agentName: 'Chef Agent',
          phase: 'Arbitrage et synthèse exécutive',
          summary: 'Validation du consensus multi-agents et clôture de l\'incident',
          reasoning: 'L\'ensemble de la chaîne de cyberdéfense a fonctionné en harmonie. Émission des alertes appropriées.',
          details: [
            'Consensus multi-agents : 100%',
            `Notification ${customRisk === 'Critique' ? 'prioritaire émise vers le RSSI' : 'enregistrée dans le SOC'}`,
            'Synthèse d\'incident intégrée au rapport quotidien',
            'Dossier de simulation archivé'
          ],
          technicalData: { consensus: '100%', closed: true },
          durationMs: 900
        }
      ]
    };
  };

  const [showRawJson, setShowRawJson] = useState<boolean>(false);

  // Exécution réelle du pipeline multi-agents sur les données synthétiques
  const realPipelineExecution = useMemo(() => {
    let rawInput: RawSecurityEventInput;
    if (isCustomMode) {
      rawInput = {
        eventId: `CUSTOM-${Date.now().toString().slice(-4)}`,
        timestamp: new Date().toISOString(),
        source: customIp,
        target: customTarget,
        category: customCategory,
        payload: {
          sourceIp: customIp,
          fileName: customCategory === 'Fichier suspect' ? 'payload_test.exe' : undefined,
          failedAttemptsCount: customCategory === 'Tentative de connexion' ? 24 : undefined,
          travelVelocityKmH: customCategory === 'Tentative de connexion' ? 4500 : undefined,
          emailSender: customCategory === 'Email de phishing' ? 'support@portal-test.net' : undefined,
          spfResult: customCategory === 'Email de phishing' ? 'FAIL' : 'PASS',
          dnsQueriesPerMin: customCategory === 'Activité malveillante' ? 120 : undefined,
          shannonEntropy: customCategory === 'Activité malveillante' ? 4.6 : undefined
        }
      };
    } else if (selectedScenarioId === 'scenario-macro-excel') {
      rawInput = {
        eventId: 'PRESET-MACRO',
        timestamp: new Date().toISOString(),
        source: 'Archive ZIP chiffrée [Externe]',
        target: 'Poste de travail [ENV-SANDBOX-PC12]',
        category: 'Fichier suspect',
        payload: {
          fileName: 'Bon_Commande_2026_Urgent.xlsm',
          fileExtension: '.xlsm',
          hasMacros: true,
          parentProcess: 'EXCEL.EXE',
          spawnedProcess: 'powershell.exe',
          commandLineArgs: '-enc aQB3AHIAIAAtAHUAcgBpACAA...',
          sourceIp: '185.220.101.5'
        }
      };
    } else if (selectedScenarioId === 'scenario-connexion-bruteforce') {
      rawInput = {
        eventId: 'PRESET-BRUTE',
        timestamp: new Date().toISOString(),
        source: 'Cluster Proxies [14 IPs]',
        target: 'Passerelle SSO / IAM [AUTH-PORTAL-TEST]',
        category: 'Tentative de connexion',
        payload: {
          sourceIp: '194.26.29.114',
          failedAttemptsCount: 54,
          travelVelocityKmH: 18400
        }
      };
    } else if (selectedScenarioId === 'scenario-email-phishing') {
      rawInput = {
        eventId: 'PRESET-PHISH',
        timestamp: new Date().toISOString(),
        source: 'Serveur SMTP rh-support-portal.net',
        target: 'Serveur de Messagerie [MAIL-EXP-01]',
        category: 'Email de phishing',
        payload: {
          emailSender: 'noreply@rh-support-portal.net',
          emailDomain: 'sso-tele-travail-connexion.xyz',
          spfResult: 'FAIL',
          domainAgeDays: 1.4,
          embeddedUrl: 'https://sso-tele-travail-connexion.xyz/auth'
        }
      };
    } else {
      rawInput = {
        eventId: 'PRESET-DNS',
        timestamp: new Date().toISOString(),
        source: 'Station R&D [STATION-DEV-04]',
        target: 'Serveur de Fichiers & DNS [DC-DNS-01]',
        category: 'Activité malveillante',
        payload: {
          sourceIp: '192.168.10.45',
          dnsQueriesPerMin: 420,
          shannonEntropy: 4.82,
          exfiltrationTargetDomain: 'data-exfil-test.cloud'
        }
      };
    }

    const step1 = DetectorAgent.run(rawInput);
    const step2 = AnalystAgent.run(step1);
    const step3 = RiskAgent.run(step2);
    const step4 = ProtectionAgent.run(step3);
    const step5 = VerificationAgent.run(step4);
    const step6 = ChiefAgent.run(step5);

    return {
      rawInput,
      steps: [step1, step2, step3, step4, step5, step6] as const,
      chiefResult: step6
    };
  }, [selectedScenarioId, isCustomMode, customTitle, customTarget, customCategory, customRisk, customIp]);

  const currentScenario = buildCurrentScenario();
  const currentScenarioRef = useRef(currentScenario);
  currentScenarioRef.current = currentScenario;

  const realPipelineExecutionRef = useRef(realPipelineExecution);
  realPipelineExecutionRef.current = realPipelineExecution;

  const onCriticalAlertTriggeredRef = useRef(onCriticalAlertTriggered);
  onCriticalAlertTriggeredRef.current = onCriticalAlertTriggered;

  const onEventCreatedRef = useRef(onEventCreated);
  onEventCreatedRef.current = onEventCreated;

  const resetSimulation = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    currentStepIndexRef.current = -1;
    setCurrentStepIndex(-1);
    setIsPlaying(false);
    setCompletedSteps([]);
    setIsFinished(false);
    setAgentLogs([]);
  };

  const advanceStep = () => {
    const scenario = currentScenarioRef.current;
    const nextIndex = currentStepIndexRef.current + 1;
    if (nextIndex < scenario.steps.length) {
      currentStepIndexRef.current = nextIndex;
      setCurrentStepIndex(nextIndex);
      
      const step = scenario.steps[nextIndex];
      
      setAgentLogs(l => [
        ...l, 
        {
          id: `log-${Date.now()}-${nextIndex}`,
          time: new Date().toLocaleTimeString('fr-FR', { minute: '2-digit', second: '2-digit' }),
          agent: step.agentName,
          text: step.summary,
          type: step.agentId
        }
      ]);
      
      setCompletedSteps(c => Array.from(new Set([...c, nextIndex])));

      if (nextIndex === 2 && scenario.expectedRisk === 'Critique') {
        const triggerAlert = onCriticalAlertTriggeredRef.current;
        setTimeout(() => {
          triggerAlert(scenario, step);
        }, 0);
      }

      if (nextIndex === scenario.steps.length - 1) {
        setIsFinished(true);
        setIsPlaying(false);
        if (timerRef.current) clearInterval(timerRef.current);
        const eventToCreate = realPipelineExecutionRef.current.chiefResult.generatedSecurityEvent;
        const createEvent = onEventCreatedRef.current;
        setTimeout(() => {
          createEvent(eventToCreate);
        }, 0);
      }
    } else {
      setIsPlaying(false);
      setIsFinished(true);
      if (timerRef.current) clearInterval(timerRef.current);
    }
  };

  useEffect(() => {
    if (isPlaying) {
      if (currentStepIndexRef.current === -1) {
        advanceStep();
      }
      const delay = (1400 / playbackSpeed);
      timerRef.current = setInterval(() => {
        if (currentStepIndexRef.current >= currentScenarioRef.current.steps.length - 1) {
          setIsPlaying(false);
          if (timerRef.current) clearInterval(timerRef.current);
          return;
        }
        advanceStep();
      }, delay);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, playbackSpeed]);

  const currentStep = currentStepIndex >= 0 ? currentScenario.steps[currentStepIndex] : null;

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[#172B4D]">
            Laboratoire de Démonstration
          </h1>
          <p className="text-sm text-[#718096] mt-0.5">
            Testez les scénarios et observez la chaîne décisionnelle des 6 agents en temps réel.
          </p>
        </div>

        {/* Controls: Play, Step, Speed, Reset */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Speed Selector */}
          <div className="flex items-center bg-white border border-[#E6EDF5] rounded-xl p-0.5 text-xs">
            <button
              onClick={() => setPlaybackSpeed(0.5)}
              className={`px-2.5 py-1 rounded-lg transition-colors cursor-pointer ${playbackSpeed === 0.5 ? 'bg-[#E5F3FF] text-[#0284C7] font-bold' : 'text-[#718096]'}`}
            >
              0.5x
            </button>
            <button
              onClick={() => setPlaybackSpeed(1)}
              className={`px-2.5 py-1 rounded-lg transition-colors cursor-pointer ${playbackSpeed === 1 ? 'bg-[#E5F3FF] text-[#0284C7] font-bold' : 'text-[#718096]'}`}
            >
              1x
            </button>
            <button
              onClick={() => setPlaybackSpeed(2)}
              className={`px-2.5 py-1 rounded-lg transition-colors cursor-pointer ${playbackSpeed === 2 ? 'bg-[#E5F3FF] text-[#0284C7] font-bold' : 'text-[#718096]'}`}
            >
              2x
            </button>
          </div>

          {/* Primary Play/Pause Button */}
          <button
            onClick={() => {
              if (isFinished) {
                resetSimulation();
                setTimeout(() => setIsPlaying(true), 80);
              } else {
                setIsPlaying(!isPlaying);
              }
            }}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-[#38A8FF] hover:bg-[#0284C7] rounded-xl transition-all cursor-pointer shadow-2xs"
          >
            {isPlaying ? (
              <>
                <Pause className="w-4 h-4 fill-current" />
                <span>Pause</span>
              </>
            ) : isFinished ? (
              <>
                <RotateCcw className="w-4 h-4" />
                <span>Relancer</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>{currentStepIndex === -1 ? 'Lancer la simulation' : 'Reprendre'}</span>
              </>
            )}
          </button>

          {/* Step-by-step Button */}
          <button
            onClick={advanceStep}
            disabled={isFinished || currentStepIndex >= currentScenario.steps.length - 1}
            className="p-2 bg-white hover:bg-[#F4F9FF] border border-[#E6EDF5] text-[#172B4D] disabled:opacity-40 rounded-xl transition-colors cursor-pointer"
            title="Étape suivante (Pas-à-pas)"
          >
            <SkipForward className="w-4 h-4" />
          </button>

          {/* Reset Button */}
          <button
            onClick={resetSimulation}
            className="p-2 bg-white hover:bg-[#F4F9FF] border border-[#E6EDF5] text-[#718096] hover:text-[#172B4D] rounded-xl transition-colors cursor-pointer"
            title="Réinitialiser"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Scenario Chooser Cards */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-[#172B4D] uppercase tracking-wider">
            Sélectionner un scénario :
          </span>
          <button
            onClick={() => {
              setIsCustomMode(!isCustomMode);
              resetSimulation();
            }}
            className={`text-xs font-semibold px-3 py-1.5 rounded-xl border transition-colors cursor-pointer flex items-center gap-1.5 ${
              isCustomMode 
                ? 'bg-[#E5F3FF] border-[#38A8FF] text-[#0284C7]' 
                : 'bg-white border-[#E6EDF5] text-[#718096] hover:text-[#172B4D]'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Scénario personnalisé</span>
          </button>
        </div>

        {!isCustomMode ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {PRESET_SCENARIOS.map((scenario) => {
              const isSelected = selectedScenarioId === scenario.id;
              const severityPill = {
                'Faible': 'bg-[#E5F3FF] text-[#0284C7]',
                'Élevé': 'bg-[#FFEDD5] text-[#EA580C]',
                'Critique': 'bg-[#FEE2E2] text-[#DC2626]'
              }[scenario.expectedRisk];

              return (
                <div
                  key={scenario.id}
                  onClick={() => {
                    setSelectedScenarioId(scenario.id);
                    resetSimulation();
                  }}
                  className={`bg-white rounded-2xl p-5 border transition-all cursor-pointer flex flex-col justify-between ${
                    isSelected
                      ? 'border-[#38A8FF] ring-2 ring-[#38A8FF]/20 shadow-xs'
                      : 'border-[#E6EDF5] hover:border-[#BEE3F8]'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <div className="w-9 h-9 rounded-xl bg-[#E5F3FF] flex items-center justify-center">
                        {scenarioIcons[scenario.id] || <FileCode className="w-4 h-4 text-[#38A8FF]" />}
                      </div>
                      <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${severityPill}`}>
                        {scenario.expectedRisk}
                      </span>
                    </div>

                    <h3 className="font-bold text-sm text-[#172B4D] mb-1 line-clamp-1">
                      {scenario.title}
                    </h3>
                    <p className="text-xs text-[#718096] line-clamp-2 leading-relaxed mb-4">
                      {scenario.description}
                    </p>
                  </div>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedScenarioId(scenario.id);
                      resetSimulation();
                      setTimeout(() => setIsPlaying(true), 80);
                    }}
                    className={`w-full flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-xl transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-[#38A8FF] hover:bg-[#0284C7] text-white shadow-2xs'
                        : 'bg-white border border-[#BEE3F8] text-[#38A8FF] hover:bg-[#F4F9FF]'
                    }`}
                  >
                    <span>{isSelected && currentStepIndex >= 0 ? 'En cours d\'analyse' : 'Lancer le scénario'}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })}
          </div>
        ) : (
          /* Custom Scenario Builder Card */
          <div className="bg-white border border-[#E6EDF5] rounded-2xl p-5 space-y-4 shadow-2xs">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-[#172B4D] flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[#38A8FF]" />
                <span>Injecteur de Scénario de Test Personnalisé</span>
              </span>
              <span className="text-xs text-[#718096]">
                Environnement bac à sable
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
              <div>
                <label className="text-[#718096] block mb-1 font-medium">Titre du scénario</label>
                <input
                  type="text"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  className="w-full bg-[#F8FAFC] border border-[#E6EDF5] rounded-lg p-2 text-[#172B4D] focus:outline-none focus:border-[#38A8FF]"
                />
              </div>

              <div>
                <label className="text-[#718096] block mb-1 font-medium">Cible simulée</label>
                <input
                  type="text"
                  value={customTarget}
                  onChange={(e) => setCustomTarget(e.target.value)}
                  className="w-full bg-[#F8FAFC] border border-[#E6EDF5] rounded-lg p-2 text-[#172B4D] focus:outline-none focus:border-[#38A8FF]"
                />
              </div>

              <div>
                <label className="text-[#718096] block mb-1 font-medium">Catégorie de menace</label>
                <select
                  value={customCategory}
                  onChange={(e) => setCustomCategory(e.target.value as any)}
                  className="w-full bg-[#F8FAFC] border border-[#E6EDF5] rounded-lg p-2 text-[#172B4D] focus:outline-none focus:border-[#38A8FF]"
                >
                  <option value="Fichier suspect">Fichier suspect</option>
                  <option value="Tentative de connexion">Tentative de connexion</option>
                  <option value="Email de phishing">Email de phishing</option>
                  <option value="Activité malveillante">Activité malveillante</option>
                </select>
              </div>

              <div>
                <label className="text-[#718096] block mb-1 font-medium">Niveau d&apos;alerte</label>
                <select
                  value={customRisk}
                  onChange={(e) => setCustomRisk(e.target.value as RiskLevel)}
                  className="w-full bg-[#F8FAFC] border border-[#E6EDF5] rounded-lg p-2 text-[#172B4D] focus:outline-none focus:border-[#38A8FF] font-semibold"
                >
                  <option value="Faible">Faible (Journalisation simple)</option>
                  <option value="Élevé">Élevé (Protection simulée + SOC)</option>
                  <option value="Critique">Critique (Alerte prioritaire RSSI)</option>
                </select>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 6-Agent Step Pipeline visual bar */}
      <section className="bg-white border border-[#E6EDF5] rounded-2xl p-5 shadow-2xs">
        <div className="flex items-center justify-between mb-4">
          <span className="text-xs font-bold text-[#172B4D] flex items-center gap-2">
            <Cpu className="w-4 h-4 text-[#38A8FF]" />
            <span>Déroulement des 6 Étapes Multi-Agents</span>
          </span>
          <span className="text-xs font-medium text-[#718096]">
            {currentStepIndex >= 0 ? `Étape ${currentStepIndex + 1} sur 6` : 'Prêt pour exécution'}
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-6 gap-2.5">
          {currentScenario.steps.map((step, idx) => {
            const isCurrent = currentStepIndex === idx;
            const isDone = completedSteps.includes(idx) && !isCurrent;

            return (
              <div
                key={step.stepNumber}
                onClick={() => {
                  if (completedSteps.includes(idx)) {
                    currentStepIndexRef.current = idx;
                    setCurrentStepIndex(idx);
                  }
                }}
                className={`p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                  isCurrent
                    ? 'bg-[#E5F3FF] border-[#38A8FF] ring-2 ring-[#38A8FF]/20 shadow-2xs'
                    : isDone
                    ? 'bg-[#F0FDF4] border-[#A7F3D0]'
                    : 'bg-[#F8FAFC] border-[#E6EDF5] opacity-60'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono text-[#718096] font-bold">
                      0{step.stepNumber}
                    </span>
                    <div>
                      {isDone ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
                      ) : isCurrent ? (
                        <span className="w-2 h-2 rounded-full bg-[#38A8FF] animate-pulse block"></span>
                      ) : (
                        <span className="text-[10px] text-slate-400">En attente</span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 mb-1 text-[#172B4D]">
                    {agentIcons[step.agentId]}
                    <span className="text-xs font-bold truncate">
                      {step.agentName.replace('Agent ', '')}
                    </span>
                  </div>

                  <div className="text-[10px] text-[#718096] line-clamp-1">
                    {step.phase}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Main Execution Output: Active Step Analysis + Terminal Log */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left 2 Cols: Step details */}
        <div className="lg:col-span-2 space-y-4">
          {currentStep ? (
            <div className="bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs space-y-4">
              {/* Step Title Header with Data Object Toggle */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 pb-4 border-b border-[#E6EDF5]">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF]">
                    {agentIcons[currentStep.agentId]}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-[#38A8FF]">
                        Étape {currentStep.stepNumber} · {currentStep.phase}
                      </span>
                      <span className="text-[11px] font-medium text-[#718096] bg-[#F1F5F9] px-2 py-0.5 rounded-full">
                        {currentStep.agentName}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-[#172B4D] mt-0.5">
                      {currentStep.summary}
                    </h3>
                  </div>
                </div>

                {/* Toggle Synthèse vs JSON réel échangé */}
                <div className="flex items-center bg-[#F1F5F9] border border-[#E6EDF5] rounded-xl p-0.5 text-xs self-start sm:self-auto">
                  <button
                    onClick={() => setShowRawJson(false)}
                    className={`px-2.5 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                      !showRawJson ? 'bg-white text-[#172B4D] shadow-2xs font-semibold' : 'text-[#718096]'
                    }`}
                  >
                    Vue Analyse
                  </button>
                  <button
                    onClick={() => setShowRawJson(true)}
                    className={`px-2.5 py-1 rounded-lg font-medium transition-colors cursor-pointer flex items-center gap-1 ${
                      showRawJson ? 'bg-[#38A8FF] text-white shadow-2xs font-semibold' : 'text-[#718096]'
                    }`}
                  >
                    <Code2 className="w-3.5 h-3.5" />
                    <span>Objet JSON Transmis</span>
                  </button>
                </div>
              </div>

              {showRawJson ? (
                /* Affichage du contrat réel transmis */
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs text-[#718096]">
                    <span className="font-semibold text-[#172B4D]">
                      Structure de données typée produite par {currentStep.agentName} :
                    </span>
                    <span className="font-mono text-[11px]">
                      Échange d&apos;objet en mémoire
                    </span>
                  </div>
                  <pre className="p-4 bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl text-xs font-mono text-[#172B4D] overflow-x-auto max-h-80 leading-relaxed">
                    {JSON.stringify(realPipelineExecution.steps[currentStepIndex] || currentStep, null, 2)}
                  </pre>
                </div>
              ) : (
                <>
                  {/* Reasoning */}
                  <div>
                    <span className="text-xs font-bold text-[#172B4D] uppercase tracking-wider block mb-1.5">
                      Raisonnement de l&apos;agent
                    </span>
                    <p className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5] text-xs text-[#172B4D] leading-relaxed">
                      {currentStep.reasoning}
                    </p>
                  </div>

              {/* Technical Points */}
              <div>
                <span className="text-xs font-bold text-[#172B4D] uppercase tracking-wider block mb-1.5">
                  Données d&apos;analyse
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {currentStep.details.map((detail, dIdx) => (
                    <div 
                      key={dIdx}
                      className="p-3 bg-[#FFFFFF] border border-[#E6EDF5] rounded-xl text-xs text-[#718096] flex items-start gap-2"
                    >
                      <span className="text-[#38A8FF] font-bold">›</span>
                      <span className="text-[#172B4D]">{detail}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Simulated Protection Action */}
              {currentStep.actionTakenSimulated && (
                <div className="bg-[#E5F3FF]/60 border border-[#BEE3F8] rounded-xl p-4">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-[#0284C7] flex items-center gap-1.5">
                      <Lock className="w-4 h-4 text-[#38A8FF]" />
                      <span>Action de protection simulée</span>
                    </span>
                    <span className="text-[10px] font-bold bg-white text-[#0284C7] border border-[#BEE3F8] px-2 py-0.5 rounded-full">
                      SIMULATION CONTRÔLÉE
                    </span>
                  </div>
                  <p className="text-xs text-[#172B4D] font-mono leading-relaxed">
                    {currentStep.actionTakenSimulated}
                  </p>
                </div>
              )}

              {/* Verification Audit */}
              {currentStep.verificationCheck && (
                <div className="bg-[#ECFDF5] border border-[#A7F3D0] rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
                    <span className="text-xs font-bold text-[#059669]">
                      Contrôle de conformité de l&apos;Agent Vérification
                    </span>
                  </div>
                  <p className="text-xs text-[#065F46] font-mono">
                    {currentStep.verificationCheck}
                  </p>
                </div>
              )}
                </>
              )}
            </div>
          ) : (
            <div className="bg-white border border-[#E6EDF5] rounded-2xl p-10 text-center flex flex-col items-center justify-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF]">
                <Play className="w-5 h-5 ml-0.5" />
              </div>
              <h3 className="font-bold text-[#172B4D] text-sm">
                Simulation prête à démarrer
              </h3>
              <p className="text-xs text-[#718096] max-w-md">
                Cliquez sur &laquo; Lancer la simulation &raquo; pour observer les 6 agents analyser et répondre à la menace.
              </p>
              <button
                onClick={() => setIsPlaying(true)}
                className="mt-2 px-4 py-2 text-xs font-semibold bg-[#38A8FF] hover:bg-[#0284C7] text-white rounded-xl transition-colors cursor-pointer"
              >
                Lancer la simulation
              </button>
            </div>
          )}

          {/* Finished Banner */}
          {isFinished && (
            <div className="bg-white border border-[#A7F3D0] rounded-2xl p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-2xs">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-full bg-[#ECFDF5] flex items-center justify-center text-[#10B981]">
                  <CheckCircle2 className="w-5 h-5" />
                </div>
                <div>
                  <div className="font-bold text-sm text-[#172B4D]">
                    Scénario de test complété avec succès
                  </div>
                  <div className="text-xs text-[#718096]">
                    Consensus atteint à 100%. Événement consigné dans l&apos;audit SOC.
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={onNavigateToChief}
                  className="px-3.5 py-2 text-xs font-semibold bg-white border border-[#E6EDF5] text-[#172B4D] hover:bg-[#F4F9FF] rounded-xl transition-colors cursor-pointer"
                >
                  Voir dans Rapports
                </button>
                <button
                  onClick={resetSimulation}
                  className="px-3.5 py-2 text-xs font-semibold bg-[#38A8FF] text-white hover:bg-[#0284C7] rounded-xl transition-colors cursor-pointer"
                >
                  Nouveau test
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right 1 Col: Terminal Stream */}
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-5 flex flex-col justify-between h-[480px] shadow-2xs">
          <div>
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#E6EDF5]">
              <span className="text-xs font-bold text-[#172B4D] flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-[#38A8FF]" />
                <span>Journal d&apos;Échanges Multi-Agents</span>
              </span>
              <span className="text-[11px] text-[#718096] font-mono">
                {agentLogs.length} messages
              </span>
            </div>

            <div className="space-y-2.5 overflow-y-auto max-h-[380px] pr-1 font-mono text-[11px]">
              {agentLogs.length === 0 ? (
                <div className="text-[#718096] text-center py-16 text-xs font-sans">
                  Les messages échangés entre les agents s&apos;afficheront ici en direct au fil des étapes.
                </div>
              ) : (
                agentLogs.map((log) => (
                  <div 
                    key={log.id}
                    className="p-2.5 bg-[#F8FAFC] rounded-xl border border-[#E6EDF5] space-y-1"
                  >
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="font-bold text-[#38A8FF]">{log.agent}</span>
                      <span className="text-[#94A3B8]">{log.time}</span>
                    </div>
                    <div className="text-[#172B4D] leading-snug">
                      {log.text}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-[#E6EDF5] text-[11px] text-[#718096] flex items-center justify-between">
            <span>Canal sécurisé inter-agents</span>
            <span className="text-[#10B981] font-semibold">● En ligne</span>
          </div>
        </div>
      </div>
    </div>
  );
};
