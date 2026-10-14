export type AgentId = 'detecteur' | 'analyste' | 'risque' | 'protection' | 'verification' | 'chef';

export type RiskLevel = 'Faible' | 'Élevé' | 'Critique';

export type EventStatus = 'Détecté' | 'En analyse' | 'Protégé (Simulé)' | 'Vérifié' | 'Clôturé';

export interface AgentInfo {
  id: AgentId;
  name: string;
  role: string;
  title: string;
  description: string;
  status: 'active' | 'analyzing' | 'idle' | 'standby';
  color: string;
  iconName: string;
  processedCount: number;
  accuracyRate: string;
  lastAction: string;
  capabilities: string[];
  responsibilities: string[];
}

export interface SecurityIoC {
  ip?: string;
  hash?: string;
  domain?: string;
  process?: string;
  filePath?: string;
  userAgent?: string;
}

export interface MitreAttack {
  id: string;
  name: string;
  tactic: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  source: string;
  target: string;
  category: 'Fichier suspect' | 'Tentative de connexion' | 'Email de phishing' | 'Activité malveillante' | 'Autre';
  title: string;
  description: string;
  riskLevel: RiskLevel;
  riskScore: number; // 0-100
  status: EventStatus;
  ioc: SecurityIoC;
  mitre?: MitreAttack;
  simulatedAction: string;
  verificationResult: string;
  chefAgentSummary: string;
  involvedAgents: AgentId[];
}

export interface SimulationStep {
  stepNumber: number;
  agentId: AgentId;
  agentName: string;
  phase: string;
  summary: string;
  reasoning: string;
  details: string[];
  technicalData: Record<string, string | number | boolean>;
  actionTakenSimulated?: string;
  verificationCheck?: string;
  durationMs: number;
}

export interface SimulationScenario {
  id: string;
  title: string;
  category: 'Fichier suspect' | 'Tentative de connexion' | 'Email de phishing' | 'Activité malveillante' | 'Personnalisé';
  difficulty: 'Standard' | 'Avancé' | 'Complexe';
  description: string;
  targetSystem: string;
  sourceEntity: string;
  initialPayload: string;
  expectedRisk: RiskLevel;
  steps: SimulationStep[];
}

export interface ChefDailyReport {
  id: string;
  date: string;
  generatedAt: string;
  totalEvents: number;
  threatsDetected: number;
  criticalThreats: number;
  mitigationsExecuted: number;
  averageResponseTime: string;
  executiveSummary: string;
  keyIncidents: {
    title: string;
    level: RiskLevel;
    resolution: string;
    simulatedProtection: string;
  }[];
  hardeningRecommendations: {
    category: string;
    priority: 'Haute' | 'Moyenne' | 'Critique';
    recommendation: string;
    rationale: string;
  }[];
  agentsPerformance: {
    agentId: AgentId;
    agentName: string;
    efficiency: string;
    status: string;
    auditStatus: string;
  }[];
}
