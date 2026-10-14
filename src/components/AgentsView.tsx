import React, { useState } from 'react';
import { AgentInfo, AgentId } from '../types/security';
import { 
  Search, 
  Cpu, 
  Gauge, 
  Shield, 
  ShieldCheck, 
  Crown, 
  CheckCircle2, 
  Layers, 
  Lock, 
  Zap, 
  ArrowRight
} from 'lucide-react';

interface AgentsViewProps {
  agents: AgentInfo[];
  selectedAgentId: string;
  onSelectAgentId: (id: string) => void;
  onLaunchLabForAgent: (agentId: string) => void;
}

export const AgentsView: React.FC<AgentsViewProps> = ({
  agents,
  selectedAgentId,
  onSelectAgentId,
  onLaunchLabForAgent
}) => {
  const [activeTabId, setActiveTabId] = useState<AgentId>(
    (selectedAgentId as AgentId) || 'detecteur'
  );

  const [diagnosticsRunning, setDiagnosticsRunning] = useState<boolean>(false);
  const [diagnosticResult, setDiagnosticResult] = useState<string | null>(null);

  const currentAgent = agents.find(a => a.id === activeTabId) || agents[0];

  const agentIcons: Record<AgentId, React.ReactNode> = {
    detecteur: <Search className="w-5 h-5 text-[#38A8FF]" />,
    analyste: <Cpu className="w-5 h-5 text-[#38A8FF]" />,
    risque: <Gauge className="w-5 h-5 text-[#38A8FF]" />,
    protection: <Shield className="w-5 h-5 text-[#38A8FF]" />,
    verification: <ShieldCheck className="w-5 h-5 text-[#38A8FF]" />,
    chef: <Crown className="w-5 h-5 text-[#38A8FF]" />
  };

  const runAgentDiagnostic = () => {
    setDiagnosticsRunning(true);
    setDiagnosticResult(null);

    setTimeout(() => {
      setDiagnosticsRunning(false);
      const results: Record<AgentId, string> = {
        detecteur: 'Auto-test Détecteur validé : 1 420 signatures de règles en mémoire, latence de capture 1.2ms, zéro saturation réseau.',
        analyste: 'Auto-test Analyste validé : Moteur de corrélation IoC opérationnel, mappage MITRE ATT&CK synchronisé, parseur d\'obfuscation actif.',
        risque: 'Auto-test Risque validé : Matrice de criticité 3 niveaux calibrée, module d\'explicabilité transparent sans biais.',
        protection: 'Auto-test Protection validé : Garde-fous bac à sable confirmés à 100%, aucune capacité offensive autorisée, liste blanche d\'actions défensives scellée.',
        verification: 'Auto-test Vérification validé : Moteur de non-régression intègre, sondes de test d\'étanchéité opérationnelles.',
        chef: 'Auto-test Chef Agent validé : Protocole de consensus unanime actif, bus d\'alerte SOC prêt, générateur de synthèses opérationnel.'
      };
      setDiagnosticResult(results[activeTabId]);
    }, 700);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[#172B4D]">
            État des 6 Agents Logiciels
          </h1>
          <p className="text-sm text-[#718096] mt-0.5">
            Surveillance et audit unitaire de chaque agent spécialisé de la plateforme.
          </p>
        </div>
      </div>

      {/* Grid of the 6 Agents Cards / Selectors */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {agents.map((agent) => {
          const isSelected = activeTabId === agent.id;
          return (
            <button
              key={agent.id}
              onClick={() => {
                setActiveTabId(agent.id);
                onSelectAgentId(agent.id);
                setDiagnosticResult(null);
              }}
              className={`p-4 rounded-2xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                isSelected
                  ? 'bg-[#E5F3FF] border-[#38A8FF] ring-2 ring-[#38A8FF]/20 shadow-xs'
                  : 'bg-white border-[#E6EDF5] hover:border-[#BEE3F8]'
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="w-8 h-8 rounded-xl bg-white border border-[#E6EDF5] flex items-center justify-center">
                  {agentIcons[agent.id]}
                </div>
                <span className="w-2 h-2 rounded-full bg-[#10B981]"></span>
              </div>
              <div>
                <div className="text-xs font-bold text-[#172B4D] line-clamp-1">
                  {agent.name}
                </div>
                <div className="text-[10px] text-[#718096] line-clamp-1 mt-0.5">
                  {agent.title.split('&')[0]}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {/* Main Agent Details Card */}
      <div className="bg-white border border-[#E6EDF5] rounded-2xl p-6 md:p-8 space-y-6 shadow-2xs">
        {/* Profile Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#E6EDF5]">
          <div className="flex items-start gap-4">
            <div className="w-14 h-14 rounded-2xl bg-[#E5F3FF] border border-[#BEE3F8] flex items-center justify-center text-[#38A8FF]">
              {agentIcons[currentAgent.id]}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-[#38A8FF] uppercase tracking-wider">
                  Rôle Spécialisé · {currentAgent.id.toUpperCase()}
                </span>
                <span className="text-[11px] font-semibold text-[#059669] bg-[#ECFDF5] border border-[#A7F3D0] px-2.5 py-0.5 rounded-full">
                  ● En ligne
                </span>
              </div>
              <h2 className="text-xl font-bold text-[#172B4D] mt-0.5">
                {currentAgent.name}
              </h2>
              <p className="text-xs text-[#718096] mt-1 max-w-2xl leading-relaxed">
                {currentAgent.description}
              </p>
            </div>
          </div>

          {/* Quick diagnostic button */}
          <div className="flex items-center gap-2.5 shrink-0">
            <button
              onClick={runAgentDiagnostic}
              disabled={diagnosticsRunning}
              className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold bg-white border border-[#E6EDF5] hover:bg-[#F4F9FF] text-[#172B4D] rounded-xl transition-colors cursor-pointer"
            >
              <Cpu className="w-4 h-4 text-[#38A8FF]" />
              <span>{diagnosticsRunning ? 'Vérification...' : 'Tester l\'agent'}</span>
            </button>

            <button
              onClick={() => onLaunchLabForAgent(currentAgent.id)}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-[#38A8FF] hover:bg-[#0284C7] text-white rounded-xl transition-colors cursor-pointer shadow-2xs"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>Voir dans le Lab</span>
            </button>
          </div>
        </div>

        {/* Diagnostic Banner if run */}
        {diagnosticResult && (
          <div className="p-4 bg-[#ECFDF5] border border-[#A7F3D0] rounded-xl text-xs text-[#065F46] flex items-start gap-3 font-mono">
            <CheckCircle2 className="w-4 h-4 text-[#10B981] shrink-0 mt-0.5" />
            <span>{diagnosticResult}</span>
          </div>
        )}

        {/* Metrics Strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5]">
            <span className="text-xs text-[#718096] block">Dossiers traités</span>
            <span className="text-xl font-bold text-[#172B4D] mt-1 block tabular-nums">
              {currentAgent.processedCount.toLocaleString()}
            </span>
          </div>
          <div className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5]">
            <span className="text-xs text-[#718096] block">Taux de précision</span>
            <span className="text-xl font-bold text-[#10B981] mt-1 block tabular-nums">
              {currentAgent.accuracyRate}
            </span>
          </div>
          <div className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5]">
            <span className="text-xs text-[#718096] block">Dernière activité</span>
            <span className="text-xs font-medium text-[#172B4D] mt-1 block truncate">
              {currentAgent.lastAction}
            </span>
          </div>
          <div className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5]">
            <span className="text-xs text-[#718096] block">Périmètre d&apos;action</span>
            <span className="text-xs font-semibold text-[#38A8FF] mt-1 block">
              Bac à sable étanche
            </span>
          </div>
        </div>

        {/* 2-Columns: Capabilities & Guardrails */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Capabilities */}
          <div className="bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl p-5 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#172B4D] flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#38A8FF]" />
              <span>Capacités Techniques</span>
            </h3>
            <div className="space-y-2">
              {currentAgent.capabilities.map((cap, i) => (
                <div 
                  key={i}
                  className="p-3 bg-white rounded-lg border border-[#E6EDF5] text-xs text-[#172B4D] flex items-start gap-2"
                >
                  <span className="text-[#38A8FF] font-bold">›</span>
                  <span>{cap}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Operational Boundaries */}
          <div className="bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl p-5 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#172B4D] flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#38A8FF]" />
              <span>Limites & Engagements Déontologiques</span>
            </h3>
            <div className="space-y-2">
              {currentAgent.responsibilities.map((resp, i) => (
                <div 
                  key={i}
                  className="p-3 bg-white rounded-lg border border-[#E6EDF5] text-xs text-[#172B4D] flex items-start gap-2"
                >
                  <span className="text-[#10B981] font-bold">✓</span>
                  <span>{resp}</span>
                </div>
              ))}
              <div className="p-3 bg-[#E5F3FF]/60 rounded-lg border border-[#BEE3F8] text-xs text-[#0284C7] flex items-start gap-2">
                <Lock className="w-4 h-4 text-[#38A8FF] shrink-0 mt-0.5" />
                <span>
                  Garantie FIRE AGENT : Aucune action offensive. Les simulations sont strictement isolées de votre machine.
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
