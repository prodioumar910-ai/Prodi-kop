import React, { useState } from 'react';
import { ChefDailyReport, SecurityEvent } from '../types/security';
import { 
  Crown, 
  FileText, 
  RefreshCw, 
  Copy, 
  Download, 
  Check, 
  ShieldCheck, 
  Sparkles, 
  CheckCircle2, 
  Shield, 
  ArrowRight
} from 'lucide-react';

interface ChefAgentViewProps {
  report: ChefDailyReport;
  events: SecurityEvent[];
  onGenerateFreshReport: () => void;
}

export const ChefAgentView: React.FC<ChefAgentViewProps> = ({
  report,
  events,
  onGenerateFreshReport
}) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [selectedScenarioForBrief, setSelectedScenarioForBrief] = useState<string>(events[0]?.id || '');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);

  const selectedEvent = events.find(e => e.id === selectedScenarioForBrief) || events[0];

  const handleCopyReport = () => {
    const text = `
RAPPORT QUOTIDIEN SOC - FIRE AGENT
Date : ${report.date} (Généré à ${report.generatedAt})
Événements analysés : ${report.totalEvents}
Menaces qualifiées : ${report.threatsDetected}
Menaces critiques : ${report.criticalThreats}
Actions de protection simulées : ${report.mitigationsExecuted}

RÉSUMÉ DE LA JOURNÉE PAR LE CHEF AGENT :
${report.executiveSummary}

RECOMMANDATIONS DE DURCISSEMENT DÉFENSIF :
${report.hardeningRecommendations.map(r => `- [${r.priority}] ${r.category}: ${r.recommendation} (${r.rationale})`).join('\n')}

ENVIRONNEMENT : Exercice didactique en bac à sable hermétique. Données fictives.
    `.trim();

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `fire-agent-rapport-soc-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const triggerRegenerate = () => {
    setIsGenerating(true);
    setTimeout(() => {
      onGenerateFreshReport();
      setIsGenerating(false);
    }, 600);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[#172B4D]">
            Rapports du Chef Agent
          </h1>
          <p className="text-sm text-[#718096] mt-0.5">
            Synthèse opérationnelle quotidienne et audit des actions de protection.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={triggerRegenerate}
            disabled={isGenerating}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-white border border-[#E6EDF5] hover:bg-[#F4F9FF] text-[#172B4D] rounded-xl transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[#38A8FF] ${isGenerating ? 'animate-spin' : ''}`} />
            <span>Actualiser</span>
          </button>

          <button
            onClick={handleCopyReport}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-white border border-[#E6EDF5] hover:bg-[#F4F9FF] text-[#172B4D] rounded-xl transition-colors cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-[#10B981]" /> : <Copy className="w-3.5 h-3.5 text-[#718096]" />}
            <span>{copied ? 'Copié' : 'Copier'}</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-[#38A8FF] hover:bg-[#0284C7] text-white rounded-xl transition-colors cursor-pointer shadow-2xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Exporter JSON</span>
          </button>
        </div>
      </div>

      {/* Scenario Briefing Generator */}
      <section className="bg-white border border-[#E6EDF5] rounded-2xl p-6 space-y-4 shadow-2xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-[#38A8FF]" />
            <h2 className="text-sm font-bold text-[#172B4D]">
              Synthèse d&apos;Incident à la Demande
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-[#718096]">Choisir un événement :</span>
            <select
              value={selectedScenarioForBrief}
              onChange={(e) => setSelectedScenarioForBrief(e.target.value)}
              className="bg-[#F8FAFC] border border-[#E6EDF5] rounded-lg px-3 py-1.5 text-xs text-[#172B4D] focus:outline-none focus:border-[#38A8FF]"
            >
              {events.map(ev => (
                <option key={ev.id} value={ev.id}>
                  {ev.id} - {ev.title} ({ev.riskLevel})
                </option>
              ))}
            </select>
          </div>
        </div>

        {selectedEvent && (
          <div className="bg-[#F4F9FF] border border-[#E6EDF5] rounded-xl p-4 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-[#38A8FF]">
                {selectedEvent.title}
              </span>
              <span className="text-[11px] text-[#718096]">
                Niveau : {selectedEvent.riskLevel}
              </span>
            </div>

            <p className="text-xs text-[#172B4D] leading-relaxed italic bg-white p-3 rounded-lg border border-[#E6EDF5]">
              &laquo; {selectedEvent.chefAgentSummary} &raquo;
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div className="p-2.5 bg-white rounded-lg border border-[#E6EDF5]">
                <span className="text-[#718096] block text-[11px] mb-0.5">Mesure simulée appliquée :</span>
                <span className="text-[#172B4D] font-mono">{selectedEvent.simulatedAction}</span>
              </div>
              <div className="p-2.5 bg-white rounded-lg border border-[#E6EDF5]">
                <span className="text-[#718096] block text-[11px] mb-0.5">Vérification de non-régression :</span>
                <span className="text-[#059669] font-mono">{selectedEvent.verificationResult}</span>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* Main Official SOC Report Document */}
      <article className="bg-white border border-[#E6EDF5] rounded-2xl p-6 md:p-8 space-y-6 shadow-2xs">
        {/* Document Header */}
        <div className="border-b border-[#E6EDF5] pb-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-2xl bg-[#E5F3FF] border border-[#BEE3F8] flex items-center justify-center text-[#38A8FF]">
              <Crown className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-[#38A8FF] uppercase tracking-wider">
                  Rapport Journalier SOC
                </span>
                <span className="text-[11px] font-mono text-[#718096] bg-[#F1F5F9] px-2 py-0.5 rounded-full">
                  {report.id}
                </span>
              </div>
              <h2 className="text-xl font-bold text-[#172B4D] mt-0.5">
                Bilan de Cyberdéfense Multi-Agents
              </h2>
            </div>
          </div>

          <div className="text-left md:text-right text-xs text-[#718096]">
            <div>Date du rapport : <span className="font-semibold text-[#172B4D]">{report.date}</span></div>
            <div>Horodatage : <span>{report.generatedAt}</span></div>
          </div>
        </div>

        {/* 1. Résumé de la journée (Requirement 8) */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#38A8FF]">
            1. Résumé de la journée
          </h3>
          <p className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5] text-xs text-[#172B4D] leading-relaxed">
            {report.executiveSummary}
          </p>
        </div>

        {/* 2. Key Metrics Summary (Requirement 8: Événements, Menaces, Actions, Vérifications) */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#38A8FF]">
            2. Indicateurs Clés de l&apos;Exercice
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5]">
              <span className="text-xs text-[#718096] block">Événements analysés</span>
              <span className="text-xl font-bold text-[#172B4D] mt-1 block tabular-nums">{report.totalEvents}</span>
            </div>
            <div className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5]">
              <span className="text-xs text-[#718096] block">Menaces détectées</span>
              <span className="text-xl font-bold text-[#38A8FF] mt-1 block tabular-nums">{report.threatsDetected}</span>
            </div>
            <div className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5]">
              <span className="text-xs text-[#718096] block">Actions réalisées</span>
              <span className="text-xl font-bold text-[#10B981] mt-1 block tabular-nums">{report.mitigationsExecuted}</span>
            </div>
            <div className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5]">
              <span className="text-xs text-[#718096] block">Résultats vérifiés</span>
              <span className="text-xl font-bold text-[#059669] mt-1 block tabular-nums">100% Conformes</span>
            </div>
          </div>
        </div>

        {/* 3. Principaux scénarios neutralisés */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#38A8FF]">
            3. Principales Menaces Traitées
          </h3>
          <div className="space-y-2.5">
            {report.keyIncidents.map((inc, i) => (
              <div 
                key={i}
                className="p-4 bg-[#F8FAFC] rounded-xl border border-[#E6EDF5] text-xs space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[#172B4D]">{inc.title}</span>
                  <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${
                    inc.level === 'Critique' ? 'bg-[#FEE2E2] text-[#DC2626]' : 'bg-[#FFEDD5] text-[#EA580C]'
                  }`}>
                    {inc.level}
                  </span>
                </div>
                <div className="text-[#718096]">
                  Résolution : {inc.resolution}
                </div>
                <div className="text-[#38A8FF] font-mono text-[11px]">
                  Protection simulée : {inc.simulatedProtection}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 4. Recommandations de durcissement */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#38A8FF]">
            4. Recommandations de Durcissement
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {report.hardeningRecommendations.map((rec, i) => (
              <div 
                key={i}
                className="bg-[#F8FAFC] p-4 rounded-xl border border-[#E6EDF5] flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-bold uppercase text-[#718096]">
                      {rec.category}
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-white border border-[#E6EDF5] text-[#172B4D]">
                      {rec.priority}
                    </span>
                  </div>
                  <h4 className="font-bold text-xs text-[#172B4D] mb-1">
                    {rec.recommendation}
                  </h4>
                  <p className="text-[11px] text-[#718096] leading-relaxed">
                    {rec.rationale}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 5. Performance des Agents */}
        <div className="space-y-2 pt-2 border-t border-[#E6EDF5]">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#38A8FF]">
            5. Audit de Performance des 6 Agents
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#F8FAFC] text-[#718096] border-b border-[#E6EDF5]">
                <tr>
                  <th className="py-2.5 px-3 font-medium">Agent</th>
                  <th className="py-2.5 px-3 font-medium">Statut</th>
                  <th className="py-2.5 px-3 font-medium">Précision</th>
                  <th className="py-2.5 px-3 font-medium">Observation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F1F5F9]">
                {report.agentsPerformance.map((ag) => (
                  <tr key={ag.agentId}>
                    <td className="py-2.5 px-3 font-semibold text-[#172B4D]">{ag.agentName}</td>
                    <td className="py-2.5 px-3 text-[#10B981] font-medium">● {ag.status}</td>
                    <td className="py-2.5 px-3 font-mono text-[#718096]">{ag.efficiency}</td>
                    <td className="py-2.5 px-3 text-[#718096] text-[11px]">{ag.auditStatus}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </article>
    </div>
  );
};
