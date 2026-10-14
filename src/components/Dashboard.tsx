import React, { useMemo } from 'react';
import { SecurityEvent, AgentInfo, ChefDailyReport } from '../types/security';
import { 
  FileText, 
  Shield, 
  AlertTriangle, 
  ShieldCheck, 
  Search, 
  Cpu, 
  Gauge, 
  CheckCircle2, 
  Crown, 
  Mail, 
  FileCode, 
  Network, 
  Activity, 
  ArrowRight,
  TrendingUp,
  FlaskConical,
  ExternalLink,
  Laptop
} from 'lucide-react';

interface DashboardProps {
  events: SecurityEvent[];
  agents: AgentInfo[];
  latestReport: ChefDailyReport;
  onSelectEvent: (event: SecurityEvent) => void;
  onNavigateToTab: (tab: 'dashboard' | 'lab' | 'agents' | 'alerts' | 'chief' | 'settings') => void;
  onSelectAgent: (agentId: string) => void;
  onLaunchScenario: (scenarioId: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  events,
  agents,
  latestReport,
  onSelectEvent,
  onNavigateToTab,
  onSelectAgent,
  onLaunchScenario
}) => {
  // Compute dynamic stats based on events
  const stats = useMemo(() => {
    const totalEvents = 48 + events.length - 5;
    const threats = events.filter(e => e.riskLevel === 'Élevé' || e.riskLevel === 'Critique').length + 4;
    const critical = events.filter(e => e.riskLevel === 'Critique').length + 1;
    const protections = events.filter(e => e.simulatedAction.length > 0).length + 3;

    return { totalEvents, threats, critical, protections };
  }, [events]);

  const agentIcons: Record<string, React.ReactNode> = {
    detecteur: <Search className="w-4 h-4 text-[#38A8FF]" />,
    analyste: <Cpu className="w-4 h-4 text-[#38A8FF]" />,
    risque: <Gauge className="w-4 h-4 text-[#38A8FF]" />,
    protection: <Shield className="w-4 h-4 text-[#38A8FF]" />,
    verification: <CheckCircle2 className="w-4 h-4 text-[#38A8FF]" />,
    chef: <Crown className="w-4 h-4 text-[#38A8FF]" />
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Greeting Header (matching screenshot) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[#172B4D]">
            Bonjour !
          </h1>
          <p className="text-sm text-[#718096] mt-0.5">
            Voici un aperçu de l&apos;activité de FIRE AGENT.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#ECFDF5] border border-[#A7F3D0] text-xs font-semibold text-[#059669]">
            <span className="w-2 h-2 rounded-full bg-[#10B981]"></span>
            <span>Système opérationnel</span>
          </div>
          <span className="text-xs text-[#718096] font-medium hidden md:inline">
            24 sept. 2026 • 10:35
          </span>
        </div>
      </div>

      {/* 4 Statistics KPI Cards (matching screenshot) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Événements analysés */}
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-5 shadow-2xs hover:shadow-xs transition-shadow">
          <div className="w-10 h-10 rounded-xl bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF] mb-3">
            <FileText className="w-5 h-5" />
          </div>
          <div className="text-xs font-semibold text-[#718096]">
            Événements analysés
          </div>
          <div className="text-3xl font-extrabold text-[#172B4D] mt-1 tabular-nums">
            {stats.totalEvents}
          </div>
          <div className="flex items-center gap-1.5 text-xs font-medium text-[#10B981] mt-2">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>+12%</span>
            <span className="text-[#718096] font-normal">(vs hier)</span>
          </div>
        </div>

        {/* Card 2: Menaces détectées */}
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-5 shadow-2xs hover:shadow-xs transition-shadow">
          <div className="w-10 h-10 rounded-xl bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF] mb-3">
            <Shield className="w-5 h-5" />
          </div>
          <div className="text-xs font-semibold text-[#718096]">
            Menaces détectées
          </div>
          <div className="text-3xl font-extrabold text-[#172B4D] mt-1 tabular-nums">
            {stats.threats}
          </div>
          <div className="flex items-center gap-1.5 text-xs font-medium text-[#10B981] mt-2">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>+75%</span>
            <span className="text-[#718096] font-normal">(vs hier)</span>
          </div>
        </div>

        {/* Card 3: Menaces critiques */}
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-5 shadow-2xs hover:shadow-xs transition-shadow">
          <div className="w-10 h-10 rounded-xl bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF] mb-3">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div className="text-xs font-semibold text-[#718096]">
            Menaces critiques
          </div>
          <div className="text-3xl font-extrabold text-[#172B4D] mt-1 tabular-nums">
            {stats.critical}
          </div>
          <div className="flex items-center gap-1.5 text-xs font-medium text-[#10B981] mt-2">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>+100%</span>
            <span className="text-[#718096] font-normal">(vs hier)</span>
          </div>
        </div>

        {/* Card 4: Actions de protection */}
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-5 shadow-2xs hover:shadow-xs transition-shadow">
          <div className="w-10 h-10 rounded-xl bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF] mb-3">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div className="text-xs font-semibold text-[#718096]">
            Actions de protection
          </div>
          <div className="text-3xl font-extrabold text-[#172B4D] mt-1 tabular-nums">
            {stats.protections}
          </div>
          <div className="flex items-center gap-1.5 text-xs font-medium text-[#10B981] mt-2">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>+50%</span>
            <span className="text-[#718096] font-normal">(vs hier)</span>
          </div>
        </div>
      </div>

      {/* Row 2: Chart & État des agents (matching screenshot) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left 2 Cols: Statistiques des menaces (Minimalist Line Chart) */}
        <div className="lg:col-span-2 bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-bold text-[#172B4D] flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#38A8FF]" />
                <span>Statistiques des menaces</span>
              </h2>
              <p className="text-xs text-[#718096] mt-0.5">
                Évolution sur les 7 derniers jours
              </p>
            </div>
          </div>

          {/* SVG Line Graph */}
          <div className="w-full h-56 pt-2">
            <svg viewBox="0 0 500 180" className="w-full h-full overflow-visible">
              {/* Horizontal Grid lines */}
              <line x1="30" y1="20" x2="490" y2="20" stroke="#F1F5F9" strokeWidth="1" />
              <line x1="30" y1="60" x2="490" y2="60" stroke="#F1F5F9" strokeWidth="1" />
              <line x1="30" y1="100" x2="490" y2="100" stroke="#F1F5F9" strokeWidth="1" />
              <line x1="30" y1="140" x2="490" y2="140" stroke="#F1F5F9" strokeWidth="1" />

              {/* Y Axis Labels */}
              <text x="15" y="24" fill="#94A3B8" fontSize="10" fontFamily="sans-serif">20</text>
              <text x="15" y="64" fill="#94A3B8" fontSize="10" fontFamily="sans-serif">15</text>
              <text x="15" y="104" fill="#94A3B8" fontSize="10" fontFamily="sans-serif">10</text>
              <text x="18" y="144" fill="#94A3B8" fontSize="10" fontFamily="sans-serif">5</text>
              <text x="18" y="175" fill="#94A3B8" fontSize="10" fontFamily="sans-serif">0</text>

              {/* Curve 1: Menaces détectées (Sky blue #38A8FF) */}
              <polyline
                fill="none"
                stroke="#38A8FF"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                points="
                  50,140
                  115,100
                  180,125
                  245,95
                  310,95
                  375,45
                  440,75
                "
              />

              {/* Points for Curve 1 */}
              {[
                { x: 50, y: 140 },
                { x: 115, y: 100 },
                { x: 180, y: 125 },
                { x: 245, y: 95 },
                { x: 310, y: 95 },
                { x: 375, y: 45 },
                { x: 440, y: 75 },
              ].map((pt, i) => (
                <circle key={i} cx={pt.x} cy={pt.y} r="3.5" fill="#38A8FF" stroke="#FFFFFF" strokeWidth="1.5" />
              ))}

              {/* Curve 2: Menaces critiques (Light blue #93C5FD) */}
              <polyline
                fill="none"
                stroke="#93C5FD"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                points="
                  50,165
                  115,145
                  180,160
                  245,140
                  310,148
                  375,125
                  440,140
                "
              />

              {/* Points for Curve 2 */}
              {[
                { x: 50, y: 165 },
                { x: 115, y: 145 },
                { x: 180, y: 160 },
                { x: 245, y: 140 },
                { x: 310, y: 148 },
                { x: 375, y: 125 },
                { x: 440, y: 140 },
              ].map((pt, i) => (
                <circle key={i} cx={pt.x} cy={pt.y} r="3" fill="#93C5FD" stroke="#FFFFFF" strokeWidth="1.5" />
              ))}

              {/* X Axis Labels */}
              <text x="40" y="175" fill="#718096" fontSize="10">18/09</text>
              <text x="105" y="175" fill="#718096" fontSize="10">19/09</text>
              <text x="170" y="175" fill="#718096" fontSize="10">20/09</text>
              <text x="235" y="175" fill="#718096" fontSize="10">21/09</text>
              <text x="300" y="175" fill="#718096" fontSize="10">22/09</text>
              <text x="365" y="175" fill="#718096" fontSize="10">23/09</text>
              <text x="430" y="175" fill="#718096" fontSize="10">24/09</text>
            </svg>
          </div>

          {/* Legend */}
          <div className="flex items-center gap-6 mt-4 pt-3 border-t border-[#E6EDF5] text-xs text-[#718096]">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#38A8FF]"></span>
              <span className="font-medium text-[#172B4D]">Menaces détectées</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#93C5FD]"></span>
              <span>Menaces critiques</span>
            </div>
          </div>
        </div>

        {/* Right 1 Col: État des agents (matching screenshot) */}
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-bold text-[#172B4D] flex items-center gap-2">
                <Cpu className="w-4 h-4 text-[#38A8FF]" />
                <span>État des agents</span>
              </h2>
              <button
                onClick={() => onNavigateToTab('agents')}
                className="text-xs font-semibold text-[#38A8FF] hover:text-[#0284C7] flex items-center gap-1 cursor-pointer"
              >
                <span>Voir tous</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* List of 6 agents */}
            <div className="space-y-3.5">
              {agents.map((agent) => (
                <div
                  key={agent.id}
                  onClick={() => {
                    onSelectAgent(agent.id);
                    onNavigateToTab('agents');
                  }}
                  className="flex items-center justify-between p-2 rounded-xl hover:bg-[#F4F9FF] transition-colors cursor-pointer group"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-[#E5F3FF] flex items-center justify-center shrink-0">
                      {agentIcons[agent.id] || <Shield className="w-4 h-4 text-[#38A8FF]" />}
                    </div>
                    <span className="text-xs font-semibold text-[#172B4D] group-hover:text-[#38A8FF] transition-colors">
                      {agent.name}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 text-xs font-medium text-[#10B981]">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]"></span>
                    <span>En ligne</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Row 3: Dernières alertes & Rapport du Chef Agent (matching screenshot) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left 2 Cols: Dernières alertes */}
        <div className="lg:col-span-2 bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-bold text-[#172B4D] flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-[#38A8FF]" />
              <span>Dernières alertes</span>
            </h2>
            <button
              onClick={() => onNavigateToTab('alerts')}
              className="text-xs font-semibold text-[#38A8FF] hover:text-[#0284C7] flex items-center gap-1 cursor-pointer"
            >
              <span>Voir tout</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Clean table matching screenshot */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="text-[#718096] border-b border-[#E6EDF5] pb-2 font-medium">
                  <th className="py-2.5 font-normal">Heure</th>
                  <th className="py-2.5 font-normal">Type</th>
                  <th className="py-2.5 font-normal">Risque</th>
                  <th className="py-2.5 font-normal text-right">Statut</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F1F5F9]">
                <tr className="hover:bg-[#F8FAFC] transition-colors cursor-pointer" onClick={() => onSelectEvent(events[0])}>
                  <td className="py-3 text-[#718096] font-mono">10:24</td>
                  <td className="py-3 font-medium text-[#172B4D] flex items-center gap-2">
                    <Mail className="w-4 h-4 text-[#718096]" />
                    <span>Email de phishing</span>
                  </td>
                  <td className="py-3">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#FEE2E2] text-[#DC2626]">
                      Critique
                    </span>
                  </td>
                  <td className="py-3 text-right">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-[#E5F3FF] text-[#0284C7]">
                      Signalée
                    </span>
                  </td>
                </tr>

                <tr className="hover:bg-[#F8FAFC] transition-colors cursor-pointer" onClick={() => onSelectEvent(events[1] || events[0])}>
                  <td className="py-3 text-[#718096] font-mono">09:47</td>
                  <td className="py-3 font-medium text-[#172B4D] flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-[#718096]" />
                    <span>Fichier suspect</span>
                  </td>
                  <td className="py-3">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#FFEDD5] text-[#EA580C]">
                      Élevé
                    </span>
                  </td>
                  <td className="py-3 text-right">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-[#ECFDF5] text-[#059669]">
                      Bloquée
                    </span>
                  </td>
                </tr>

                <tr className="hover:bg-[#F8FAFC] transition-colors cursor-pointer" onClick={() => onSelectEvent(events[2] || events[0])}>
                  <td className="py-3 text-[#718096] font-mono">08:32</td>
                  <td className="py-3 font-medium text-[#172B4D] flex items-center gap-2">
                    <Network className="w-4 h-4 text-[#718096]" />
                    <span>Connexion inhabituelle</span>
                  </td>
                  <td className="py-3">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#FFEDD5] text-[#EA580C]">
                      Élevé
                    </span>
                  </td>
                  <td className="py-3 text-right">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-[#E5F3FF] text-[#0284C7]">
                      Analysée
                    </span>
                  </td>
                </tr>

                <tr className="hover:bg-[#F8FAFC] transition-colors cursor-pointer" onClick={() => onSelectEvent(events[3] || events[0])}>
                  <td className="py-3 text-[#718096] font-mono">07:15</td>
                  <td className="py-3 font-medium text-[#172B4D] flex items-center gap-2">
                    <Activity className="w-4 h-4 text-[#718096]" />
                    <span>Activité suspecte</span>
                  </td>
                  <td className="py-3">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-[#E5F3FF] text-[#0284C7]">
                      Faible
                    </span>
                  </td>
                  <td className="py-3 text-right">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-[#F1F5F9] text-[#64748B]">
                      Enregistrée
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Right 1 Col: Rapport du Chef Agent */}
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <FileText className="w-4 h-4 text-[#38A8FF]" />
              <h2 className="text-base font-bold text-[#172B4D]">
                Rapport du Chef Agent
              </h2>
            </div>

            <div className="p-4 bg-[#F4F9FF] border border-[#E6EDF5] rounded-xl space-y-3">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-white border border-[#E6EDF5] flex items-center justify-center text-[#38A8FF] shadow-2xs">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-sm font-bold text-[#172B4D]">
                    Rapport du jour
                  </div>
                  <div className="text-xs text-[#718096]">
                    24 septembre 2026
                  </div>
                </div>
              </div>

              <p className="text-xs text-[#718096] leading-relaxed">
                Le système a analysé 48 événements. 7 menaces ont été détectées dont 2 critiques. Toutes les actions de protection se sont déroulées avec succès dans l&apos;environnement de test.
              </p>
            </div>
          </div>

          <button
            onClick={() => onNavigateToTab('chief')}
            className="mt-4 w-full flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-[#38A8FF] bg-white border border-[#38A8FF] hover:bg-[#F4F9FF] rounded-xl transition-colors cursor-pointer"
          >
            <span>Voir le rapport complet</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Row 4: Laboratoire de démonstration (matching screenshot) */}
      <section className="bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-bold text-[#172B4D] flex items-center gap-2">
              <FlaskConical className="w-4 h-4 text-[#38A8FF]" />
              <span>Laboratoire de démonstration</span>
            </h2>
            <p className="text-xs text-[#718096] mt-0.5">
              Testez les scénarios et observez le travail des agents en temps réel.
            </p>
          </div>

          <span className="self-start sm:self-auto inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#E5F3FF] text-[#0284C7] text-xs font-semibold">
            <Laptop className="w-3.5 h-3.5" />
            Environnement de test
          </span>
        </div>

        {/* 4 Cards Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Scenario 1 */}
          <div className="bg-[#FFFFFF] border border-[#E6EDF5] rounded-xl p-4 flex flex-col justify-between hover:border-[#BEE3F8] transition-colors">
            <div>
              <div className="w-9 h-9 rounded-lg bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF] mb-3">
                <FileCode className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-bold text-[#172B4D] mb-1">
                Fichier suspect
              </h3>
              <p className="text-xs text-[#718096] leading-relaxed mb-4">
                Analyse d&apos;un fichier potentiellement malveillant.
              </p>
            </div>

            <button
              onClick={() => onLaunchScenario('scenario-macro-excel')}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold text-white bg-[#38A8FF] hover:bg-[#0284C7] rounded-lg transition-colors cursor-pointer shadow-2xs"
            >
              <span>Lancer le scénario</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Scenario 2 */}
          <div className="bg-[#FFFFFF] border border-[#E6EDF5] rounded-xl p-4 flex flex-col justify-between hover:border-[#BEE3F8] transition-colors">
            <div>
              <div className="w-9 h-9 rounded-lg bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF] mb-3">
                <Network className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-bold text-[#172B4D] mb-1">
                Connexion inhabituelle
              </h3>
              <p className="text-xs text-[#718096] leading-relaxed mb-4">
                Tentative de connexion depuis une localisation suspecte.
              </p>
            </div>

            <button
              onClick={() => onLaunchScenario('scenario-connexion-bruteforce')}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold text-[#38A8FF] bg-white border border-[#BEE3F8] hover:bg-[#F4F9FF] rounded-lg transition-colors cursor-pointer"
            >
              <span>Lancer le scénario</span>
            </button>
          </div>

          {/* Scenario 3 */}
          <div className="bg-[#FFFFFF] border border-[#E6EDF5] rounded-xl p-4 flex flex-col justify-between hover:border-[#BEE3F8] transition-colors">
            <div>
              <div className="w-9 h-9 rounded-lg bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF] mb-3">
                <Mail className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-bold text-[#172B4D] mb-1">
                Email de phishing
              </h3>
              <p className="text-xs text-[#718096] leading-relaxed mb-4">
                Email frauduleux avec lien malveillant.
              </p>
            </div>

            <button
              onClick={() => onLaunchScenario('scenario-email-phishing')}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold text-[#38A8FF] bg-white border border-[#BEE3F8] hover:bg-[#F4F9FF] rounded-lg transition-colors cursor-pointer"
            >
              <span>Lancer le scénario</span>
            </button>
          </div>

          {/* Scenario 4 */}
          <div className="bg-[#FFFFFF] border border-[#E6EDF5] rounded-xl p-4 flex flex-col justify-between hover:border-[#BEE3F8] transition-colors">
            <div>
              <div className="w-9 h-9 rounded-lg bg-[#E5F3FF] flex items-center justify-center text-[#38A8FF] mb-3">
                <Activity className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-bold text-[#172B4D] mb-1">
                Activité malveillante
              </h3>
              <p className="text-xs text-[#718096] leading-relaxed mb-4">
                Comportement anormal sur le système.
              </p>
            </div>

            <button
              onClick={() => onLaunchScenario('scenario-activite-malveillante')}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold text-[#38A8FF] bg-white border border-[#BEE3F8] hover:bg-[#F4F9FF] rounded-lg transition-colors cursor-pointer"
            >
              <span>Lancer le scénario</span>
            </button>
          </div>
        </div>
      </section>
    </div>
  );
};
