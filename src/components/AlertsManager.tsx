import React, { useState } from 'react';
import { SecurityEvent, RiskLevel } from '../types/security';
import { 
  Bell, 
  Search, 
  PhoneCall, 
  Mail, 
  FileCode, 
  Network, 
  Activity, 
  Check, 
  Lock, 
  ShieldAlert, 
  ArrowRight
} from 'lucide-react';

interface AlertsManagerProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
  onAcknowledgeEvent: (eventId: string) => void;
}

export const AlertsManager: React.FC<AlertsManagerProps> = ({
  events,
  onSelectEvent,
  onAcknowledgeEvent
}) => {
  const [activeFilter, setActiveFilter] = useState<'all' | RiskLevel>('all');
  const [search, setSearch] = useState('');
  const [notificationDispatched, setNotificationDispatched] = useState<string | null>(null);

  const criticalEvents = events.filter(e => e.riskLevel === 'Critique');
  const highEvents = events.filter(e => e.riskLevel === 'Élevé');
  const lowEvents = events.filter(e => e.riskLevel === 'Faible');

  const filteredEvents = events.filter(e => {
    const matchesFilter = activeFilter === 'all' || e.riskLevel === activeFilter;
    const matchesSearch = 
      e.title.toLowerCase().includes(search.toLowerCase()) ||
      e.id.toLowerCase().includes(search.toLowerCase()) ||
      e.source.toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const simulateRssiEscalation = (event: SecurityEvent) => {
    setNotificationDispatched(`Notification d'urgence simulée transmise au RSSI pour l'incident [${event.id}] : SMS d'astreinte & alerte prioritaire canal SOC.`);
    setTimeout(() => {
      setNotificationDispatched(null);
    }, 5000);
  };

  const categoryIcons: Record<string, React.ReactNode> = {
    'Email de phishing': <Mail className="w-4 h-4 text-[#718096]" />,
    'Fichier suspect': <FileCode className="w-4 h-4 text-[#718096]" />,
    'Tentative de connexion': <Network className="w-4 h-4 text-[#718096]" />,
    'Activité malveillante': <Activity className="w-4 h-4 text-[#718096]" />
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[#172B4D]">
            Gestionnaire d&apos;Alertes
          </h1>
          <p className="text-sm text-[#718096] mt-0.5">
            Suivi des détections, qualification du risque et suivi des mesures de protection simulées.
          </p>
        </div>
      </div>

      {/* Simulated Notification Toast */}
      {notificationDispatched && (
        <div className="p-4 bg-[#E5F3FF] border border-[#BEE3F8] rounded-2xl text-xs text-[#0284C7] flex items-start gap-3 shadow-sm">
          <PhoneCall className="w-4 h-4 text-[#38A8FF] shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-bold text-[#172B4D] block mb-0.5">
              [Simulation d&apos;escalade RSSI réussie]
            </span>
            <span>{notificationDispatched}</span>
          </div>
        </div>
      )}

      {/* 3 Tiers Cards (Soft colors matching prompt requirements) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Tier 1: Faible (Soft Blue) */}
        <div 
          onClick={() => setActiveFilter('Faible')}
          className={`bg-white p-5 rounded-2xl border transition-all cursor-pointer flex flex-col justify-between ${
            activeFilter === 'Faible' ? 'border-[#38A8FF] ring-2 ring-[#38A8FF]/20' : 'border-[#E6EDF5] hover:border-[#BEE3F8]'
          }`}
        >
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-[#0284C7] uppercase">
                Faible (Information)
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-[#E5F3FF] text-[#0284C7]">
                {lowEvents.length}
              </span>
            </div>
            <h3 className="text-sm font-bold text-[#172B4D] mb-1">
              Enregistrer l&apos;événement
            </h3>
            <p className="text-xs text-[#718096] leading-relaxed">
              Consignation passive dans l&apos;audit sans interruption de service.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-[#E6EDF5] text-[11px] text-[#718096]">
            Action : Télémétrie & archivage
          </div>
        </div>

        {/* Tier 2: Élevé (Soft Orange) */}
        <div 
          onClick={() => setActiveFilter('Élevé')}
          className={`bg-white p-5 rounded-2xl border transition-all cursor-pointer flex flex-col justify-between ${
            activeFilter === 'Élevé' ? 'border-[#38A8FF] ring-2 ring-[#38A8FF]/20' : 'border-[#E6EDF5] hover:border-[#BEE3F8]'
          }`}
        >
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-[#EA580C] uppercase">
                Élevé (Protection)
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-[#FFEDD5] text-[#EA580C]">
                {highEvents.length}
              </span>
            </div>
            <h3 className="text-sm font-bold text-[#172B4D] mb-1">
              Mesure simulée & Signalement
            </h3>
            <p className="text-xs text-[#718096] leading-relaxed">
              Blocage automatique au banc d&apos;essai et notification à l&apos;équipe SOC.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-[#E6EDF5] text-[11px] text-[#718096]">
            Action : Protection simulée + SOC
          </div>
        </div>

        {/* Tier 3: Critique (Soft Red) */}
        <div 
          onClick={() => setActiveFilter('Critique')}
          className={`bg-white p-5 rounded-2xl border transition-all cursor-pointer flex flex-col justify-between ${
            activeFilter === 'Critique' ? 'border-[#38A8FF] ring-2 ring-[#38A8FF]/20' : 'border-[#E6EDF5] hover:border-[#BEE3F8]'
          }`}
        >
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-[#DC2626] uppercase">
                Critique (Prioritaire)
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-[#FEE2E2] text-[#DC2626]">
                {criticalEvents.length}
              </span>
            </div>
            <h3 className="text-sm font-bold text-[#172B4D] mb-1">
              Alerte d&apos;urgence & RSSI
            </h3>
            <p className="text-xs text-[#718096] leading-relaxed">
              Alerte prioritaire, isolement logique hôte virtuel et simulation d&apos;astreinte RSSI.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-[#E6EDF5] text-[11px] text-[#DC2626] font-semibold">
            Action : Escalade prioritaire d&apos;astreinte
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white p-3.5 rounded-2xl border border-[#E6EDF5] flex flex-col sm:flex-row items-center justify-between gap-3 shadow-2xs">
        <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto">
          <button
            onClick={() => setActiveFilter('all')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-xl transition-colors cursor-pointer ${
              activeFilter === 'all' ? 'bg-[#38A8FF] text-white shadow-2xs' : 'text-[#718096] hover:bg-[#F4F9FF]'
            }`}
          >
            Toutes ({events.length})
          </button>
          <button
            onClick={() => setActiveFilter('Critique')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-xl transition-colors cursor-pointer ${
              activeFilter === 'Critique' ? 'bg-[#FEE2E2] text-[#DC2626]' : 'text-[#718096] hover:bg-[#F4F9FF]'
            }`}
          >
            Critiques ({criticalEvents.length})
          </button>
          <button
            onClick={() => setActiveFilter('Élevé')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-xl transition-colors cursor-pointer ${
              activeFilter === 'Élevé' ? 'bg-[#FFEDD5] text-[#EA580C]' : 'text-[#718096] hover:bg-[#F4F9FF]'
            }`}
          >
            Élevées ({highEvents.length})
          </button>
          <button
            onClick={() => setActiveFilter('Faible')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-xl transition-colors cursor-pointer ${
              activeFilter === 'Faible' ? 'bg-[#E5F3FF] text-[#0284C7]' : 'text-[#718096] hover:bg-[#F4F9FF]'
            }`}
          >
            Faibles ({lowEvents.length})
          </button>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Rechercher une alerte..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl text-[#172B4D] placeholder-slate-400 focus:outline-none focus:border-[#38A8FF]"
          />
        </div>
      </div>

      {/* Table on desktop, Cards on mobile (Requirement 10: perfect mobile experience) */}
      <div className="bg-white border border-[#E6EDF5] rounded-2xl shadow-2xs overflow-hidden">
        {/* Desktop Table View */}
        <div className="hidden md:block overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="text-[#718096] border-b border-[#E6EDF5] bg-[#F8FAFC]">
                <th className="py-3 px-5 font-medium">Heure</th>
                <th className="py-3 px-5 font-medium">Type d&apos;événement</th>
                <th className="py-3 px-5 font-medium">Niveau de risque</th>
                <th className="py-3 px-5 font-medium">État de traitement</th>
                <th className="py-3 px-5 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F1F5F9]">
              {filteredEvents.map((evt) => {
                const riskPill = {
                  'Faible': 'bg-[#E5F3FF] text-[#0284C7]',
                  'Élevé': 'bg-[#FFEDD5] text-[#EA580C]',
                  'Critique': 'bg-[#FEE2E2] text-[#DC2626]'
                }[evt.riskLevel];

                const statusPill = {
                  'Clôturé': 'bg-[#ECFDF5] text-[#059669]',
                  'Protégé (Simulé)': 'bg-[#ECFDF5] text-[#059669]',
                  'En analyse': 'bg-[#E5F3FF] text-[#0284C7]',
                  'Détecté': 'bg-[#F1F5F9] text-[#64748B]',
                  'Vérifié': 'bg-[#ECFDF5] text-[#059669]'
                }[evt.status] || 'bg-[#F1F5F9] text-[#64748B]';

                return (
                  <tr 
                    key={evt.id} 
                    className="hover:bg-[#F8FAFC] transition-colors cursor-pointer"
                    onClick={() => onSelectEvent(evt)}
                  >
                    <td className="py-3.5 px-5 text-[#718096] font-mono whitespace-nowrap">
                      {evt.timestamp}
                    </td>
                    <td className="py-3.5 px-5">
                      <div className="font-semibold text-[#172B4D] flex items-center gap-2">
                        {categoryIcons[evt.category] || <Activity className="w-4 h-4 text-[#718096]" />}
                        <span>{evt.title}</span>
                      </div>
                      <div className="text-[11px] text-[#718096] mt-0.5">
                        {evt.source} → {evt.target}
                      </div>
                    </td>
                    <td className="py-3.5 px-5">
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${riskPill}`}>
                        {evt.riskLevel}
                      </span>
                    </td>
                    <td className="py-3.5 px-5">
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-medium ${statusPill}`}>
                        {evt.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-5 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                        {evt.riskLevel === 'Critique' && (
                          <button
                            onClick={() => simulateRssiEscalation(evt)}
                            className="px-2.5 py-1 text-[11px] font-semibold bg-[#FEE2E2] hover:bg-red-200 text-[#DC2626] rounded-lg transition-colors cursor-pointer"
                          >
                            Alerter RSSI
                          </button>
                        )}
                        <button
                          onClick={() => onSelectEvent(evt)}
                          className="px-2.5 py-1 text-[11px] font-medium text-[#38A8FF] hover:bg-[#E5F3FF] rounded-lg transition-colors cursor-pointer"
                        >
                          Détails
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Mobile Cards View (no cut text, responsive touch-friendly cards) */}
        <div className="md:hidden divide-y divide-[#F1F5F9]">
          {filteredEvents.map((evt) => {
            const riskPill = {
              'Faible': 'bg-[#E5F3FF] text-[#0284C7]',
              'Élevé': 'bg-[#FFEDD5] text-[#EA580C]',
              'Critique': 'bg-[#FEE2E2] text-[#DC2626]'
            }[evt.riskLevel];

            return (
              <div 
                key={evt.id}
                onClick={() => onSelectEvent(evt)}
                className="p-4 space-y-2 hover:bg-[#F8FAFC] transition-colors cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs text-[#718096] font-mono">{evt.timestamp}</span>
                  <span className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${riskPill}`}>
                    {evt.riskLevel}
                  </span>
                </div>

                <div className="font-semibold text-sm text-[#172B4D]">
                  {evt.title}
                </div>

                <div className="text-xs text-[#718096]">
                  {evt.source}
                </div>

                <div className="pt-2 flex items-center justify-between border-t border-[#F1F5F9]">
                  <span className="text-xs font-medium text-[#10B981]">
                    ● {evt.status}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectEvent(evt);
                    }}
                    className="text-xs font-semibold text-[#38A8FF]"
                  >
                    Examiner →
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
