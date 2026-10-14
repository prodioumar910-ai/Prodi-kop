import React from 'react';
import { SecurityEvent } from '../types/security';
import { X, ShieldAlert, CheckCircle2, Terminal, Lock } from 'lucide-react';

interface EventDetailModalProps {
  event: SecurityEvent | null;
  onClose: () => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({ event, onClose }) => {
  if (!event) return null;

  const severityPill = {
    'Faible': 'bg-[#E5F3FF] text-[#0284C7]',
    'Élevé': 'bg-[#FFEDD5] text-[#EA580C]',
    'Critique': 'bg-[#FEE2E2] text-[#DC2626]'
  }[event.riskLevel];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-fade-in">
      <div 
        className="bg-white border border-[#E6EDF5] rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-xl overflow-hidden"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        {/* Modal Header */}
        <div className="flex items-start justify-between p-6 border-b border-[#E6EDF5] bg-[#F8FAFC]">
          <div className="flex items-start gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-white border border-[#E6EDF5] flex items-center justify-center text-[#38A8FF] shadow-2xs">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-[#718096] font-semibold">{event.id}</span>
                <span className={`text-[11px] font-semibold px-2.5 py-0.5 rounded-full ${severityPill}`}>
                  {event.riskLevel} · Score: {event.riskScore}/100
                </span>
                <span className="text-[11px] font-medium bg-white text-[#718096] px-2 py-0.5 rounded-full border border-[#E6EDF5]">
                  {event.status}
                </span>
              </div>
              <h3 id="modal-title" className="text-base font-bold text-[#172B4D] mt-1">
                {event.title}
              </h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 rounded-lg transition-colors cursor-pointer"
            aria-label="Fermer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-4 text-xs text-[#172B4D]">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 p-3.5 bg-[#F8FAFC] rounded-xl border border-[#E6EDF5]">
            <div>
              <span className="text-[#718096] block text-[11px]">Horodatage</span>
              <span className="font-mono font-medium text-[#172B4D]">{event.timestamp}</span>
            </div>
            <div>
              <span className="text-[#718096] block text-[11px]">Source</span>
              <span className="font-mono font-medium text-[#172B4D] truncate block">{event.source}</span>
            </div>
            <div>
              <span className="text-[#718096] block text-[11px]">Cible</span>
              <span className="font-mono font-medium text-[#172B4D] truncate block">{event.target}</span>
            </div>
            <div>
              <span className="text-[#718096] block text-[11px]">Catégorie</span>
              <span className="font-medium text-[#172B4D]">{event.category}</span>
            </div>
            {event.mitre && (
              <div className="col-span-2">
                <span className="text-[#718096] block text-[11px]">MITRE ATT&CK</span>
                <span className="font-mono text-[#0284C7] font-medium">
                  {event.mitre.id} - {event.mitre.name} ({event.mitre.tactic})
                </span>
              </div>
            )}
          </div>

          {/* Description */}
          <div>
            <h4 className="text-[11px] uppercase tracking-wider text-[#718096] font-bold mb-1">
              Description de l&apos;événement
            </h4>
            <p className="bg-[#F8FAFC] p-3.5 rounded-xl border border-[#E6EDF5] text-[#172B4D] leading-relaxed">
              {event.description}
            </p>
          </div>

          {/* IoC (Indicators of Compromise) */}
          <div>
            <h4 className="text-[11px] uppercase tracking-wider text-[#718096] font-bold mb-1 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-[#38A8FF]" />
              <span>Marqueurs Techniques (IoC)</span>
            </h4>
            <div className="bg-[#F8FAFC] p-3.5 rounded-xl border border-[#E6EDF5] font-mono text-[11px] space-y-1.5">
              {event.ioc.ip && (
                <div className="flex items-center justify-between">
                  <span className="text-[#718096]">Adresse IP suspecte :</span>
                  <span className="text-[#0284C7] font-bold">{event.ioc.ip}</span>
                </div>
              )}
              {event.ioc.domain && (
                <div className="flex items-center justify-between">
                  <span className="text-[#718096]">Domaine analysé :</span>
                  <span className="text-[#EA580C]">{event.ioc.domain}</span>
                </div>
              )}
              {event.ioc.hash && (
                <div className="flex flex-col gap-0.5">
                  <span className="text-[#718096]">Empreinte SHA256 :</span>
                  <span className="text-[#172B4D] break-all text-[10px]">{event.ioc.hash}</span>
                </div>
              )}
              {event.ioc.filePath && (
                <div className="flex flex-col gap-0.5">
                  <span className="text-[#718096]">Fichier cible :</span>
                  <span className="text-[#172B4D] break-all">{event.ioc.filePath}</span>
                </div>
              )}
              {event.ioc.process && (
                <div className="flex flex-col gap-0.5">
                  <span className="text-[#718096]">Processus :</span>
                  <span className="text-[#0284C7] break-all">{event.ioc.process}</span>
                </div>
              )}
            </div>
          </div>

          {/* Simulated Protection Action */}
          <div className="bg-[#E5F3FF]/60 border border-[#BEE3F8] rounded-xl p-3.5">
            <div className="flex items-center gap-2 mb-1">
              <Lock className="w-4 h-4 text-[#38A8FF]" />
              <span className="font-semibold text-[#0284C7] text-xs">
                Mesure de Protection Simulée
              </span>
              <span className="text-[10px] bg-white text-[#0284C7] border border-[#BEE3F8] px-2 py-0.5 rounded-full ml-auto">
                SIMULATION CONTRÔLÉE
              </span>
            </div>
            <p className="text-[#172B4D] text-xs leading-relaxed">
              {event.simulatedAction}
            </p>
          </div>

          {/* Verification Audit */}
          <div className="bg-[#ECFDF5] border border-[#A7F3D0] rounded-xl p-3.5">
            <div className="flex items-center gap-2 mb-1">
              <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
              <span className="font-semibold text-[#059669] text-xs">
                Vérification de Conformité
              </span>
            </div>
            <p className="text-[#065F46] text-xs leading-relaxed">
              {event.verificationResult}
            </p>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-[#E6EDF5] bg-[#F8FAFC] flex items-center justify-between">
          <span className="text-[11px] text-[#718096]">
            Dossier d&apos;exercice FIRE AGENT · Données de test
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-white bg-[#38A8FF] hover:bg-[#0284C7] rounded-xl transition-colors cursor-pointer shadow-2xs"
          >
            Fermer
          </button>
        </div>
      </div>
    </div>
  );
};
