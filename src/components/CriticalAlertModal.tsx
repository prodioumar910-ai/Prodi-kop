import React from 'react';
import { SimulationScenario, SimulationStep } from '../types/security';
import { AlertTriangle, PhoneCall, Check, X } from 'lucide-react';

interface CriticalAlertModalProps {
  scenario: SimulationScenario | null;
  step: SimulationStep | null;
  onClose: () => void;
  onAcknowledge: () => void;
}

export const CriticalAlertModal: React.FC<CriticalAlertModalProps> = ({
  scenario,
  step,
  onClose,
  onAcknowledge
}) => {
  if (!scenario || !step) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-fade-in">
      <div 
        className="bg-white border border-[#E6EDF5] rounded-2xl max-w-lg w-full p-6 shadow-xl space-y-5"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="alert-dialog-title"
      >
        {/* Banner with soft red icon */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-2xl bg-[#FEE2E2] flex items-center justify-center text-[#DC2626]">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[#DC2626] bg-[#FEE2E2] px-2.5 py-0.5 rounded-full">
                Alerte Prioritaire SOC · Critique
              </span>
              <h2 id="alert-dialog-title" className="text-base font-bold text-[#172B4D] mt-1">
                Menace Critique Détectée
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1.5 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Incident Summary */}
        <div className="bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl p-4 space-y-2 text-xs">
          <div className="flex items-center justify-between text-[#718096] text-[11px]">
            <span>Cible : <span className="text-[#172B4D] font-bold">{scenario.targetSystem}</span></span>
            <span className="text-[#DC2626] font-bold">Score 94 / 100</span>
          </div>

          <h3 className="text-sm font-bold text-[#172B4D]">
            {scenario.title}
          </h3>

          <p className="text-[#718096] leading-relaxed">
            {step.reasoning}
          </p>
        </div>

        {/* Simulated RSSI Notification Dispatch */}
        <div className="bg-[#E5F3FF]/70 border border-[#BEE3F8] rounded-xl p-3.5 flex items-start gap-3 text-xs text-[#0284C7]">
          <PhoneCall className="w-4 h-4 text-[#38A8FF] shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <span className="font-bold text-[#172B4D] block">
              [Simulation d&apos;astreinte active]
            </span>
            <p className="text-[#718096] text-[11px]">
              Notification prioritaire transmise au Responsable de Sécurité (RSSI). Isolement logique de test enclenché.
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-end gap-2.5 pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold bg-white border border-[#E6EDF5] hover:bg-[#F4F9FF] text-[#172B4D] rounded-xl transition-colors cursor-pointer"
          >
            Fermer
          </button>
          <button
            onClick={() => {
              onAcknowledge();
              onClose();
            }}
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-[#38A8FF] hover:bg-[#0284C7] text-white rounded-xl shadow-2xs transition-all cursor-pointer"
          >
            <Check className="w-4 h-4" />
            <span>Accuser réception & Poursuivre</span>
          </button>
        </div>
      </div>
    </div>
  );
};
