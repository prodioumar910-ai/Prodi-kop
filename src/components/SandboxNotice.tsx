import React, { useState } from 'react';
import { ShieldCheck, Info, ChevronDown, ChevronUp } from 'lucide-react';

export const SandboxNotice: React.FC = () => {
  const [expanded, setExpanded] = useState(false);

  return (
    <aside 
      aria-label="Avertissement environnement de démonstration"
      className="bg-[#F0F7FF] border-b border-[#E6EDF5] text-xs text-[#718096] px-4 md:px-8 py-2"
    >
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 font-semibold text-[#38A8FF] text-[11px] bg-white border border-[#BEE3F8] px-2 py-0.5 rounded-full shadow-2xs">
            <ShieldCheck className="w-3.5 h-3.5 text-[#38A8FF] shrink-0" />
            Environnement de Simulation Sécurisé
          </span>
          <span className="text-[#172B4D] font-medium hidden sm:inline">
            Prototype didactique · Données et actions de protection strictement simulées en bac à sable.
          </span>
        </div>

        <button
          onClick={() => setExpanded(!expanded)}
          className="inline-flex items-center gap-1 text-[#38A8FF] hover:text-[#0284C7] transition-colors cursor-pointer text-[11px] self-start sm:self-auto font-medium"
        >
          <Info className="w-3.5 h-3.5" />
          <span>Charte de Transparence & Sécurité</span>
          {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </button>
      </div>

      {expanded && (
        <div className="max-w-7xl mx-auto mt-2.5 pt-2.5 border-t border-[#E6EDF5] grid grid-cols-1 md:grid-cols-3 gap-3 text-[#718096] text-[11px]">
          <div className="bg-white p-3 rounded-xl border border-[#E6EDF5] shadow-2xs">
            <div className="font-semibold text-[#172B4D] mb-1">Protection Intègre des Systèmes</div>
            <p>
              Aucun fichier de votre machine n&apos;est lu ni modifié. Les flux d&apos;attaque et contre-mesures proviennent exclusivement d&apos;un banc d&apos;essai virtuel.
            </p>
          </div>
          <div className="bg-white p-3 rounded-xl border border-[#E6EDF5] shadow-2xs">
            <div className="font-semibold text-[#172B4D] mb-1">Actions Défensives Contrôlées</div>
            <p>
              Les blocages d&apos;IP et isolements réseau sont simulés à titre de démonstration sans capacité offensive.
            </p>
          </div>
          <div className="bg-white p-3 rounded-xl border border-[#E6EDF5] shadow-2xs">
            <div className="font-semibold text-[#172B4D] mb-1">Architecture SaaS Extensible</div>
            <p>
              Orchestration modulaire prête pour une connexion ultérieure aux API d&apos;EDR ou SIEM via un backend sécurisé.
            </p>
          </div>
        </div>
      )}
    </aside>
  );
};
