import React, { useState } from 'react';
import { 
  Settings, 
  RotateCcw, 
  Sliders, 
  Bell, 
  ShieldCheck, 
  Info, 
  CheckCircle2,
  Terminal,
  Laptop
} from 'lucide-react';
import { FireAgentTestEngine, TestSuiteSummary } from '../tests/fireAgentSuite';

interface SettingsViewProps {
  onResetData: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onResetData }) => {
  const [resetSuccess, setResetSuccess] = useState(false);
  const [simulatedRssiAlerts, setSimulatedRssiAlerts] = useState(true);
  const [autoAcknowledgeLow, setAutoAcknowledgeLow] = useState(true);
  const [runningTests, setRunningTests] = useState(false);
  const [testSummary, setTestSummary] = useState<TestSuiteSummary | null>(null);

  const handleReset = () => {
    onResetData();
    setResetSuccess(true);
    setTimeout(() => setResetSuccess(false), 3000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[#172B4D]">
            Paramètres du Système
          </h1>
          <p className="text-sm text-[#718096] mt-0.5">
            Configuration du banc d&apos;essai et gestion des préférences de simulation.
          </p>
        </div>
      </div>

      {resetSuccess && (
        <div className="p-4 bg-[#ECFDF5] border border-[#A7F3D0] rounded-2xl text-xs text-[#065F46] flex items-center gap-3">
          <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
          <span>Données du banc d&apos;essai réinitialisées avec succès à l&apos;état initial.</span>
        </div>
      )}

      {/* Settings Sections */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Section 1: Notifications & Alertes */}
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-[#E6EDF5]">
            <Bell className="w-4 h-4 text-[#38A8FF]" />
            <h2 className="text-base font-bold text-[#172B4D]">
              Gestion des Alertes & Escalades
            </h2>
          </div>

          <div className="space-y-4 text-xs">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-semibold text-[#172B4D] block">
                  Simulation d&apos;Astreinte RSSI (Niveau 3)
                </span>
                <span className="text-[#718096] text-[11px]">
                  Déclencher automatiquement un toast de simulation d&apos;appel/SMS pour les incidents critiques.
                </span>
              </div>
              <input
                type="checkbox"
                checked={simulatedRssiAlerts}
                onChange={(e) => setSimulatedRssiAlerts(e.target.checked)}
                className="w-4 h-4 accent-[#38A8FF] rounded cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <span className="font-semibold text-[#172B4D] block">
                  Archivage Automatique des Événements Faibles
                </span>
                <span className="text-[#718096] text-[11px]">
                  Consigner silencieusement les événements mineurs dans l&apos;audit sans pop-up intempestif.
                </span>
              </div>
              <input
                type="checkbox"
                checked={autoAcknowledgeLow}
                onChange={(e) => setAutoAcknowledgeLow(e.target.checked)}
                className="w-4 h-4 accent-[#38A8FF] rounded cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* Section 2: Banc d'essai et Données */}
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-[#E6EDF5]">
            <RotateCcw className="w-4 h-4 text-[#38A8FF]" />
            <h2 className="text-base font-bold text-[#172B4D]">
              Maintenance du Bac à Sable
            </h2>
          </div>

          <div className="space-y-4 text-xs">
            <p className="text-[#718096] leading-relaxed">
              Vous pouvez réinitialiser l&apos;ensemble des événements et rapports simulés pour restaurer les métriques de base de la démonstration.
            </p>

            <button
              onClick={handleReset}
              className="px-4 py-2 text-xs font-semibold bg-[#F4F9FF] border border-[#BEE3F8] hover:bg-[#E5F3FF] text-[#0284C7] rounded-xl transition-colors cursor-pointer"
            >
              Réinitialiser les données de test
            </button>
          </div>
        </div>

        {/* Section 3: Banc de Validation & Tests Automatisés (Objectif 4) */}
        <div className="md:col-span-2 bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#E6EDF5]">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#38A8FF]" />
              <h2 className="text-base font-bold text-[#172B4D]">
                Banc de Validation & Tests Automatisés du Prototype
              </h2>
            </div>
            <button
              onClick={() => {
                setRunningTests(true);
                setTimeout(() => {
                  setTestSummary(FireAgentTestEngine.runAllTests());
                  setRunningTests(false);
                }, 300);
              }}
              disabled={runningTests}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-[#38A8FF] hover:bg-[#0284C7] text-white rounded-xl transition-colors cursor-pointer shadow-2xs disabled:opacity-50"
            >
              <span>{runningTests ? 'Exécution des tests...' : 'Exécuter la suite de tests (10 tests)'}</span>
            </button>
          </div>

          <p className="text-xs text-[#718096] leading-relaxed">
            Exécute une série de vérifications programmatiques sur l&apos;orchestration des 6 agents, la consistance du calcul de risque et la génération des rapports à l&apos;aide de données synthétiques inoffensives.
          </p>

          {testSummary && (
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between p-3.5 bg-[#ECFDF5] border border-[#A7F3D0] rounded-xl text-xs text-[#065F46]">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
                  <span className="font-bold">
                    Résultat Global : {testSummary.passed} / {testSummary.total} tests validés
                  </span>
                </div>
                <span className="font-mono text-[#059669]">
                  Durée : {testSummary.durationMs.toFixed(2)} ms
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                {testSummary.results.map((res, i) => (
                  <div 
                    key={i} 
                    className="p-3 bg-[#F8FAFC] rounded-xl border border-[#E6EDF5] space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-[#172B4D]">
                        {i + 1}. {res.name}
                      </span>
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#ECFDF5] text-[#059669]">
                        {res.passed ? 'VALIDÉ' : 'ÉCHEC'}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#718096]">
                      {res.message}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Section 4: Charte & Déontologie */}
        <div className="md:col-span-2 bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs space-y-3">
          <div className="flex items-center gap-2 pb-3 border-b border-[#E6EDF5]">
            <ShieldCheck className="w-4 h-4 text-[#38A8FF]" />
            <h2 className="text-base font-bold text-[#172B4D]">
              À propos de FIRE AGENT v1.0.0
            </h2>
          </div>

          <div className="text-xs text-[#718096] space-y-2 leading-relaxed">
            <p>
              FIRE AGENT est un système de cybersécurité basé sur la collaboration autonome de 6 agents logiciels spécialisés (Détecteur, Analyste, Risque, Protection, Vérification et Chef Agent).
            </p>
            <p>
              Ce prototype fonctionne dans un environnement de test hermétique : aucune machine réelle n&apos;est scannée, aucun fichier local n&apos;est modifié et aucune capacité offensive n&apos;est intégrée.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
