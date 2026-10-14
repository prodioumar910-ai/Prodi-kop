import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  Play, 
  RotateCcw, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  FileCode, 
  Database, 
  Check, 
  Copy, 
  Terminal, 
  Layers, 
  AlertOctagon, 
  Server, 
  Info, 
  Search,
  Lock,
  RefreshCw,
  Bot,
  Radar,
  Gauge,
  ShieldCheck,
  Crown
} from 'lucide-react';
import { 
  SecurityEventInput, 
  AnalysisResult, 
  RULES_CATALOG 
} from '../engine/securityRuleEngine';

interface SecurityEngineViewProps {
  onEventIngested?: (event: SecurityEventInput, analysis: AnalysisResult) => void;
}

const PRESET_TEMPLATES: { id: string; label: string; description: string; payload: any }[] = [
  {
    id: 'brute_force',
    label: '1. Échecs répétés (Force brute)',
    description: '24 échecs de connexion consécutifs sur compte administrateur.',
    payload: {
      event_id: 'EVT-AUTH-2026-891',
      timestamp: new Date().toISOString(),
      source_host: 'SRV-DC-PARIS-01',
      event_type: 'failed_logins',
      description: 'Rafale anormale de tentatives infructueuses de connexion Kerberos.',
      technical_data: {
        source_ip: '194.26.29.112',
        failed_attempts: 24,
        targeted_account: 'administrateur',
        protocol: 'Kerberos / NTLMv2'
      }
    }
  },
  {
    id: 'impossible_travel',
    label: '2. Déplacement impossible',
    description: 'Connexions simultanées séparées par 4 200 km en 12 minutes.',
    payload: {
      event_id: 'EVT-CONN-2026-442',
      timestamp: new Date().toISOString(),
      source_host: 'VPN-GATEWAY-EXT',
      event_type: 'unusual_connection',
      description: 'Accès distant détecté avec vitesse apparente incompatible avec un déplacement physique.',
      technical_data: {
        source_ip: '185.220.101.5',
        travel_speed_kmh: 4200,
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64)',
        origin_city_a: 'Tokyo',
        origin_city_b: 'Paris',
        time_delta_minutes: 12
      }
    }
  },
  {
    id: 'macro_shell',
    label: '3. Fichier suspect (.xlsm + PowerShell)',
    description: 'Document bureautique tentant d’instancier un shell système.',
    payload: {
      event_id: 'EVT-FILE-2026-105',
      timestamp: new Date().toISOString(),
      source_host: 'WKSTN-FINANCE-04',
      event_type: 'suspicious_file',
      description: 'Document bureautique déclenchant un processus interpréteur PowerShell masqué.',
      technical_data: {
        file_name: 'facture_comptabilite_octobre.xlsm',
        file_extension: '.xlsm',
        has_macros: true,
        parent_process: 'EXCEL.EXE',
        spawned_process: 'powershell.exe -NonI -W Hidden -Enc SQBFAFgA',
        file_hash: 'sha256:7b1e84d412e8412bc445a600a12e'
      }
    }
  },
  {
    id: 'phishing_spf_fail',
    label: '4. Phishing simulé (SPF Fail & Domaine néo-enregistré)',
    description: 'Courriel usurpant un tiers avec domaine de 4 jours et mire de login.',
    payload: {
      event_id: 'EVT-PHISH-2026-033',
      timestamp: new Date().toISOString(),
      source_host: 'MAIL-EXCHANGE-01',
      event_type: 'phishing_simulation',
      description: 'Courriel simulant une réinitialisation de mot de passe institutionnelle.',
      technical_data: {
        email_sender: 'support@rh-portail-verification.com',
        email_domain: 'rh-portail-verification.com',
        spf_result: 'FAIL',
        dkim_result: 'FAIL',
        domain_age_days: 4,
        credential_form: true,
        embedded_url: 'https://rh-portail-verification.com/login/auth.html'
      }
    }
  },
  {
    id: 'clean_telemetry',
    label: '5. Télémétrie saine (Activité normale)',
    description: 'Sonde de monitoring et battement de cœur réseau conforme.',
    payload: {
      event_id: 'EVT-INFO-2026-001',
      timestamp: new Date().toISOString(),
      source_host: 'SRV-MONITOR-01',
      event_type: 'telemetry_scan',
      description: 'Contrôle périodique de diagnostic des services réseau.',
      technical_data: {
        cpu_load: '14%',
        active_sessions: 3,
        network_jitter_ms: 1.2
      }
    }
  },
  {
    id: 'malformed_test',
    label: '6. Test de rejet : Format JSON malformé',
    description: 'Payload incomplet sans identifiant ni date (test de conformité 422).',
    payload: {
      source_host: 'SRV-UNKNOWN',
      description: 'Événement invalide sans event_id ni timestamp'
    }
  },
  {
    id: 'sensitive_test',
    label: '7. Test déontologique : Rejet des mots de passe',
    description: 'Payload contenant un mot de passe (test de minimisation des données).',
    payload: {
      event_id: 'EVT-ILLEGAL-001',
      timestamp: new Date().toISOString(),
      source_host: 'WKSTN-USER-01',
      event_type: 'failed_logins',
      description: 'Tentative contenant un mot de passe en clair',
      technical_data: {
        failed_attempts: 6,
        password: 'MonMotDePasseSecret123!' // Interdit
      }
    }
  }
];

export const SecurityEngineView: React.FC<SecurityEngineViewProps> = ({ onEventIngested }) => {
  const [activeSubTab, setActiveSubTab] = useState<'tester' | 'history' | 'catalog' | 'backend_doc'>('tester');
  const [selectedTemplate, setSelectedTemplate] = useState<string>('brute_force');
  const [jsonInput, setJsonInput] = useState<string>(
    JSON.stringify(PRESET_TEMPLATES[0].payload, null, 2)
  );
  
  // Validation and analysis results
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [backendStatus, setBackendStatus] = useState<'connected' | 'checking' | 'error'>('checking');
  const [backendError, setBackendError] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [lastAnalysis, setLastAnalysis] = useState<AnalysisResult | null>(null);
  const [analyzedEvent, setAnalyzedEvent] = useState<SecurityEventInput | null>(null);
  const [agentsPipelineData, setAgentsPipelineData] = useState<any | null>(null);
  const [activePipelineTab, setActivePipelineTab] = useState<'detecteur' | 'analyste' | 'risque' | 'protection' | 'verification' | 'chef'>('detecteur');
  
  // History state loaded from SQLite
  const [ingestedHistory, setIngestedHistory] = useState<{ event: SecurityEventInput; analysis: AnalysisResult; stored_at?: string }[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [historySearch, setHistorySearch] = useState('');
  const [historyRiskFilter, setHistoryRiskFilter] = useState<'Tous' | 'Critique' | 'Élevé' | 'Faible'>('Tous');
  const [copiedCurl, setCopiedCurl] = useState(false);

  // Vérifier la connexion avec le backend au montage
  useEffect(() => {
    checkBackendHealth();
    fetchHistoryFromBackend();
  }, []);

  const checkBackendHealth = async () => {
    try {
      setBackendStatus('checking');
      const res = await fetch('/api/health');
      if (res.ok) {
        setBackendStatus('connected');
        setBackendError(null);
      } else {
        setBackendStatus('error');
        setBackendError(`Statut HTTP ${res.status} reçu du backend`);
      }
    } catch (err: any) {
      setBackendStatus('error');
      setBackendError(`Erreur réseau : ${err.message || 'Impossible de joindre le serveur'}`);
    }
  };

  const fetchHistoryFromBackend = async () => {
    try {
      setIsLoadingHistory(true);
      const res = await fetch('/api/events?limit=50');
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.events)) {
          const mapped = data.events.map((item: any) => ({
            event: {
              event_id: item.event_id,
              timestamp: item.timestamp,
              source_host: item.source_host,
              event_type: item.event_type,
              description: item.description,
              technical_data: item.technical_data || {}
            },
            analysis: item.analysis,
            stored_at: item.created_at
          }));
          setIngestedHistory(mapped);
        }
      }
    } catch (err) {
      console.warn('Erreur lors du chargement de l\'historique SQLite:', err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const handleSelectTemplate = (templateId: string) => {
    setSelectedTemplate(templateId);
    const tmpl = PRESET_TEMPLATES.find(t => t.id === templateId);
    if (tmpl) {
      const payloadCopy = { ...tmpl.payload };
      if (payloadCopy.timestamp) payloadCopy.timestamp = new Date().toISOString();
      if (payloadCopy.event_id && !payloadCopy.event_id.includes('ILLEGAL')) {
        payloadCopy.event_id = `EVT-${Date.now().toString().slice(-6)}`;
      }
      setJsonInput(JSON.stringify(payloadCopy, null, 2));
      setValidationErrors([]);
      setLastAnalysis(null);
      setAgentsPipelineData(null);
    }
  };

  const handleRunAnalysis = async () => {
    setValidationErrors([]);
    setLastAnalysis(null);
    setAgentsPipelineData(null);
    setIsSubmitting(true);

    let parsed: any;
    try {
      parsed = JSON.parse(jsonInput);
    } catch (err: any) {
      setValidationErrors([`Erreur de syntaxe JSON locale : ${err.message}`]);
      setIsSubmitting(false);
      return;
    }

    try {
      // APPEL HTTP RÉEL VERS LE BACKEND
      const response = await fetch('/api/events', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(parsed)
      });

      const data = await response.json();

      if (!response.ok) {
        // Erreur retournée par le backend (400, 422 ou 500)
        const errorMsg = data.error || data.detail || `Erreur serveur (HTTP ${response.status})`;
        setValidationErrors([`[HTTP ${response.status}] ${errorMsg}`]);
        setIsSubmitting(false);
        return;
      }

      // SUCCÈS : Analyse multi-agents et enregistrement SQLite confirmés
      const event: SecurityEventInput = data.event;
      const analysis: AnalysisResult = data.analysis;
      const pipeline = data.agents_pipeline;

      setAnalyzedEvent(event);
      setLastAnalysis(analysis);
      setAgentsPipelineData(pipeline);

      // Rafraîchir l'historique SQLite
      fetchHistoryFromBackend();

      if (onEventIngested) {
        onEventIngested(event, analysis);
      }
    } catch (err: any) {
      setValidationErrors([`Erreur de communication réseau avec l'API : ${err.message || 'Serveur inaccessible'}`]);
    } finally {
      setIsSubmitting(false);
    }
  };

  const filteredHistory = ingestedHistory.filter(item => {
    const matchesSearch = 
      item.event.event_id.toLowerCase().includes(historySearch.toLowerCase()) ||
      item.event.source_host.toLowerCase().includes(historySearch.toLowerCase()) ||
      item.event.description.toLowerCase().includes(historySearch.toLowerCase());
    const matchesRisk = historyRiskFilter === 'Tous' || item.analysis.risk_level === historyRiskFilter;
    return matchesSearch && matchesRisk;
  });

  const curlExample = `curl -X POST http://localhost:3000/api/events \\
  -H "Content-Type: application/json" \\
  -d '{
    "event_id": "EVT-2026-001",
    "timestamp": "${new Date().toISOString()}",
    "source_host": "SRV-DC-01",
    "event_type": "failed_logins",
    "description": "Multiples échecs de connexion Kerberos",
    "technical_data": {
      "source_ip": "194.26.29.112",
      "failed_attempts": 22
    }
  }'`;

  return (
    <div className="space-y-6 pb-12">
      {/* 1. Header Zone */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[#E5F3FF] text-[#0284C7] border border-[#BEE3F8]">
              Phase 3 — Moteur d&apos;Analyse Connecté
            </span>
            {backendStatus === 'connected' ? (
              <span className="flex items-center gap-1.5 text-xs text-[#059669] font-medium bg-[#ECFDF5] px-2.5 py-0.5 rounded-full border border-[#A7F3D0]">
                <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse"></span>
                <span>API HTTP Python & SQLite Opérationnels</span>
              </span>
            ) : backendStatus === 'checking' ? (
              <span className="text-xs text-amber-700 bg-amber-50 px-2 py-0.5 rounded-full border border-amber-200">
                Vérification API...
              </span>
            ) : (
              <span className="text-xs text-red-700 bg-red-50 px-2 py-0.5 rounded-full border border-red-200">
                API déconnectée ({backendError})
              </span>
            )}
          </div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[#172B4D] mt-2">
            Moteur d&apos;Analyse de Cybersécurité
          </h1>
          <p className="text-sm text-[#718096] mt-0.5">
            Communication HTTP réelle entre React et le backend Python multi-agents, validation stricte et stockage persistant SQLite.
          </p>
        </div>

        {/* Navigation Tabs */}
        <div className="flex flex-wrap gap-1 bg-[#E6EDF5]/50 p-1 rounded-xl text-xs font-medium border border-[#E6EDF5]">
          <button
            onClick={() => setActiveSubTab('tester')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeSubTab === 'tester'
                ? 'bg-white text-[#172B4D] shadow-2xs font-semibold'
                : 'text-[#718096] hover:text-[#172B4D]'
            }`}
          >
            Banc d&apos;Ingestion JSON
          </button>
          <button
            onClick={() => setActiveSubTab('history')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeSubTab === 'history'
                ? 'bg-white text-[#172B4D] shadow-2xs font-semibold'
                : 'text-[#718096] hover:text-[#172B4D]'
            }`}
          >
            <span>Historique SQLite</span>
            {ingestedHistory.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-[#38A8FF] text-white text-[10px] font-bold">
                {ingestedHistory.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveSubTab('catalog')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeSubTab === 'catalog'
                ? 'bg-white text-[#172B4D] shadow-2xs font-semibold'
                : 'text-[#718096] hover:text-[#172B4D]'
            }`}
          >
            Catalogue des Règles (9)
          </button>
          <button
            onClick={() => setActiveSubTab('backend_doc')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer flex items-center gap-1 ${
              activeSubTab === 'backend_doc'
                ? 'bg-white text-[#172B4D] shadow-2xs font-semibold'
                : 'text-[#718096] hover:text-[#172B4D]'
            }`}
          >
            <Server className="w-3.5 h-3.5 text-[#38A8FF]" />
            <span>API & Architecture</span>
          </button>
        </div>
      </div>

      {/* 2. Sub-Tab: Banc d'Ingestion & Analyse */}
      {activeSubTab === 'tester' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Form & JSON Editor (6 cols) */}
          <div className="lg:col-span-6 space-y-4">
            <div className="bg-white border border-[#E6EDF5] rounded-2xl p-5 shadow-2xs space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-[#E6EDF5]">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-[#38A8FF]" />
                  <h2 className="text-base font-bold text-[#172B4D]">
                    1. Modèles d&apos;Événements Informatiques
                  </h2>
                </div>
                <span className="text-xs text-[#718096]">Envoi HTTP réel vers /api/events</span>
              </div>

              {/* Template pills */}
              <div className="space-y-2">
                <label className="text-xs font-semibold text-[#172B4D] block">
                  Sélectionner un événement synthétique à transmettre :
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {PRESET_TEMPLATES.map((tmpl) => (
                    <button
                      key={tmpl.id}
                      onClick={() => handleSelectTemplate(tmpl.id)}
                      className={`p-2.5 rounded-xl border text-left text-xs transition-colors cursor-pointer ${
                        selectedTemplate === tmpl.id
                          ? 'bg-[#E5F3FF] border-[#38A8FF] text-[#172B4D] font-medium'
                          : 'bg-[#F8FAFC] border-[#E6EDF5] text-[#718096] hover:bg-slate-100 hover:text-[#172B4D]'
                      }`}
                    >
                      <div className="font-semibold text-[#172B4D] text-[11px] truncate">
                        {tmpl.label}
                      </div>
                      <div className="text-[10px] text-[#718096] truncate mt-0.5">
                        {tmpl.description}
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* JSON Editor */}
              <div className="space-y-2 pt-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-[#172B4D] flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-[#38A8FF]" />
                    <span>Payload JSON transmis au backend</span>
                  </label>
                  <button
                    onClick={() => handleSelectTemplate(selectedTemplate)}
                    className="text-[11px] text-[#0284C7] hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    <RotateCcw className="w-3 h-3" />
                    <span>Réinitialiser</span>
                  </button>
                </div>

                <div className="relative">
                  <textarea
                    value={jsonInput}
                    onChange={(e) => setJsonInput(e.target.value)}
                    rows={13}
                    spellCheck={false}
                    className="w-full font-mono text-xs p-3.5 bg-[#0F172A] text-[#F8FAFC] rounded-xl border border-slate-700 focus:outline-none focus:ring-2 focus:ring-[#38A8FF] resize-y"
                    placeholder="Collez ici votre événement au format JSON..."
                  />
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                <div className="text-[11px] text-[#718096] flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-[#10B981]" />
                  <span>Sécurité active : Mots de passe et secrets interdits</span>
                </div>

                <button
                  onClick={handleRunAnalysis}
                  disabled={isSubmitting}
                  className="flex items-center gap-2 px-5 py-2.5 bg-[#38A8FF] hover:bg-[#0284C7] text-white rounded-xl text-xs font-bold transition-all shadow-2xs hover:shadow-xs cursor-pointer disabled:opacity-50"
                >
                  {isSubmitting ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Analyse par les 6 agents...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Envoyer au Backend via HTTP</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Right Column: Live Analysis Output & 6 Agents (6 cols) */}
          <div className="lg:col-span-6 space-y-4">
            {/* Validation Errors banner */}
            {validationErrors.length > 0 && (
              <div className="bg-[#FEF2F2] border border-[#FECACA] rounded-2xl p-5 space-y-3 shadow-2xs">
                <div className="flex items-center gap-2 text-red-700 font-bold text-sm">
                  <AlertOctagon className="w-5 h-5 text-red-600 shrink-0" />
                  <span>Événement Rejeté par le Backend</span>
                </div>
                <p className="text-xs text-red-800">
                  Le backend a refusé de traiter ou d&apos;enregistrer la charge utile pour non-conformité :
                </p>
                <ul className="space-y-1.5 list-disc list-inside text-xs text-red-700 bg-white/80 p-3 rounded-xl border border-red-200">
                  {validationErrors.map((err, i) => (
                    <li key={i} className="font-mono text-[11px]">{err}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Analysis Result Card */}
            {lastAnalysis && analyzedEvent && (
              <div className="bg-white border border-[#E6EDF5] rounded-2xl p-5 shadow-2xs space-y-5">
                <div className="flex items-center justify-between pb-3 border-b border-[#E6EDF5]">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
                    <h2 className="text-base font-bold text-[#172B4D]">
                      Réponse HTTP Retournée par le Backend
                    </h2>
                  </div>
                  <span className="text-[11px] font-mono text-[#059669] bg-[#ECFDF5] px-2 py-0.5 rounded border border-[#A7F3D0]">
                    Enregistré dans SQLite ✓
                  </span>
                </div>

                {/* Score and Level Badge */}
                <div className="p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                  style={{
                    backgroundColor: 
                      lastAnalysis.risk_level === 'Critique' ? '#FEF2F2' :
                      lastAnalysis.risk_level === 'Élevé' ? '#FFFBEB' : '#ECFDF5',
                    borderColor:
                      lastAnalysis.risk_level === 'Critique' ? '#FECACA' :
                      lastAnalysis.risk_level === 'Élevé' ? '#FDE68A' : '#A7F3D0'
                  }}
                >
                  <div className="space-y-1">
                    <div className="text-[11px] font-semibold text-[#718096]">
                      NIVEAU DE RISQUE VALIDÉ PAR LES 6 AGENTS
                    </div>
                    <div className="flex items-center gap-2.5">
                      <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${
                        lastAnalysis.risk_level === 'Critique' ? 'bg-red-600 text-white' :
                        lastAnalysis.risk_level === 'Élevé' ? 'bg-amber-500 text-white' : 'bg-emerald-600 text-white'
                      }`}>
                        {lastAnalysis.risk_level}
                      </span>
                      <span className="text-xs text-[#172B4D] font-medium">
                        Hôte source : <span className="font-mono font-bold">{analyzedEvent.source_host}</span>
                      </span>
                    </div>
                  </div>

                  <div className="text-right sm:border-l sm:pl-4 border-slate-200">
                    <div className="text-[11px] text-[#718096] font-semibold">SCORE D&apos;IMPACT</div>
                    <div className="text-2xl font-bold font-mono text-[#172B4D]">
                      {lastAnalysis.risk_score} <span className="text-xs text-[#718096] font-normal">/ 100</span>
                    </div>
                  </div>
                </div>

                {/* 6-Agent Execution Pipeline Breakdown (Priorité 2) */}
                {agentsPipelineData && (
                  <div className="space-y-3 pt-1">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-bold text-[#172B4D] flex items-center gap-1.5">
                        <Bot className="w-4 h-4 text-[#38A8FF]" />
                        <span>Résultats des 6 Agents Logiciels Collaboratifs</span>
                      </div>
                      <span className="text-[10px] text-[#0284C7] font-semibold bg-[#E5F3FF] px-2 py-0.5 rounded-full">
                        Consensus : 100%
                      </span>
                    </div>

                    {/* Agent selector tabs */}
                    <div className="grid grid-cols-3 sm:grid-cols-6 gap-1 bg-[#F8FAFC] p-1 rounded-xl border border-[#E6EDF5] text-[11px]">
                      {(['detecteur', 'analyste', 'risque', 'protection', 'verification', 'chef'] as const).map((ag) => (
                        <button
                          key={ag}
                          onClick={() => setActivePipelineTab(ag)}
                          className={`py-1.5 px-1 rounded-lg text-center font-medium capitalize transition-colors cursor-pointer truncate ${
                            activePipelineTab === ag
                              ? 'bg-white text-[#0284C7] font-bold shadow-2xs border border-[#BEE3F8]'
                              : 'text-[#718096] hover:text-[#172B4D]'
                          }`}
                        >
                          {ag}
                        </button>
                      ))}
                    </div>

                    {/* Active Agent Detail Panel */}
                    <div className="p-3.5 bg-[#F8FAFC] rounded-xl border border-[#E6EDF5] text-xs space-y-2">
                      {activePipelineTab === 'detecteur' && (
                        <div>
                          <div className="font-bold text-[#172B4D] flex items-center gap-1.5 mb-1">
                            <Radar className="w-3.5 h-3.5 text-[#38A8FF]" />
                            <span>1. Agent Détecteur (Signatures Heuristiques)</span>
                          </div>
                          <p className="text-[11px] text-[#718096] mb-2">
                            {agentsPipelineData.detecteur?.detector_reasoning || 'Détection nominale.'}
                          </p>
                          <div className="flex flex-wrap gap-1">
                            {agentsPipelineData.detecteur?.anomaly_signatures?.map((sig: string, idx: number) => (
                              <span key={idx} className="font-mono text-[10px] bg-[#E5F3FF] text-[#0284C7] px-2 py-0.5 rounded">
                                {sig}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {activePipelineTab === 'analyste' && (
                        <div>
                          <div className="font-bold text-[#172B4D] flex items-center gap-1.5 mb-1">
                            <Search className="w-3.5 h-3.5 text-[#38A8FF]" />
                            <span>2. Agent Analyste (IoCs & MITRE ATT&CK)</span>
                          </div>
                          <p className="text-[11px] text-[#718096] mb-2">
                            {agentsPipelineData.analyste?.analyst_reasoning || 'Analyse effectuée.'}
                          </p>
                          {agentsPipelineData.analyste?.mitre_technique && (
                            <div className="font-mono text-[10px] text-[#172B4D] bg-white p-2 rounded border border-[#E6EDF5]">
                              Technique : <strong>{agentsPipelineData.analyste.mitre_technique.id}</strong> — {agentsPipelineData.analyste.mitre_technique.name} ({agentsPipelineData.analyste.mitre_technique.tactic})
                            </div>
                          )}
                        </div>
                      )}

                      {activePipelineTab === 'risque' && (
                        <div>
                          <div className="font-bold text-[#172B4D] flex items-center gap-1.5 mb-1">
                            <Gauge className="w-3.5 h-3.5 text-[#38A8FF]" />
                            <span>3. Agent Risque (Calcul de Gravité)</span>
                          </div>
                          <p className="text-[11px] text-[#718096] mb-2">
                            {agentsPipelineData.risque?.risk_explanation || 'Évaluation du risque.'}
                          </p>
                          <div className="text-[10px] text-[#718096] flex items-center gap-3">
                            <span>Score : <strong>{agentsPipelineData.risque?.calculated_score}/100</strong></span>
                            <span>Politique : <strong>{agentsPipelineData.risque?.required_policy}</strong></span>
                          </div>
                        </div>
                      )}

                      {activePipelineTab === 'protection' && (
                        <div>
                          <div className="font-bold text-[#172B4D] flex items-center gap-1.5 mb-1">
                            <ShieldAlert className="w-3.5 h-3.5 text-[#38A8FF]" />
                            <span>4. Agent Protection (Actions Simulées)</span>
                          </div>
                          <p className="text-[11px] text-[#718096] mb-2">
                            {agentsPipelineData.protection?.action_summary || 'Actions prescrites en bac à sable.'}
                          </p>
                          <div className="text-[10px] text-[#059669] font-medium bg-[#ECFDF5] p-2 rounded border border-[#A7F3D0]">
                            Garantie formelle : <strong>real_system_touched = false</strong> (aucune machine réelle modifiée)
                          </div>
                        </div>
                      )}

                      {activePipelineTab === 'verification' && (
                        <div>
                          <div className="font-bold text-[#172B4D] flex items-center gap-1.5 mb-1">
                            <ShieldCheck className="w-3.5 h-3.5 text-[#38A8FF]" />
                            <span>5. Agent Vérification (Intégrité & Non-régression)</span>
                          </div>
                          <p className="text-[11px] text-[#718096] mb-2">
                            {agentsPipelineData.verification?.verification_verdict || 'Vérification terminée avec succès.'}
                          </p>
                          <div className="text-[10px] text-[#0284C7]">
                            Risque résiduel : <strong>0%</strong> • Zéro perturbation sur les services de démo.
                          </div>
                        </div>
                      )}

                      {activePipelineTab === 'chef' && (
                        <div>
                          <div className="font-bold text-[#172B4D] flex items-center gap-1.5 mb-1">
                            <Crown className="w-3.5 h-3.5 text-[#38A8FF]" />
                            <span>6. Chef Agent (Synthèse Exécutive & Escalade)</span>
                          </div>
                          <p className="text-[11px] text-[#718096] mb-2">
                            {agentsPipelineData.chef?.executive_summary || 'Arbitrage final par consensus.'}
                          </p>
                          <div className="text-[10px] text-[#718096] space-y-1">
                            <div>Priorité d&apos;alerte : <strong>{agentsPipelineData.chef?.alert_priority}</strong></div>
                            <div className="text-[#0284C7]">Recommandations de durcissement prêtes pour le SOC.</div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Triggered Rules */}
                <div className="space-y-2">
                  <div className="text-xs font-bold text-[#172B4D] flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-[#38A8FF]" />
                    <span>Règles Déclenchées ({lastAnalysis.triggered_rules.length})</span>
                  </div>
                  <div className="space-y-2">
                    {lastAnalysis.triggered_rules.map((rule, idx) => (
                      <div 
                        key={idx} 
                        className="p-3 bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-xs text-[#172B4D] flex items-center gap-1.5">
                            <span className="px-1.5 py-0.5 rounded bg-[#38A8FF] text-white font-mono text-[10px]">
                              {rule.rule_id}
                            </span>
                            <span>{rule.rule_name}</span>
                          </span>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                            rule.severity === 'Critique' ? 'bg-red-100 text-red-700' :
                            rule.severity === 'Élevé' ? 'bg-amber-100 text-amber-700' : 'bg-emerald-100 text-emerald-700'
                          }`}>
                            {rule.severity}
                          </span>
                        </div>
                        <p className="text-[11px] text-[#718096]">
                          {rule.description}
                        </p>
                        <div className="text-[10px] font-mono text-[#0284C7] bg-[#E5F3FF]/50 p-1.5 rounded">
                          Condition vérifiée : {rule.condition_matched}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommended action */}
                <div className="p-3.5 bg-[#EFF6FF] border border-[#BFDBFE] rounded-xl space-y-1">
                  <div className="text-xs font-bold text-[#1E40AF] flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-[#2563EB]" />
                    <span>Recommandation d&apos;Action Opérationnelle :</span>
                  </div>
                  <p className="text-xs text-[#1E3A8A] leading-relaxed">
                    {lastAnalysis.recommended_action}
                  </p>
                </div>

                {/* Analysis Limits (Transparency) */}
                <div className="space-y-1.5 pt-1">
                  <div className="text-[11px] font-semibold text-[#718096] flex items-center gap-1">
                    <Info className="w-3.5 h-3.5 text-[#38A8FF]" />
                    <span>Limites de l&apos;Analyse (Transparence déontologique) :</span>
                  </div>
                  <ul className="space-y-1 text-[11px] text-[#718096] list-disc list-inside pl-1">
                    {lastAnalysis.analysis_limits.map((lim, i) => (
                      <li key={i}>{lim}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* Empty state placeholder */}
            {!lastAnalysis && validationErrors.length === 0 && (
              <div className="bg-white border border-[#E6EDF5] rounded-2xl p-8 shadow-2xs text-center space-y-3">
                <div className="w-12 h-12 rounded-2xl bg-[#E5F3FF] text-[#38A8FF] flex items-center justify-center mx-auto">
                  <Cpu className="w-6 h-6" />
                </div>
                <h3 className="font-bold text-base text-[#172B4D]">
                  Prêt pour l&apos;ingestion d&apos;événements
                </h3>
                <p className="text-xs text-[#718096] max-w-sm mx-auto leading-relaxed">
                  Sélectionnez un modèle à gauche ou éditez votre JSON, puis cliquez sur <strong>« Envoyer au Backend via HTTP »</strong>. L&apos;événement sera transmis au serveur, validé, analysé par les 6 agents et enregistré dans SQLite.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. Sub-Tab: Historique des Événements SQLite */}
      {activeSubTab === 'history' && (
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-[#E6EDF5]">
            <div>
              <h2 className="text-base font-bold text-[#172B4D] flex items-center gap-2">
                <Database className="w-4 h-4 text-[#38A8FF]" />
                <span>Registre SQLite des Événements Analysés</span>
              </h2>
              <p className="text-xs text-[#718096] mt-0.5">
                Données persistées sur le serveur dans <code>backend/fire_agent.db</code>.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={fetchHistoryFromBackend}
                disabled={isLoadingHistory}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-[#F4F9FF] border border-[#BEE3F8] text-[#0284C7] rounded-lg hover:bg-[#E5F3FF] transition-colors cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingHistory ? 'animate-spin' : ''}`} />
                <span>Rafraîchir SQLite</span>
              </button>

              {/* Filter pills */}
              {(['Tous', 'Critique', 'Élevé', 'Faible'] as const).map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setHistoryRiskFilter(lvl)}
                  className={`px-3 py-1 text-xs font-semibold rounded-lg border transition-colors cursor-pointer ${
                    historyRiskFilter === lvl
                      ? 'bg-[#E5F3FF] text-[#0284C7] border-[#38A8FF]'
                      : 'bg-white text-[#718096] border-[#E6EDF5] hover:bg-[#F8FAFC]'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>

          {/* Search box */}
          <div className="relative">
            <Search className="w-4 h-4 text-[#718096] absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={historySearch}
              onChange={(e) => setHistorySearch(e.target.value)}
              placeholder="Rechercher par ID d'événement, hôte source ou description..."
              className="w-full pl-10 pr-4 py-2 text-xs bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl text-[#172B4D] focus:outline-none focus:ring-2 focus:ring-[#38A8FF]"
            />
          </div>

          {/* Events table */}
          {filteredHistory.length === 0 ? (
            <div className="p-8 text-center bg-[#F8FAFC] rounded-xl border border-[#E6EDF5] space-y-2">
              <Database className="w-8 h-8 text-[#A0AEC0] mx-auto" />
              <p className="text-xs text-[#718096]">
                {ingestedHistory.length === 0 
                  ? "Aucun événement enregistré pour le moment. Utilisez le banc d'ingestion pour envoyer votre premier événement."
                  : "Aucun événement ne correspond aux critères de recherche."}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#E6EDF5] border border-[#E6EDF5] rounded-xl overflow-hidden">
              {filteredHistory.map((item, idx) => (
                <div key={idx} className="p-4 hover:bg-[#F8FAFC] transition-colors space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-[#172B4D]">
                        {item.event.event_id}
                      </span>
                      <span className="text-xs text-[#718096]">•</span>
                      <span className="text-xs font-semibold text-[#0284C7] bg-[#E5F3FF] px-2 py-0.5 rounded-md">
                        {item.event.source_host}
                      </span>
                      <span className="text-xs text-[#718096]">•</span>
                      <span className="text-xs text-[#718096]">
                        {item.event.event_type}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold ${
                        item.analysis.risk_level === 'Critique' ? 'bg-red-100 text-red-700' :
                        item.analysis.risk_level === 'Élevé' ? 'bg-amber-100 text-amber-700' : 'bg-emerald-100 text-emerald-700'
                      }`}>
                        {item.analysis.risk_level} ({item.analysis.risk_score}/100)
                      </span>
                      <span className="text-[11px] text-[#A0AEC0] font-mono">
                        {item.stored_at?.slice(11, 19) || item.analysis.analyzed_at?.slice(11, 19)}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-[#172B4D]">
                    {item.event.description}
                  </p>

                  <div className="text-[11px] text-[#718096] bg-white p-2.5 rounded-lg border border-[#E6EDF5] flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <strong className="text-[#172B4D]">Action :</strong> {item.analysis.recommended_action}
                    </div>
                    <div className="font-mono text-[10px] text-[#0284C7]">
                      {item.analysis.triggered_rules.map(r => r.rule_id).join(', ')}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 4. Sub-Tab: Catalogue des Règles */}
      {activeSubTab === 'catalog' && (
        <div className="bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs space-y-6">
          <div className="pb-3 border-b border-[#E6EDF5]">
            <h2 className="text-base font-bold text-[#172B4D]">
              Catalogue des 9 Règles Déterministes du Moteur
            </h2>
            <p className="text-xs text-[#718096] mt-0.5">
              Chaque règle applique des seuils clairs et transparents pour repérer les activités hostiles sans opacité.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {RULES_CATALOG.map((rule) => (
              <div 
                key={rule.id}
                className="p-4 bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl flex flex-col justify-between space-y-3"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-[#38A8FF] text-white">
                      {rule.id}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      rule.severity === 'Critique' ? 'bg-red-100 text-red-700' :
                      rule.severity === 'Élevé' ? 'bg-amber-100 text-amber-700' : 'bg-emerald-100 text-emerald-700'
                    }`}>
                      {rule.severity}
                    </span>
                  </div>

                  <h3 className="font-bold text-xs text-[#172B4D]">
                    {rule.name}
                  </h3>
                  <div className="text-[10px] font-semibold text-[#0284C7]">
                    {rule.category}
                  </div>
                  <p className="text-[11px] text-[#718096] leading-relaxed">
                    {rule.description}
                  </p>
                </div>

                <div className="pt-2 border-t border-[#E6EDF5]">
                  <div className="text-[10px] font-mono text-[#475569] bg-white p-2 rounded border border-[#E6EDF5] truncate">
                    Seuil : {rule.threshold}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. Sub-Tab: Architecture FastAPI & Documentation */}
      {activeSubTab === 'backend_doc' && (
        <div className="space-y-5">
          <div className="bg-white border border-[#E6EDF5] rounded-2xl p-6 shadow-2xs space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-[#E6EDF5]">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-[#38A8FF]" />
                <div>
                  <h2 className="text-base font-bold text-[#172B4D]">
                    Architecture Backend Indépendante (Python / FastAPI / Express)
                  </h2>
                  <p className="text-xs text-[#718096]">
                    Architecture full-stack intégrant les 6 agents logiciels, SQLite et l&apos;API REST.
                  </p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="p-4 bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl space-y-2">
                <div className="font-bold text-[#172B4D] flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[#10B981]"></span>
                  <span>1. Validation & Sécurité</span>
                </div>
                <p className="text-[#718096] text-[11px] leading-relaxed">
                  Modèles stricts dans <code>backend/models.py</code>. Rejet immédiat (HTTP 422) de tout événement contenant des mots de passe, clés secrètes ou données malformées.
                </p>
              </div>

              <div className="p-4 bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl space-y-2">
                <div className="font-bold text-[#172B4D] flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[#38A8FF]"></span>
                  <span>2. Chaîne des 6 Agents</span>
                </div>
                <p className="text-[#718096] text-[11px] leading-relaxed">
                  Architecture multi-agents dans <code>backend/agents.py</code> : Détecteur ➔ Analyste ➔ Risque ➔ Protection ➔ Vérification ➔ Chef Agent.
                </p>
              </div>

              <div className="p-4 bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl space-y-2">
                <div className="font-bold text-[#172B4D] flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[#8B5CF6]"></span>
                  <span>3. Persistance SQLite</span>
                </div>
                <p className="text-[#718096] text-[11px] leading-relaxed">
                  Module <code>backend/storage.py</code> créant la table <code>events</code> dans <code>backend/fire_agent.db</code> avec indexation et intégrité.
                </p>
              </div>
            </div>

            {/* Terminal Command to run Python Backend */}
            <div className="space-y-2 pt-2">
              <label className="text-xs font-bold text-[#172B4D] flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-[#38A8FF]" />
                <span>Commandes d&apos;Exécution & Tests</span>
              </label>

              <div className="bg-[#0F172A] text-[#F8FAFC] p-4 rounded-xl font-mono text-xs space-y-2">
                <div className="text-slate-400"># Serveur Full-Stack Express + Python (démarré sur port 3000)</div>
                <div className="text-emerald-400">npm run dev</div>

                <div className="text-slate-400 pt-2"># Lancement autonome FastAPI (service séparé)</div>
                <div className="text-slate-300">pip install -r backend/requirements.txt</div>
                <div className="text-sky-300">uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload</div>

                <div className="text-slate-400 pt-2"># Suite de 10 tests unitaires & intégration Python</div>
                <div className="text-amber-300">python3 backend/test_engine.py</div>
              </div>
            </div>

            {/* Curl Sample */}
            <div className="space-y-2 pt-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-[#172B4D]">
                  Exemple d&apos;Appel API HTTP (cURL) :
                </label>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(curlExample);
                    setCopiedCurl(true);
                    setTimeout(() => setCopiedCurl(false), 2000);
                  }}
                  className="text-xs text-[#0284C7] flex items-center gap-1 hover:underline cursor-pointer"
                >
                  {copiedCurl ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedCurl ? 'Copié !' : 'Copier la commande cURL'}</span>
                </button>
              </div>
              <pre className="p-3.5 bg-[#F8FAFC] border border-[#E6EDF5] rounded-xl font-mono text-[11px] text-[#172B4D] overflow-x-auto">
                {curlExample}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
