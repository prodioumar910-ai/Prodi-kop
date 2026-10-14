import React, { useState } from 'react';
import { 
  INITIAL_AGENTS, 
  INITIAL_EVENTS, 
  INITIAL_CHEF_REPORT 
} from './data/initialData';
import { 
  SecurityEvent, 
  AgentInfo, 
  ChefDailyReport, 
  SimulationScenario, 
  SimulationStep 
} from './types/security';
import { Sidebar, ActiveTab } from './components/Sidebar';
import { Header } from './components/Header';
import { SandboxNotice } from './components/SandboxNotice';
import { Dashboard } from './components/Dashboard';
import { SimulationLab } from './components/SimulationLab';
import { AgentsView } from './components/AgentsView';
import { AlertsManager } from './components/AlertsManager';
import { ChefAgentView } from './components/ChefAgentView';
import { SettingsView } from './components/SettingsView';
import { SecurityEngineView } from './components/SecurityEngineView';
import { EventDetailModal } from './components/EventDetailModal';
import { CriticalAlertModal } from './components/CriticalAlertModal';
import { FireLogo } from './components/FireLogo';
import { Shield } from 'lucide-react';
import { SecurityEventInput, AnalysisResult } from './engine/securityRuleEngine';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [events, setEvents] = useState<SecurityEvent[]>(INITIAL_EVENTS);
  const [agents, setAgents] = useState<AgentInfo[]>(INITIAL_AGENTS);
  const [latestReport, setLatestReport] = useState<ChefDailyReport>(INITIAL_CHEF_REPORT);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [labScenarioToLaunch, setLabScenarioToLaunch] = useState<string | undefined>(undefined);

  // Modals state
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [criticalAlertData, setCriticalAlertData] = useState<{
    scenario: SimulationScenario;
    step: SimulationStep;
  } | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('detecteur');

  // Handle new event created in lab
  const handleEventCreated = (newEvent: SecurityEvent) => {
    setEvents(prev => [newEvent, ...prev]);

    setAgents(prevAgents => prevAgents.map(ag => {
      if (newEvent.involvedAgents.includes(ag.id)) {
        return {
          ...ag,
          processedCount: ag.processedCount + 1,
          lastAction: `Incident [${newEvent.id}] neutralisé`
        };
      }
      return ag;
    }));
  };

  // Handle event ingested from Security Engine (Phase 3)
  const handleEventIngestedFromEngine = (input: SecurityEventInput, analysis: AnalysisResult) => {
    const categoryMap: Record<string, SecurityEvent['category']> = {
      failed_logins: 'Tentative de connexion',
      suspicious_file: 'Fichier suspect',
      phishing_simulation: 'Email de phishing',
      unusual_connection: 'Tentative de connexion',
      telemetry_scan: 'Activité malveillante',
      generic_event: 'Activité malveillante'
    };

    const newEvt: SecurityEvent = {
      id: input.event_id,
      timestamp: "À l'instant",
      source: input.source_host,
      target: input.technical_data?.source_ip || "Station hôte",
      category: categoryMap[input.event_type] || 'Activité malveillante',
      title: `${input.event_type.replace('_', ' ')} : ${input.description.slice(0, 45)}`,
      description: analysis.decision_reasons[0] || input.description,
      riskLevel: analysis.risk_level,
      riskScore: analysis.risk_score,
      status: analysis.risk_level === 'Critique' ? 'Détecté' : 'Clôturé',
      ioc: {
        ip: input.technical_data?.source_ip,
        domain: input.technical_data?.email_domain,
        hash: input.technical_data?.file_hash,
        process: input.technical_data?.spawned_process
      },
      mitre: {
        id: analysis.triggered_rules[0]?.rule_id || 'T1046',
        name: analysis.triggered_rules[0]?.rule_name || 'Règle d\'analyse',
        tactic: 'Détection Déterministe'
      },
      simulatedAction: analysis.recommended_action,
      verificationResult: "Validé par le moteur de règles de cybersécurité.",
      chefAgentSummary: `Incident [${input.event_id}] évalué avec un score de ${analysis.risk_score}/100. ${analysis.decision_reasons.join(' ')}`,
      involvedAgents: ['detecteur', 'analyste', 'risque', 'protection', 'verification', 'chef']
    };

    setEvents(prev => [newEvt, ...prev]);
  };

  // Mark event acknowledged
  const handleAcknowledgeEvent = (eventId: string) => {
    setEvents(prev => prev.map(ev => {
      if (ev.id === eventId) {
        return { ...ev, status: 'Clôturé' };
      }
      return ev;
    }));
  };

  // Generate fresh report
  const handleGenerateFreshReport = () => {
    const totalEventsCount = events.length + 48;
    const threatsCount = events.filter(e => e.riskLevel === 'Élevé' || e.riskLevel === 'Critique').length + 7;
    const criticalCount = events.filter(e => e.riskLevel === 'Critique').length + 2;
    const nowTime = new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });

    const newReport: ChefDailyReport = {
      ...latestReport,
      id: `RAPPORT-SOC-${Date.now().toString().slice(-4)}`,
      generatedAt: `24 septembre 2026 à ${nowTime}`,
      totalEvents: totalEventsCount,
      threatsDetected: threatsCount,
      criticalThreats: criticalCount,
      executiveSummary: `Mise à jour à ${nowTime} : Le système FIRE AGENT supervise ${totalEventsCount} événements de démonstration. ${threatsCount} menaces ont été interceptées et évaluées par les agents logiciels. Toutes les actions de protection se sont déroulées avec succès dans l'environnement de test.`,
      keyIncidents: events.slice(0, 3).map(e => ({
        title: e.title,
        level: e.riskLevel,
        resolution: `Analysé par la chaîne multi-agents. Neutralisé au banc d'essai.`,
        simulatedProtection: e.simulatedAction
      }))
    };

    setLatestReport(newReport);
  };

  const handleResetData = () => {
    setEvents(INITIAL_EVENTS);
    setAgents(INITIAL_AGENTS);
    setLatestReport(INITIAL_CHEF_REPORT);
  };

  const handleLaunchScenarioFromDashboard = (scenarioId: string) => {
    setLabScenarioToLaunch(scenarioId);
    setActiveTab('lab');
  };

  const criticalCount = events.filter(e => e.riskLevel === 'Critique' && e.status !== 'Clôturé').length;

  return (
    <div className="min-h-screen bg-[#F4F9FF] text-[#172B4D] flex font-sans antialiased">
      {/* 1. Desktop & Mobile Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        criticalAlertCount={criticalCount}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      {/* 2. Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col min-h-screen">
        {/* Transparency Banner */}
        <SandboxNotice />

        {/* Top Header */}
        <Header
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          criticalAlertCount={criticalCount}
          onNavigateToAlerts={() => setActiveTab('alerts')}
        />

        {/* Page Viewport */}
        <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
          {activeTab === 'dashboard' && (
            <Dashboard
              events={events}
              agents={agents}
              latestReport={latestReport}
              onSelectEvent={setSelectedEvent}
              onNavigateToTab={setActiveTab}
              onSelectAgent={setSelectedAgentId}
              onLaunchScenario={handleLaunchScenarioFromDashboard}
            />
          )}

          {activeTab === 'engine' && (
            <SecurityEngineView
              onEventIngested={handleEventIngestedFromEngine}
            />
          )}

          {activeTab === 'lab' && (
            <SimulationLab
              initialScenarioId={labScenarioToLaunch}
              onEventCreated={handleEventCreated}
              onCriticalAlertTriggered={(scenario, step) => {
                setCriticalAlertData({ scenario, step });
              }}
              onNavigateToChief={() => setActiveTab('chief')}
            />
          )}

          {activeTab === 'agents' && (
            <AgentsView
              agents={agents}
              selectedAgentId={selectedAgentId}
              onSelectAgentId={setSelectedAgentId}
              onLaunchLabForAgent={(agentId) => {
                setSelectedAgentId(agentId);
                setActiveTab('lab');
              }}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsManager
              events={events}
              onSelectEvent={setSelectedEvent}
              onAcknowledgeEvent={handleAcknowledgeEvent}
            />
          )}

          {activeTab === 'chief' && (
            <ChefAgentView
              report={latestReport}
              events={events}
              onGenerateFreshReport={handleGenerateFreshReport}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView
              onResetData={handleResetData}
            />
          )}
        </main>

        {/* Footer (matching bottom of user screenshot) */}
        <footer className="bg-white border-t border-[#E6EDF5] py-4 px-4 sm:px-8 text-xs text-[#718096]">
          <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#38A8FF]" />
              <span className="font-bold text-[#172B4D]">FIRE AGENT</span>
              <span className="text-[#A0AEC0]">v1.0.0</span>
              <span className="text-[#CBD5E1]">|</span>
              <span>Prototype de démonstration - Données fictives</span>
            </div>

            <div className="text-[#718096] text-center sm:text-right">
              Ensemble pour un environnement numérique plus sûr
            </div>
          </div>
        </footer>
      </div>

      {/* Global Modals */}
      <EventDetailModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />

      <CriticalAlertModal
        scenario={criticalAlertData?.scenario || null}
        step={criticalAlertData?.step || null}
        onClose={() => setCriticalAlertData(null)}
        onAcknowledge={() => setCriticalAlertData(null)}
      />
    </div>
  );
}
