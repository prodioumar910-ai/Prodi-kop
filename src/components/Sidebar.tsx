import React from 'react';
import { FireLogo } from './FireLogo';
import { 
  Home, 
  FlaskConical, 
  Bot, 
  Bell, 
  FileText, 
  Settings, 
  ShieldCheck, 
  Info,
  X,
  Cpu
} from 'lucide-react';

export type ActiveTab = 'dashboard' | 'engine' | 'lab' | 'agents' | 'alerts' | 'chief' | 'settings';

interface SidebarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  criticalAlertCount: number;
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  criticalAlertCount,
  mobileOpen = false,
  onCloseMobile
}) => {
  const navItems: { id: ActiveTab; label: string; icon: React.ReactNode; badge?: number }[] = [
    { id: 'dashboard', label: 'Tableau de bord', icon: <Home className="w-4 h-4" /> },
    { id: 'engine', label: "Moteur d'Analyse", icon: <Cpu className="w-4 h-4" /> },
    { id: 'lab', label: 'Laboratoire', icon: <FlaskConical className="w-4 h-4" /> },
    { id: 'agents', label: 'Agents', icon: <Bot className="w-4 h-4" /> },
    { id: 'alerts', label: 'Alertes', icon: <Bell className="w-4 h-4" />, badge: criticalAlertCount },
    { id: 'chief', label: 'Rapports', icon: <FileText className="w-4 h-4" /> },
    { id: 'settings', label: 'Paramètres', icon: <Settings className="w-4 h-4" /> },
  ];

  const handleSelect = (id: ActiveTab) => {
    setActiveTab(id);
    if (onCloseMobile) onCloseMobile();
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div 
          onClick={onCloseMobile}
          className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs z-40 md:hidden"
        />
      )}

      {/* Sidebar Container */}
      <aside 
        className={`fixed md:sticky top-0 left-0 z-50 h-screen w-64 bg-white border-r border-[#E6EDF5] flex flex-col justify-between p-5 transition-transform duration-200 ease-in-out md:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        <div>
          {/* Top Brand Logo & Mobile Close */}
          <div className="flex items-center justify-between pb-6 border-b border-[#E6EDF5]/70">
            <FireLogo size="md" />
            {onCloseMobile && (
              <button 
                onClick={onCloseMobile}
                className="md:hidden p-1 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100"
                aria-label="Fermer le menu"
              >
                <X className="w-5 h-5" />
              </button>
            )}
          </div>

          {/* Navigation Links */}
          <nav className="mt-6 space-y-1.5" aria-label="Navigation principale">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleSelect(item.id)}
                  className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-medium transition-colors cursor-pointer text-left ${
                    isActive
                      ? 'bg-[#E5F3FF] text-[#172B4D] font-semibold'
                      : 'text-[#718096] hover:bg-[#F4F9FF] hover:text-[#172B4D]'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className={isActive ? 'text-[#38A8FF]' : 'text-[#718096]'}>
                      {item.icon}
                    </span>
                    <span>{item.label}</span>
                  </div>

                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-red-100 text-red-600">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom Sandbox Notice Card (matching screenshot) */}
        <div className="pt-4 border-t border-[#E6EDF5]">
          <div className="p-3 bg-[#F4F9FF] border border-[#E6EDF5] rounded-xl text-xs space-y-1.5">
            <div className="flex items-center gap-1.5 font-bold text-[#172B4D]">
              <ShieldCheck className="w-4 h-4 text-[#38A8FF]" />
              <span>FIRE AGENT</span>
            </div>
            <p className="text-[11px] text-[#718096]">
              Prototype de démonstration
            </p>
            <div className="pt-1 flex items-center gap-1 text-[11px] text-[#38A8FF] font-medium">
              <Info className="w-3.5 h-3.5" />
              <span>Données fictives</span>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};
