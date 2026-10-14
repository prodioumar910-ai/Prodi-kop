import React from 'react';
import { Bell, ChevronDown, Menu } from 'lucide-react';
import { FireLogo } from './FireLogo';

interface TopBarProps {
  onOpenMobileMenu: () => void;
  criticalAlertCount: number;
  onNavigateToAlerts: () => void;
}

export const Header: React.FC<TopBarProps> = ({
  onOpenMobileMenu,
  criticalAlertCount,
  onNavigateToAlerts
}) => {
  return (
    <header className="bg-white border-b border-[#E6EDF5] sticky top-0 z-30 px-4 md:px-8 py-3.5">
      <div className="flex items-center justify-between gap-4">
        {/* Left: Mobile Hamburger & Logo (Mobile only) */}
        <div className="flex items-center gap-3">
          <button
            onClick={onOpenMobileMenu}
            className="md:hidden p-2 text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-lg cursor-pointer"
            aria-label="Ouvrir le menu"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="md:hidden">
            <FireLogo size="sm" />
          </div>

          {/* Desktop Search / Quick breadcrumb */}
          <div className="hidden md:flex items-center gap-2 text-xs text-[#718096]">
            <span className="font-semibold text-[#172B4D]">Espace Opérationnel</span>
            <span>/</span>
            <span>Supervision Multi-Agents</span>
          </div>
        </div>

        {/* Right: Operational Status & User profile */}
        <div className="flex items-center gap-3 md:gap-5">
          {/* Status badge: matching screenshot */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-[#ECFDF5] border border-[#A7F3D0]/60 text-xs font-medium text-[#059669]">
            <span className="w-2 h-2 rounded-full bg-[#10B981]"></span>
            <span>Système opérationnel</span>
          </div>

          {/* Notification Bell */}
          <button
            onClick={onNavigateToAlerts}
            className="relative p-2 text-slate-500 hover:text-slate-800 hover:bg-slate-100 rounded-xl transition-colors cursor-pointer"
            aria-label="Notifications"
          >
            <Bell className="w-5 h-5" />
            {criticalAlertCount > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full ring-2 ring-white"></span>
            )}
          </button>

          {/* User Profile Pill */}
          <div className="flex items-center gap-2 pl-2 border-l border-[#E6EDF5]">
            <div className="w-8 h-8 rounded-full bg-[#E5F3FF] text-[#38A8FF] font-bold text-xs flex items-center justify-center">
              M
            </div>
            <span className="hidden md:inline text-xs font-semibold text-[#172B4D]">
              Utilisateur
            </span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400 hidden md:inline" />
          </div>
        </div>
      </div>
    </header>
  );
};
