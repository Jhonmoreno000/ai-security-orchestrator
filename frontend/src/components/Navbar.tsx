import React from 'react';
import {
  ShieldCheckIcon,
  RadarIcon,
  BugIcon,
  CpuIcon,
  FileTextIcon,
  TargetIcon,
  ActivityIcon,
} from './icons/Icons';

export type ActiveTab = 'dashboard' | 'scans' | 'findings' | 'assistant' | 'reports' | 'targets';

interface NavbarProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  onOpenNewScan: () => void;
  wsConnected: boolean;
  activeScansCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onTabChange,
  onOpenNewScan,
  wsConnected,
  activeScansCount,
}) => {
  const tabs = [
    {
      id: 'dashboard' as ActiveTab,
      label: 'Dashboard SOC',
      icon: <RadarIcon className="w-4 h-4" />,
    },
    {
      id: 'scans' as ActiveTab,
      label: 'Auditorías',
      badge: activeScansCount > 0 ? activeScansCount : undefined,
      icon: <ShieldCheckIcon className="w-4 h-4" />,
    },
    {
      id: 'findings' as ActiveTab,
      label: 'Vulnerabilidades',
      icon: <BugIcon className="w-4 h-4" />,
    },
    {
      id: 'assistant' as ActiveTab,
      label: 'AI SecOps Agent',
      icon: <CpuIcon className="w-4 h-4" />,
    },
    {
      id: 'reports' as ActiveTab,
      label: 'Reportes & SARIF',
      icon: <FileTextIcon className="w-4 h-4" />,
    },
    {
      id: 'targets' as ActiveTab,
      label: 'Scope & Perímetro',
      icon: <TargetIcon className="w-4 h-4" />,
    },
  ];

  return (
    <header className="sticky top-0 z-40 bg-[#080c14]/95 backdrop-blur-xl border-b border-slate-800/90 shadow-2xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Platform Label */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => onTabChange('dashboard')}>
            <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-gradient-to-tr from-sky-600 to-indigo-600 p-[1px]">
              <div className="w-full h-full bg-[#0d1322] rounded-lg flex items-center justify-center text-sky-400">
                <ShieldCheckIcon className="w-5 h-5" />
              </div>
              <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 bg-emerald-400 border border-[#080c14] rounded-full animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-sm tracking-tight text-white font-mono">
                  AI SECURITY ORCHESTRATOR
                </span>
                <span className="hidden sm:inline-block px-1.5 py-0.2 text-[9px] font-mono font-bold uppercase tracking-wider bg-sky-500/10 text-sky-400 border border-sky-500/30 rounded">
                  ENTERPRISE
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-mono hidden sm:block">Plataforma de Auditoría de Ciberseguridad Asistida por IA</p>
            </div>
          </div>

          {/* Nav Items */}
          <nav className="hidden md:flex items-center gap-1 bg-[#0d1322]/80 p-1 rounded-lg border border-slate-800">
            {tabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => onTabChange(tab.id)}
                  className={`relative flex items-center gap-2 px-3 py-1.5 text-xs font-semibold rounded-md transition-all duration-150 ${
                    isActive
                      ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                  {tab.badge !== undefined && (
                    <span className="ml-1 px-1.5 py-0.2 text-[9px] font-mono font-bold bg-sky-400 text-slate-950 rounded">
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Action & Live Signal */}
          <div className="flex items-center gap-3">
            {/* WebSocket Stream Indicator */}
            <div
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono border ${
                wsConnected
                  ? 'bg-emerald-950/40 text-emerald-400 border-emerald-500/30'
                  : 'bg-rose-950/40 text-rose-400 border-rose-500/30'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-emerald-400 animate-ping' : 'bg-rose-500'}`} />
              <span className="font-semibold hidden lg:inline">{wsConnected ? 'STREAM ACTIVO' : 'DESCONECTADO'}</span>
            </div>

            {/* Launch Audit Action */}
            <button
              onClick={onOpenNewScan}
              className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-bold font-mono uppercase tracking-wide rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-md shadow-sky-500/20 hover:shadow-sky-500/40 transition-all duration-150"
            >
              <ActivityIcon className="w-3.5 h-3.5" />
              <span>Nueva Auditoría</span>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Submenu Bar */}
      <div className="flex md:hidden overflow-x-auto px-4 py-2 bg-[#090d16] border-t border-slate-800 gap-2">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`flex items-center gap-1.5 px-3 py-1 text-xs whitespace-nowrap rounded-md font-medium ${
              activeTab === tab.id ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' : 'text-slate-400 bg-slate-900'
            }`}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>
    </header>
  );
};
