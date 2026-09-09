import React from 'react';
import {
  LayoutDashboard,
  AlertOctagon,
  KeyRound,
  Activity,
  Server,
  ClipboardCheck,
  Flame,
  Wrench,
  FileText,
  Settings,
  ChevronRight,
  ShieldCheck
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'findings', label: 'Security Findings', icon: AlertOctagon, badge: true },
  { id: 'iam', label: 'IAM Analyzer', icon: KeyRound },
  { id: 'cloudtrail', label: 'CloudTrail Monitor', icon: Activity },
  { id: 'resources', label: 'AWS Resources', icon: Server },
  { id: 'compliance', label: 'Compliance', icon: ClipboardCheck },
  { id: 'risk', label: 'Risk Analysis', icon: Flame },
  { id: 'remediation', label: 'Remediation', icon: Wrench },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export default function Sidebar({ activeTab = 'dashboard', onNavigate, openFindingsCount = 0 }) {
  return (
    <aside className="w-64 shrink-0 hidden md:flex flex-col border-r border-slate-800/80 bg-slate-950/70 p-4 space-y-6">
      {/* Platform Status Chip */}
      <div className="p-3.5 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="font-mono text-slate-400 font-bold uppercase">Scanner Status</span>
          <span className="flex items-center gap-1.5 text-emerald-400 font-bold font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            LIVE
          </span>
        </div>
        <div className="text-[11px] text-slate-400">
          Continuous evaluation active across 8 AWS core services.
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 space-y-1">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate?.(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-semibold tracking-wide transition group ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-500/15 to-blue-500/10 border border-cyan-500/30 text-cyan-300 shadow-[0_0_15px_rgba(0,242,254,0.1)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={`w-4 h-4 transition ${
                    isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-300'
                  }`}
                />
                <span>{item.label}</span>
              </div>

              <div className="flex items-center gap-1.5">
                {item.badge && openFindingsCount > 0 && (
                  <span className="px-1.5 py-0.5 rounded-md bg-rose-950 border border-rose-800 text-[10px] font-mono font-bold text-rose-400">
                    {openFindingsCount}
                  </span>
                )}
                {isActive && <ChevronRight className="w-3.5 h-3.5 text-cyan-400" />}
              </div>
            </button>
          );
        })}
      </nav>

      {/* Bottom Footer Info */}
      <div className="pt-4 border-t border-slate-800/80 text-[11px] text-slate-500 space-y-1 font-mono">
        <div className="flex items-center justify-between">
          <span>Engine:</span>
          <span className="text-slate-400">v2.4.0 (Python/FastAPI)</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Ruleset:</span>
          <span className="text-slate-400">AWS CIS v2.0 + NIST</span>
        </div>
      </div>
    </aside>
  );
}
