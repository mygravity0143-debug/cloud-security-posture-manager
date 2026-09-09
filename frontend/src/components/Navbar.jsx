import React, { useState } from 'react';
import {
  Shield,
  Bell,
  Search,
  User,
  ChevronDown,
  Cloud,
  CheckCircle,
  AlertTriangle,
  Radio,
  ExternalLink,
  Lock
} from 'lucide-react';
import { getActiveRole, setActiveRole } from '../services/api';

export default function Navbar({
  criticalAlerts = [],
  activeMode = 'simulation',
  onSearchSubmit,
  onRoleChanged,
  onNavigate
}) {
  const [showRoleDropdown, setShowRoleDropdown] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const currentRole = getActiveRole();

  const handleRoleSelect = (roleName) => {
    setActiveRole(roleName);
    setShowRoleDropdown(false);
    onRoleChanged?.(roleName);
  };

  const handleSearchKeyDown = (e) => {
    if (e.key === 'Enter' && searchTerm.trim()) {
      onSearchSubmit?.(searchTerm.trim());
      onNavigate?.('findings');
    }
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-xl">
      <div className="flex items-center justify-between h-16 px-4 sm:px-6 lg:px-8">
        {/* Left: Brand / Logo */}
        <div className="flex items-center gap-4">
          <div
            onClick={() => onNavigate?.('dashboard')}
            className="flex items-center gap-3 cursor-pointer group"
          >
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 group-hover:border-cyan-400/60 transition shadow-[0_0_15px_rgba(0,242,254,0.2)]">
              <Shield className="w-5 h-5 text-cyan-400 group-hover:scale-110 transition-transform" />
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyan-400 radar-dot" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold text-white tracking-tight text-base sm:text-lg">
                  AWS CSPM
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 font-bold">
                  SOC v2.4
                </span>
              </div>
              <span className="text-[11px] text-slate-400 font-mono hidden sm:block">
                Cloud Security Posture Manager
              </span>
            </div>
          </div>

          {/* Account Indicator Badge */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
            <Cloud className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">AWS:</span>
            <span className="text-white font-semibold">123456789012</span>
            <span className="text-slate-500">[Production / us-east-1]</span>
          </div>

          {/* Engine Mode Badge */}
          <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900/90 border border-slate-700 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-slate-400 text-[11px]">Mode:</span>
            <span className="text-cyan-400 font-bold uppercase text-[11px]">
              {activeMode === 'simulation' ? 'Enterprise Simulation' : 'Live AWS Boto3'}
            </span>
          </div>
        </div>

        {/* Center: Search input */}
        <div className="hidden md:flex items-center flex-1 max-w-xs lg:max-w-md mx-4">
          <div className="relative w-full">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search findings, resources, CVEs, or rules... (Press Enter)"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyDown={handleSearchKeyDown}
              className="w-full pl-9 pr-4 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition font-mono"
            />
          </div>
        </div>

        {/* Right: Notifications & User Role Switcher */}
        <div className="flex items-center gap-3">
          {/* Notifications Drawer Toggle */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 transition"
              aria-label="View security notifications"
            >
              <Bell className="w-4 h-4" />
              {criticalAlerts.length > 0 && (
                <span className="absolute -top-1 -right-1 flex items-center justify-center w-4 h-4 rounded-full bg-rose-500 text-[10px] font-bold text-white shadow-[0_0_8px_rgba(244,63,94,0.6)]">
                  {criticalAlerts.length}
                </span>
              )}
            </button>

            {/* Notifications Dropdown */}
            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-2xl glass-panel-critical bg-slate-950 border border-rose-900/50 shadow-2xl p-4 space-y-3 z-50">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <div className="flex items-center gap-1.5 text-xs font-bold text-rose-400 font-mono">
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    <span>CRITICAL SECURITY ALERTS</span>
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-950 text-rose-300">
                    {criticalAlerts.length} active
                  </span>
                </div>

                <div className="space-y-2 max-h-72 overflow-y-auto">
                  {criticalAlerts.length === 0 ? (
                    <div className="p-4 text-center text-xs text-slate-400">
                      No open critical alerts. All posture gates pass!
                    </div>
                  ) : (
                    criticalAlerts.map((alt) => (
                      <div
                        key={alt.id}
                        onClick={() => {
                          setShowNotifications(false);
                          onNavigate?.('findings');
                        }}
                        className="p-2.5 rounded-xl bg-slate-900/90 border border-rose-900/30 hover:border-rose-700/60 cursor-pointer transition space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px] font-mono">
                          <span className="text-cyan-400">{alt.rule_id}</span>
                          <span className="text-rose-400 font-semibold">Critical</span>
                        </div>
                        <div className="text-xs font-semibold text-slate-200 line-clamp-1">
                          {alt.title}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono truncate">
                          {alt.resource_name}
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <button
                  onClick={() => {
                    setShowNotifications(false);
                    onNavigate?.('findings');
                  }}
                  className="w-full py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-cyan-400 text-xs font-semibold border border-slate-800 transition text-center block"
                >
                  View All Security Findings
                </button>
              </div>
            )}
          </div>

          {/* User Profile & Role Switcher */}
          <div className="relative">
            <button
              onClick={() => setShowRoleDropdown(!showRoleDropdown)}
              className="flex items-center gap-2.5 pl-2 pr-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs transition"
            >
              <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center text-black font-black text-xs">
                {currentRole[0]}
              </div>
              <div className="text-left hidden sm:block">
                <div className="font-bold text-white text-xs leading-none">
                  {currentRole === 'Security Administrator'
                    ? 'Sarah Connor'
                    : currentRole === 'Security Analyst'
                    ? 'Marcus Vance'
                    : 'Auditor Riley'}
                </div>
                <div className="text-[10px] text-cyan-400 font-mono leading-tight mt-0.5">
                  {currentRole}
                </div>
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            </button>

            {/* Role Switcher Menu */}
            {showRoleDropdown && (
              <div className="absolute right-0 mt-2 w-64 rounded-2xl glass-panel bg-slate-950 border border-slate-800 shadow-2xl p-2 z-50 space-y-1">
                <div className="px-3 py-2 border-b border-slate-800/80">
                  <div className="text-[11px] font-mono uppercase text-slate-400 font-bold">
                    Switch Active RBAC Role
                  </div>
                  <div className="text-[10px] text-slate-500">
                    Test different permissions live
                  </div>
                </div>

                <button
                  onClick={() => handleRoleSelect('Security Administrator')}
                  className={`w-full text-left p-2.5 rounded-xl text-xs flex items-start gap-2.5 transition ${
                    currentRole === 'Security Administrator'
                      ? 'bg-cyan-950/60 border border-cyan-800/80 text-cyan-300'
                      : 'hover:bg-slate-900 text-slate-300'
                  }`}
                >
                  <Lock className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold">Security Administrator</div>
                    <div className="text-[10px] text-slate-400">
                      Full access: Scan, Remediate, Export, Settings
                    </div>
                  </div>
                </button>

                <button
                  onClick={() => handleRoleSelect('Security Analyst')}
                  className={`w-full text-left p-2.5 rounded-xl text-xs flex items-start gap-2.5 transition ${
                    currentRole === 'Security Analyst'
                      ? 'bg-cyan-950/60 border border-cyan-800/80 text-cyan-300'
                      : 'hover:bg-slate-900 text-slate-300'
                  }`}
                >
                  <Shield className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold">Security Analyst</div>
                    <div className="text-[10px] text-slate-400">
                      View findings, CloudTrail, Reports, Update status
                    </div>
                  </div>
                </button>

                <button
                  onClick={() => handleRoleSelect('Viewer')}
                  className={`w-full text-left p-2.5 rounded-xl text-xs flex items-start gap-2.5 transition ${
                    currentRole === 'Viewer'
                      ? 'bg-cyan-950/60 border border-cyan-800/80 text-cyan-300'
                      : 'hover:bg-slate-900 text-slate-300'
                  }`}
                >
                  <User className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold">Viewer</div>
                    <div className="text-[10px] text-slate-400">
                      Read-only access to dashboards and reports
                    </div>
                  </div>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
