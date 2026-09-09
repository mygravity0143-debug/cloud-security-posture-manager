import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  UserX,
  Clock,
  Lock,
  AlertOctagon,
  RefreshCw,
  ExternalLink
} from 'lucide-react';
import { api } from '../services/api';

export default function IamAnalyzerPage({ onOpenFinding }) {
  const [userData, setUserData] = useState(null);
  const [roleData, setRoleData] = useState(null);
  const [summaryData, setSummaryData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('users'); // 'users' or 'roles'

  useEffect(() => {
    Promise.all([api.getIamUsers(), api.getIamRoles(), api.getIamSummary()])
      .then(([users, roles, summary]) => {
        setUserData(users);
        setRoleData(roles);
        setSummaryData(summary);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const rootMfa = summaryData?.root_mfa_enabled;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2.5">
            <KeyRound className="w-5 h-5 text-cyan-400" />
            <span>IAM Security Analyzer</span>
          </h1>
          <p className="text-xs text-slate-400">
            Identity governance, MFA posture evaluation, access key hygiene, and privilege escalation detection.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('users')}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === 'users'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'bg-slate-900 text-slate-400 hover:text-white'
            }`}
          >
            IAM Users ({userData?.users?.length || 0})
          </button>
          <button
            onClick={() => setActiveTab('roles')}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === 'roles'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'bg-slate-900 text-slate-400 hover:text-white'
            }`}
          >
            IAM Roles ({roleData?.roles?.length || 0})
          </button>
        </div>
      </div>

      {/* Root Account MFA Warning or Pass Banner */}
      <div
        className={`p-4 rounded-2xl border flex items-start gap-3.5 ${
          !rootMfa
            ? 'bg-rose-950/40 border-rose-800/80 text-rose-200'
            : 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
        }`}
      >
        {!rootMfa ? (
          <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0 mt-0.5" />
        ) : (
          <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5" />
        )}
        <div className="space-y-1 text-xs">
          <div className="font-bold font-mono uppercase tracking-wide">
            {!rootMfa
              ? 'CRITICAL SECURITY DEFICIENCY: Root Account MFA is Disabled'
              : 'AWS Root Account MFA is Securely Enforced'}
          </div>
          <p className="text-slate-300 leading-relaxed">
            {!rootMfa
              ? "The AWS root account currently has no Multi-Factor Authentication (MFA) device bound. A breach of root credentials provides attackers permanent, unrestricted control over the cloud environment. Enable a hardware or virtual MFA device immediately."
              : "Hardware or virtual MFA device is actively enforced for the account owner. Least privilege policies recommended."}
          </p>
        </div>
      </div>

      {/* Top IAM Summary KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-4 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] font-mono uppercase text-slate-400 font-semibold">
            Total IAM Users
          </span>
          <div className="text-2xl font-black text-white font-mono mt-1">
            {summaryData?.total_iam_users || 0}
          </div>
          <span className="text-[10px] text-slate-500">Evaluated accounts</span>
        </div>

        <div className="p-4 rounded-2xl glass-panel bg-amber-950/20 border border-amber-900/40">
          <span className="text-[11px] font-mono uppercase text-amber-400 font-semibold">
            Users Without MFA
          </span>
          <div className="text-2xl font-black text-amber-400 font-mono mt-1">
            {summaryData?.users_without_mfa || 0}
          </div>
          <span className="text-[10px] text-amber-400/80">Console login risk</span>
        </div>

        <div className="p-4 rounded-2xl glass-panel bg-yellow-950/20 border border-yellow-900/40">
          <span className="text-[11px] font-mono uppercase text-yellow-400 font-semibold">
            Keys Older than 90 Days
          </span>
          <div className="text-2xl font-black text-yellow-300 font-mono mt-1">
            {summaryData?.active_keys_over_90_days || 0}
          </div>
          <span className="text-[10px] text-yellow-400/80">Require rotation</span>
        </div>

        <div className="p-4 rounded-2xl glass-panel bg-rose-950/20 border border-rose-900/40">
          <span className="text-[11px] font-mono uppercase text-rose-400 font-semibold">
            Admin Privileges
          </span>
          <div className="text-2xl font-black text-rose-400 font-mono mt-1">
            {summaryData?.users_with_admin_privileges || 0}
          </div>
          <span className="text-[10px] text-rose-400/80">AdministratorAccess</span>
        </div>
      </div>

      {/* Main Table View */}
      {activeTab === 'users' ? (
        <div className="rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 overflow-hidden">
          <div className="p-4 border-b border-slate-800 bg-slate-900/80 flex items-center justify-between">
            <h3 className="text-sm font-bold text-white tracking-tight">
              IAM User Security & Credential Inventory
            </h3>
            <span className="text-xs font-mono text-slate-400">
              Evaluated against CIS Section 1
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400 font-mono uppercase">
                  <th className="p-3.5">User / ARN</th>
                  <th className="p-3.5">MFA Status</th>
                  <th className="p-3.5">Access Keys</th>
                  <th className="p-3.5">Last Activity</th>
                  <th className="p-3.5">Assigned Policies</th>
                  <th className="p-3.5">Risk Rating</th>
                  <th className="p-3.5">Risk Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-300">
                {userData?.users?.map((u) => {
                  const isCritical = u.risk_level === 'Critical';
                  const isHigh = u.risk_level === 'High';
                  const isMedium = u.risk_level === 'Medium';
                  const isSecure = u.risk_level === 'Secure';

                  return (
                    <tr key={u.username} className="hover:bg-slate-900/50 transition">
                      <td className="p-3.5 font-mono">
                        <div className="font-bold text-white text-xs">{u.username}</div>
                        <div className="text-[10px] text-slate-500 truncate max-w-[180px]">{u.arn}</div>
                      </td>

                      <td className="p-3.5">
                        {u.mfa_enabled ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-400 font-mono">
                            <UserCheck className="w-3.5 h-3.5" />
                            Enabled
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-rose-400 font-mono bg-rose-950/60 px-2 py-0.5 rounded border border-rose-900">
                            <UserX className="w-3.5 h-3.5" />
                            Missing
                          </span>
                        )}
                      </td>

                      <td className="p-3.5 font-mono text-[11px]">
                        {u.access_keys?.length === 0 ? (
                          <span className="text-slate-500">None</span>
                        ) : (
                          u.access_keys?.map((k) => (
                            <div key={k.key_id} className="space-y-0.5">
                              <span className="text-slate-300">{k.key_id.substring(0, 10)}...</span>
                              <span
                                className={`ml-1 text-[10px] ${
                                  k.age_days > 90 ? 'text-amber-400 font-bold' : 'text-slate-500'
                                }`}
                              >
                                ({k.age_days}d old)
                              </span>
                            </div>
                          ))
                        )}
                      </td>

                      <td className="p-3.5 font-mono text-[11px] text-slate-400">
                        {u.days_inactive === 0 ? 'Active Today' : `${u.days_inactive} days ago`}
                      </td>

                      <td className="p-3.5">
                        <div className="flex flex-wrap gap-1 max-w-xs">
                          {u.attached_policies?.map((p) => (
                            <span
                              key={p.name}
                              className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                                p.has_wildcard
                                  ? 'bg-rose-950 text-rose-300 border border-rose-800 font-bold'
                                  : 'bg-slate-800 text-slate-300'
                              }`}
                            >
                              {p.name}
                            </span>
                          ))}
                        </div>
                      </td>

                      <td className="p-3.5">
                        <span
                          className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                            isCritical
                              ? 'bg-rose-950 text-rose-400 border border-rose-800'
                              : isHigh
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : isMedium
                              ? 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                              : isSecure
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {u.risk_level}
                        </span>
                      </td>

                      <td className="p-3.5 text-xs text-slate-400 max-w-xs">
                        {u.risk_reason}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* IAM Roles Table */
        <div className="rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 overflow-hidden">
          <div className="p-4 border-b border-slate-800 bg-slate-900/80">
            <h3 className="text-sm font-bold text-white tracking-tight">
              IAM Roles & Trust Relationships
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400 font-mono uppercase">
                  <th className="p-3.5">Role Name</th>
                  <th className="p-3.5">Trust Principal</th>
                  <th className="p-3.5">Attached Policies</th>
                  <th className="p-3.5">Risk Rating</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-300">
                {roleData?.roles?.map((r) => (
                  <tr key={r.role_name} className="hover:bg-slate-900/50 transition">
                    <td className="p-3.5 font-mono font-bold text-white">
                      {r.role_name}
                    </td>
                    <td className="p-3.5 font-mono text-[11px] text-cyan-400">
                      {r.trust_principal}
                    </td>
                    <td className="p-3.5">
                      <div className="flex flex-wrap gap-1">
                        {r.attached_policies?.map((pol) => (
                          <span
                            key={pol}
                            className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                              pol === 'AdministratorAccess'
                                ? 'bg-rose-950 text-rose-300 border border-rose-800 font-bold'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {pol}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="p-3.5">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                          r.risk_level === 'Critical'
                            ? 'bg-rose-950 text-rose-400 border border-rose-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}
                      >
                        {r.risk_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* IAM Hardening Best Practices Guide Card */}
      <div className="p-5 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 space-y-3">
        <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          <span>Recommended IAM Hardening Actions</span>
        </h3>
        <ul className="space-y-2 text-xs text-slate-300">
          <li className="flex items-start gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
            <span>
              <strong>Remove Direct AdministratorAccess:</strong> Do not attach AdministratorAccess directly to users. Transition to AWS IAM Identity Center (SSO) with short-lived session tokens.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
            <span>
              <strong>Mandate MFA Registration:</strong> Implement an IAM condition statement (<code>aws:MultiFactorAuthPresent: true</code>) that denies all API/Console actions until MFA is authenticated.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
            <span>
              <strong>Automate Access Key Expiration:</strong> Programmatically deactivate any IAM access keys older than 90 days and mandate IAM roles for automated pipelines (GitHub Actions OIDC, etc.).
            </span>
          </li>
        </ul>
      </div>
    </div>
  );
}
