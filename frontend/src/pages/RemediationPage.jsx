import React, { useState, useEffect } from 'react';
import {
  Wrench,
  CheckCircle2,
  AlertTriangle,
  History,
  Terminal,
  Layers,
  Shield,
  RefreshCw,
  Copy,
  Check
} from 'lucide-react';
import { api, getActiveRole } from '../services/api';

export default function RemediationPage({ onRefreshDashboard, onNavigate }) {
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('actions'); // 'actions' or 'audit'
  const [remediatingKey, setRemediatingKey] = useState(null);
  const [successBanner, setSuccessBanner] = useState('');
  const [errorBanner, setErrorBanner] = useState('');

  const currentRole = getActiveRole();
  const isAdmin = currentRole === 'Security Administrator';

  const fetchAuditLogs = async () => {
    setLoading(true);
    try {
      const data = await api.getRemediationAuditLog();
      setAuditLogs(data.audit_logs || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  const SAFE_ACTIONS = [
    {
      id: 'FIND-S3-PUB-acme-customer-pii-raw',
      title: 'Enforce S3 Block Public Access on PII Data Bucket',
      resource: 'acme-customer-pii-raw',
      service: 'S3',
      severity: 'Critical',
      impact: 'Blocks anonymous internet reads/writes and secures 142,000+ files.',
      actionDesc: 'Applies S3 BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets.',
    },
    {
      id: 'FIND-EC2-SSH-sg-0a1b2c3d4e5f-public-web',
      title: 'Revoke Unrestricted SSH (0.0.0.0/0:22) on Public SG',
      resource: 'sg-0a1b2c3d4e5f-public-web',
      service: 'EC2 Security Groups',
      severity: 'Critical',
      impact: 'Removes global ingress on port 22, stopping brute force attacks.',
      actionDesc: 'Revokes ingress rule matching protocol tcp port 22 cidr 0.0.0.0/0.',
    },
    {
      id: 'FIND-EC2-RDP-sg-0987654321ab-bastion',
      title: 'Revoke Unrestricted RDP (0.0.0.0/0:3389) on Bastion SG',
      resource: 'sg-0987654321ab-bastion',
      service: 'EC2 Security Groups',
      severity: 'Critical',
      impact: 'Prevents unauthorized remote desktop access to Windows hosts.',
      actionDesc: 'Revokes ingress rule matching port 3389 cidr 0.0.0.0/0.',
    },
    {
      id: 'FIND-KMS-ROT-key-prod-data-key-001',
      title: 'Enable Automatic Annual KMS CMK Key Rotation',
      resource: 'alias/prod-data-encryption-key',
      service: 'KMS',
      severity: 'Medium',
      impact: 'Rotates customer encryption key yearly without breaking existing ciphertext.',
      actionDesc: 'Calls kms:EnableKeyRotation on key-prod-data-key-001.',
    },
    {
      id: 'FIND-EC2-IMDS-i-0a1b2c3d4e5f67890',
      title: 'Enforce IMDSv2 (Session Tokens) on Backend EC2',
      resource: 'prod-api-server-01 (i-0a1b2c3d4e5f67890)',
      service: 'EC2',
      severity: 'Medium',
      impact: 'Eliminates Server-Side Request Forgery (SSRF) role credential theft.',
      actionDesc: 'Sets MetadataOptions HttpTokens = required.',
    },
    {
      id: 'FIND-IAM-KEY-AKIAI44QH8DHBEXAMPLE2',
      title: 'Deactivate Compromised/Old Access Key (>90 days)',
      resource: 'alex.dev (AKIAI44QH8DHBEXAMPLE2)',
      service: 'IAM',
      severity: 'Medium',
      impact: 'Deactivates static developer key older than 145 days.',
      actionDesc: 'Updates access key status to Inactive.',
    },
  ];

  const handleExecute = async (findingId) => {
    if (!isAdmin) {
      setErrorBanner('Permission Denied: Only Security Administrator can trigger automated remediations.');
      return;
    }
    setRemediatingKey(findingId);
    setSuccessBanner('');
    setErrorBanner('');
    try {
      const res = await api.executeRemediation(findingId);
      if (res.success) {
        setSuccessBanner(res.message);
        fetchAuditLogs();
        onRefreshDashboard?.();
      } else {
        setErrorBanner(res.message || 'Remediation failed');
      }
    } catch (err) {
      setErrorBanner(err.message || 'Remediation execution error');
    } finally {
      setRemediatingKey(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Wrench className="w-5 h-5 text-cyan-400" />
            <span>Automated Security Remediation Console</span>
          </h1>
          <p className="text-xs text-slate-400">
            One-click safe cloud configuration fixes, automated rollback safety, and immutable remediation audit trails.
          </p>
        </div>

        {/* Tab switch */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('actions')}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === 'actions'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'bg-slate-900 text-slate-400 hover:text-white'
            }`}
          >
            1-Click Remediations
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold uppercase tracking-wider transition flex items-center gap-1.5 ${
              activeTab === 'audit'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'bg-slate-900 text-slate-400 hover:text-white'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            Remediation Audit Log ({auditLogs.length})
          </button>
        </div>
      </div>

      {/* RBAC Notice */}
      <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-400 flex items-center justify-between font-mono">
        <div>
          <span>Active Role: </span>
          <strong className="text-white">{currentRole}</strong>
          {!isAdmin && (
            <span className="text-amber-400 ml-2">
              (View-only access. Switch to Security Administrator to apply fixes)
            </span>
          )}
        </div>
        <span className="text-emerald-400 font-bold">Safe Mode Active</span>
      </div>

      {successBanner && (
        <div className="p-3.5 rounded-xl bg-emerald-950/80 border border-emerald-700 text-emerald-300 text-xs flex items-center gap-2 font-mono">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{successBanner}</span>
        </div>
      )}

      {errorBanner && (
        <div className="p-3.5 rounded-xl bg-rose-950/80 border border-rose-700 text-rose-300 text-xs flex items-center gap-2 font-mono">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorBanner}</span>
        </div>
      )}

      {/* Main Tab Content */}
      {activeTab === 'actions' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {SAFE_ACTIONS.map((action) => {
            const isWorking = remediatingKey === action.id;

            return (
              <div
                key={action.id}
                className="p-5 rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 hover:border-cyan-500/40 transition flex flex-col justify-between space-y-4 group"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-400 font-bold">
                      {action.service}
                    </span>
                    <span
                      className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold ${
                        action.severity === 'Critical'
                          ? 'bg-rose-950 text-rose-400 border border-rose-900'
                          : 'bg-yellow-950 text-yellow-300 border border-yellow-900'
                      }`}
                    >
                      {action.severity}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-white tracking-tight group-hover:text-cyan-300 transition">
                    {action.title}
                  </h3>

                  <div className="text-[11px] font-mono text-slate-400 truncate">
                    Target: {action.resource}
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed font-sans">
                    {action.impact}
                  </p>

                  <div className="text-[11px] text-slate-500 font-mono bg-slate-900/60 p-2.5 rounded-xl border border-slate-800">
                    Action: {action.actionDesc}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                  <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    Zero downtime safe
                  </span>

                  <button
                    onClick={() => handleExecute(action.id)}
                    disabled={isWorking || !isAdmin}
                    className={`px-4 py-2 rounded-xl text-xs font-bold tracking-wide flex items-center gap-1.5 transition ${
                      isAdmin
                        ? 'bg-cyan-500 hover:bg-cyan-400 text-black shadow-[0_0_15px_rgba(0,242,254,0.3)]'
                        : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                    }`}
                  >
                    <Wrench className={`w-3.5 h-3.5 ${isWorking ? 'animate-spin' : ''}`} />
                    <span>{isWorking ? 'Executing...' : '1-Click Remediate'}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* Remediation Audit Log Table */
        <div className="rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 overflow-hidden">
          <div className="p-4 border-b border-slate-800 bg-slate-900/80 flex items-center justify-between">
            <h3 className="text-sm font-bold text-white tracking-tight">
              Remediation Execution Audit Trail (Immutable Records)
            </h3>
            <span className="text-xs text-slate-400 font-mono">
              SOC Compliance Audit Log
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400 font-mono uppercase">
                  <th className="p-3.5">Audit ID</th>
                  <th className="p-3.5">Action Executed</th>
                  <th className="p-3.5">Initiated By</th>
                  <th className="p-3.5">Timestamp</th>
                  <th className="p-3.5">Execution Result</th>
                  <th className="p-3.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-300 font-mono">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-900/50 transition">
                    <td className="p-3.5 font-bold text-cyan-400">
                      {log.id}
                    </td>
                    <td className="p-3.5 font-sans font-medium text-white max-w-xs">
                      {log.action}
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5">{log.finding_id}</div>
                    </td>
                    <td className="p-3.5 text-slate-300 text-[11px]">
                      {log.user}
                    </td>
                    <td className="p-3.5 text-slate-400 text-[11px]">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="p-3.5 text-emerald-400 text-[11px] font-sans">
                      {log.result}
                    </td>
                    <td className="p-3.5">
                      <span className="px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold uppercase">
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
