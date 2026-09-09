import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldAlert,
  Wrench,
  Terminal,
  CheckCircle2,
  Copy,
  Check,
  AlertTriangle,
  ExternalLink,
  Lock,
  Layers
} from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import { api, getActiveRole } from '../services/api';

export default function FindingDetailModal({ finding, onClose, onFindingUpdated }) {
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' or 'remediation'
  const [snippets, setSnippets] = useState(null);
  const [loadingSnippets, setLoadingSnippets] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState('');
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [remediating, setRemediating] = useState(false);
  const [actionSuccess, setActionSuccess] = useState('');
  const [actionError, setActionError] = useState('');

  const currentRole = getActiveRole();
  const isAdmin = currentRole === 'Security Administrator';

  useEffect(() => {
    if (finding?.id) {
      setLoadingSnippets(true);
      api
        .getRemediationSnippets(finding.id)
        .then((data) => setSnippets(data.snippets))
        .catch(() => setSnippets(null))
        .finally(() => setLoadingSnippets(false));
    }
  }, [finding?.id]);

  if (!finding) return null;

  const handleStatusChange = async (newStatus) => {
    setUpdatingStatus(true);
    setActionSuccess('');
    setActionError('');
    try {
      await api.updateFindingStatus(finding.id, newStatus);
      setActionSuccess(`Status successfully updated to "${newStatus}"`);
      onFindingUpdated?.();
    } catch (err) {
      setActionError(err.message || 'Failed to update status');
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleExecuteRemediation = async () => {
    if (!isAdmin) {
      setActionError('Permission Denied: Only Security Administrator can trigger automated remediation.');
      return;
    }
    setRemediating(true);
    setActionSuccess('');
    setActionError('');
    try {
      const res = await api.executeRemediation(finding.id);
      if (res.success) {
        setActionSuccess(res.message || 'Automated remediation executed successfully.');
        onFindingUpdated?.();
      } else {
        setActionError(res.message || 'Remediation failed');
      }
    } catch (err) {
      setActionError(err.message || 'Remediation request error');
    } finally {
      setRemediating(false);
    }
  };

  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippet(type);
    setTimeout(() => setCopiedSnippet(''), 2500);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-3xl my-8 rounded-2xl glass-panel-glow bg-slate-900/95 border border-slate-700 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b border-slate-800 bg-slate-950/60">
          <div className="space-y-1.5 pr-6">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800">
                {finding.id}
              </span>
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold uppercase">
                {finding.service}
              </span>
              <span className="text-xs font-mono text-slate-400">
                Rule: {finding.rule_id}
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              {finding.title}
            </h2>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 bg-slate-950/40 px-6">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition ${
              activeTab === 'overview'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Finding Details & Evidence
          </button>
          <button
            onClick={() => setActiveTab('remediation')}
            className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'remediation'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Wrench className="w-3.5 h-3.5" />
            Remediation & Code Snippets
          </button>
        </div>

        {/* Notification alerts */}
        {actionSuccess && (
          <div className="mx-6 mt-4 p-3 rounded-lg bg-emerald-950/80 border border-emerald-700 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            <span>{actionSuccess}</span>
          </div>
        )}
        {actionError && (
          <div className="mx-6 mt-4 p-3 rounded-lg bg-rose-950/80 border border-rose-700 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{actionError}</span>
          </div>
        )}

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-slate-300 text-sm">
          {activeTab === 'overview' ? (
            <>
              {/* Metadata Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 rounded-xl bg-slate-950/50 border border-slate-800/80 text-xs">
                <div>
                  <span className="text-slate-500 uppercase font-mono">Affected Resource</span>
                  <div className="font-semibold text-white mt-0.5 break-all">{finding.resource_name}</div>
                  <div className="font-mono text-slate-400 mt-0.5 text-[11px] break-all">{finding.resource_id}</div>
                </div>
                <div>
                  <span className="text-slate-500 uppercase font-mono">AWS Account / Region</span>
                  <div className="font-semibold text-white mt-0.5">{finding.account_id} (Production)</div>
                  <div className="text-slate-400 mt-0.5">{finding.region}</div>
                </div>
                <div>
                  <span className="text-slate-500 uppercase font-mono">Risk Points (Weight)</span>
                  <div className="font-semibold text-rose-400 mt-0.5 font-mono">
                    +{finding.risk_score} points penalty
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 uppercase font-mono">Detection Time</span>
                  <div className="font-mono text-slate-400 mt-0.5">{finding.detected_at}</div>
                </div>
              </div>

              {/* Description */}
              <div className="space-y-1.5">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  Security Risk Description
                </h4>
                <p className="text-slate-300 leading-relaxed bg-slate-950/40 p-3 rounded-xl border border-slate-800/60">
                  {finding.description}
                </p>
              </div>

              {/* Evidence */}
              <div className="space-y-1.5">
                <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  Configuration Evidence
                </h4>
                <div className="font-mono text-xs bg-slate-950 p-3.5 rounded-xl border border-slate-800 text-amber-300 break-all">
                  {finding.evidence}
                </div>
              </div>

              {/* Compliance Mappings */}
              {finding.compliance_mappings && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5" />
                    Mapped Compliance Controls
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(finding.compliance_mappings).map(([std, ctrl]) => (
                      <span
                        key={std}
                        className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 text-xs font-mono"
                      >
                        <strong className="text-cyan-400">{std}:</strong> {ctrl}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendation */}
              <div className="space-y-1.5">
                <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Actionable Recommendation
                </h4>
                <p className="text-slate-200 bg-emerald-950/20 p-3 rounded-xl border border-emerald-900/40 leading-relaxed text-xs">
                  {finding.recommendation}
                </p>
              </div>
            </>
          ) : (
            <>
              {/* Remediation Tab */}
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs uppercase font-mono text-slate-400 font-bold">
                      Remediation Strategy
                    </span>
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-bold uppercase ${
                        finding.remediation_type === 'automated'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : 'bg-slate-800 text-slate-400 border border-slate-700'
                      }`}
                    >
                      {finding.remediation_type === 'automated'
                        ? '1-Click Safe Automated Fix'
                        : 'Manual AWS Console/CLI Action'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {finding.recommendation}
                  </p>
                </div>

                {/* Code Snippets (CLI & Terraform) */}
                {loadingSnippets ? (
                  <div className="p-8 text-center text-xs text-slate-500 font-mono">
                    Generating remediation code snippets...
                  </div>
                ) : snippets ? (
                  <div className="space-y-4">
                    {/* AWS CLI */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono text-cyan-400 font-bold flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5" /> AWS CLI Command
                        </span>
                        <button
                          onClick={() => copyToClipboard(snippets.aws_cli, 'cli')}
                          className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 font-mono transition"
                        >
                          {copiedSnippet === 'cli' ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                          <span>{copiedSnippet === 'cli' ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto">
                        {snippets.aws_cli}
                      </pre>
                    </div>

                    {/* Terraform */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono text-purple-400 font-bold flex items-center gap-1.5">
                          <Layers className="w-3.5 h-3.5" /> Terraform (IaC) Snippet
                        </span>
                        <button
                          onClick={() => copyToClipboard(snippets.terraform, 'tf')}
                          className="text-xs text-slate-400 hover:text-purple-400 flex items-center gap-1 font-mono transition"
                        >
                          {copiedSnippet === 'tf' ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                          <span>{copiedSnippet === 'tf' ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-purple-300 overflow-x-auto">
                        {snippets.terraform}
                      </pre>
                    </div>
                  </div>
                ) : null}
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex flex-wrap items-center justify-between p-4 border-t border-slate-800 bg-slate-950/80 gap-3">
          {/* Finding Status Transition dropdown */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">Status:</span>
            <select
              value={finding.status}
              disabled={updatingStatus}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-semibold text-white focus:outline-none focus:border-cyan-400"
            >
              <option value="Open">Open</option>
              <option value="In Progress">In Progress</option>
              <option value="Accepted Risk">Accepted Risk</option>
              <option value="Resolved">Resolved</option>
            </select>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-3">
            {finding.remediation_type === 'automated' && finding.status !== 'Resolved' && (
              <button
                onClick={handleExecuteRemediation}
                disabled={remediating || !isAdmin}
                title={!isAdmin ? 'Only Security Administrator can execute remediation' : ''}
                className={`px-4 py-2 rounded-xl text-xs font-bold tracking-wide flex items-center gap-1.5 transition ${
                  isAdmin
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black shadow-[0_0_15px_rgba(0,242,254,0.3)]'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                }`}
              >
                <Wrench className="w-3.5 h-3.5" />
                <span>{remediating ? 'Applying Fix...' : '1-Click Remediate'}</span>
              </button>
            )}

            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
