import React, { useState, useEffect } from 'react';
import {
  ClipboardCheck,
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { api } from '../services/api';

export default function CompliancePage({ onOpenFinding }) {
  const [complianceData, setComplianceData] = useState(null);
  const [selectedFrameworkId, setSelectedFrameworkId] = useState('cis_aws');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getCompliance()
      .then((data) => {
        setComplianceData(data);
        if (data.frameworks?.length > 0) {
          setSelectedFrameworkId(data.frameworks[0].id);
        }
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

  const frameworks = complianceData?.frameworks || [];
  const activeFw = frameworks.find((f) => f.id === selectedFrameworkId) || frameworks[0];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2.5">
            <ClipboardCheck className="w-5 h-5 text-cyan-400" />
            <span>Compliance & Regulatory Posture</span>
          </h1>
          <p className="text-xs text-slate-400">
            Mapping security configurations to industry cloud standards, CIS benchmarks, and audit control frameworks.
          </p>
        </div>

        <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono">
          <span className="text-slate-400">Average Compliance:</span>
          <span className="text-cyan-400 font-bold text-sm">
            {complianceData?.overall_compliance_percentage || 80}%
          </span>
        </div>
      </div>

      {/* Framework Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {frameworks.map((fw) => {
          const isSelected = fw.id === selectedFrameworkId;
          const score = fw.score_percent;
          let badgeColor = 'text-cyan-400 border-cyan-500/40 bg-cyan-950/60';
          if (score >= 85) badgeColor = 'text-emerald-400 border-emerald-500/40 bg-emerald-950/60';
          else if (score < 70) badgeColor = 'text-rose-400 border-rose-500/40 bg-rose-950/60';

          return (
            <div
              key={fw.id}
              onClick={() => setSelectedFrameworkId(fw.id)}
              className={`p-4 rounded-2xl border cursor-pointer transition flex flex-col justify-between space-y-3 ${
                isSelected
                  ? 'glass-panel-glow bg-slate-900/90 border-cyan-500 shadow-[0_0_20px_rgba(0,242,254,0.15)]'
                  : 'glass-panel bg-slate-950/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between">
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-semibold">
                  {fw.category}
                </span>
                <span className={`text-base font-black font-mono px-2 py-0.5 rounded-lg border ${badgeColor}`}>
                  {score}%
                </span>
              </div>

              <div>
                <h3 className="text-xs font-bold text-white tracking-tight">{fw.name}</h3>
                <span className="text-[11px] text-slate-400 font-mono">{fw.version}</span>
              </div>

              {/* Progress bar */}
              <div className="space-y-1.5 pt-1">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span className="text-emerald-400">{fw.passed_controls} Passed</span>
                  <span className="text-rose-400">{fw.failed_controls} Failed</span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-400 transition-all duration-700"
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Framework Control Breakdown Table */}
      {activeFw && (
        <div className="rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 overflow-hidden space-y-0">
          <div className="p-4 border-b border-slate-800 bg-slate-900/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                <span>{activeFw.name} Controls Evaluation</span>
                <span className="text-xs font-mono text-cyan-400">({activeFw.version})</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Detailed audit checklist with pass/fail telemetry and actionable remediation paths.
              </p>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-emerald-400 font-bold">{activeFw.passed_controls} Compliant</span>
              <span className="text-slate-500">•</span>
              <span className="text-rose-400 font-bold">{activeFw.failed_controls} Non-Compliant</span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400 font-mono uppercase">
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5">Control ID</th>
                  <th className="p-3.5">Domain / Section</th>
                  <th className="p-3.5">Control Objective & Requirements</th>
                  <th className="p-3.5">Mapped Rule</th>
                  <th className="p-3.5">Recommendation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-300">
                {activeFw.controls?.map((ctrl) => {
                  const isFailed = ctrl.status === 'FAILED';

                  return (
                    <tr
                      key={ctrl.control_id}
                      className={`hover:bg-slate-900/50 transition ${
                        isFailed ? 'bg-rose-950/10' : ''
                      }`}
                    >
                      <td className="p-3.5">
                        {isFailed ? (
                          <span className="inline-flex items-center gap-1 font-bold text-rose-400 font-mono text-[11px] bg-rose-950/80 px-2 py-0.5 rounded border border-rose-900">
                            <XCircle className="w-3.5 h-3.5" />
                            FAILED
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 font-bold text-emerald-400 font-mono text-[11px]">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            PASSED
                          </span>
                        )}
                      </td>

                      <td className="p-3.5 font-mono font-bold text-cyan-400">
                        {ctrl.control_id}
                      </td>

                      <td className="p-3.5 font-mono text-slate-400 text-[11px]">
                        {ctrl.section}
                      </td>

                      <td className="p-3.5 text-slate-200 font-medium max-w-sm">
                        {ctrl.title}
                      </td>

                      <td className="p-3.5 font-mono text-[11px] text-slate-400">
                        {ctrl.mapped_rule}
                      </td>

                      <td className="p-3.5 text-xs text-slate-300 max-w-xs">
                        <div className="text-[11px] text-slate-400 leading-relaxed">
                          {ctrl.recommendation}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
