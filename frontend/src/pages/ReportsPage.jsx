import React, { useState, useEffect } from 'react';
import {
  FileText,
  FileDown,
  Printer,
  ShieldCheck,
  AlertOctagon,
  KeyRound,
  Activity,
  ClipboardCheck,
  RefreshCw,
  Clock
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { api } from '../services/api';

export default function ReportsPage() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getReportSummary()
      .then(setReport)
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

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadCsv = () => {
    window.open(api.getExportCsvUrl(), '_blank');
  };

  const handleDownloadJson = () => {
    window.open(api.getExportJsonUrl(), '_blank');
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Export Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800 print:hidden">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2.5">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Security & Compliance Audit Reports</span>
          </h1>
          <p className="text-xs text-slate-400">
            Generate executive compliance summaries, technical findings matrices, and downloadable auditor packages.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleDownloadCsv}
            className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition font-mono"
          >
            <FileDown className="w-3.5 h-3.5" />
            Download CSV
          </button>
          <button
            onClick={handleDownloadJson}
            className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition font-mono"
          >
            <FileDown className="w-3.5 h-3.5" />
            Download JSON
          </button>
          <button
            onClick={handlePrint}
            className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold flex items-center gap-1.5 transition shadow-[0_0_15px_rgba(0,242,254,0.3)]"
          >
            <Printer className="w-3.5 h-3.5" />
            Print / Save PDF
          </button>
        </div>
      </div>

      {/* Printable Executive Report Preview Card */}
      <div className="p-8 rounded-3xl glass-panel bg-slate-950/90 border border-slate-800 space-y-8 text-slate-200">
        {/* Document Header */}
        <div className="flex flex-col sm:flex-row sm:items-start justify-between border-b border-slate-800 pb-6 gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800 font-bold">
                AUDIT DOCUMENT #CSPM-2026-09
              </span>
              <span className="text-xs text-slate-500 font-mono">CLASSIFIED: INTERNAL</span>
            </div>
            <h2 className="text-2xl font-black text-white tracking-tight">
              {report.report_title}
            </h2>
            <div className="text-xs text-slate-400 font-mono">
              AWS Account: {report.account_id} ({report.account_name}) • Primary Region: {report.region}
            </div>
          </div>

          <div className="text-right font-mono space-y-1">
            <div className="text-xs text-slate-500">Generated On</div>
            <div className="text-xs font-bold text-white">
              {new Date(report.generated_at).toLocaleString()}
            </div>
            <div className="text-xs text-cyan-400">CSPM Engine v2.4.0</div>
          </div>
        </div>

        {/* Executive Score & Metrics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 p-5 rounded-2xl bg-slate-900/80 border border-slate-800 text-center">
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase">Overall Posture</div>
            <div className="text-3xl font-black text-white font-mono mt-1">
              {report.overall_security_score}/100
            </div>
            <div className="text-[11px] text-cyan-400 font-bold mt-0.5">{report.posture_status}</div>
          </div>

          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase">Active Findings</div>
            <div className="text-3xl font-black text-white font-mono mt-1">
              {report.total_active_findings}
            </div>
            <div className="text-[11px] text-rose-400 mt-0.5">
              {report.severity_summary?.Critical || 0} Critical / {report.severity_summary?.High || 0} High
            </div>
          </div>

          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase">Remediated Items</div>
            <div className="text-3xl font-black text-emerald-400 font-mono mt-1">
              {report.total_resolved_findings}
            </div>
            <div className="text-[11px] text-emerald-400/80 mt-0.5">Resolved configurations</div>
          </div>

          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase">Audit Compliance</div>
            <div className="text-3xl font-black text-purple-400 font-mono mt-1">
              80%
            </div>
            <div className="text-[11px] text-purple-300 mt-0.5">Average CIS & NIST pass</div>
          </div>
        </div>

        {/* Pillar Sub-Scores Row */}
        <div className="space-y-3">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
            Security Pillar Breakdown
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {Object.entries(report.pillar_scores || {}).map(([pillar, score]) => (
              <div key={pillar} className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-center">
                <div className="text-[10px] font-mono uppercase text-slate-400 truncate">{pillar}</div>
                <div className="text-xl font-black text-cyan-400 font-mono mt-1">{score}%</div>
              </div>
            ))}
          </div>
        </div>

        {/* Critical Vulnerabilities List */}
        <div className="space-y-3">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
            <AlertOctagon className="w-4 h-4" />
            <span>High-Priority Security Risks Requiring Immediate Action</span>
          </h3>
          <div className="space-y-2">
            {report.critical_vulnerabilities?.map((vuln) => (
              <div
                key={vuln.id}
                className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-900/40 space-y-1.5 text-xs"
              >
                <div className="flex items-center justify-between font-mono">
                  <span className="text-rose-400 font-bold">{vuln.title}</span>
                  <span className="text-slate-400 text-[11px]">{vuln.service} ({vuln.rule_id})</span>
                </div>
                <div className="text-slate-400 font-mono text-[11px]">
                  Resource: {vuln.resource}
                </div>
                <div className="text-slate-300 text-[11px]">
                  <strong className="text-emerald-400">Recommendation: </strong>
                  {vuln.recommendation}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Key Recommendations */}
        <div className="space-y-3 pt-2">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400">
            Strategic Remediation Roadmap
          </h3>
          <ul className="space-y-2 text-xs text-slate-300">
            {report.key_recommendations?.map((rec, idx) => (
              <li key={idx} className="flex items-start gap-2.5">
                <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 flex items-center justify-center font-mono font-bold text-[10px] shrink-0 mt-0.5">
                  {idx + 1}
                </span>
                <span className="leading-relaxed">{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
