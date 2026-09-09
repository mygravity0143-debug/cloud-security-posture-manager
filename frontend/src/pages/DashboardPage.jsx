import React, { useState } from 'react';
import {
  ShieldAlert,
  Play,
  FileDown,
  Server,
  KeyRound,
  Shield,
  Activity,
  Database,
  Lock,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Clock
} from 'lucide-react';
import ScoreGauge from '../components/ScoreGauge';
import SeverityBadge from '../components/SeverityBadge';
import { api, getActiveRole } from '../services/api';

export default function DashboardPage({
  dashboardData,
  onRefresh,
  onOpenFinding,
  onNavigate
}) {
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const currentRole = getActiveRole();
  const isAdmin = currentRole === 'Security Administrator';

  if (!dashboardData) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center space-y-3">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
          <p className="text-xs text-slate-400 font-mono">Loading CSPM Security Dashboard...</p>
        </div>
      </div>
    );
  }

  const {
    overall_security_score,
    previous_security_score,
    posture_status,
    posture_color,
    severity_summary = {},
    pillar_scores = {},
    findings_by_service = {},
    score_history = [],
    total_active_findings = 0,
    total_resolved_findings = 0,
    last_security_scan,
    aws_account = {},
    critical_alerts = [],
    recent_cloudtrail_activity = []
  } = dashboardData;

  const handleRunScan = async () => {
    if (!isAdmin) {
      alert('Access Denied: Only Security Administrator can trigger on-demand scans.');
      return;
    }
    setScanning(true);
    setScanMessage('');
    try {
      const res = await api.triggerScan();
      setScanMessage(res.message);
      onRefresh?.();
    } catch (err) {
      alert(err.message || 'Scan trigger failed');
    } finally {
      setScanning(false);
    }
  };

  const pillarCards = [
    { name: 'IAM Security', score: pillar_scores.iam_security_score ?? 80, icon: KeyRound, desc: 'MFA, Access Keys, Wildcards' },
    { name: 'Network Security', score: pillar_scores.network_security_score ?? 75, icon: Server, desc: 'VPC, SG Ports 22/3389' },
    { name: 'Logging & Audit', score: pillar_scores.logging_monitoring_score ?? 85, icon: Activity, desc: 'CloudTrail, VPC Flow Logs' },
    { name: 'Data Encryption', score: pillar_scores.encryption_score ?? 78, icon: Lock, desc: 'S3, RDS, KMS Key Rotation' },
    { name: 'Compliance Score', score: pillar_scores.compliance_score ?? 82, icon: Shield, desc: 'CIS Benchmark, NIST CSF' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner with Quick Actions */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-black text-white tracking-tight">
              Enterprise Cloud Security Posture
            </h1>
            <span className="px-2 py-0.5 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-400 text-xs font-mono font-semibold">
              Live Monitoring
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 font-mono">
            <span className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              Last Scan: {last_security_scan ? new Date(last_security_scan).toLocaleTimeString() : 'Just now'}
            </span>
            <span>•</span>
            <span>Target: AWS {aws_account.id} ({aws_account.name})</span>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleRunScan}
            disabled={scanning || !isAdmin}
            className={`px-4 py-2 rounded-xl text-xs font-bold tracking-wide flex items-center gap-2 transition ${
              isAdmin
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black shadow-[0_0_20px_rgba(0,242,254,0.3)]'
                : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
            }`}
          >
            <Play className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
            <span>{scanning ? 'Scanning AWS Environment...' : 'Run Security Scan'}</span>
          </button>

          <button
            onClick={() => onNavigate?.('reports')}
            className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-semibold flex items-center gap-2 transition"
          >
            <FileDown className="w-3.5 h-3.5 text-slate-400" />
            <span>Generate Report</span>
          </button>
        </div>
      </div>

      {scanMessage && (
        <div className="p-3 rounded-xl bg-cyan-950/80 border border-cyan-700 text-cyan-300 text-xs flex items-center gap-2 font-mono">
          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
          <span>{scanMessage}</span>
        </div>
      )}

      {/* Top Main Row: Posture Gauge & Pillar Meters */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Overall Posture Score Gauge */}
        <div className="lg:col-span-5">
          <ScoreGauge
            score={overall_security_score}
            previousScore={previous_security_score}
            statusLabel={posture_status}
            statusColor={posture_color}
          />
        </div>

        {/* Right: Pillar Scores Grid */}
        <div className="lg:col-span-7 grid grid-cols-2 sm:grid-cols-3 gap-3">
          {pillarCards.map((pillar) => {
            const Icon = pillar.icon;
            const pScore = pillar.score;
            let barColor = 'bg-cyan-400';
            if (pScore >= 85) barColor = 'bg-emerald-400';
            else if (pScore >= 70) barColor = 'bg-cyan-400';
            else if (pScore >= 50) barColor = 'bg-amber-400';
            else barColor = 'bg-rose-500';

            return (
              <div
                key={pillar.name}
                className="p-3.5 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800/80 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <div className="p-1.5 rounded-lg bg-slate-800/80 text-cyan-400">
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="font-mono text-base font-black text-white">
                    {pScore}%
                  </span>
                </div>

                <div className="space-y-1.5 mt-3">
                  <div className="font-bold text-xs text-slate-200 line-clamp-1">
                    {pillar.name}
                  </div>
                  {/* Mini progress bar */}
                  <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${barColor}`}
                      style={{ width: `${pScore}%` }}
                    />
                  </div>
                  <div className="text-[10px] text-slate-400 truncate">
                    {pillar.desc}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* KPI Stat Cards: Severity Counts */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Active */}
        <div
          onClick={() => onNavigate?.('findings')}
          className="p-3.5 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition"
        >
          <span className="text-[11px] font-mono uppercase text-slate-400 font-semibold">
            Active Findings
          </span>
          <div className="text-2xl font-black text-white font-mono mt-1">
            {total_active_findings}
          </div>
          <span className="text-[10px] text-slate-500">Total detected</span>
        </div>

        {/* Critical */}
        <div
          onClick={() => onNavigate?.('findings')}
          className="p-3.5 rounded-2xl glass-panel bg-rose-950/30 border border-rose-900/40 hover:border-rose-700 cursor-pointer transition relative overflow-hidden"
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-rose-400 font-semibold">
              Critical
            </span>
            <span className="w-2 h-2 rounded-full bg-rose-500 pulse-critical" />
          </div>
          <div className="text-2xl font-black text-rose-400 font-mono mt-1">
            {severity_summary.Critical || 0}
          </div>
          <span className="text-[10px] text-rose-400/80">Immediate threat</span>
        </div>

        {/* High */}
        <div
          onClick={() => onNavigate?.('findings')}
          className="p-3.5 rounded-2xl glass-panel bg-amber-950/20 border border-amber-900/40 hover:border-amber-700 cursor-pointer transition"
        >
          <span className="text-[11px] font-mono uppercase text-amber-400 font-semibold">
            High Risk
          </span>
          <div className="text-2xl font-black text-amber-400 font-mono mt-1">
            {severity_summary.High || 0}
          </div>
          <span className="text-[10px] text-amber-400/80">High impact</span>
        </div>

        {/* Medium */}
        <div
          onClick={() => onNavigate?.('findings')}
          className="p-3.5 rounded-2xl glass-panel bg-yellow-950/20 border border-yellow-900/40 hover:border-yellow-700 cursor-pointer transition"
        >
          <span className="text-[11px] font-mono uppercase text-yellow-400 font-semibold">
            Medium Risk
          </span>
          <div className="text-2xl font-black text-yellow-300 font-mono mt-1">
            {severity_summary.Medium || 0}
          </div>
          <span className="text-[10px] text-yellow-400/80">Moderate severity</span>
        </div>

        {/* Low */}
        <div
          onClick={() => onNavigate?.('findings')}
          className="p-3.5 rounded-2xl glass-panel bg-sky-950/20 border border-sky-900/40 hover:border-sky-700 cursor-pointer transition"
        >
          <span className="text-[11px] font-mono uppercase text-sky-400 font-semibold">
            Low Risk
          </span>
          <div className="text-2xl font-black text-sky-300 font-mono mt-1">
            {severity_summary.Low || 0}
          </div>
          <span className="text-[10px] text-sky-400/80">Best practice gap</span>
        </div>

        {/* Resolved */}
        <div
          onClick={() => onNavigate?.('findings')}
          className="p-3.5 rounded-2xl glass-panel bg-emerald-950/20 border border-emerald-900/40 hover:border-emerald-700 cursor-pointer transition"
        >
          <span className="text-[11px] font-mono uppercase text-emerald-400 font-semibold">
            Resolved
          </span>
          <div className="text-2xl font-black text-emerald-400 font-mono mt-1">
            {total_resolved_findings}
          </div>
          <span className="text-[10px] text-emerald-400/80">Remediated</span>
        </div>
      </div>

      {/* Interactive Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Chart 1: Security Score Trend Over Time */}
        <div className="lg:col-span-7 p-5 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white tracking-tight">
                Security Posture Score Over Time
              </h3>
              <p className="text-xs text-slate-400">30-day evaluation timeline and progression</p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
              Score: {overall_security_score}/100
            </span>
          </div>

          {/* SVG Trend Area Graph */}
          <div className="relative h-44 w-full pt-4">
            <svg viewBox="0 0 500 160" className="w-full h-full overflow-visible">
              <defs>
                <linearGradient id="scoreAreaGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00f2fe" stopOpacity="0.4" />
                  <stop offset="100%" stopColor="#00f2fe" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Grid Lines */}
              <line x1="0" y1="30" x2="500" y2="30" stroke="#1e293b" strokeDasharray="3 3" />
              <line x1="0" y1="75" x2="500" y2="75" stroke="#1e293b" strokeDasharray="3 3" />
              <line x1="0" y1="120" x2="500" y2="120" stroke="#1e293b" strokeDasharray="3 3" />

              {/* Y Axis Labels */}
              <text x="5" y="28" fill="#64748b" fontSize="10" fontFamily="monospace">90</text>
              <text x="5" y="73" fill="#64748b" fontSize="10" fontFamily="monospace">75</text>
              <text x="5" y="118" fill="#64748b" fontSize="10" fontFamily="monospace">60</text>

              {/* Trend Polyline & Area */}
              {(() => {
                const points = score_history.map((pt, idx) => {
                  const x = 50 + idx * 80;
                  // Map score 50..100 to y 140..20
                  const y = 140 - ((pt.score - 50) / 50) * 120;
                  return { x, y, score: pt.score, date: pt.date };
                });

                const polyPoints = points.map((p) => `${p.x},${p.y}`).join(' ');
                const areaPath = `M ${points[0].x},150 L ${points.map((p) => `${p.x},${p.y}`).join(' L ')} L ${points[points.length - 1].x},150 Z`;

                return (
                  <>
                    <path d={areaPath} fill="url(#scoreAreaGradient)" />
                    <polyline
                      fill="none"
                      stroke="#00f2fe"
                      strokeWidth="3"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      points={polyPoints}
                    />
                    {points.map((p, i) => (
                      <g key={i}>
                        <circle cx={p.x} cy={p.y} r="4" fill="#06090e" stroke="#00f2fe" strokeWidth="2.5" />
                        <text
                          x={p.x}
                          y={p.y - 8}
                          textAnchor="middle"
                          fill="#f8fafc"
                          fontSize="10"
                          fontWeight="bold"
                          fontFamily="monospace"
                        >
                          {p.score}
                        </text>
                        <text
                          x={p.x}
                          y="155"
                          textAnchor="middle"
                          fill="#94a3b8"
                          fontSize="10"
                          fontFamily="monospace"
                        >
                          {p.date}
                        </text>
                      </g>
                    ))}
                  </>
                );
              })()}
            </svg>
          </div>
        </div>

        {/* Chart 2: Findings by AWS Service */}
        <div className="lg:col-span-5 p-5 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white tracking-tight">
              Findings by AWS Service
            </h3>
            <span className="text-xs text-slate-400 font-mono">
              {Object.keys(findings_by_service).length} services affected
            </span>
          </div>

          <div className="space-y-2.5 pt-1">
            {Object.entries(findings_by_service).map(([service, count]) => {
              const maxCount = Math.max(...Object.values(findings_by_service), 1);
              const percentage = Math.round((count / maxCount) * 100);
              return (
                <div key={service} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-300 font-mono">{service}</span>
                    <span className="font-mono text-cyan-400 font-bold">{count} finding(s)</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-600 transition-all duration-700"
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bottom Row: Recent Critical Alerts & CloudTrail SOC Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Recent Critical Security Findings */}
        <div className="lg:col-span-7 p-5 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h3 className="text-sm font-bold text-white tracking-tight">
                Critical Security Findings Requiring Action
              </h3>
            </div>
            <button
              onClick={() => onNavigate?.('findings')}
              className="text-xs text-cyan-400 hover:underline font-mono"
            >
              View All Findings →
            </button>
          </div>

          <div className="space-y-2">
            {critical_alerts.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400">
                No active critical findings. Security controls healthy!
              </div>
            ) : (
              critical_alerts.map((f) => (
                <div
                  key={f.id}
                  onClick={() => onOpenFinding?.(f)}
                  className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="text-[11px] font-mono text-slate-400">
                        {f.service} • {f.rule_id}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition line-clamp-1">
                      {f.title}
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono truncate">
                      {f.resource_name}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="px-2 py-1 rounded bg-slate-800 text-[11px] font-mono text-slate-300">
                      +{f.risk_score} pts
                    </span>
                    <button className="px-3 py-1.5 rounded-lg bg-slate-800 group-hover:bg-cyan-950 group-hover:text-cyan-300 text-slate-300 text-xs font-semibold transition">
                      Details
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Live CloudTrail Activity Snippet */}
        <div className="lg:col-span-5 p-5 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white tracking-tight">
                CloudTrail Real-Time SOC Ticker
              </h3>
            </div>
            <button
              onClick={() => onNavigate?.('cloudtrail')}
              className="text-xs text-cyan-400 hover:underline font-mono"
            >
              Full Stream →
            </button>
          </div>

          <div className="space-y-2 max-h-80 overflow-y-auto">
            {recent_cloudtrail_activity.map((evt) => (
              <div
                key={evt.id}
                className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1"
              >
                <div className="flex items-center justify-between text-[11px] font-mono">
                  <span className="text-cyan-400 font-bold">{evt.event_name}</span>
                  <span className="text-slate-500">
                    {new Date(evt.event_time).toLocaleTimeString()}
                  </span>
                </div>
                <div className="text-xs text-slate-300 line-clamp-1 font-mono">
                  User: <span className="text-white font-semibold">{evt.username}</span> ({evt.source_ip})
                </div>
                <div className="text-[11px] text-slate-400 line-clamp-1">
                  {evt.details}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
