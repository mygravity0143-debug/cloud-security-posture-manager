import React, { useState, useEffect } from 'react';
import {
  Flame,
  ShieldAlert,
  AlertTriangle,
  Layers,
  ArrowUpRight,
  TrendingDown,
  RefreshCw,
  Target
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { api } from '../services/api';

export default function RiskAnalysisPage({ onNavigate }) {
  const [riskData, setRiskData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getRiskScore()
      .then(setRiskData)
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

  const {
    overall_security_score,
    posture_status,
    posture_color,
    total_penalty_points,
    points_formula,
    severity_breakdown = {},
    attack_surfaces = [],
    highest_risk_resources = []
  } = riskData || {};

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Flame className="w-5 h-5 text-rose-500" />
            <span>Risk Scoring Engine & Attack Surface Matrix</span>
          </h1>
          <p className="text-xs text-slate-400">
            Multi-dimensional risk quantification, blast radius calculations, and exposure perimeter ranking.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono">
            <span className="text-slate-400">Total Penalty:</span>{' '}
            <span className="text-rose-400 font-bold text-sm">-{total_penalty_points} pts</span>
          </div>
        </div>
      </div>

      {/* Formula & Weighting Explainer Card */}
      <div className="p-5 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
            <Target className="w-4 h-4 text-cyan-400" />
            <span>Security Posture Scoring Formula</span>
          </h3>
          <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
            Current Score: {overall_security_score}/100 ({posture_status})
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
          <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-900/50">
            <div className="text-xs font-mono font-bold text-rose-400">CRITICAL</div>
            <div className="text-xl font-black text-white font-mono mt-1">10 pts</div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              {severity_breakdown.Critical || 0} active ({ (severity_breakdown.Critical || 0) * 10 } penalty)
            </div>
          </div>

          <div className="p-3 rounded-xl bg-amber-950/30 border border-amber-900/50">
            <div className="text-xs font-mono font-bold text-amber-400">HIGH</div>
            <div className="text-xl font-black text-white font-mono mt-1">7 pts</div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              {severity_breakdown.High || 0} active ({ (severity_breakdown.High || 0) * 7 } penalty)
            </div>
          </div>

          <div className="p-3 rounded-xl bg-yellow-950/20 border border-yellow-900/50">
            <div className="text-xs font-mono font-bold text-yellow-400">MEDIUM</div>
            <div className="text-xl font-black text-white font-mono mt-1">4 pts</div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              {severity_breakdown.Medium || 0} active ({ (severity_breakdown.Medium || 0) * 4 } penalty)
            </div>
          </div>

          <div className="p-3 rounded-xl bg-sky-950/20 border border-sky-900/50">
            <div className="text-xs font-mono font-bold text-sky-400">LOW</div>
            <div className="text-xl font-black text-white font-mono mt-1">1 pt</div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              {severity_breakdown.Low || 0} active ({ (severity_breakdown.Low || 0) * 1 } penalty)
            </div>
          </div>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed font-mono bg-slate-950 p-3 rounded-xl border border-slate-800">
          Formula: Overall Posture Score is calculated dynamically on a 0–100 scale: <br />
          <span className="text-cyan-400">
            Score = max(0, 100 - [Total Penalty Points / Expected Maximum Threshold] * 100)
          </span>
          <br />Remediating a single Critical finding recovers <strong>10 full risk points</strong>!
        </p>
      </div>

      {/* Attack Surface Vectors */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {attack_surfaces.map((vec, idx) => (
          <div
            key={idx}
            className="p-4 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800 space-y-3"
          >
            <div className="flex items-start justify-between">
              <span
                className={`text-[10px] font-mono uppercase px-2.5 py-0.5 rounded-full font-bold border ${
                  vec.risk_level === 'Critical'
                    ? 'bg-rose-950 text-rose-400 border-rose-900'
                    : vec.risk_level === 'High'
                    ? 'bg-amber-950 text-amber-400 border-amber-900'
                    : 'bg-yellow-950 text-yellow-300 border-yellow-900'
                }`}
              >
                {vec.risk_level} Vector
              </span>
              <span className="text-xs font-mono text-cyan-400 font-bold">
                {vec.findings_count} finding(s)
              </span>
            </div>

            <div>
              <h3 className="text-xs font-bold text-white tracking-tight">{vec.category}</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">{vec.description}</p>
            </div>

            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-300">
              <span className="text-emerald-400 font-semibold">Remediation: </span>
              {vec.recommendation}
            </div>
          </div>
        ))}
      </div>

      {/* Highest Risk Resources List */}
      <div className="rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 bg-slate-900/80 flex items-center justify-between">
          <h3 className="text-sm font-bold text-white tracking-tight">
            Highest Risk Cloud Resources (Target Attack Perimeter)
          </h3>
          <button
            onClick={() => onNavigate?.('resources')}
            className="text-xs text-cyan-400 hover:underline font-mono"
          >
            View All Assets →
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400 font-mono uppercase">
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Resource Name / ID</th>
                <th className="p-3.5">Service</th>
                <th className="p-3.5">Top Vulnerability Trigger</th>
                <th className="p-3.5">Risk Penalty</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-300 font-mono">
              {highest_risk_resources.map((item) => (
                <tr key={item.resource_id} className="hover:bg-slate-900/50 transition">
                  <td className="p-3.5">
                    <SeverityBadge severity={item.severity} />
                  </td>
                  <td className="p-3.5">
                    <div className="font-bold text-white text-xs font-sans">{item.resource_name}</div>
                    <div className="text-[10px] text-slate-500 truncate max-w-[240px]">{item.resource_id}</div>
                  </td>
                  <td className="p-3.5 uppercase font-bold text-slate-200">
                    {item.service}
                  </td>
                  <td className="p-3.5 text-xs text-slate-300 font-sans max-w-sm line-clamp-1">
                    {item.top_finding}
                  </td>
                  <td className="p-3.5 font-bold text-rose-400">
                    +{item.risk_score} pts
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
