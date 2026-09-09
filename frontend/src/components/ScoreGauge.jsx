import React from 'react';
import { ShieldCheck, TrendingUp, TrendingDown } from 'lucide-react';

export default function ScoreGauge({ score = 82, previousScore = 74, statusLabel = 'Good', statusColor = 'blue' }) {
  // SVG circular arc calculations
  const size = 180;
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const scoreDelta = score - previousScore;

  // Determine stroke color
  let strokeGradientId = 'gauge-blue';
  let glowColor = 'rgba(56, 189, 248, 0.4)';
  if (score >= 85) {
    strokeGradientId = 'gauge-emerald';
    glowColor = 'rgba(16, 185, 129, 0.4)';
  } else if (score >= 70) {
    strokeGradientId = 'gauge-blue';
    glowColor = 'rgba(56, 189, 248, 0.4)';
  } else if (score >= 50) {
    strokeGradientId = 'gauge-amber';
    glowColor = 'rgba(245, 158, 11, 0.4)';
  } else {
    strokeGradientId = 'gauge-rose';
    glowColor = 'rgba(244, 63, 94, 0.4)';
  }

  return (
    <div className="flex flex-col sm:flex-row items-center gap-6 p-6 rounded-2xl glass-panel relative overflow-hidden">
      {/* Background cyber radial glow */}
      <div
        className="absolute w-44 h-44 rounded-full blur-3xl opacity-20 pointer-events-none"
        style={{ backgroundColor: glowColor, top: '-20px', left: '-20px' }}
      />

      {/* SVG Circular Gauge */}
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="transform -rotate-90">
          <defs>
            <linearGradient id="gauge-emerald" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#10b981" />
              <stop offset="100%" stopColor="#34d399" />
            </linearGradient>
            <linearGradient id="gauge-blue" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#00f2fe" />
              <stop offset="100%" stopColor="#4facfe" />
            </linearGradient>
            <linearGradient id="gauge-amber" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#f59e0b" />
              <stop offset="100%" stopColor="#fbbf24" />
            </linearGradient>
            <linearGradient id="gauge-rose" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#f43f5e" />
              <stop offset="100%" stopColor="#fb7185" />
            </linearGradient>
          </defs>

          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="none"
          />

          {/* Progress circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={`url(#${strokeGradientId})`}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="none"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center score readout */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className="text-4xl font-black tracking-tight text-white font-mono">
            {score}
          </span>
          <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">
            / 100
          </span>
        </div>
      </div>

      {/* Posture Score Breakdown and Status */}
      <div className="flex-1 text-center sm:text-left space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-800/80 border border-slate-700 text-xs font-semibold text-slate-300">
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          <span>Security Posture Rating</span>
        </div>

        <h3 className="text-2xl font-bold text-white tracking-tight flex items-center justify-center sm:justify-start gap-2">
          <span>{statusLabel}</span>
          <span
            className={`w-2.5 h-2.5 rounded-full ${
              score >= 85
                ? 'bg-emerald-400'
                : score >= 70
                ? 'bg-cyan-400'
                : score >= 50
                ? 'bg-amber-400'
                : 'bg-rose-500'
            }`}
          />
        </h3>

        <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
          Overall weighted risk evaluation across identity, network access boundaries, data encryption, and audit logging.
        </p>

        {/* Score comparison metrics */}
        <div className="pt-2 flex flex-wrap items-center justify-center sm:justify-start gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="text-slate-500">Baseline Audit:</span>
            <span className="font-semibold text-white">{previousScore}/100</span>
          </div>

          <div
            className={`flex items-center gap-1 px-2 py-0.5 rounded ${
              scoreDelta >= 0 ? 'text-emerald-400 bg-emerald-950/60 border border-emerald-800/60' : 'text-rose-400 bg-rose-950/60 border border-rose-800/60'
            }`}
          >
            {scoreDelta >= 0 ? (
              <TrendingUp className="w-3 h-3" />
            ) : (
              <TrendingDown className="w-3 h-3" />
            )}
            <span className="font-bold">
              {scoreDelta >= 0 ? `+${scoreDelta}` : scoreDelta} points
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
