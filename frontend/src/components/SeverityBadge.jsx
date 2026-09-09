import React from 'react';

export default function SeverityBadge({ severity = 'Medium', className = '' }) {
  const sev = (severity || 'Medium').toLowerCase();

  const styles = {
    critical: {
      bg: 'bg-rose-950/70',
      text: 'text-rose-400',
      border: 'border-rose-500/50',
      dot: 'bg-rose-500',
      shadow: 'shadow-[0_0_12px_rgba(244,63,94,0.3)]',
    },
    high: {
      bg: 'bg-amber-950/70',
      text: 'text-amber-400',
      border: 'border-amber-500/50',
      dot: 'bg-amber-500',
      shadow: 'shadow-[0_0_10px_rgba(245,158,11,0.2)]',
    },
    medium: {
      bg: 'bg-yellow-950/60',
      text: 'text-yellow-300',
      border: 'border-yellow-500/40',
      dot: 'bg-yellow-400',
      shadow: '',
    },
    low: {
      bg: 'bg-sky-950/60',
      text: 'text-sky-300',
      border: 'border-sky-500/40',
      dot: 'bg-sky-400',
      shadow: '',
    },
    secure: {
      bg: 'bg-emerald-950/60',
      text: 'text-emerald-300',
      border: 'border-emerald-500/40',
      dot: 'bg-emerald-400',
      shadow: '',
    },
    informational: {
      bg: 'bg-slate-800/80',
      text: 'text-slate-300',
      border: 'border-slate-600',
      dot: 'bg-slate-400',
      shadow: '',
    },
  };

  const current = styles[sev] || styles.medium;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-wide border uppercase ${current.bg} ${current.text} ${current.border} ${current.shadow} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${current.dot} ${sev === 'critical' ? 'pulse-critical' : ''}`} />
      <span>{severity}</span>
    </span>
  );
}
