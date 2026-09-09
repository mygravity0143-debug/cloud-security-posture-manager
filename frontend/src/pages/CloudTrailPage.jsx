import React, { useState, useEffect } from 'react';
import {
  Activity,
  Radio,
  Search,
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Plus,
  RefreshCw,
  Terminal,
  Globe,
  User
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { api } from '../services/api';

export default function CloudTrailPage() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [isLiveStreaming, setIsLiveStreaming] = useState(true);
  const [trailConfig, setTrailConfig] = useState(null);
  const [anomaliesCount, setAnomaliesCount] = useState(0);

  // Simulation modal state
  const [showSimulateModal, setShowSimulateModal] = useState(false);
  const [simAction, setSimAction] = useState('DeleteBucketPolicy');
  const [simService, setSimService] = useState('s3.amazonaws.com');
  const [simUser, setSimUser] = useState('attacker.temp');
  const [simSeverity, setSimSeverity] = useState('Critical');
  const [simStatus, setSimStatus] = useState('AccessDenied');
  const [simDetails, setSimDetails] = useState('Attacker attempted to wipe S3 bucket security policies.');

  const fetchEvents = async () => {
    try {
      const res = await api.getCloudTrailEvents({
        category: categoryFilter,
        search,
      });
      setEvents(res.events || []);
      setTrailConfig(res.trail_configuration);
      setAnomaliesCount(res.anomalies_detected || 0);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [categoryFilter]);

  // Live polling effect every 6 seconds if live streaming is active
  useEffect(() => {
    if (!isLiveStreaming) return;
    const interval = setInterval(() => {
      fetchEvents();
    }, 6000);
    return () => clearInterval(interval);
  }, [isLiveStreaming, categoryFilter, search]);

  const handleSimulateSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.simulateCloudTrailEvent({
        event_name: simAction,
        event_source: simService,
        username: simUser,
        severity: simSeverity,
        status: simStatus,
        details: simDetails,
      });
      setShowSimulateModal(false);
      fetchEvents();
    } catch (err) {
      alert(err.message || 'Simulation failed');
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>CloudTrail Real-Time Security Monitoring</span>
          </h1>
          <p className="text-xs text-slate-400">
            Live audit ingestion of AWS API calls, console authentications, privilege escalations, and unauthorized access attempts.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Live toggle */}
          <button
            onClick={() => setIsLiveStreaming(!isLiveStreaming)}
            className={`px-3 py-1.5 rounded-xl text-xs font-mono font-bold flex items-center gap-2 border transition ${
              isLiveStreaming
                ? 'bg-cyan-950/80 border-cyan-700 text-cyan-300'
                : 'bg-slate-900 border-slate-800 text-slate-500'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                isLiveStreaming ? 'bg-cyan-400 radar-dot' : 'bg-slate-600'
              }`}
            />
            <span>{isLiveStreaming ? 'LIVE STREAMING' : 'PAUSED'}</span>
          </button>

          {/* Simulate Event Button */}
          <button
            onClick={() => setShowSimulateModal(true)}
            className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white text-xs font-bold flex items-center gap-1.5 transition shadow-[0_0_15px_rgba(244,63,94,0.3)]"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Simulate Security Event</span>
          </button>
        </div>
      </div>

      {/* CloudTrail Configuration & Status Bar */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="p-4 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400 font-semibold">
              Trail Name
            </span>
            <div className="text-xs font-bold text-white font-mono mt-1 truncate max-w-[200px]">
              {trailConfig?.name || 'acme-enterprise-security-trail'}
            </div>
          </div>
          <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-mono font-bold">
            LOGGING
          </span>
        </div>

        <div className="p-4 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400 font-semibold">
              Multi-Region Coverage
            </span>
            <div className="text-xs font-bold text-white font-mono mt-1">
              {trailConfig?.is_multi_region ? 'Enabled (All Regions)' : 'Single Region Only'}
            </div>
          </div>
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
              trailConfig?.is_multi_region
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                : 'bg-rose-950 text-rose-400 border border-rose-800'
            }`}
          >
            {trailConfig?.is_multi_region ? 'Compliant' : 'Risk'}
          </span>
        </div>

        <div className="p-4 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400 font-semibold">
              Recent Anomalies Detected
            </span>
            <div className="text-xs font-bold text-rose-400 font-mono mt-1">
              {anomaliesCount} unauthorized / critical event(s)
            </div>
          </div>
          <AlertTriangle className="w-5 h-5 text-rose-400" />
        </div>
      </div>

      {/* Filter Tabs & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800">
        <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto">
          {[
            { id: 'all', label: 'All Events' },
            { id: 'critical', label: 'Critical Events' },
            { id: 'iam', label: 'IAM / Policies' },
            { id: 'network', label: 'Network / SG' },
            { id: 'auth', label: 'Console Login' },
            { id: 'unauthorized', label: 'Unauthorized (Denied)' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setCategoryFilter(tab.id)}
              className={`px-3 py-1.5 rounded-xl text-xs font-semibold tracking-wide transition ${
                categoryFilter === tab.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search events, IPs, users..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && fetchEvents()}
            className="w-full pl-8 pr-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
          />
        </div>
      </div>

      {/* Real-time Timeline Event Stream */}
      <div className="space-y-3">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-500 font-mono">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto text-cyan-400 mb-2" />
            Streaming CloudTrail events...
          </div>
        ) : events.length === 0 ? (
          <div className="p-12 rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 text-center text-slate-400 font-mono text-xs">
            No events match the selected category filter.
          </div>
        ) : (
          events.map((evt) => {
            const isDenied = evt.status === 'AccessDenied' || evt.error_message;
            const isCritical = evt.severity === 'Critical';

            return (
              <div
                key={evt.id}
                className={`p-4 rounded-2xl border transition space-y-2 ${
                  isCritical
                    ? 'bg-rose-950/30 border-rose-900/60 shadow-[0_0_15px_rgba(244,63,94,0.1)]'
                    : isDenied
                    ? 'bg-amber-950/20 border-amber-900/50'
                    : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                }`}
              >
                {/* Event Row Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={evt.severity} />
                    <span className="font-mono text-xs font-bold text-white">
                      {evt.event_name}
                    </span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                      {evt.event_source}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                    <span
                      className={`inline-flex items-center gap-1 font-bold ${
                        isDenied ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {isDenied ? (
                        <XCircle className="w-3.5 h-3.5 text-rose-400" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      )}
                      <span>{evt.status}</span>
                    </span>
                    <span>•</span>
                    <span>{new Date(evt.event_time).toLocaleTimeString()}</span>
                  </div>
                </div>

                {/* Event Details Narrative */}
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {evt.details}
                </p>

                {/* Metadata Pill Row */}
                <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] font-mono text-slate-400">
                  <span className="flex items-center gap-1">
                    <User className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Actor: <strong className="text-white">{evt.username}</strong></span>
                  </span>
                  <span>•</span>
                  <span className="flex items-center gap-1">
                    <Globe className="w-3.5 h-3.5 text-slate-500" />
                    <span>IP: <strong className="text-slate-300">{evt.source_ip}</strong></span>
                  </span>
                  <span>•</span>
                  <span className="truncate max-w-xs text-slate-500">
                    Agent: {evt.user_agent}
                  </span>
                </div>

                {evt.error_message && (
                  <div className="mt-2 p-2 rounded-lg bg-rose-950/70 border border-rose-900 text-rose-300 text-[11px] font-mono break-all">
                    {evt.error_message}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Simulate New Event Modal */}
      {showSimulateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="relative w-full max-w-md rounded-2xl glass-panel bg-slate-900 border border-slate-700 shadow-2xl p-6 space-y-4">
            <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>Simulate CloudTrail Event Ingestion</span>
            </h3>

            <form onSubmit={handleSimulateSubmit} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 font-mono block mb-1">API Action Name</label>
                <input
                  type="text"
                  value={simAction}
                  onChange={(e) => setSimAction(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 font-mono block mb-1">AWS Service Principal</label>
                <input
                  type="text"
                  value={simService}
                  onChange={(e) => setSimService(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 font-mono block mb-1">Username / IAM Identity</label>
                <input
                  type="text"
                  value={simUser}
                  onChange={(e) => setSimUser(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 font-mono block mb-1">Severity</label>
                  <select
                    value={simSeverity}
                    onChange={(e) => setSimSeverity(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 font-mono block mb-1">Status</label>
                  <select
                    value={simStatus}
                    onChange={(e) => setSimStatus(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                  >
                    <option value="AccessDenied">AccessDenied</option>
                    <option value="Success">Success</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-400 font-mono block mb-1">Event Details</label>
                <textarea
                  value={simDetails}
                  onChange={(e) => setSimDetails(e.target.value)}
                  rows="3"
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                  required
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowSimulateModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold"
                >
                  Publish Event
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
