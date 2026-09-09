import React, { useState, useEffect } from 'react';
import {
  Server,
  Search,
  Filter,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Globe,
  RefreshCw,
  ExternalLink
} from 'lucide-react';
import { api } from '../services/api';

export default function ResourcesPage({ onNavigate }) {
  const [resources, setResources] = useState([]);
  const [summary, setSummary] = useState({ total: 0, compliant_count: 0, at_risk_count: 0 });
  const [loading, setLoading] = useState(true);
  const [serviceFilter, setServiceFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [search, setSearch] = useState('');

  const fetchResources = async () => {
    setLoading(true);
    try {
      const data = await api.getResources({
        service: serviceFilter,
        status: statusFilter,
      });
      setResources(data.resources || []);
      setSummary({
        total: data.total_unfiltered || data.total,
        compliant_count: data.compliant_count,
        at_risk_count: data.at_risk_count,
      });
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResources();
  }, [serviceFilter, statusFilter]);

  const filteredResources = resources.filter((r) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      r.name.toLowerCase().includes(s) ||
      r.id.toLowerCase().includes(s) ||
      r.service.toLowerCase().includes(s) ||
      r.type.toLowerCase().includes(s)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Server className="w-5 h-5 text-cyan-400" />
            <span>AWS Multi-Service Resource Inventory</span>
          </h1>
          <p className="text-xs text-slate-400">
            Real-time configuration discovery, perimeter exposure mapping, and encryption audit across cloud assets.
          </p>
        </div>

        <button
          onClick={fetchResources}
          className="px-3.5 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition font-mono"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Inventory</span>
        </button>
      </div>

      {/* Resource Posture KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="p-4 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] font-mono uppercase text-slate-400 font-semibold">
            Monitored Cloud Assets
          </span>
          <div className="text-2xl font-black text-white font-mono mt-1">
            {summary.total}
          </div>
          <span className="text-[10px] text-slate-500">Across 8 AWS services</span>
        </div>

        <div className="p-4 rounded-2xl glass-panel bg-emerald-950/20 border border-emerald-900/40">
          <span className="text-[11px] font-mono uppercase text-emerald-400 font-semibold">
            Compliant Assets
          </span>
          <div className="text-2xl font-black text-emerald-400 font-mono mt-1">
            {summary.compliant_count}
          </div>
          <span className="text-[10px] text-emerald-400/80">Zero open security findings</span>
        </div>

        <div className="p-4 rounded-2xl glass-panel bg-rose-950/20 border border-rose-900/40">
          <span className="text-[11px] font-mono uppercase text-rose-400 font-semibold">
            At-Risk Assets
          </span>
          <div className="text-2xl font-black text-rose-400 font-mono mt-1">
            {summary.at_risk_count}
          </div>
          <span className="text-[10px] text-rose-400/80">Active security findings attached</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3.5 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3.5 top-2.5 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search resource name, ARN, type, or service..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
          />
        </div>

        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          <select
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Services</option>
            <option value="S3">S3</option>
            <option value="EC2">EC2</option>
            <option value="Security Groups">Security Groups</option>
            <option value="RDS">RDS</option>
            <option value="Lambda">Lambda</option>
            <option value="KMS">KMS</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Postures</option>
            <option value="Compliant">Compliant</option>
            <option value="At Risk">At Risk</option>
          </select>
        </div>
      </div>

      {/* Resources Table */}
      <div className="rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400 font-mono uppercase">
                <th className="p-3.5">Resource Name / ARN</th>
                <th className="p-3.5">Service & Type</th>
                <th className="p-3.5">Region</th>
                <th className="p-3.5">Internet Exposed</th>
                <th className="p-3.5">Encryption</th>
                <th className="p-3.5">Attached Findings</th>
                <th className="p-3.5">Posture Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-300 font-mono">
              {loading ? (
                <tr>
                  <td colSpan="7" className="p-12 text-center text-slate-500">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-cyan-400 mb-2" />
                    Loading resource catalog...
                  </td>
                </tr>
              ) : filteredResources.length === 0 ? (
                <tr>
                  <td colSpan="7" className="p-12 text-center text-slate-400 font-sans">
                    No resources match the selected criteria.
                  </td>
                </tr>
              ) : (
                filteredResources.map((res) => (
                  <tr key={res.id} className="hover:bg-slate-900/50 transition">
                    <td className="p-3.5">
                      <div className="font-bold text-white text-xs font-sans">{res.name}</div>
                      <div className="text-[10px] text-slate-500 truncate max-w-[220px]">{res.id}</div>
                      <div className="text-[10px] text-slate-400 font-sans mt-0.5">{res.details}</div>
                    </td>

                    <td className="p-3.5">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 text-[10px] font-bold uppercase">
                        {res.service}
                      </span>
                      <div className="text-[10px] text-slate-500 mt-0.5">{res.type}</div>
                    </td>

                    <td className="p-3.5 text-slate-400 text-[11px]">
                      {res.region}
                    </td>

                    <td className="p-3.5">
                      {res.is_public ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-bold text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-900">
                          <Globe className="w-3.5 h-3.5" />
                          Public Exposure
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-slate-400">
                          <Lock className="w-3.5 h-3.5 text-slate-500" />
                          Private Tier
                        </span>
                      )}
                    </td>

                    <td className="p-3.5">
                      {res.encrypted ? (
                        <span className="text-emerald-400 text-[11px] flex items-center gap-1 font-semibold">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          Encrypted
                        </span>
                      ) : (
                        <span className="text-rose-400 text-[11px] flex items-center gap-1 font-semibold">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          Unencrypted
                        </span>
                      )}
                    </td>

                    <td className="p-3.5">
                      {res.findings_count > 0 ? (
                        <button
                          onClick={() => onNavigate?.('findings')}
                          className="px-2.5 py-0.5 rounded-full bg-rose-950 text-rose-400 border border-rose-800 text-[11px] font-bold hover:bg-rose-900 transition"
                        >
                          {res.findings_count} finding(s) →
                        </button>
                      ) : (
                        <span className="text-slate-500 text-[11px]">0 findings</span>
                      )}
                    </td>

                    <td className="p-3.5">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          res.status === 'Compliant'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : 'bg-rose-950 text-rose-400 border border-rose-800'
                        }`}
                      >
                        {res.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
