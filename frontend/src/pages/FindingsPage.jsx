import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  FileDown,
  Wrench,
  ExternalLink,
  CheckCircle2,
  RefreshCw,
  AlertTriangle
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { api, getActiveRole } from '../services/api';

export default function FindingsPage({
  initialSearch = '',
  onOpenFinding,
  onRefreshDashboard
}) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState(initialSearch);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [serviceFilter, setServiceFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [remediatingId, setRemediatingId] = useState(null);
  const [bannerNotice, setBannerNotice] = useState('');

  const currentRole = getActiveRole();
  const isAdmin = currentRole === 'Security Administrator';

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const data = await api.getFindings({
        search,
        severity: severityFilter,
        service: serviceFilter,
        status: statusFilter,
      });
      setFindings(data.findings || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [severityFilter, serviceFilter, statusFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchFindings();
  };

  const handleQuickRemediate = async (finding) => {
    if (!isAdmin) {
      alert('Access Denied: Only Security Administrator can trigger automated remediation.');
      return;
    }
    setRemediatingId(finding.id);
    setBannerNotice('');
    try {
      const res = await api.executeRemediation(finding.id);
      if (res.success) {
        setBannerNotice(`Successfully remediated "${finding.title}"!`);
        fetchFindings();
        onRefreshDashboard?.();
      } else {
        alert(res.message);
      }
    } catch (err) {
      alert(err.message || 'Remediation failed');
    } finally {
      setRemediatingId(null);
    }
  };

  const handleDownload = (format) => {
    const url = format === 'csv' ? api.getExportCsvUrl() : api.getExportJsonUrl();
    window.open(url, '_blank');
  };

  return (
    <div className="space-y-6">
      {/* Header & Export controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight">
            Security Findings Management
          </h1>
          <p className="text-xs text-slate-400">
            Audit, triage, and remediate detected misconfigurations across AWS resources.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => handleDownload('csv')}
            className="px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition font-mono"
          >
            <FileDown className="w-3.5 h-3.5" />
            CSV Export
          </button>
          <button
            onClick={() => handleDownload('json')}
            className="px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition font-mono"
          >
            <FileDown className="w-3.5 h-3.5" />
            JSON Export
          </button>
        </div>
      </div>

      {bannerNotice && (
        <div className="p-3.5 rounded-xl bg-emerald-950/80 border border-emerald-700 text-emerald-300 text-xs flex items-center gap-2 font-mono">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{bannerNotice}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl glass-panel bg-slate-900/60 border border-slate-800 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col lg:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Search className="absolute left-3.5 top-2.5 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search by title, resource name, rule ID (e.g. S3-001, EC2-001), or description..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2.5 w-full lg:w-auto">
            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-400"
            >
              <option value="all">Severity: All</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            {/* Service Filter */}
            <select
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
              className="px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-400"
            >
              <option value="all">Service: All</option>
              <option value="IAM">IAM</option>
              <option value="S3">S3</option>
              <option value="EC2">EC2</option>
              <option value="Security Groups">Security Groups</option>
              <option value="VPC">VPC</option>
              <option value="CloudTrail">CloudTrail</option>
              <option value="RDS">RDS</option>
              <option value="Lambda">Lambda</option>
              <option value="KMS">KMS</option>
            </select>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-400"
            >
              <option value="all">Status: All</option>
              <option value="Open">Open</option>
              <option value="In Progress">In Progress</option>
              <option value="Accepted Risk">Accepted Risk</option>
              <option value="Resolved">Resolved</option>
            </select>

            <button
              type="submit"
              className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-black font-bold text-xs transition"
            >
              Filter
            </button>
          </div>
        </form>
      </div>

      {/* Findings Data Table */}
      <div className="rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400 font-mono uppercase tracking-wider">
                <th className="p-3.5 font-bold">Severity</th>
                <th className="p-3.5 font-bold">Finding ID / Rule</th>
                <th className="p-3.5 font-bold">Service</th>
                <th className="p-3.5 font-bold">Vulnerability Title</th>
                <th className="p-3.5 font-bold">Affected Resource</th>
                <th className="p-3.5 font-bold">Risk</th>
                <th className="p-3.5 font-bold">Status</th>
                <th className="p-3.5 font-bold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan="8" className="p-12 text-center text-slate-500 font-mono">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-cyan-400 mb-2" />
                    Loading security findings...
                  </td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan="8" className="p-12 text-center text-slate-400 font-mono">
                    No findings match the selected filter criteria.
                  </td>
                </tr>
              ) : (
                findings.map((f) => {
                  const isRemediating = remediatingId === f.id;
                  const canAutomate = f.remediation_type === 'automated' && f.status !== 'Resolved';

                  return (
                    <tr
                      key={f.id}
                      className="hover:bg-slate-900/60 transition group cursor-pointer"
                      onClick={() => onOpenFinding?.(f)}
                    >
                      <td className="p-3.5">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="p-3.5 font-mono text-[11px]">
                        <span className="text-cyan-400 font-bold block">{f.id}</span>
                        <span className="text-slate-500">{f.rule_id}</span>
                      </td>
                      <td className="p-3.5 font-mono text-[11px] uppercase font-bold text-slate-200">
                        {f.service}
                      </td>
                      <td className="p-3.5 max-w-xs">
                        <div className="font-semibold text-white group-hover:text-cyan-300 transition line-clamp-1">
                          {f.title}
                        </div>
                        <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                          {f.description}
                        </div>
                      </td>
                      <td className="p-3.5 font-mono text-[11px] max-w-[160px] truncate text-slate-400">
                        {f.resource_name}
                      </td>
                      <td className="p-3.5 font-mono text-xs font-bold text-rose-400">
                        +{f.risk_score} pts
                      </td>
                      <td className="p-3.5">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                            f.status === 'Resolved'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : f.status === 'In Progress'
                              ? 'bg-blue-950 text-blue-400 border border-blue-800'
                              : f.status === 'Accepted Risk'
                              ? 'bg-purple-950 text-purple-400 border border-purple-800'
                              : 'bg-rose-950/60 text-rose-400 border border-rose-900'
                          }`}
                        >
                          {f.status}
                        </span>
                      </td>
                      <td className="p-3.5 text-right space-x-2" onClick={(e) => e.stopPropagation()}>
                        {canAutomate && (
                          <button
                            onClick={() => handleQuickRemediate(f)}
                            disabled={isRemediating || !isAdmin}
                            title={!isAdmin ? 'Security Administrator required' : '1-Click Remediate'}
                            className={`px-2.5 py-1 rounded-lg font-bold text-[11px] transition ${
                              isAdmin
                                ? 'bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/50'
                                : 'bg-slate-800 text-slate-600 cursor-not-allowed'
                            }`}
                          >
                            {isRemediating ? 'Fixing...' : 'Remediate'}
                          </button>
                        )}
                        <button
                          onClick={() => onOpenFinding?.(f)}
                          className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
