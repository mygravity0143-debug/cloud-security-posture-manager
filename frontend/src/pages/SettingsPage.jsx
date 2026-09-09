import React, { useState, useEffect } from 'react';
import {
  Settings,
  Cloud,
  Bell,
  Mail,
  Shield,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Send,
  Lock,
  UserCheck
} from 'lucide-react';
import { api, getActiveRole } from '../services/api';

export default function SettingsPage({ onRefreshDashboard, onModeChanged }) {
  const [settingsData, setSettingsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState('simulation');
  const [region, setRegion] = useState('us-east-1');
  const [snsArn, setSnsArn] = useState('');
  const [alertEmail, setAlertEmail] = useState('');
  const [saving, setSaving] = useState(false);
  const [testingAlert, setTestingAlert] = useState(false);
  const [bannerNotice, setBannerNotice] = useState('');
  const [alertResult, setAlertResult] = useState(null);

  const currentRole = getActiveRole();
  const isAdmin = currentRole === 'Security Administrator';

  useEffect(() => {
    api
      .getSettings()
      .then((data) => {
        setSettingsData(data);
        const s = data.settings || {};
        setMode(s.mode || 'simulation');
        setRegion(s.aws_region || 'us-east-1');
        setSnsArn(s.sns_topic_arn || '');
        setAlertEmail(s.alert_email || '');
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    if (!isAdmin) {
      alert('Access Denied: Only Security Administrator can change system configurations.');
      return;
    }
    setSaving(true);
    setBannerNotice('');
    try {
      const res = await api.updateSettings({
        mode,
        aws_region: region,
        sns_topic_arn: snsArn,
        alert_email: alertEmail,
      });
      setBannerNotice(res.message);
      onModeChanged?.(mode);
      onRefreshDashboard?.();
    } catch (err) {
      alert(err.message || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleTestAlert = async () => {
    setTestingAlert(true);
    setAlertResult(null);
    try {
      const res = await api.sendTestAlert('all');
      setAlertResult(res.alert_payload);
      setBannerNotice(res.message);
    } catch (err) {
      alert(err.message || 'Test alert dispatch failed');
    } finally {
      setTestingAlert(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const isAwsConnected = settingsData?.aws_connection_status?.connected;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel bg-slate-950/60 border border-slate-800">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Settings className="w-5 h-5 text-cyan-400" />
            <span>Settings & AWS Configuration</span>
          </h1>
          <p className="text-xs text-slate-400">
            Configure scanner engine execution mode, AWS region targeting, and Amazon SNS alert dispatch channels.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-slate-400">Current User:</span>
          <span className="text-cyan-400 font-bold">{currentRole}</span>
        </div>
      </div>

      {bannerNotice && (
        <div className="p-3.5 rounded-xl bg-emerald-950/80 border border-emerald-700 text-emerald-300 text-xs flex items-center gap-2 font-mono">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{bannerNotice}</span>
        </div>
      )}

      {/* Main Settings Form */}
      <form onSubmit={handleSaveSettings} className="space-y-6">
        {/* Engine Execution Mode Switcher */}
        <div className="p-6 rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 space-y-4">
          <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
            <Cloud className="w-4 h-4 text-cyan-400" />
            <span>Scanner Execution Engine Mode</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Simulation Option */}
            <div
              onClick={() => setMode('simulation')}
              className={`p-4 rounded-2xl border cursor-pointer transition space-y-2 ${
                mode === 'simulation'
                  ? 'glass-panel-glow bg-cyan-950/30 border-cyan-500 shadow-[0_0_15px_rgba(0,242,254,0.15)]'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-white">Enterprise Simulation Mode (Default)</span>
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
              </div>
              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                Full fidelity enterprise simulation with pre-seeded multi-tier VPCs, S3 data buckets, IAM users, and live CloudTrail events. Ideal for evaluations and testing without requiring live AWS credentials or billing.
              </p>
            </div>

            {/* Live AWS Boto3 Option */}
            <div
              onClick={() => setMode('aws')}
              className={`p-4 rounded-2xl border cursor-pointer transition space-y-2 ${
                mode === 'aws'
                  ? 'glass-panel-glow bg-cyan-950/30 border-cyan-500 shadow-[0_0_15px_rgba(0,242,254,0.15)]'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-white">Live AWS Mode (Boto3 SDK)</span>
                <span className={`w-2.5 h-2.5 rounded-full ${isAwsConnected ? 'bg-emerald-400' : 'bg-amber-400'}`} />
              </div>
              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                Connects directly to your real AWS account via AWS credentials / IAM Role using Boto3 to inspect live cloud resources and configurations.
              </p>
              <div className="text-[11px] font-mono text-slate-500">
                Connection Status: {isAwsConnected ? 'Connected' : 'Credentials Not Configured (Runs safely)'}
              </div>
            </div>
          </div>
        </div>

        {/* AWS & Alert Settings Grid */}
        <div className="p-6 rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 space-y-4">
          <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
            <Bell className="w-4 h-4 text-cyan-400" />
            <span>Regional Target & Notification Pipeline</span>
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="text-slate-400 font-mono block mb-1.5 font-semibold">
                Default AWS Region
              </label>
              <select
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white font-mono focus:outline-none focus:border-cyan-400"
              >
                <option value="us-east-1">us-east-1 (N. Virginia)</option>
                <option value="us-west-2">us-west-2 (Oregon)</option>
                <option value="eu-west-1">eu-west-1 (Ireland)</option>
                <option value="ap-south-1">ap-south-1 (Mumbai)</option>
                <option value="ap-southeast-1">ap-southeast-1 (Singapore)</option>
              </select>
            </div>

            <div>
              <label className="text-slate-400 font-mono block mb-1.5 font-semibold">
                Alert Email Recipient
              </label>
              <input
                type="email"
                value={alertEmail}
                onChange={(e) => setAlertEmail(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white font-mono focus:outline-none focus:border-cyan-400"
                placeholder="security-admin@enterprise.internal"
              />
            </div>

            <div className="sm:col-span-2">
              <label className="text-slate-400 font-mono block mb-1.5 font-semibold">
                Amazon SNS Topic ARN (Critical Security Findings)
              </label>
              <input
                type="text"
                value={snsArn}
                onChange={(e) => setSnsArn(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white font-mono focus:outline-none focus:border-cyan-400"
                placeholder="arn:aws:sns:us-east-1:123456789012:cspm-critical-security-alerts"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between pt-4 border-t border-slate-800 gap-3">
            <button
              type="button"
              onClick={handleTestAlert}
              disabled={testingAlert}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-semibold flex items-center gap-2 transition font-mono"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{testingAlert ? 'Dispatching...' : 'Dispatch Test Security Alert'}</span>
            </button>

            <button
              type="submit"
              disabled={saving || !isAdmin}
              className={`px-5 py-2 rounded-xl text-xs font-bold tracking-wide transition ${
                isAdmin
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black shadow-[0_0_15px_rgba(0,242,254,0.3)]'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
              }`}
            >
              {saving ? 'Saving...' : 'Save Configuration'}
            </button>
          </div>
        </div>
      </form>

      {/* Test Alert Payload Inspector */}
      {alertResult && (
        <div className="p-5 rounded-2xl glass-panel bg-slate-950/80 border border-cyan-800/80 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-bold font-mono">
              <CheckCircle2 className="w-4 h-4" />
              <span>ALERT DISPATCH PAYLOAD VERIFIED</span>
            </div>
            <span className="text-[10px] font-mono text-slate-500">{alertResult.timestamp}</span>
          </div>

          <pre className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
            {JSON.stringify(alertResult, null, 2)}
          </pre>
        </div>
      )}

      {/* Role-Based Access Control (RBAC) Matrix Reference */}
      <div className="p-6 rounded-2xl glass-panel bg-slate-950/70 border border-slate-800 space-y-4">
        <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          <span>Role-Based Access Control (RBAC) Governance Matrix</span>
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400 uppercase">
                <th className="p-3">User Role</th>
                <th className="p-3">Trigger Scans</th>
                <th className="p-3">1-Click Remediate</th>
                <th className="p-3">Update Status</th>
                <th className="p-3">Export Reports</th>
                <th className="p-3">Configure Settings</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              <tr>
                <td className="p-3 font-bold text-cyan-400">Security Administrator</td>
                <td className="p-3 text-emerald-400 font-bold">YES</td>
                <td className="p-3 text-emerald-400 font-bold">YES</td>
                <td className="p-3 text-emerald-400 font-bold">YES</td>
                <td className="p-3 text-emerald-400 font-bold">YES</td>
                <td className="p-3 text-emerald-400 font-bold">YES</td>
              </tr>
              <tr>
                <td className="p-3 font-bold text-blue-400">Security Analyst</td>
                <td className="p-3 text-slate-500">NO</td>
                <td className="p-3 text-slate-500">NO</td>
                <td className="p-3 text-emerald-400 font-bold">YES</td>
                <td className="p-3 text-emerald-400 font-bold">YES</td>
                <td className="p-3 text-slate-500">NO</td>
              </tr>
              <tr>
                <td className="p-3 font-bold text-slate-400">Viewer</td>
                <td className="p-3 text-slate-500">NO</td>
                <td className="p-3 text-slate-500">NO</td>
                <td className="p-3 text-slate-500">NO</td>
                <td className="p-3 text-emerald-400 font-bold">YES</td>
                <td className="p-3 text-slate-500">NO</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
