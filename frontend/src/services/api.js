/**
 * API service layer for Cloud Security Posture Manager (CSPM).
 * Interacts with FastAPI backend endpoints.
 */

const API_BASE = '/api';

// Current active role stored in memory/localStorage for RBAC testing
let currentRole = localStorage.getItem('cspm_user_role') || 'Security Administrator';

export function getActiveRole() {
  return currentRole;
}

export function setActiveRole(role) {
  currentRole = role;
  localStorage.setItem('cspm_user_role', role);
}

async function fetchJson(endpoint, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'x-user-role': currentRole,
    ...options.headers,
  };

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = `Request failed: ${response.statusText}`;
    try {
      const err = await response.json();
      errorDetail = err.detail || errorDetail;
    } catch (_) {}
    throw new Error(errorDetail);
  }

  return response.json();
}

export const api = {
  // Dashboard
  getDashboard: () => fetchJson('/dashboard'),

  // Findings
  getFindings: (params = {}) => {
    const query = new URLSearchParams();
    if (params.severity && params.severity !== 'all') query.set('severity', params.severity);
    if (params.service && params.service !== 'all') query.set('service', params.service);
    if (params.status && params.status !== 'all') query.set('status', params.status);
    if (params.search) query.set('search', params.search);
    const qs = query.toString();
    return fetchJson(`/findings${qs ? `?${qs}` : ''}`);
  },
  getFindingById: (id) => fetchJson(`/findings/${id}`),
  updateFindingStatus: (id, status) =>
    fetchJson(`/findings/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),

  // IAM Analyzer
  getIamUsers: () => fetchJson('/iam/users'),
  getIamRoles: () => fetchJson('/iam/roles'),
  getIamSummary: () => fetchJson('/iam/summary'),

  // CloudTrail
  getCloudTrailEvents: (params = {}) => {
    const query = new URLSearchParams();
    if (params.severity && params.severity !== 'all') query.set('severity', params.severity);
    if (params.category && params.category !== 'all') query.set('category', params.category);
    if (params.search) query.set('search', params.search);
    const qs = query.toString();
    return fetchJson(`/cloudtrail/events${qs ? `?${qs}` : ''}`);
  },
  simulateCloudTrailEvent: (eventData) =>
    fetchJson('/cloudtrail/simulate-event', {
      method: 'POST',
      body: JSON.stringify(eventData),
    }),

  // AWS Resources
  getResources: (params = {}) => {
    const query = new URLSearchParams();
    if (params.service && params.service !== 'all') query.set('service', params.service);
    if (params.status && params.status !== 'all') query.set('status', params.status);
    const qs = query.toString();
    return fetchJson(`/aws/resources${qs ? `?${qs}` : ''}`);
  },

  // Compliance
  getCompliance: () => fetchJson('/compliance'),

  // Risk Score
  getRiskScore: () => fetchJson('/risk-score'),

  // Remediation
  executeRemediation: (findingId) =>
    fetchJson('/remediation', {
      method: 'POST',
      body: JSON.stringify({ finding_id: findingId }),
    }),
  getRemediationAuditLog: () => fetchJson('/remediation/audit-log'),
  getRemediationSnippets: (findingId) => fetchJson(`/remediation/snippets/${findingId}`),

  // Scan
  triggerScan: (service = null) =>
    fetchJson('/scan', {
      method: 'POST',
      body: JSON.stringify(service ? { service } : {}),
    }),
  getScanHistory: () => fetchJson('/scan/history'),

  // Reports
  getReportSummary: () => fetchJson('/reports'),
  getExportCsvUrl: () => `${API_BASE}/reports/export/csv`,
  getExportJsonUrl: () => `${API_BASE}/reports/export/json`,

  // Auth & RBAC
  getCurrentUser: () => fetchJson('/auth/me'),
  getAvailableRoles: () => fetchJson('/auth/users'),

  // Settings
  getSettings: () => fetchJson('/settings'),
  updateSettings: (settingsData) =>
    fetchJson('/settings', {
      method: 'POST',
      body: JSON.stringify(settingsData),
    }),
  sendTestAlert: (channel = 'all') =>
    fetchJson('/settings/test-alert', {
      method: 'POST',
      body: JSON.stringify({ channel }),
    }),
};
