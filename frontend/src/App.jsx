import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import FindingDetailModal from './components/FindingDetailModal';

// Pages
import DashboardPage from './pages/DashboardPage';
import FindingsPage from './pages/FindingsPage';
import IamAnalyzerPage from './pages/IamAnalyzerPage';
import CloudTrailPage from './pages/CloudTrailPage';
import ResourcesPage from './pages/ResourcesPage';
import CompliancePage from './pages/CompliancePage';
import RiskAnalysisPage from './pages/RiskAnalysisPage';
import RemediationPage from './pages/RemediationPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';

import { api } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [dashboardData, setDashboardData] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [globalSearch, setGlobalSearch] = useState('');
  const [activeMode, setActiveMode] = useState('simulation');
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const loadDashboardTelemetry = async () => {
    try {
      const data = await api.getDashboard();
      setDashboardData(data);
      if (data.aws_account?.mode) {
        setActiveMode(data.aws_account.mode);
      }
    } catch (err) {
      console.error('Error fetching dashboard telemetry:', err);
    }
  };

  useEffect(() => {
    loadDashboardTelemetry();
  }, [refreshTrigger]);

  const handleGlobalSearch = (term) => {
    setGlobalSearch(term);
    setActiveTab('findings');
  };

  const handleRoleChanged = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  const openFindingsCount = dashboardData?.total_active_findings || 0;
  const criticalAlerts = dashboardData?.critical_alerts || [];

  return (
    <div className="min-h-screen bg-[#06090e] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Top Navigation Bar */}
      <Navbar
        criticalAlerts={criticalAlerts}
        activeMode={activeMode}
        onSearchSubmit={handleGlobalSearch}
        onRoleChanged={handleRoleChanged}
        onNavigate={setActiveTab}
      />

      {/* Main App Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onNavigate={setActiveTab}
          openFindingsCount={openFindingsCount}
        />

        {/* Dynamic Page Container */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 space-y-6">
          {activeTab === 'dashboard' && (
            <DashboardPage
              dashboardData={dashboardData}
              onRefresh={loadDashboardTelemetry}
              onOpenFinding={setSelectedFinding}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'findings' && (
            <FindingsPage
              initialSearch={globalSearch}
              onOpenFinding={setSelectedFinding}
              onRefreshDashboard={loadDashboardTelemetry}
            />
          )}

          {activeTab === 'iam' && (
            <IamAnalyzerPage
              onOpenFinding={setSelectedFinding}
            />
          )}

          {activeTab === 'cloudtrail' && (
            <CloudTrailPage />
          )}

          {activeTab === 'resources' && (
            <ResourcesPage
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'compliance' && (
            <CompliancePage
              onOpenFinding={setSelectedFinding}
            />
          )}

          {activeTab === 'risk' && (
            <RiskAnalysisPage
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'remediation' && (
            <RemediationPage
              onRefreshDashboard={loadDashboardTelemetry}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'reports' && (
            <ReportsPage />
          )}

          {activeTab === 'settings' && (
            <SettingsPage
              onRefreshDashboard={loadDashboardTelemetry}
              onModeChanged={setActiveMode}
            />
          )}
        </main>
      </div>

      {/* Finding Deep Dive & Remediation Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onFindingUpdated={() => {
            loadDashboardTelemetry();
            setSelectedFinding(null);
          }}
        />
      )}
    </div>
  );
}
