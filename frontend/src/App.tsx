import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Navbar,
  DashboardView,
  ScansView,
  NewScanModal,
  ScanProgress,
  FindingsTable,
  FindingDetailModal,
  AIAssistantView,
  ReportsView,
  TargetsView,
  ToastContainer,
  ToastMessage,
} from './components';
import { ActiveTab } from './components/Navbar';
import { Finding, Scan, SecurityOverviewStats, ScannerType } from './types';
import { api } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState<SecurityOverviewStats | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isNewScanOpen, setIsNewScanOpen] = useState(false);
  const [liveStreamScanId, setLiveStreamScanId] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const wsRef = useRef<WebSocket | null>(null);

  const addToast = useCallback((type: ToastMessage['type'], title: string, message?: string) => {
    const id = String(Date.now() + Math.random());
    setToasts((prev) => [...prev, { id, type, title, message }]);
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Fetch initial data
  const loadInitialData = useCallback(async () => {
    try {
      const [statsData, scansData, findingsData] = await Promise.all([
        api.getOverviewStats(),
        api.getScans(),
        api.getFindings(),
      ]);
      setStats(statsData);
      setScans(scansData.scans || []);
      setFindings(findingsData.findings || []);
    } catch (e) {
      console.error('Failed to load initial data:', e);
    }
  }, []);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // Global WebSocket listener for live multi-scan updates
  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = window.location.port === '5173' ? 'ws://localhost:8000' : `${proto}//${window.location.host}`;
    let reconnectTimer: any = null;

    const connectGlobalWS = () => {
      try {
        const ws = new WebSocket(`${wsUrl}/ws/global`);
        wsRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.event === 'SCAN_STARTED') {
              addToast('info', 'Auditoría Iniciada', `Orquestando contenedores para ${data.data?.target || 'objetivo'}`);
              loadInitialData();
            } else if (data.event === 'SCAN_FINISHED') {
              addToast('success', 'Auditoría Finalizada', `Total hallazgos: ${data.data?.total_findings || 0}`);
              loadInitialData();
            }
          } catch (e) {
            console.error('WS Parse Error:', e);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimer = setTimeout(connectGlobalWS, 4000);
        };

        ws.onerror = () => {
          setWsConnected(false);
          ws.close();
        };
      } catch (e) {
        setWsConnected(false);
      }
    };

    connectGlobalWS();

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, [loadInitialData, addToast]);

  // Handle launch new scan
  const handleLaunchScan = async (
    target: string,
    scanners: ScannerType[],
    timeout: number,
    options: Record<string, any>
  ) => {
    const res = await api.createScan(target, scanners, timeout, options);
    addToast('success', 'Escaneo Programado', res.message);
    setLiveStreamScanId(res.scan_id);
    setSelectedScanId(res.scan_id);
    await loadInitialData();
  };

  // Handle delete scan
  const handleDeleteScan = async (scanId: string) => {
    await api.deleteScan(scanId);
    addToast('info', 'Auditoría Eliminada', `ID: ${scanId.slice(0, 8)}`);
    setScans((prev) => prev.filter((s) => s.id !== scanId));
    if (selectedScanId === scanId) setSelectedScanId(null);
    if (liveStreamScanId === scanId) setLiveStreamScanId(null);
    loadInitialData();
  };

  // Handle quick audit from Targets page
  const handleQuickAuditFromTarget = (_targetUrl: string) => {
    setIsNewScanOpen(true);
  };

  // Handle selecting a scan to inspect findings
  const handleSelectScan = async (scanId: string) => {
    setSelectedScanId(scanId);
    setActiveTab('findings');
    try {
      const data = await api.getScanFindings(scanId);
      setFindings(data.findings || []);
    } catch (e) {
      console.error('Failed to load scan findings:', e);
    }
  };

  // Handle retest triggered from modal
  const handleRetestFinding = async (finding: Finding) => {
    addToast('success', 'Retest Ejecutado', `Verificación completada para ${finding.title}`);
    await loadInitialData();
  };

  const selectedScanObj = scans.find((s) => s.id === selectedScanId);
  const activeScansCount = scans.filter((s) => s.status === 'running').length;

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onOpenNewScan={() => setIsNewScanOpen(true)}
        wsConnected={wsConnected}
        activeScansCount={activeScansCount}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Live Active Scan Monitor Banner (if running) */}
        {liveStreamScanId && (
          <div className="mb-8">
            <ScanProgress
              scanId={liveStreamScanId}
              targetUrl={selectedScanObj?.target || 'Auditoría en progreso'}
              onComplete={() => {
                loadInitialData();
                addToast('success', 'Auditoría Completada', 'Los hallazgos han sido guardados en el sistema.');
              }}
              onClose={() => setLiveStreamScanId(null)}
            />
          </div>
        )}

        {/* Dynamic Views */}
        {activeTab === 'dashboard' && (
          <DashboardView
            stats={stats}
            recentScans={scans}
            activeScan={selectedScanObj || null}
            onSelectScan={handleSelectScan}
            onOpenNewScan={() => setIsNewScanOpen(true)}
            onNavigateTab={(tab) => {
              if (tab === 'findings' && !selectedScanId) {
                api.getFindings().then((d) => setFindings(d.findings || []));
              }
              setActiveTab(tab as ActiveTab);
            }}
          />
        )}

        {activeTab === 'scans' && (
          <ScansView
            scans={scans}
            onSelectScan={handleSelectScan}
            onOpenNewScan={() => setIsNewScanOpen(true)}
            onDeleteScan={handleDeleteScan}
            onViewLiveProgress={(scanId) => setLiveStreamScanId(scanId)}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsTable
            findings={findings}
            onSelectFinding={setSelectedFinding}
            selectedScanTarget={selectedScanObj?.target}
          />
        )}

        {activeTab === 'assistant' && <AIAssistantView />}

        {activeTab === 'reports' && <ReportsView scans={scans} />}

        {activeTab === 'targets' && <TargetsView onQuickAudit={handleQuickAuditFromTarget} />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#090d16] py-6 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>AI Security Orchestrator &bull; Plataforma de Auditoría Autónoma Multimotor</span>
          <div className="flex items-center gap-4 text-[11px] text-slate-400">
            <span>ZAP DAST</span>
            <span>&bull;</span>
            <span>Nuclei</span>
            <span>&bull;</span>
            <span>Semgrep SAST</span>
            <span>&bull;</span>
            <span>Trivy SBOM</span>
            <span>&bull;</span>
            <span>AI Analyst</span>
          </div>
        </div>
      </footer>

      {/* New Scan Launch Modal */}
      <NewScanModal
        isOpen={isNewScanOpen}
        onClose={() => setIsNewScanOpen(false)}
        onSubmit={handleLaunchScan}
      />

      {/* Finding Detail & Retest Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onRetest={handleRetestFinding}
          onStatusChange={(id, newStatus) => {
            setSelectedFinding((prev) => (prev && prev.id === id ? { ...prev, status: newStatus } : prev));
            setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, status: newStatus } : f)));
          }}
        />
      )}

      {/* Floating Toast Alerts */}
      <ToastContainer toasts={toasts} onDismiss={removeToast} />
    </div>
  );
}
