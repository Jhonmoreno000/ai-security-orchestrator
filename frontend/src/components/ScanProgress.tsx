import React, { useEffect, useState, useRef, useCallback } from 'react';
import { WSEvent, WSJobProgress, WSJobCompleted, WSScanFinished, WSErrorEvent } from '../types';
import { getWsBaseUrl, api } from '../services/api';
import {
  TerminalIcon,
  CloseIcon,
} from './icons/Icons';

interface Step {
  id: string;
  label: string;
  desc: string;
  status: 'pending' | 'running' | 'completed' | 'error';
  scanner?: string;
  findings_count?: number;
}

interface ScanProgressProps {
  scanId: string;
  targetUrl?: string;
  wsUrl?: string;
  onComplete?: (summary: any) => void;
  onClose?: () => void;
}

const INITIAL_PIPELINE_STEPS: Step[] = [
  { id: 'policy', label: '1. Policy & Perimeter Engine', desc: 'Validación de alcance y aislamiento de red', status: 'completed' },
  { id: 'scanners_spawn', label: '2. Contenedores Docker Desplegados', desc: 'Inicialización de imágenes aisladas', status: 'running' },
  { id: 'scanners_exec', label: '3. Ejecución de Heurísticas', desc: 'ZAP DAST, Nuclei, Semgrep SAST y Trivy', status: 'pending' },
  { id: 'correlation', label: '4. Correlación SHA-256', desc: 'Deduplicación y normalización de hallazgos', status: 'pending' },
  { id: 'ai_analyst', label: '5. Razonamiento AI Analyst', desc: 'Evaluación de falsos positivos y parches de código', status: 'pending' },
  { id: 'report', label: '6. Compilación de Reporte', desc: 'Generación de artefactos SARIF y reporte ejecutivo', status: 'pending' },
];

export const ScanProgress: React.FC<ScanProgressProps> = ({
  scanId,
  targetUrl = 'Target Endpoint',
  wsUrl = getWsBaseUrl(),
  onComplete,
  onClose,
}) => {
  const [steps, setSteps] = useState<Step[]>(INITIAL_PIPELINE_STEPS);
  const [progress, setProgress] = useState(15);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [completed, setCompleted] = useState(false);
  const [logs, setLogs] = useState<Array<{ time: string; text: string; type: 'info' | 'warn' | 'err' | 'ok' }>>([
    { time: new Date().toLocaleTimeString(), text: `[SYSTEM] Enlazando pipeline de auditoría: ${scanId.slice(0, 8)}`, type: 'info' },
    { time: new Date().toLocaleTimeString(), text: `[POLICY] Verificación de alcance superada para ${targetUrl}`, type: 'ok' },
  ]);

  const wsRef = useRef<WebSocket | null>(null);
  const terminalEndRef = useRef<HTMLDivElement | null>(null);

  const addLog = useCallback((text: string, type: 'info' | 'warn' | 'err' | 'ok' = 'info') => {
    setLogs((prev) => [...prev.slice(-100), { time: new Date().toLocaleTimeString(), text, type }]);
  }, []);

  const updateStep = useCallback((stepId: string, updates: Partial<Step>) => {
    setSteps((prev) => prev.map((s) => (s.id === stepId ? { ...s, ...updates } : s)));
  }, []);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const handleWSEvent = useCallback((event: WSEvent) => {
    switch (event.event) {
      case 'SCAN_STARTED': {
        updateStep('policy', { status: 'completed' });
        updateStep('scanners_spawn', { status: 'completed' });
        updateStep('scanners_exec', { status: 'running' });
        setProgress(30);
        addLog(`[ORCHESTRATOR] Motores de auditoría inicializados para ${event.data.target || targetUrl}`, 'info');
        break;
      }

      case 'JOB_PROGRESS': {
        const data = event as WSJobProgress;
        const sName = data.data.scanner?.toUpperCase() || 'ENGINE';
        updateStep('scanners_exec', { status: 'running', scanner: data.data.scanner });
        setProgress(Math.min(85, 30 + (data.data.progress_percent || 10) * 0.5));
        addLog(`[${sName}] ${data.data.message || 'Heurísticas activas contra endpoint...'}`, 'info');
        break;
      }

      case 'JOB_COMPLETED': {
        const data = event as WSJobCompleted;
        const sName = data.data.scanner?.toUpperCase() || 'ENGINE';
        addLog(`[${sName}] Finalizado exitosamente (${data.data.findings_count} hallazgos, ${data.data.duration_ms}ms)`, 'ok');
        updateStep('scanners_exec', { findings_count: data.data.findings_count });
        setProgress(75);
        break;
      }

      case 'SCAN_FINISHED': {
        const data = event as WSScanFinished;
        if (completed) return;
        setCompleted(true);
        updateStep('scanners_exec', { status: 'completed' });
        updateStep('correlation', { status: 'completed' });
        updateStep('ai_analyst', { status: 'completed' });
        updateStep('report', { status: 'completed' });
        setProgress(100);
        addLog(`[COMPLETE] Auditoría finalizada. Hallazgos totales: ${data.data.total_findings} (Críticos: ${data.data.critical})`, 'ok');
        onComplete?.(data.data);
        setTimeout(() => onClose?.(), 3000);
        break;
      }

      case 'ERROR': {
        const data = event as WSErrorEvent;
        setError(data.data.error || 'Error en ejecución de escáner');
        addLog(`[ERROR] ${data.data.error}`, 'err');
        break;
      }
    }
  }, [addLog, updateStep, targetUrl, onComplete]);

  useEffect(() => {
    let reconnectTimer: any = null;

    const connect = () => {
      try {
        const cleanWsUrl = wsUrl.replace(/^http/, 'ws');
        const ws = new WebSocket(`${cleanWsUrl}/ws/scan/${scanId}`);
        wsRef.current = ws;

        ws.onopen = () => {
          setIsConnected(true);
          setError(null);
          addLog('[SOCKET] Canal de telemetría bidireccional establecido con el Orchestrator', 'ok');
        };

        ws.onmessage = (msgEvent) => {
          try {
            const data = JSON.parse(msgEvent.data);
            handleWSEvent(data);
          } catch (e) {
            console.error('Failed to parse WS event:', e);
          }
        };

        ws.onclose = () => {
          setIsConnected(false);
        };

        ws.onerror = () => {
          setIsConnected(false);
          ws.close();
        };
      } catch (e) {
        setIsConnected(false);
      }
    };

    connect();

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [scanId, wsUrl, handleWSEvent, addLog]);

  // REST polling fallback: if WS events are missed (race condition / fast scan), poll scan status
  useEffect(() => {
    let pollTimer: any = null;
    let finished = false;

    const pollScanStatus = async () => {
      if (finished) return;
      try {
        const scansData = await api.getScans();
        const scan = scansData.scans?.find((s: any) => s.id === scanId);
        if (scan && scan.status === 'completed' && !finished) {
          finished = true;
          setCompleted(true);
          updateStep('scanners_exec', { status: 'completed' });
          updateStep('correlation', { status: 'completed' });
          updateStep('ai_analyst', { status: 'completed' });
          updateStep('report', { status: 'completed' });
          setProgress(100);
          addLog(`[POLL] Auditoría finalizada detectada por polling REST. Hallazgos totales: ${scan.findings_count}`, 'ok');
          onComplete?.({
            total_findings: scan.findings_count,
            critical: scan.summary?.critical || 0,
            high: scan.summary?.high || 0,
            medium: scan.summary?.medium || 0,
            low: scan.summary?.low || 0,
            info: scan.summary?.info || 0,
          });
          setTimeout(() => onClose?.(), 3000);
        }
      } catch {
        // silently ignore poll errors
      }
    };

    // Start polling after 3s if not already finished by WS
    pollTimer = setTimeout(() => {
      const interval = setInterval(() => {
        if (finished) { clearInterval(interval); return; }
        pollScanStatus();
      }, 2000);
      pollTimer = interval;
    }, 3000);

    return () => {
      finished = true;
      if (pollTimer) clearTimeout(pollTimer);
    };
  }, [scanId, onComplete, updateStep, addLog, onClose]);

  return (
    <div className="p-6 rounded-xl bg-[#0d1322] border border-sky-500/30 shadow-2xl space-y-5">
      {/* Header Info */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-sky-950 text-sky-400 border border-sky-500/30">
              PIPELINE TELEMETRY
            </span>
            <span className="text-xs font-mono text-slate-500">SCAN ID: {scanId}</span>
          </div>
          <h3 className="text-base font-bold font-mono text-white mt-1">{targetUrl}</h3>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs font-mono">
            <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400 animate-ping' : 'bg-rose-500'}`} />
            <span className={isConnected ? 'text-emerald-400 font-bold' : 'text-rose-400'}>
              {isConnected ? 'STREAM ACTIVO' : 'CONECTANDO...'}
            </span>
          </div>
          {onClose && (
            <button
              onClick={onClose}
              className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition-colors"
            >
              <CloseIcon className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="p-3 rounded bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs font-mono">
          [ADVERTENCIA] {error}
        </div>
      )}

      {/* Progress Bar */}
      <div>
        <div className="flex justify-between text-xs font-mono text-slate-300 mb-1.5">
          <span>Ejecución del Pipeline de Seguridad</span>
          <span className="text-sky-400 font-bold">{Math.round(progress)}%</span>
        </div>
        <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden p-0.5 border border-slate-800">
          <div
            className="h-full bg-gradient-to-r from-sky-500 to-emerald-400 rounded-full transition-all duration-500"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* Stages Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
        {steps.map((step) => {
          const isDone = step.status === 'completed';
          const isRunning = step.status === 'running';

          return (
            <div
              key={step.id}
              className={`p-3 rounded-lg border transition-all ${
                isRunning
                  ? 'bg-sky-950/40 border-sky-500/50'
                  : isDone
                  ? 'bg-[#080c14] border-slate-800 text-slate-300'
                  : 'bg-[#080c14]/50 border-slate-800/60 text-slate-600'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className={`text-xs font-mono font-bold ${isRunning ? 'text-sky-300' : isDone ? 'text-white' : 'text-slate-500'}`}>
                  {step.label}
                </span>
                <div>
                  {isDone && <span className="text-emerald-400 font-mono font-bold text-[10px]">[OK]</span>}
                  {isRunning && (
                    <div className="w-3 h-3 border-2 border-sky-400 border-t-transparent rounded-full animate-spin" />
                  )}
                  {!isDone && !isRunning && <span className="text-slate-600 font-mono text-[10px]">[WAIT]</span>}
                </div>
              </div>
              <p className="text-[10px] text-slate-400 leading-snug">{step.desc}</p>
              {step.scanner && (
                <div className="mt-1.5 text-[9px] font-mono text-sky-400 font-bold uppercase bg-sky-950 px-1.5 py-0.2 rounded border border-sky-500/30 inline-block">
                  MOTOR: {step.scanner}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Terminal View */}
      <div>
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1.5">
          <div className="flex items-center gap-1.5">
            <TerminalIcon className="w-3.5 h-3.5 text-sky-400" />
            <span className="font-semibold text-slate-200">Terminal de Telemetría (Live Output)</span>
          </div>
          <span className="text-[10px] text-slate-500">BUFFER: OK</span>
        </div>

        <div className="h-40 p-3 rounded-lg bg-[#060911] border border-slate-800 font-mono text-xs text-slate-300 overflow-y-auto space-y-1 select-text">
          {logs.map((log, index) => {
            const colorClass =
              log.type === 'ok'
                ? 'text-emerald-400'
                : log.type === 'err'
                ? 'text-rose-400'
                : log.type === 'warn'
                ? 'text-amber-400'
                : 'text-slate-300';

            return (
              <div key={index} className="flex items-start gap-2 leading-relaxed">
                <span className="text-slate-600 select-none text-[10px]">[{log.time}]</span>
                <span className={colorClass}>{log.text}</span>
              </div>
            );
          })}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
};
