import React, { useState, useEffect } from 'react';
import { Finding, FindingAnalysisResult, SeverityLevel } from '../types';
import { api } from '../services/api';
import {
  CpuIcon,
  TerminalIcon,
  RefreshIcon,
  CopyIcon,
  CloseIcon,
  CodeIcon,
} from './icons/Icons';

interface FindingDetailModalProps {
  finding: Finding;
  onClose: () => void;
  onRetest: (finding: Finding) => Promise<void>;
  onStatusChange?: (findingId: string, newStatus: string) => void;
}

const SEVERITY_BADGES: Record<SeverityLevel, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
  INFO: 'badge-info',
};

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onRetest,
  onStatusChange,
}) => {
  const [activeTab, setActiveTab] = useState<'ai' | 'evidence' | 'remediation' | 'retest'>('ai');
  const [analysis, setAnalysis] = useState<FindingAnalysisResult | null>(null);
  const [loadingAI, setLoadingAI] = useState(false);
  const [retesting, setRetesting] = useState(false);
  const [retestResult, setRetestResult] = useState<any>(null);
  const [copiedCode, setCopiedCode] = useState(false);

  const sev = (finding.severity || 'INFO').toUpperCase() as SeverityLevel;
  const badgeClass = SEVERITY_BADGES[sev] || 'badge-info';
  const isFixed = finding.status === 'FIXED';

  useEffect(() => {
    const fetchAI = async () => {
      setLoadingAI(true);
      try {
        const data = await api.getFindingAIAnalysis(finding.id);
        setAnalysis(data);
      } catch (e) {
        console.error('Failed to fetch AI analysis:', e);
      } finally {
        setLoadingAI(false);
      }
    };
    fetchAI();
  }, [finding.id]);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleRunRetest = async () => {
    setRetesting(true);
    try {
      const res = await api.triggerRetest(finding.id);
      setRetestResult(res);
      await onRetest(finding);
      if (onStatusChange) onStatusChange(finding.id, res.new_status);
    } catch (e) {
      console.error('Retest execution failed:', e);
    } finally {
      setRetesting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto flex items-center justify-center p-4 sm:p-6 bg-slate-950/85 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-4xl bg-[#0d1322] border border-slate-700 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 bg-[#090d16] flex items-start justify-between gap-4">
          <div className="space-y-1.5 flex-1">
            <div className="flex flex-wrap items-center gap-2 font-mono">
              <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded ${badgeClass}`}>
                {sev}
              </span>
              <span className="px-2 py-0.5 text-[10px] font-bold uppercase rounded bg-slate-800 text-sky-400 border border-slate-700">
                MOTOR: {finding.scanner}
              </span>
              {finding.cwe && (
                <span className="px-2 py-0.5 text-[10px] rounded bg-slate-900 text-slate-300 border border-slate-800">
                  {finding.cwe}
                </span>
              )}
              {finding.cvss_score && (
                <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-slate-900 text-amber-400 border border-slate-800">
                  CVSS {finding.cvss_score}
                </span>
              )}
              <span
                className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded ${
                  isFixed ? 'badge-fixed' : 'bg-amber-950/40 text-amber-400 border border-amber-500/30'
                }`}
              >
                {finding.status}
              </span>
            </div>
            <h2 className="text-base sm:text-lg font-bold text-white leading-snug">{finding.title}</h2>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <CloseIcon className="w-4 h-4" />
          </button>
        </div>

        {/* Specs Bar */}
        <div className="px-5 py-2.5 bg-[#080c14] border-b border-slate-800 grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] font-mono text-slate-400">
          <div className="truncate" title={finding.url || 'N/A'}>
            <span className="text-slate-500">ENDPOINT:</span>{' '}
            <span className="text-slate-200">{finding.url || 'N/A'}</span>
          </div>
          <div>
            <span className="text-slate-500">FINGERPRINT:</span>{' '}
            <span className="text-sky-400">{finding.fingerprint || 'fp-auto'}</span>
          </div>
          <div className="sm:text-right">
            <span className="text-slate-500">REGISTRADO:</span>{' '}
            <span className="text-slate-300">{finding.created_at ? new Date(finding.created_at).toLocaleString() : 'Reciente'}</span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="px-5 border-b border-slate-800 bg-[#0a0f1d] flex gap-1 font-mono text-xs">
          {[
            { id: 'ai', label: 'ANÁLISIS AI ANALYST', icon: <CpuIcon className="w-3.5 h-3.5" /> },
            { id: 'evidence', label: 'EVIDENCIA TÉCNICA', icon: <TerminalIcon className="w-3.5 h-3.5" /> },
            { id: 'remediation', label: 'PARCHE & CÓDIGO', icon: <CodeIcon className="w-3.5 h-3.5" /> },
            { id: 'retest', label: 'MOTOR DE RETEST', icon: <RefreshIcon className="w-3.5 h-3.5" /> },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-2.5 px-3 font-semibold border-b-2 flex items-center gap-1.5 transition-all ${
                activeTab === tab.id
                  ? 'border-sky-500 text-sky-300 bg-sky-500/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        {/* Content Area */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1 text-slate-300 text-xs sm:text-sm">
          {/* Tab 1: AI Analyst */}
          {activeTab === 'ai' && (
            <div className="space-y-3.5 animate-fade-in">
              {loadingAI ? (
                <div className="flex flex-col items-center justify-center py-10 space-y-2 font-mono text-xs text-slate-400">
                  <div className="w-6 h-6 border-2 border-sky-400 border-t-transparent rounded-full animate-spin" />
                  <span>Evaluando modelo de amenazas con AI Analyst...</span>
                </div>
              ) : (
                <>
                  {/* Summary */}
                  <div className="p-4 rounded-lg bg-[#080c14] border border-slate-800 space-y-1.5">
                    <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-sky-400">
                      Resumen Ejecutivo del Vector de Ataque
                    </div>
                    <p className="text-xs text-slate-200 leading-relaxed font-sans">
                      {analysis?.summary || finding.description || 'Vulnerabilidad identificada durante la auditoría.'}
                    </p>
                  </div>

                  {/* Business Impact */}
                  <div className="p-4 rounded-lg bg-rose-950/20 border border-rose-500/25 space-y-1.5">
                    <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-rose-400">
                      Evaluación de Impacto en el Negocio
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed font-sans">
                      {analysis?.business_impact ||
                        'Potencial vector de ataque para acceso no autorizado, manipulación de datos o exfiltración.'}
                    </p>
                  </div>

                  {/* False Positive Evaluation */}
                  <div className="p-4 rounded-lg bg-[#080c14] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">
                        Probabilidad de Falso Positivo
                      </div>
                      <p className="text-xs text-slate-300 mt-1 font-sans">
                        {analysis?.false_positive_reasoning || 'Confirmado mediante heurística directa del escáner.'}
                      </p>
                    </div>
                    <span
                      className={`px-2.5 py-1 text-[10px] font-mono font-bold uppercase rounded border self-start sm:self-auto ${
                        (analysis?.false_positive_likelihood || 'LOW').toUpperCase() === 'LOW'
                          ? 'bg-emerald-950/50 text-emerald-400 border-emerald-500/30'
                          : 'bg-amber-950/50 text-amber-400 border-amber-500/30'
                      }`}
                    >
                      {analysis?.false_positive_likelihood || 'LOW'} FP RISK
                    </span>
                  </div>
                </>
              )}
            </div>
          )}

          {/* Tab 2: Evidence */}
          {activeTab === 'evidence' && (
            <div className="space-y-3 animate-fade-in font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Payload &amp; Traza de Evidencia Capturada
                </span>
                {finding.evidence && (
                  <button
                    onClick={() => handleCopy(finding.evidence!)}
                    className="text-sky-400 hover:text-sky-300 flex items-center gap-1"
                  >
                    <CopyIcon className="w-3.5 h-3.5" />
                    <span>{copiedCode ? 'Copiado' : 'Copiar'}</span>
                  </button>
                )}
              </div>

              {finding.evidence ? (
                <pre className="p-3.5 rounded-lg bg-[#060911] border border-slate-800 text-sky-300 overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">
                  {finding.evidence}
                </pre>
              ) : (
                <div className="p-6 text-center rounded-lg bg-[#080c14] border border-slate-800 text-slate-500">
                  Sin trazas adicionales disponibles.
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Remediation & Code */}
          {activeTab === 'remediation' && (
            <div className="space-y-3.5 animate-fade-in">
              <div className="p-4 rounded-lg bg-[#080c14] border border-slate-800 space-y-2">
                <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-400">
                  Instrucciones Técnicas de Mitigación
                </div>
                {analysis?.remediation_steps && analysis.remediation_steps.length > 0 ? (
                  <ol className="space-y-1.5 text-xs text-slate-200 font-sans">
                    {analysis.remediation_steps.map((step, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="w-4 h-4 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center text-[10px] font-mono font-bold flex-shrink-0 mt-0.5">
                          {idx + 1}
                        </span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p className="text-xs text-slate-300 whitespace-pre-wrap font-sans">
                    {finding.remediation || 'Validar y sanitizar entradas en el controlador correspondiente.'}
                  </p>
                )}
              </div>

              {/* Code block */}
              {(analysis?.code_example || finding.remediation?.includes('```')) && (
                <div className="space-y-1.5 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300 font-bold">Parche de Código Recomendado:</span>
                    <button
                      onClick={() => handleCopy(analysis?.code_example || finding.remediation!)}
                      className="px-2 py-0.5 rounded bg-slate-800 text-sky-400 border border-slate-700 hover:bg-slate-700 flex items-center gap-1"
                    >
                      <CopyIcon className="w-3 h-3" />
                      <span>{copiedCode ? 'Copiado' : 'Copiar'}</span>
                    </button>
                  </div>
                  <pre className="p-3.5 rounded-lg bg-[#060911] border border-slate-800 text-emerald-300 overflow-x-auto shadow-inner leading-relaxed">
                    {analysis?.code_example || finding.remediation}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Retest Engine */}
          {activeTab === 'retest' && (
            <div className="space-y-4 animate-fade-in font-mono text-xs">
              <div className="p-4 rounded-lg bg-[#080c14] border border-slate-800 space-y-2.5">
                <div className="flex items-center gap-2 text-white font-bold text-xs uppercase">
                  <RefreshIcon className="w-3.5 h-3.5 text-sky-400" />
                  <span>Validación de Regresión con Retest Engine</span>
                </div>
                <p className="text-slate-300 leading-relaxed font-sans text-xs">
                  El motor de Retest ejecuta una sonda dirigida contra <code className="text-sky-400">{finding.url}</code> usando la heurística de <strong className="text-white">{finding.scanner?.toUpperCase()}</strong> para verificar si el SHA-256 fingerprint de la vulnerabilidad persiste o ha sido mitigado.
                </p>

                <div className="pt-1">
                  <button
                    onClick={handleRunRetest}
                    disabled={retesting}
                    className="px-4 py-2 text-xs font-bold font-mono uppercase tracking-wide rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-md shadow-emerald-500/20 disabled:opacity-50 flex items-center gap-2 transition-all"
                  >
                    {retesting ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                        <span>Ejecutando Retest...</span>
                      </>
                    ) : (
                      <>
                        <RefreshIcon className="w-3.5 h-3.5" />
                        <span>Ejecutar Retest Ahora</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {retestResult && (
                <div
                  className={`p-3.5 rounded-lg border ${
                    retestResult.new_status === 'FIXED'
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : 'bg-amber-950/40 border-amber-500/40 text-amber-300'
                  } space-y-1.5`}
                >
                  <div className="flex items-center justify-between font-bold">
                    <span>RESULTADO DEL RETEST: {retestResult.new_status}</span>
                    <span>{retestResult.duration_ms}ms</span>
                  </div>
                  <p className="font-sans text-xs">{retestResult.notes}</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-[#090d16] flex items-center justify-between font-mono text-xs">
          <div className="text-slate-500">
            ID: {finding.id}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleRunRetest}
              disabled={retesting}
              className="px-3.5 py-1.5 font-bold uppercase rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50"
            >
              {retesting ? 'Validando...' : 'Retest'}
            </button>
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
            >
              Cerrar
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
