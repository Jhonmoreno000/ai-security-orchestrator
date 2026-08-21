import React from 'react';
import { Scan, SecurityOverviewStats } from '../types';
import {
  ShieldCheckIcon,
  AlertOctagonIcon,
  AlertTriangleIcon,
  ActivityIcon,
  ServerIcon,
  RadarIcon,
  LockIcon,
} from './icons/Icons';

interface DashboardViewProps {
  stats: SecurityOverviewStats | null;
  recentScans: Scan[];
  activeScan: Scan | null;
  onSelectScan: (scanId: string) => void;
  onOpenNewScan: () => void;
  onNavigateTab: (tab: 'scans' | 'findings' | 'assistant' | 'reports' | 'targets') => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  stats,
  recentScans,
  onSelectScan,
  onOpenNewScan,
  onNavigateTab,
}) => {
  const score = stats?.posture_score ?? 94;
  const rating = stats?.rating ?? 'A';
  const breakdown = stats?.severity_breakdown ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const totalFindings = stats?.total_findings ?? 0;

  const getScoreColor = (sc: number) => {
    if (sc >= 90) return 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20';
    if (sc >= 75) return 'text-sky-400 border-sky-500/30 bg-sky-950/20';
    if (sc >= 55) return 'text-amber-400 border-amber-500/30 bg-amber-950/20';
    return 'text-rose-400 border-rose-500/30 bg-rose-950/20';
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Banner / Telemetry Status */}
      <div className="relative overflow-hidden rounded-xl bg-[#0d1322] border border-slate-800 p-6 sm:p-7 shadow-2xl">
        <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-sky-500/10 text-sky-400 border border-sky-500/30 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
                CENTRO DE OPERACIONES DE SEGURIDAD (SOC)
              </span>
              <span className="text-xs font-mono text-slate-400">Heurísticas DAST, SAST, SBOM &amp; CVEs Activas</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight font-mono">
              Consola de Postura de Seguridad &amp; DevSecOps
            </h1>
            <p className="text-slate-400 text-xs sm:text-sm max-w-2xl leading-relaxed">
              Monitoreo continuo de vectores de ataque, correlación de vulnerabilidades y verificación mediante motor de retest automatizado.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => onNavigateTab('findings')}
              className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
            >
              Matriz de Hallazgos
            </button>
            <button
              onClick={onOpenNewScan}
              className="px-4 py-2 text-xs font-bold font-mono uppercase tracking-wide rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-md shadow-sky-500/20 transition-all flex items-center gap-2"
            >
              <ActivityIcon className="w-3.5 h-3.5" />
              <span>Ejecutar Auditoría</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Posture Score Card */}
        <div className={`p-5 rounded-xl border ${getScoreColor(score)} flex flex-col justify-between`}>
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">Índice de Postura</span>
            <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-white/10">{rating} Grade</span>
          </div>
          <div className="my-2 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono tracking-tight">{score}</span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
          </div>
          <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-1000 ${
                score >= 90 ? 'bg-emerald-400' : score >= 75 ? 'bg-sky-400' : score >= 55 ? 'bg-amber-400' : 'bg-rose-500'
              }`}
              style={{ width: `${score}%` }}
            />
          </div>
        </div>

        {/* Total Scans */}
        <div className="p-5 rounded-xl bg-[#0d1322] border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">Total Auditorías</span>
            <div className="p-1 rounded bg-sky-500/10 text-sky-400">
              <RadarIcon className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold font-mono text-white tracking-tight">{stats?.total_scans ?? 0}</span>
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            <span className="text-sky-400 font-bold">{stats?.active_scans ?? 0}</span> en ejecución
          </div>
        </div>

        {/* Critical CVEs */}
        <div className="p-5 rounded-xl bg-[#0d1322] border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">Críticas (CVSS 9.0+)</span>
            <div className="p-1 rounded bg-rose-500/10 text-rose-400">
              <AlertOctagonIcon className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold font-mono text-rose-400 tracking-tight">{breakdown.critical}</span>
          </div>
          <div className="text-[11px] font-mono text-rose-400">
            {breakdown.critical > 0 ? 'Vulnerabilidad activa' : 'Sin amenazas críticas'}
          </div>
        </div>

        {/* Total Findings */}
        <div className="p-5 rounded-xl bg-[#0d1322] border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">Hallazgos Abiertos</span>
            <div className="p-1 rounded bg-amber-500/10 text-amber-400">
              <AlertTriangleIcon className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold font-mono text-white tracking-tight">{totalFindings}</span>
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            <span className="text-amber-400 font-bold">{breakdown.high}</span> severidad alta
          </div>
        </div>

        {/* Fix Rate */}
        <div className="p-5 rounded-xl bg-[#0d1322] border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">Tasa de Mitigación</span>
            <div className="p-1 rounded bg-emerald-500/10 text-emerald-400">
              <ShieldCheckIcon className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold font-mono text-emerald-400 tracking-tight">
              {stats?.fix_rate_percent ?? 100}%
            </span>
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            {stats?.fixed_findings ?? 0} validadas por Retest
          </div>
        </div>
      </div>

      {/* Severity Breakdown Bar */}
      <div className="p-6 rounded-xl bg-[#0d1322] border border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wider">
              Distribución de Vulnerabilidades por Nivel de Severidad
            </h3>
            <p className="text-xs text-slate-400">Heurística basada en el estándar CVSS v3.1 y OWASP Top 10</p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {totalFindings} hallazgos clasificados
          </span>
        </div>

        {/* Color Theory Proportional Bar */}
        <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden flex gap-0.5 p-0.5 border border-slate-800">
          {totalFindings > 0 ? (
            <>
              {breakdown.critical > 0 && (
                <div
                  className="h-full bg-rose-500 rounded-sm"
                  style={{ width: `${(breakdown.critical / totalFindings) * 100}%` }}
                />
              )}
              {breakdown.high > 0 && (
                <div
                  className="h-full bg-orange-500 rounded-sm"
                  style={{ width: `${(breakdown.high / totalFindings) * 100}%` }}
                />
              )}
              {breakdown.medium > 0 && (
                <div
                  className="h-full bg-amber-400 rounded-sm"
                  style={{ width: `${(breakdown.medium / totalFindings) * 100}%` }}
                />
              )}
              {breakdown.low > 0 && (
                <div
                  className="h-full bg-sky-400 rounded-sm"
                  style={{ width: `${(breakdown.low / totalFindings) * 100}%` }}
                />
              )}
              {breakdown.info > 0 && (
                <div
                  className="h-full bg-teal-400 rounded-sm"
                  style={{ width: `${(breakdown.info / totalFindings) * 100}%` }}
                />
              )}
            </>
          ) : (
            <div className="h-full w-full bg-emerald-500/20 rounded-sm flex items-center justify-center text-[10px] text-emerald-400 font-mono">
              Perímetro Seguro &bull; Sin vulnerabilidades activas
            </div>
          )}
        </div>

        {/* Severity Metrics Row */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-4">
          <div className="p-3 rounded-lg bg-[#080c14] border border-rose-500/25">
            <div className="text-[10px] font-mono font-bold uppercase text-rose-400">CRÍTICO (CVSS 9.0 - 10.0)</div>
            <div className="text-lg font-bold font-mono text-rose-400 mt-1">{breakdown.critical}</div>
          </div>
          <div className="p-3 rounded-lg bg-[#080c14] border border-orange-500/25">
            <div className="text-[10px] font-mono font-bold uppercase text-orange-400">ALTO (CVSS 7.0 - 8.9)</div>
            <div className="text-lg font-bold font-mono text-orange-400 mt-1">{breakdown.high}</div>
          </div>
          <div className="p-3 rounded-lg bg-[#080c14] border border-amber-500/25">
            <div className="text-[10px] font-mono font-bold uppercase text-amber-400">MEDIO (CVSS 4.0 - 6.9)</div>
            <div className="text-lg font-bold font-mono text-amber-400 mt-1">{breakdown.medium}</div>
          </div>
          <div className="p-3 rounded-lg bg-[#080c14] border border-sky-500/25">
            <div className="text-[10px] font-mono font-bold uppercase text-sky-400">BAJO (CVSS 0.1 - 3.9)</div>
            <div className="text-lg font-bold font-mono text-sky-400 mt-1">{breakdown.low}</div>
          </div>
          <div className="p-3 rounded-lg bg-[#080c14] border border-teal-500/25">
            <div className="text-[10px] font-mono font-bold uppercase text-teal-400">INFORMATIVO</div>
            <div className="text-lg font-bold font-mono text-teal-400 mt-1">{breakdown.info}</div>
          </div>
        </div>
      </div>

      {/* Grid: Engines Status & Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Engines (1 col) */}
        <div className="p-6 rounded-xl bg-[#0d1322] border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold font-mono text-white uppercase tracking-wider flex items-center gap-2">
                <ServerIcon className="w-4 h-4 text-sky-400" />
                <span>Motores de Seguridad</span>
              </h3>
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-500/30">
                5 ACTIVOS
              </span>
            </div>

            <div className="space-y-2.5">
              {[
                { name: 'ZAP Scanner', type: 'DAST', desc: 'Análisis dinámico de inyecciones y cabeceras' },
                { name: 'Nuclei Engine', type: 'CVE PROBE', desc: 'Plantillas de vulnerabilidades y exploits conocidos' },
                { name: 'Semgrep Engine', type: 'SAST', desc: 'Inspección estática de código y secretos' },
                { name: 'Trivy Scanner', type: 'SBOM', desc: 'Auditoría de dependencias y paquetes CVE' },
                { name: 'AI Analyst Core', type: 'LLM AGENT', desc: 'Razonamiento contextual y parches de código' },
              ].map((engine) => (
                <div key={engine.name} className="flex items-center justify-between p-3 rounded-lg bg-[#080c14] border border-slate-800">
                  <div className="flex items-center gap-2.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    <div>
                      <div className="text-xs font-bold text-slate-200 font-mono">{engine.name}</div>
                      <div className="text-[10px] text-slate-400">{engine.desc}</div>
                    </div>
                  </div>
                  <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase bg-slate-900 text-sky-400 rounded border border-slate-700">
                    {engine.type}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-center">
            <button
              onClick={() => onNavigateTab('targets')}
              className="text-xs font-mono text-sky-400 hover:text-sky-300 font-semibold"
            >
              Configurar Perímetro &amp; Scope &rarr;
            </button>
          </div>
        </div>

        {/* Recent Audits (2 cols) */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-[#0d1322] border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-xs font-bold font-mono text-white uppercase tracking-wider">
                  Registro de Auditorías Recientes
                </h3>
                <p className="text-xs text-slate-400">Historial de escaneos y estado de ejecución</p>
              </div>
              <button
                onClick={() => onNavigateTab('scans')}
                className="text-xs font-mono text-sky-400 hover:text-sky-300 font-semibold"
              >
                Ver Todas ({stats?.total_scans ?? 0}) &rarr;
              </button>
            </div>

            {recentScans.length === 0 ? (
              <div className="text-center py-12 px-4 rounded-lg border border-dashed border-slate-800 bg-[#080c14]">
                <RadarIcon className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <h4 className="text-xs font-bold text-slate-300 uppercase font-mono">Sin auditorías registradas</h4>
                <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1 mb-4">
                  Inicia un escaneo para que los motores ZAP, Nuclei, Semgrep y Trivy analicen tu objetivo.
                </p>
                <button
                  onClick={onOpenNewScan}
                  className="px-3.5 py-1.5 text-xs font-bold font-mono uppercase rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950"
                >
                  Lanzar Primer Escaneo
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                {recentScans.slice(0, 5).map((scan) => {
                  const isRunning = scan.status === 'running';
                  return (
                    <div
                      key={scan.id}
                      onClick={() => onSelectScan(scan.id)}
                      className="flex items-center justify-between p-3 rounded-lg bg-[#080c14] hover:bg-slate-900 border border-slate-800 hover:border-sky-500/40 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-7 h-7 rounded bg-slate-900 border border-slate-800 flex items-center justify-center text-sky-400">
                          <LockIcon className="w-3.5 h-3.5" />
                        </div>
                        <div>
                          <div className="text-xs font-bold font-mono text-slate-200 flex items-center gap-2">
                            <span>{scan.target}</span>
                            <span className="text-[10px] text-slate-500">#{scan.id.slice(0, 8)}</span>
                          </div>
                          <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                            {scan.scanners.map((s) => String(s).toUpperCase()).join(' &bull; ')}
                            {scan.duration_seconds && ` &bull; ${scan.duration_seconds}s`}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <div className="text-right hidden sm:block font-mono">
                          <span className="text-xs font-bold text-white">{scan.findings_count || 0}</span>
                          <span className="text-[10px] text-slate-500 block">hallazgos</span>
                        </div>
                        <span
                          className={`px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded border ${
                            scan.status === 'completed'
                              ? 'bg-emerald-950/50 text-emerald-400 border-emerald-500/30'
                              : isRunning
                              ? 'bg-sky-950/50 text-sky-400 border-sky-500/30 animate-pulse'
                              : 'bg-slate-900 text-slate-400 border-slate-800'
                          }`}
                        >
                          {scan.status}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex justify-between items-center text-xs font-mono text-slate-400">
            <span>Telemetría WebSocket en vivo</span>
            <button
              onClick={() => onNavigateTab('reports')}
              className="text-sky-400 hover:text-sky-300 font-semibold"
            >
              Exportar Reportes SARIF &rarr;
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
