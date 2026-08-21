import React, { useState } from 'react';
import { Scan } from '../types';
import { api } from '../services/api';
import {
  SearchIcon,
  ActivityIcon,
  TrashIcon,
} from './icons/Icons';

interface ScansViewProps {
  scans: Scan[];
  onSelectScan: (scanId: string) => void;
  onOpenNewScan: () => void;
  onDeleteScan: (scanId: string) => void;
  onViewLiveProgress: (scanId: string) => void;
}

export const ScansView: React.FC<ScansViewProps> = ({
  scans,
  onSelectScan,
  onOpenNewScan,
  onDeleteScan,
  onViewLiveProgress,
}) => {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filteredScans = scans.filter((scan) => {
    if (statusFilter !== 'ALL' && scan.status?.toLowerCase() !== statusFilter.toLowerCase()) {
      return false;
    }
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      const matchTarget = scan.target?.toLowerCase().includes(q);
      const matchId = scan.id?.toLowerCase().includes(q);
      return matchTarget || matchId;
    }
    return true;
  });

  const getStatusBadge = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return 'bg-emerald-950/50 text-emerald-400 border-emerald-500/30';
      case 'running':
        return 'bg-sky-950/50 text-sky-400 border-sky-500/30 animate-pulse';
      case 'queued':
      case 'pending':
        return 'bg-amber-950/50 text-amber-400 border-amber-500/30';
      case 'failed':
        return 'bg-rose-950/50 text-rose-400 border-rose-500/30';
      default:
        return 'bg-slate-900 text-slate-400 border-slate-800';
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-6 rounded-xl bg-[#0d1322] border border-slate-800 shadow-xl">
        <div>
          <h2 className="text-base sm:text-lg font-bold font-mono text-white uppercase tracking-wider">
            Gestor de Auditorías &amp; Pipeline de Seguridad
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Registro de ejecuciones multimotor, telemetría y exportación de reportes SARIF
          </p>
        </div>

        <button
          onClick={onOpenNewScan}
          className="px-4 py-2 text-xs font-bold font-mono uppercase tracking-wide rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-md shadow-sky-500/20 transition-all flex items-center gap-1.5"
        >
          <ActivityIcon className="w-3.5 h-3.5" />
          <span>Nueva Auditoría</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-3 p-4 rounded-xl bg-[#0d1322] border border-slate-800 font-mono text-xs">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
            <SearchIcon className="w-3.5 h-3.5" />
          </div>
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Buscar por URL o ID de escaneo..."
            className="w-full pl-9 pr-4 py-2 bg-[#080c14] border border-slate-700 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
          />
        </div>

        {/* Status Filter Buttons */}
        <div className="flex flex-wrap items-center gap-1.5 w-full md:w-auto">
          {[
            { id: 'ALL', label: 'TODOS' },
            { id: 'running', label: 'EN EJECUCIÓN' },
            { id: 'completed', label: 'COMPLETADOS' },
            { id: 'failed', label: 'FALLIDOS' },
          ].map((f) => (
            <button
              key={f.id}
              onClick={() => setStatusFilter(f.id)}
              className={`px-2.5 py-1 text-[11px] font-bold uppercase rounded transition-colors ${
                statusFilter === f.id
                  ? 'bg-sky-500 text-slate-950'
                  : 'bg-[#080c14] text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Scans Table */}
      <div className="rounded-xl bg-[#0d1322] border border-slate-800 overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#080c14] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="px-5 py-3.5">Target / Objetivo</th>
                <th className="px-5 py-3.5">Motores</th>
                <th className="px-5 py-3.5">Hallazgos</th>
                <th className="px-5 py-3.5">Duración</th>
                <th className="px-5 py-3.5">Estado</th>
                <th className="px-5 py-3.5 text-right">Acciones</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredScans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-16 text-center text-slate-500 font-mono text-xs">
                    [INFO] No se encontraron auditorías registradas.
                  </td>
                </tr>
              ) : (
                filteredScans.map((scan) => {
                  const summary = scan.summary || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
                  const isRunning = scan.status === 'running';

                  return (
                    <tr
                      key={scan.id}
                      className="hover:bg-slate-900/60 transition-colors group cursor-pointer font-mono"
                      onClick={() => onSelectScan(scan.id)}
                    >
                      {/* Target & ID */}
                      <td className="px-5 py-4">
                        <div className="font-bold text-slate-200 group-hover:text-sky-300 transition-colors text-xs font-mono">
                          {scan.target}
                        </div>
                        <div className="text-[10px] text-slate-500 mt-0.5">
                          ID: {scan.id.slice(0, 8)} &bull; {new Date(scan.created_at).toLocaleString()}
                        </div>
                      </td>

                      {/* Scanners */}
                      <td className="px-5 py-4">
                        <div className="flex flex-wrap gap-1">
                          {scan.scanners.map((s) => (
                            <span
                              key={String(s)}
                              className="px-1.5 py-0.2 text-[9px] font-bold uppercase rounded bg-slate-900 text-sky-400 border border-slate-700"
                            >
                              {String(s)}
                            </span>
                          ))}
                        </div>
                      </td>

                      {/* Findings Badges */}
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-1 text-[10px]">
                          {summary.critical > 0 && (
                            <span className="px-1.5 py-0.2 rounded badge-critical font-bold">
                              {summary.critical} C
                            </span>
                          )}
                          {summary.high > 0 && (
                            <span className="px-1.5 py-0.2 rounded badge-high font-bold">
                              {summary.high} H
                            </span>
                          )}
                          {summary.medium > 0 && (
                            <span className="px-1.5 py-0.2 rounded badge-medium font-bold">
                              {summary.medium} M
                            </span>
                          )}
                          {summary.low > 0 && (
                            <span className="px-1.5 py-0.2 rounded badge-low font-bold">
                              {summary.low} L
                            </span>
                          )}
                          {summary.total === 0 && <span className="text-slate-500 text-[10px]">0</span>}
                        </div>
                      </td>

                      {/* Duration */}
                      <td className="px-5 py-4 text-slate-400 text-xs">
                        {scan.duration_seconds ? `${scan.duration_seconds}s` : isRunning ? '...' : '-'}
                      </td>

                      {/* Status */}
                      <td className="px-5 py-4">
                        <span className={`inline-block px-2 py-0.5 text-[10px] font-bold uppercase rounded border ${getStatusBadge(scan.status)}`}>
                          {scan.status}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="px-5 py-4 text-right space-x-1.5" onClick={(e) => e.stopPropagation()}>
                        {isRunning && (
                          <button
                            onClick={() => onViewLiveProgress(scan.id)}
                            className="px-2 py-1 text-xs font-semibold rounded bg-sky-950 text-sky-400 border border-sky-500/30 hover:bg-sky-900"
                          >
                            Stream
                          </button>
                        )}
                        <a
                          href={api.getReportUrl(scan.id, 'html')}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-block px-2 py-1 text-xs font-semibold rounded bg-slate-800 text-sky-300 border border-slate-700 hover:bg-slate-700"
                        >
                          Reporte
                        </a>
                        <button
                          onClick={() => onDeleteScan(scan.id)}
                          className="px-1.5 py-1 text-xs text-slate-500 hover:text-rose-400 rounded hover:bg-rose-950/30"
                        >
                          <TrashIcon className="w-3.5 h-3.5 inline" />
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
};
