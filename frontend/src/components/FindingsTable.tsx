import React, { useState, useMemo } from 'react';
import { Finding, SeverityLevel } from '../types';
import {
  SearchIcon,
} from './icons/Icons';

interface FindingsTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  selectedScanTarget?: string;
}

type SeverityFilter = 'ALL' | SeverityLevel;

const SEVERITY_BADGES: Record<SeverityLevel, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
  INFO: 'badge-info',
};

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings, onSelectFinding, selectedScanTarget }) => {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');
  const [scannerFilter, setScannerFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [sortField, setSortField] = useState<'severity' | 'cvss' | 'date'>('severity');
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc');

  const counts = useMemo(() => {
    const c = { ALL: findings.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, OPEN: 0, FIXED: 0 };
    findings.forEach((f) => {
      const sev = (f.severity || 'INFO').toUpperCase() as SeverityLevel;
      if (c[sev] !== undefined) c[sev]++;
      if (f.status === 'FIXED') c.FIXED++;
      else c.OPEN++;
    });
    return c;
  }, [findings]);

  const filtered = useMemo(() => {
    let result = findings.filter((f) => {
      const sev = (f.severity || 'INFO').toUpperCase() as SeverityLevel;
      if (severityFilter !== 'ALL' && sev !== severityFilter) return false;
      if (scannerFilter !== 'ALL' && f.scanner?.toLowerCase() !== scannerFilter.toLowerCase()) return false;
      if (statusFilter === 'OPEN' && f.status === 'FIXED') return false;
      if (statusFilter === 'FIXED' && f.status !== 'FIXED') return false;

      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        const inTitle = f.title?.toLowerCase().includes(q);
        const inDesc = f.description?.toLowerCase().includes(q);
        const inCwe = f.cwe?.toLowerCase().includes(q);
        const inUrl = f.url?.toLowerCase().includes(q);
        const inScanner = f.scanner?.toLowerCase().includes(q);
        return inTitle || inDesc || inCwe || inUrl || inScanner;
      }
      return true;
    });

    result.sort((a, b) => {
      if (sortField === 'severity') {
        const sevA = SEVERITY_ORDER[(a.severity || 'INFO').toUpperCase() as SeverityLevel] || 0;
        const sevB = SEVERITY_ORDER[(b.severity || 'INFO').toUpperCase() as SeverityLevel] || 0;
        return sortDir === 'desc' ? sevB - sevA : sevA - sevB;
      }
      if (sortField === 'cvss') {
        const cA = a.cvss_score || 0;
        const cB = b.cvss_score || 0;
        return sortDir === 'desc' ? cB - cA : cA - cB;
      }
      const dA = a.created_at ? new Date(a.created_at).getTime() : 0;
      const dB = b.created_at ? new Date(b.created_at).getTime() : 0;
      return sortDir === 'desc' ? dB - dA : dA - dB;
    });

    return result;
  }, [findings, severityFilter, scannerFilter, statusFilter, searchTerm, sortField, sortDir]);

  const toggleSort = (field: 'severity' | 'cvss' | 'date') => {
    if (sortField === field) {
      setSortDir((prev) => (prev === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header Bar */}
      <div className="p-6 rounded-xl bg-[#0d1322] border border-slate-800 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base sm:text-lg font-bold font-mono text-white uppercase tracking-wider">
              Inventario de Vulnerabilidades &amp; Hallazgos
            </h2>
            {selectedScanTarget && (
              <span className="text-xs px-2.5 py-0.5 rounded font-mono bg-sky-500/10 text-sky-400 border border-sky-500/30">
                TARGET: {selectedScanTarget}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Correlación multimotor con evidencias técnicas y validación continua
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 rounded bg-amber-950/60 text-amber-400 border border-amber-500/30 font-bold">
            {counts.OPEN} ABIERTAS
          </span>
          <span className="px-2.5 py-1 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-500/30 font-bold">
            {counts.FIXED} MITIGADAS
          </span>
        </div>
      </div>

      {/* Filter and Query Controls */}
      <div className="p-4 rounded-xl bg-[#0d1322] border border-slate-800 space-y-3">
        <div className="flex flex-col md:flex-row items-center justify-between gap-3">
          {/* Search */}
          <div className="relative w-full md:w-80">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <SearchIcon className="w-3.5 h-3.5" />
            </div>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar título, CWE, URL o fingerprint..."
              className="w-full pl-9 pr-4 py-2 bg-[#080c14] border border-slate-700 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>

          {/* Engine and Status Filters */}
          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto font-mono text-xs">
            <span className="text-slate-500 text-[11px] uppercase">Motor:</span>
            {['ALL', 'zap', 'nuclei', 'semgrep', 'trivy'].map((engine) => (
              <button
                key={engine}
                onClick={() => setScannerFilter(engine)}
                className={`px-2 py-1 text-[11px] font-bold uppercase rounded transition-colors ${
                  scannerFilter === engine
                    ? 'bg-sky-500 text-slate-950'
                    : 'bg-[#080c14] text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {engine}
              </button>
            ))}

            <span className="text-slate-500 text-[11px] uppercase ml-2">Estado:</span>
            {['ALL', 'OPEN', 'FIXED'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2 py-1 text-[11px] font-bold uppercase rounded transition-colors ${
                  statusFilter === st
                    ? 'bg-sky-500 text-slate-950'
                    : 'bg-[#080c14] text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {st === 'ALL' ? 'TODOS' : st === 'OPEN' ? 'ABIERTAS' : 'CORREGIDAS'}
              </button>
            ))}
          </div>
        </div>

        {/* Severity Filter Badges */}
        <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-slate-800 font-mono text-xs">
          <span className="text-slate-500 text-[11px] uppercase mr-1">Severidad:</span>
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as SeverityFilter[]).map((sev) => {
            const isSelected = severityFilter === sev;
            const badgeClass = sev !== 'ALL' ? SEVERITY_BADGES[sev] : '';
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-0.5 text-[11px] font-bold uppercase rounded transition-all ${
                  isSelected
                    ? sev === 'ALL'
                      ? 'bg-sky-500 text-slate-950'
                      : `${badgeClass} ring-1 ring-white/30`
                    : 'bg-[#080c14] text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {sev} ({counts[sev as keyof typeof counts] || 0})
              </button>
            );
          })}
        </div>
      </div>

      {/* Findings Table */}
      <div className="rounded-xl bg-[#0d1322] border border-slate-800 overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#080c14] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th
                  className="px-5 py-3.5 cursor-pointer hover:text-white"
                  onClick={() => toggleSort('severity')}
                >
                  Severidad {sortField === 'severity' && (sortDir === 'desc' ? '↓' : '↑')}
                </th>
                <th className="px-5 py-3.5 font-sans">Título de Vulnerabilidad &amp; Vector</th>
                <th className="px-5 py-3.5">Motor</th>
                <th className="px-5 py-3.5">CWE / OWASP</th>
                <th
                  className="px-5 py-3.5 cursor-pointer hover:text-white"
                  onClick={() => toggleSort('cvss')}
                >
                  CVSS {sortField === 'cvss' && (sortDir === 'desc' ? '↓' : '↑')}
                </th>
                <th className="px-5 py-3.5">Estado</th>
                <th className="px-5 py-3.5 text-right">Acción</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-5 py-16 text-center text-slate-500 font-mono text-xs">
                    [INFO] No se encontraron hallazgos registrados para los filtros aplicados.
                  </td>
                </tr>
              ) : (
                filtered.map((finding) => {
                  const sev = (finding.severity || 'INFO').toUpperCase() as SeverityLevel;
                  const badgeClass = SEVERITY_BADGES[sev] || 'badge-info';
                  const isFixed = finding.status === 'FIXED';

                  return (
                    <tr
                      key={finding.id}
                      onClick={() => onSelectFinding(finding)}
                      className="hover:bg-slate-900/60 transition-colors group cursor-pointer"
                    >
                      {/* Severity Pill */}
                      <td className="px-5 py-3.5">
                        <span className={`inline-flex px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded ${badgeClass}`}>
                          {sev}
                        </span>
                      </td>

                      {/* Title & Target Endpoint */}
                      <td className="px-5 py-3.5 max-w-md">
                        <div className="font-bold text-slate-200 group-hover:text-sky-300 transition-colors text-xs truncate">
                          {finding.title}
                        </div>
                        {finding.url && (
                          <div className="text-[11px] font-mono text-slate-500 truncate mt-0.5">
                            {finding.url}
                          </div>
                        )}
                      </td>

                      {/* Scanner */}
                      <td className="px-5 py-3.5 font-mono">
                        <span className="px-1.5 py-0.5 text-[10px] font-bold uppercase rounded bg-slate-900 text-sky-400 border border-slate-700">
                          {finding.scanner}
                        </span>
                      </td>

                      {/* CWE */}
                      <td className="px-5 py-3.5 font-mono text-slate-300 text-xs">
                        <div>{finding.cwe || 'CWE-N/A'}</div>
                        {finding.owasp && <div className="text-[10px] text-slate-500">{finding.owasp}</div>}
                      </td>

                      {/* CVSS Score */}
                      <td className="px-5 py-3.5 font-mono font-bold">
                        <span className={finding.cvss_score && finding.cvss_score >= 7 ? 'text-rose-400' : 'text-amber-400'}>
                          {finding.cvss_score ? `${finding.cvss_score}` : '-'}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="px-5 py-3.5 font-mono">
                        <span
                          className={`inline-flex px-2 py-0.5 text-[10px] font-bold uppercase rounded ${
                            isFixed ? 'badge-fixed' : 'bg-amber-950/40 text-amber-400 border border-amber-500/30'
                          }`}
                        >
                          {finding.status}
                        </span>
                      </td>

                      {/* Action Arrow */}
                      <td className="px-5 py-3.5 text-right font-mono">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectFinding(finding);
                          }}
                          className="px-2.5 py-1 text-xs font-semibold rounded bg-slate-800 text-sky-400 hover:bg-sky-500 hover:text-slate-950 transition-all"
                        >
                          Inspeccionar &rarr;
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
