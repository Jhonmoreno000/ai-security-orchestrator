import React, { useState } from 'react';
import { Scan } from '../types';
import { api } from '../services/api';
import {
  FileTextIcon,
  DownloadIcon,
  ExternalLinkIcon,
} from './icons/Icons';

interface ReportsViewProps {
  scans: Scan[];
}

export const ReportsView: React.FC<ReportsViewProps> = ({ scans }) => {
  const [selectedScanId, setSelectedScanId] = useState<string>(scans[0]?.id || '');
  const [format, setFormat] = useState<'html' | 'json'>('html');

  const selectedScan = scans.find((s) => s.id === selectedScanId) || scans[0];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="p-6 rounded-xl bg-[#0d1322] border border-slate-800 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base sm:text-lg font-bold font-mono text-white uppercase tracking-wider">
            Centro de Reportes &amp; Cumplimiento SARIF
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Generación técnica, documentación de evidencias y exportación compatible con pipelines CI/CD
          </p>
        </div>

        {selectedScan && (
          <div className="flex items-center gap-2.5 font-mono text-xs">
            <a
              href={api.getReportUrl(selectedScan.id, 'html')}
              target="_blank"
              rel="noreferrer"
              className="px-3.5 py-1.5 font-bold uppercase rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-md transition-colors flex items-center gap-1.5"
            >
              <ExternalLinkIcon className="w-3.5 h-3.5" />
              <span>Ver HTML</span>
            </a>
            <a
              href={api.getReportUrl(selectedScan.id, 'json')}
              download={`security-report-${selectedScan.id}.json`}
              className="px-3.5 py-1.5 font-bold uppercase rounded-lg bg-slate-800 hover:bg-slate-700 text-sky-400 border border-slate-700 transition-colors flex items-center gap-1.5"
            >
              <DownloadIcon className="w-3.5 h-3.5" />
              <span>Descargar SARIF JSON</span>
            </a>
          </div>
        )}
      </div>

      {scans.length === 0 ? (
        <div className="p-12 text-center rounded-xl bg-[#0d1322] border border-slate-800 text-slate-500 font-mono text-xs">
          [INFO] No hay auditorías registradas para generar reportes.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 font-mono">
          {/* Scan List */}
          <div className="p-4 rounded-xl bg-[#0d1322] border border-slate-800 space-y-2.5">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
              AUDITORÍAS DISPONIBLES ({scans.length})
            </div>

            <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
              {scans.map((scan) => {
                const isSelected = (selectedScanId || scans[0]?.id) === scan.id;
                return (
                  <div
                    key={scan.id}
                    onClick={() => setSelectedScanId(scan.id)}
                    className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-sky-950/50 border-sky-500/60 text-white shadow-sm'
                        : 'bg-[#080c14] border-slate-800 hover:border-slate-700 text-slate-400'
                    }`}
                  >
                    <div className="text-xs font-bold truncate text-slate-200">{scan.target}</div>
                    <div className="flex items-center justify-between text-[10px] mt-1 text-slate-400">
                      <span>{scan.findings_count || 0} hallazgos</span>
                      <span className="uppercase">{scan.status}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Report Frame */}
          <div className="lg:col-span-3 rounded-xl bg-[#0d1322] border border-slate-800 overflow-hidden flex flex-col shadow-2xl">
            <div className="p-3 bg-[#080c14] border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs text-slate-300">
                <FileTextIcon className="w-3.5 h-3.5 text-sky-400" />
                <span>PREVIEW: <strong className="text-white">{selectedScan?.target}</strong></span>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setFormat('html')}
                  className={`px-2 py-0.5 text-[11px] font-bold uppercase rounded ${
                    format === 'html' ? 'bg-sky-500 text-slate-950' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  HTML Preview
                </button>
                <button
                  onClick={() => setFormat('json')}
                  className={`px-2 py-0.5 text-[11px] font-bold uppercase rounded ${
                    format === 'json' ? 'bg-sky-500 text-slate-950' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  SARIF JSON
                </button>
              </div>
            </div>

            {selectedScan ? (
              <div className="flex-1 min-h-[550px] bg-[#080c14]">
                <iframe
                  src={api.getReportUrl(selectedScan.id, format)}
                  title="Security Report"
                  className="w-full h-full min-h-[550px] border-0"
                />
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
