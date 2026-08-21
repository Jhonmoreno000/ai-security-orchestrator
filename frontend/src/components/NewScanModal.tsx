import React, { useState } from 'react';
import { ScannerType } from '../types';
import {
  ShieldCheckIcon,
  RadarIcon,
  CodeIcon,
  LayersIcon,
  CloseIcon,
  ActivityIcon,
  LockIcon,
  CpuIcon,
} from './icons/Icons';

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (target: string, scanners: ScannerType[], timeout: number, options: Record<string, any>) => Promise<void>;
}

export const NewScanModal: React.FC<NewScanModalProps> = ({ isOpen, onClose, onSubmit }) => {
  const [target, setTarget] = useState('http://testphp.vulnweb.com');
  const [selectedScanners, setSelectedScanners] = useState<ScannerType[]>(['zap', 'nuclei', 'semgrep', 'trivy']);
  const [timeout, setTimeoutVal] = useState(300);
  const [activeProfile, setActiveProfile] = useState<string>('full');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [customHeaders, setCustomHeaders] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const profiles = [
    {
      id: 'full',
      name: 'Auditoría Integral (DAST + SAST + SBOM)',
      badge: 'Completo',
      desc: 'Orquesta ZAP (Web DAST), Nuclei (CVEs), Semgrep (SAST) y Trivy (Dependencias)',
      tools: ['zap', 'nuclei', 'semgrep', 'trivy'] as ScannerType[],
      icon: <ShieldCheckIcon className="w-4 h-4 text-sky-400" />,
    },
    {
      id: 'web',
      name: 'Escaneo Dinámico de Aplicación (DAST)',
      badge: 'Superficie',
      desc: 'Detección de inyecciones XSS, SQLi, CSRF y cabeceras inseguras',
      tools: ['zap', 'nuclei'] as ScannerType[],
      icon: <RadarIcon className="w-4 h-4 text-emerald-400" />,
    },
    {
      id: 'sast',
      name: 'Análisis Estático de Código (SAST)',
      badge: 'Código',
      desc: 'Inspección de patrones inseguros, fugas de secretos y JWT tokens',
      tools: ['semgrep'] as ScannerType[],
      icon: <CodeIcon className="w-4 h-4 text-amber-400" />,
    },
    {
      id: 'sbom',
      name: 'Auditoría de Supply Chain & SBOM',
      badge: 'Librerías',
      desc: 'Análisis de CVEs en librerías open-source y dependencias de contenedor',
      tools: ['trivy'] as ScannerType[],
      icon: <LayersIcon className="w-4 h-4 text-indigo-400" />,
    },
  ];

  const handleSelectProfile = (pId: string) => {
    setActiveProfile(pId);
    const p = profiles.find((x) => x.id === pId);
    if (p) {
      setSelectedScanners(p.tools);
    }
  };

  const toggleScanner = (tool: ScannerType) => {
    setActiveProfile('custom');
    if (selectedScanners.includes(tool)) {
      if (selectedScanners.length > 1) {
        setSelectedScanners(selectedScanners.filter((t) => t !== tool));
      }
    } else {
      setSelectedScanners([...selectedScanners, tool]);
    }
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      setError('Especifique un target válido (URL o dirección de host).');
      return;
    }
    if (selectedScanners.length === 0) {
      setError('Seleccione al menos un motor de escaneo.');
      return;
    }

    setError(null);
    setLoading(true);
    try {
      const options: Record<string, any> = {};
      if (customHeaders.trim()) {
        options['headers'] = customHeaders.trim();
      }
      await onSubmit(target.trim(), selectedScanners, timeout, options);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Error al orquestar la auditoría');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto flex items-center justify-center p-4 sm:p-6 bg-slate-950/85 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl bg-[#0d1322] border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 bg-[#090d16] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
              <ActivityIcon className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold font-mono uppercase text-white tracking-wider">
                Configuración de Nueva Auditoría de Seguridad
              </h3>
              <p className="text-xs text-slate-400">Parámetros de ejecución para el orquestador multimotor</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <CloseIcon className="w-4 h-4" />
          </button>
        </div>

        {/* Form Content */}
        <form onSubmit={handleLaunch} className="p-6 space-y-5 max-h-[78vh] overflow-y-auto">
          {error && (
            <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-500/40 text-rose-300 text-xs font-mono">
              [ERROR] {error}
            </div>
          )}

          {/* Target URL Input */}
          <div>
            <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-300 mb-1.5">
              Objetivo / Endpoint a Auditar <span className="text-sky-400">*</span>
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://api.empresa.com o http://localhost:8000"
              required
              className="w-full px-3.5 py-2.5 bg-[#080c14] border border-slate-700 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />

            {/* Quick Chips */}
            <div className="flex flex-wrap items-center gap-1.5 mt-2">
              <span className="text-[10px] font-mono text-slate-500 uppercase">Presets rápidos:</span>
              {[
                { label: 'TestPHP Web', url: 'http://testphp.vulnweb.com' },
                { label: 'Local API Backend', url: 'http://localhost:8000' },
                { label: 'Juice Shop Demo', url: 'https://juice-shop.herokuapp.com' },
              ].map((chip) => (
                <button
                  key={chip.label}
                  type="button"
                  onClick={() => setTarget(chip.url)}
                  className="px-2 py-0.5 text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700"
                >
                  {chip.label}
                </button>
              ))}
            </div>
          </div>

          {/* Scan Profiles Grid */}
          <div>
            <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-300 mb-1.5">
              Perfil de Escaneo
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {profiles.map((p) => {
                const isSelected = activeProfile === p.id;
                return (
                  <div
                    key={p.id}
                    onClick={() => handleSelectProfile(p.id)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-sky-950/40 border-sky-500/60 shadow-sm'
                        : 'bg-[#080c14] border-slate-800 hover:border-slate-700 text-slate-400'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2 font-bold font-mono text-xs text-slate-200">
                        {p.icon}
                        <span>{p.name}</span>
                      </div>
                      <span className={`text-[9px] font-mono font-bold uppercase px-1.5 py-0.2 rounded ${
                        isSelected ? 'bg-sky-500 text-slate-950' : 'bg-slate-800 text-slate-400'
                      }`}>
                        {p.badge}
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400 leading-snug">{p.desc}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Engine Selection */}
          <div>
            <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-300 mb-1.5">
              Motores Seleccionados ({selectedScanners.length}/4)
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {[
                { id: 'zap' as ScannerType, label: 'ZAP DAST', desc: 'Inyecciones web' },
                { id: 'nuclei' as ScannerType, label: 'Nuclei Probe', desc: 'Exploits CVE' },
                { id: 'semgrep' as ScannerType, label: 'Semgrep SAST', desc: 'Código estático' },
                { id: 'trivy' as ScannerType, label: 'Trivy SBOM', desc: 'Paquetes y CVEs' },
              ].map((tool) => {
                const isChecked = selectedScanners.includes(tool.id);
                return (
                  <div
                    key={tool.id}
                    onClick={() => toggleScanner(tool.id)}
                    className={`p-2.5 rounded-lg border cursor-pointer select-none transition-all ${
                      isChecked
                        ? 'bg-slate-900 border-sky-500/60 text-sky-400'
                        : 'bg-[#080c14] border-slate-800 text-slate-500 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1 font-mono text-xs font-bold">
                      <span>{tool.label}</span>
                      <span className="text-[10px]">{isChecked ? '[X]' : '[ ]'}</span>
                    </div>
                    <p className="text-[10px] text-slate-400">{tool.desc}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Advanced Accordion */}
          <div className="border border-slate-800 rounded-lg overflow-hidden bg-[#080c14]">
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="w-full p-3 text-left text-xs font-mono font-bold uppercase text-slate-400 hover:text-slate-200 flex items-center justify-between"
            >
              <div className="flex items-center gap-2">
                <CpuIcon className="w-3.5 h-3.5 text-sky-400" />
                <span>Parámetros de Timeout &amp; Guardrails</span>
              </div>
              <span className="text-[10px]">{showAdvanced ? '▲' : '▼'}</span>
            </button>

            {showAdvanced && (
              <div className="p-4 pt-0 space-y-3 border-t border-slate-800 font-mono text-xs">
                <div>
                  <div className="flex justify-between text-slate-300 mb-1">
                    <span>Límite de Ejecución por Contenedor:</span>
                    <span className="text-sky-400 font-bold">{timeout}s</span>
                  </div>
                  <input
                    type="range"
                    min="30"
                    max="900"
                    step="30"
                    value={timeout}
                    onChange={(e) => setTimeoutVal(Number(e.target.value))}
                    className="w-full accent-sky-500"
                  />
                  <div className="flex justify-between text-[10px] text-slate-500">
                    <span>30s</span>
                    <span>300s (Estándar)</span>
                    <span>900s</span>
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Cabeceras HTTP / Bearer Token:</label>
                  <textarea
                    value={customHeaders}
                    onChange={(e) => setCustomHeaders(e.target.value)}
                    placeholder="Authorization: Bearer eyJhbGciOi..."
                    rows={2}
                    className="w-full p-2 bg-[#0d1322] border border-slate-700 rounded text-xs text-white placeholder-slate-600 focus:outline-none"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Guardrails notice */}
          <div className="p-3 rounded-lg bg-[#080c14] border border-slate-800 text-[11px] font-mono text-slate-400 flex items-start gap-2">
            <LockIcon className="w-3.5 h-3.5 text-sky-400 flex-shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-300 uppercase">Policy Engine Guardrail:</strong> El alcance está estrictamente confinado al target seleccionado para prevenir accesos fuera de perímetro.
            </div>
          </div>

          {/* Actions */}
          <div className="pt-2 flex items-center justify-end gap-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2 text-xs font-bold font-mono uppercase tracking-wide rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-md shadow-sky-500/20 disabled:opacity-50 transition-all flex items-center gap-2"
            >
              {loading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                  <span>Desplegando Contenedores...</span>
                </>
              ) : (
                <>
                  <span>Orquestar Auditoría</span>
                  <span>&rarr;</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
