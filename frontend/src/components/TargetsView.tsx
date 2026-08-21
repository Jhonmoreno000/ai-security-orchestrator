import React, { useState, useEffect } from 'react';
import { TargetScope } from '../types';
import { api } from '../services/api';
import {
  LockIcon,
  TrashIcon,
} from './icons/Icons';

interface TargetsViewProps {
  onQuickAudit: (targetUrl: string) => void;
}

export const TargetsView: React.FC<TargetsViewProps> = ({ onQuickAudit }) => {
  const [targets, setTargets] = useState<TargetScope[]>([]);
  const [_loading, setLoading] = useState(true);
  const [url, setUrl] = useState('');
  const [label, setLabel] = useState('');
  const [scopeRule, setScopeRule] = useState('');
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    try {
      const data = await api.getTargets();
      setTargets(data.targets || []);
    } catch (e) {
      console.error('Failed to fetch targets:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setCreating(true);
    try {
      const scopeRules = scopeRule.trim() ? scopeRule.split(',').map((s) => s.trim()) : [url.trim()];
      await api.createTarget(url.trim(), label.trim() || 'Custom Target', 'url', scopeRules);
      setUrl('');
      setLabel('');
      setScopeRule('');
      fetchTargets();
    } catch (e) {
      console.error('Error creating target:', e);
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteTarget = async (targetId: string) => {
    try {
      await api.deleteTarget(targetId);
      setTargets((prev) => prev.filter((t) => t.id !== targetId));
    } catch (e) {
      console.error('Error deleting target:', e);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="p-6 rounded-xl bg-[#0d1322] border border-slate-800 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base sm:text-lg font-bold font-mono text-white uppercase tracking-wider">
              Control de Perímetro &amp; Policy Scope Engine
            </h2>
            <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-sky-950 text-sky-400 border border-sky-500/30 rounded">
              GUARDRAILS ENFORCED
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Definición de listas blancas de alcance para confinar la ejecución de los escáneres ZAP y Nuclei
          </p>
        </div>
      </div>

      {/* Grid: Policy Rules & Add Target */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        {/* Rules Card */}
        <div className="p-5 rounded-xl bg-[#0d1322] border border-slate-800 space-y-3 shadow-xl">
          <div className="flex items-center gap-2 font-bold text-white uppercase tracking-wider text-xs">
            <LockIcon className="w-3.5 h-3.5 text-sky-400" />
            <span>Reglas Activas del Policy Engine</span>
          </div>
          <div className="space-y-2 text-slate-300">
            <div className="p-2.5 rounded-lg bg-[#080c14] border border-slate-800">
              <div className="font-bold text-sky-400 mb-0.5 uppercase text-[10px]">1. Aislamiento Estricto de Red</div>
              <p className="text-[11px] text-slate-400 font-sans">
                Bloqueo automático de solicitudes dirigidas a hosts no autorizados en la lista de alcance.
              </p>
            </div>

            <div className="p-2.5 rounded-lg bg-[#080c14] border border-slate-800">
              <div className="font-bold text-sky-400 mb-0.5 uppercase text-[10px]">2. Filtrado de Metacaracteres</div>
              <p className="text-[11px] text-slate-400 font-sans">
                Detección y anulación de inyecciones de comandos en parámetros CLI (<code>;</code>, <code>&&</code>, <code>|</code>).
              </p>
            </div>

            <div className="p-2.5 rounded-lg bg-[#080c14] border border-slate-800">
              <div className="font-bold text-sky-400 mb-0.5 uppercase text-[10px]">3. Cuotas de Concurrencia</div>
              <p className="text-[11px] text-slate-400 font-sans">
                Límite de 2 contenedores simultáneos &bull; Timeout global de 300s.
              </p>
            </div>
          </div>
        </div>

        {/* Add Target Form (2 cols) */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#0d1322] border border-slate-800 shadow-xl space-y-3 font-sans">
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
            Registrar Nuevo Objetivo en el Scope
          </h3>

          <form onSubmit={handleAddTarget} className="space-y-3 font-mono text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] uppercase tracking-wider text-slate-400 mb-1">
                  URL / Host Primario *
                </label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://api.empresa.com"
                  required
                  className="w-full px-3 py-2 bg-[#080c14] border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-[11px] uppercase tracking-wider text-slate-400 mb-1">
                  Identificador / Sistema
                </label>
                <input
                  type="text"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="API Gateway Producción"
                  className="w-full px-3 py-2 bg-[#080c14] border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] uppercase tracking-wider text-slate-400 mb-1">
                Hosts Whitelist / Alcance (separados por coma):
              </label>
              <input
                type="text"
                value={scopeRule}
                onChange={(e) => setScopeRule(e.target.value)}
                placeholder="api.empresa.com, auth.empresa.com, *.empresa.com"
                className="w-full px-3 py-2 bg-[#080c14] border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div className="pt-1 flex justify-end">
              <button
                type="submit"
                disabled={creating || !url.trim()}
                className="px-4 py-2 text-xs font-bold font-mono uppercase tracking-wide rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-md disabled:opacity-50 transition-all flex items-center gap-1.5"
              >
                <span>+ Agregar a Scope</span>
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Target Inventory Table */}
      <div className="rounded-xl bg-[#0d1322] border border-slate-800 overflow-hidden shadow-2xl">
        <div className="p-3.5 bg-[#080c14] border-b border-slate-800 flex items-center justify-between font-mono">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-300">
            INVENTARIO DE PERÍMETROS AUTORIZADOS ({targets.length})
          </div>
        </div>

        <div className="overflow-x-auto font-mono text-xs">
          <table className="w-full text-left">
            <thead className="bg-[#080c14] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="px-5 py-3">Host / URL</th>
                <th className="px-5 py-3">Etiqueta</th>
                <th className="px-5 py-3">Reglas de Alcance</th>
                <th className="px-5 py-3">Estado</th>
                <th className="px-5 py-3 text-right">Acción</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {targets.map((target) => (
                <tr key={target.id} className="hover:bg-slate-900/60 transition-colors font-mono">
                  <td className="px-5 py-3.5 font-bold text-sky-400">
                    {target.url}
                  </td>
                  <td className="px-5 py-3.5 text-slate-300">
                    {target.label || 'Target'}
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex flex-wrap gap-1">
                      {target.scope_rules?.map((rule, i) => (
                        <span
                          key={i}
                          className="px-1.5 py-0.2 text-[9px] rounded bg-slate-900 text-sky-300 border border-slate-700"
                        >
                          {rule}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className="px-2 py-0.5 text-[9px] font-bold uppercase rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                      AUTORIZADO
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-right space-x-1.5">
                    <button
                      onClick={() => onQuickAudit(target.url)}
                      className="px-2.5 py-1 text-xs font-semibold rounded bg-sky-500 hover:bg-sky-400 text-slate-950 transition-colors"
                    >
                      Auditar &rarr;
                    </button>
                    <button
                      onClick={() => handleDeleteTarget(target.id)}
                      className="px-1.5 py-1 text-xs text-slate-500 hover:text-rose-400 rounded hover:bg-rose-950/30"
                    >
                      <TrashIcon className="w-3.5 h-3.5 inline" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
