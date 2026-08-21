import React, { useState, useRef, useEffect } from 'react';
import { ChatMessage } from '../types';
import { api } from '../services/api';
import {
  SendIcon,
  ShieldCheckIcon,
  CodeIcon,
  LayersIcon,
  BotIcon,
  UserIcon,
  RefreshIcon,
} from './icons/Icons';

export const AIAssistantView: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: '1',
      role: 'assistant',
      content:
        '### AI SecOps Analyst Console\n\nAgente autónomo de Ciberseguridad y DevSecOps activo. Servicios disponibles:\n- Evaluación de severidad y vectores de ataque identificados por ZAP, Nuclei, Semgrep y Trivy.\n- Generación de parches de código parametrizados para FastAPI, Python, Node.js y React.\n- Configuración de políticas de aislamiento de red y control de perímetros.',
      timestamp: new Date().toLocaleTimeString(),
      provider: 'CodeLlama / SecOps Specialist',
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const suggestedPrompts = [
    {
      label: 'Mitigación de SQL Injection (CWE-89)',
      prompt: 'Cómo soluciono una vulnerabilidad de SQL Injection en Python / SQLAlchemy usando consultas parametrizadas?',
      icon: <CodeIcon className="w-3.5 h-3.5 text-sky-400" />,
    },
    {
      label: 'Content-Security-Policy (CSP)',
      prompt: 'Cómo configuro una cabecera de Content-Security-Policy (CSP) estricta para evitar Cross-Site Scripting?',
      icon: <ShieldCheckIcon className="w-3.5 h-3.5 text-emerald-400" />,
    },
    {
      label: 'Mecanismo de Retest SHA-256',
      prompt: 'Explícame el flujo de verificación de vulnerabilidades y comparación de SHA-256 fingerprints del Retest Engine.',
      icon: <RefreshIcon className="w-3.5 h-3.5 text-amber-400" />,
    },
    {
      label: 'Hardening de Contenedor Dockerfile',
      prompt: 'Cuáles son las mejores prácticas para corregir vulnerabilidades CVE críticas reportadas por Trivy en un Dockerfile?',
      icon: <LayersIcon className="w-3.5 h-3.5 text-indigo-400" />,
    },
  ];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || input;
    if (!query.trim() || loading) return;

    const userMsg: ChatMessage = {
      id: String(Date.now()),
      role: 'user',
      content: query.trim(),
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInput('');
    setLoading(true);

    try {
      const history = [...messages, userMsg].map((m) => ({ role: m.role, content: m.content }));
      const res = await api.sendAIChat(history);

      const assistantMsg: ChatMessage = {
        id: String(Date.now() + 1),
        role: 'assistant',
        content: res.reply,
        timestamp: new Date().toLocaleTimeString(),
        provider: res.provider || 'AI Analyst',
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (e: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: String(Date.now() + 1),
          role: 'assistant',
          content: '[ERROR] No se pudo establecer conexión con el motor de IA.',
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in max-w-5xl mx-auto">
      {/* Header */}
      <div className="p-6 rounded-xl bg-[#0d1322] border border-slate-800 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base sm:text-lg font-bold font-mono text-white uppercase tracking-wider">
              AI SecOps Analyst Assistant
            </h2>
            <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-500/30 rounded">
              LLM AGENT READY
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Asesoría técnica en ciberseguridad, análisis de vectores y generación de parches
          </p>
        </div>

        <div className="text-xs font-mono text-slate-400 bg-[#080c14] px-3 py-1.5 rounded-lg border border-slate-800">
          MODEL: <span className="text-sky-400 font-bold">CodeLlama Specialist</span>
        </div>
      </div>

      {/* Suggested Prompts */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
        {suggestedPrompts.map((s, idx) => (
          <button
            key={idx}
            onClick={() => handleSendMessage(s.prompt)}
            className="p-3 text-left rounded-lg bg-[#0d1322] hover:bg-slate-900 border border-slate-800 hover:border-sky-500/40 transition-colors text-xs"
          >
            <div className="flex items-center gap-1.5 font-mono font-bold text-sky-400 mb-1">
              {s.icon}
              <span className="truncate">{s.label}</span>
            </div>
            <div className="text-[11px] text-slate-400 line-clamp-2">{s.prompt}</div>
          </button>
        ))}
      </div>

      {/* Chat Container */}
      <div className="h-[520px] rounded-xl bg-[#0d1322] border border-slate-800 overflow-hidden flex flex-col shadow-2xl">
        {/* Feed */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4">
          {messages.map((msg) => {
            const isUser = msg.role === 'user';
            return (
              <div
                key={msg.id}
                className={`flex gap-3 ${isUser ? 'justify-end' : 'justify-start'}`}
              >
                {!isUser && (
                  <div className="w-7 h-7 rounded bg-slate-900 border border-slate-800 flex items-center justify-center text-sky-400 flex-shrink-0 mt-1">
                    <BotIcon className="w-4 h-4" />
                  </div>
                )}

                <div
                  className={`max-w-2xl p-4 rounded-xl text-xs sm:text-sm leading-relaxed ${
                    isUser
                      ? 'bg-sky-500/20 text-sky-200 border border-sky-500/40 rounded-br-none'
                      : 'bg-[#080c14] text-slate-200 border border-slate-800 rounded-bl-none'
                  }`}
                >
                  <div className="flex items-center justify-between gap-4 mb-1.5 text-[10px] opacity-60 font-mono">
                    <span>{isUser ? 'OPERADOR SECOPS' : `AI ANALYST (${msg.provider || 'CORE'})`}</span>
                    <span>{msg.timestamp}</span>
                  </div>

                  <div className="prose prose-invert prose-sm max-w-none whitespace-pre-wrap font-sans text-xs sm:text-sm">
                    {msg.content}
                  </div>
                </div>

                {isUser && (
                  <div className="w-7 h-7 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 flex-shrink-0 mt-1">
                    <UserIcon className="w-4 h-4" />
                  </div>
                )}
              </div>
            );
          })}

          {loading && (
            <div className="flex gap-2.5 items-center text-xs font-mono text-slate-400">
              <div className="w-7 h-7 rounded bg-slate-900 border border-slate-800 flex items-center justify-center text-sky-400">
                <BotIcon className="w-4 h-4" />
              </div>
              <div className="p-2.5 rounded-lg bg-[#080c14] border border-slate-800 flex items-center gap-2">
                <div className="w-3 h-3 border-2 border-sky-400 border-t-transparent rounded-full animate-spin" />
                <span>Razonando sobre heurísticas y mitigaciones...</span>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="p-3.5 border-t border-slate-800 bg-[#080c14]">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-2.5"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Consulta sobre vectores de ataque, CWEs, parches de código o mitigaciones..."
              disabled={loading}
              className="flex-1 px-3.5 py-2.5 bg-[#0d1322] border border-slate-700 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="px-4 py-2.5 text-xs font-bold font-mono uppercase tracking-wide rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-md disabled:opacity-40 transition-all flex items-center gap-1.5"
            >
              <SendIcon className="w-3.5 h-3.5" />
              <span>Enviar</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
