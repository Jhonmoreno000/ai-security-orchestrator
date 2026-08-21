import React, { useEffect } from 'react';
import {
  CheckCircleIcon,
  AlertTriangleIcon,
  AlertOctagonIcon,
  CloseIcon,
} from './icons/Icons';

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message?: string;
}

interface ToastProps {
  toast: ToastMessage;
  onDismiss: (id: string) => void;
}

const Toast: React.FC<ToastProps> = ({ toast, onDismiss }) => {
  useEffect(() => {
    const timer = setTimeout(() => onDismiss(toast.id), 6000);
    return () => clearTimeout(timer);
  }, [toast.id, onDismiss]);

  const config: Record<string, { border: string; bg: string; icon: React.ReactNode; titleColor: string }> = {
    success: {
      border: 'border-emerald-500/40',
      bg: 'bg-emerald-950/80',
      icon: <CheckCircleIcon className="w-4 h-4 text-emerald-400" />,
      titleColor: 'text-emerald-300',
    },
    error: {
      border: 'border-rose-500/40',
      bg: 'bg-rose-950/80',
      icon: <AlertOctagonIcon className="w-4 h-4 text-rose-400" />,
      titleColor: 'text-rose-300',
    },
    warning: {
      border: 'border-amber-500/40',
      bg: 'bg-amber-950/80',
      icon: <AlertTriangleIcon className="w-4 h-4 text-amber-400" />,
      titleColor: 'text-amber-300',
    },
    info: {
      border: 'border-sky-500/40',
      bg: 'bg-sky-950/80',
      icon: <CheckCircleIcon className="w-4 h-4 text-sky-400" />,
      titleColor: 'text-sky-300',
    },
  };

  const c = config[toast.type] || config.info;

  return (
    <div
      className={`flex items-start gap-3 p-3.5 rounded-lg border ${c.border} ${c.bg} backdrop-blur-xl shadow-2xl min-w-[320px] max-w-md animate-slide-in`}
    >
      <div className="flex-shrink-0 mt-0.5">{c.icon}</div>
      <div className="flex-1 min-w-0">
        <div className={`text-xs font-mono font-bold uppercase tracking-wider ${c.titleColor}`}>
          {toast.title}
        </div>
        {toast.message && (
          <p className="text-[11px] text-slate-300 mt-0.5 leading-relaxed font-sans">{toast.message}</p>
        )}
      </div>
      <button
        onClick={() => onDismiss(toast.id)}
        className="flex-shrink-0 p-0.5 text-slate-500 hover:text-white rounded transition-colors"
      >
        <CloseIcon className="w-3.5 h-3.5" />
      </button>
    </div>
  );
};

interface ToastContainerProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2.5">
      {toasts.map((toast) => (
        <Toast key={toast.id} toast={toast} onDismiss={onDismiss} />
      ))}
    </div>
  );
};
