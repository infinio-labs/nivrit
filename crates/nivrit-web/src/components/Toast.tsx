import { useEffect } from 'react';
import { CheckCircle2, XCircle, X } from 'lucide-react';

export interface ToastMessage {
  id: string;
  message: string;
  type: 'success' | 'error';
}

export function ToastContainer({
  toasts,
  onDismiss,
}: {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}) {
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      {toasts.map((t) => (
        <Toast key={t.id} toast={t} onDismiss={onDismiss} />
      ))}
    </div>
  );
}

function Toast({ toast, onDismiss }: { toast: ToastMessage; onDismiss: (id: string) => void }) {
  useEffect(() => {
    const timer = setTimeout(() => onDismiss(toast.id), 4000);
    return () => clearTimeout(timer);
  }, [toast.id, onDismiss]);

  const isSuccess = toast.type === 'success';
  return (
    <div
      className={`flex items-center gap-3 rounded-lg px-4 py-3 shadow-lg ${
        isSuccess
          ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900'
          : 'bg-red-600 text-white'
      }`}
    >
      {isSuccess ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
      <span className="text-sm font-medium">{toast.message}</span>
      <button onClick={() => onDismiss(toast.id)} className="ml-2 opacity-80 hover:opacity-100">
        <X size={16} />
      </button>
    </div>
  );
}
