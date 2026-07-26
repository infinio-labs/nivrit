import { useState } from 'react';
import { AlertTriangle, Check, Copy } from './icons';
import { Button, Card } from './ui';

export function RecoveryCodeModal({ code, onClose }: { code: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <Card className="w-full max-w-md p-6 shadow-xl">
        <div className="mb-5 flex items-start gap-4">
          <div className="rounded-full bg-amber-100 p-2 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400">
            <AlertTriangle size={22} />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
              Save your recovery code
            </h2>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              This is the only way to recover your account if you lose your password. We cannot
              reset it for you.
            </p>
          </div>
        </div>

        <div className="mb-5 flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-800">
          <code className="text-sm font-bold tracking-wider text-slate-900 dark:text-slate-100">
            {code}
          </code>
          <button
            type="button"
            onClick={() => {
              navigator.clipboard.writeText(code);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
            className="shrink-0 rounded-md p-2 text-slate-500 hover:bg-slate-200 hover:text-slate-900 dark:hover:bg-slate-700 dark:hover:text-slate-100"
            aria-label="Copy recovery code"
          >
            {copied ? <Check size={18} /> : <Copy size={18} />}
          </button>
        </div>

        <Button onClick={onClose} className="w-full">
          I have saved it
        </Button>
      </Card>
    </div>
  );
}
