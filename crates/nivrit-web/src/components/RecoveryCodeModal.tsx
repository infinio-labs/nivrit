import { useState } from 'react';
import { AlertTriangle, Check, Copy } from './icons';
import { Button, Card } from './ui';

/**
 * Shows the recovery code once, and makes it awkward to dismiss by accident.
 *
 * The code is generated on this device and never sent to the server, so nobody
 * — including the operator — can reissue it. Losing it together with the master
 * password means the account's secrets are unrecoverable by anyone, permanently.
 * That justifies an explicit acknowledgement rather than a single button a user
 * can click past while skimming.
 */
export function RecoveryCodeModal({ code, onClose }: { code: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);

  function download() {
    // A file is the difference between "I meant to write it down" and having it.
    const body =
      `Nivrit recovery code\n\n${code}\n\n` +
      `Store this somewhere safe and offline.\n` +
      `It is the only way to regain access if you forget your master password.\n` +
      `Nivrit never received this code and cannot reissue it.\n`;
    const url = URL.createObjectURL(new Blob([body], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nivrit-recovery-code.txt';
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="recovery-title"
    >
      <Card className="w-full max-w-md p-6 shadow-xl">
        <div className="mb-5 flex items-start gap-4">
          <div className="rounded-full bg-amber-100 p-2 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400">
            <AlertTriangle size={22} />
          </div>
          <div>
            <h2
              id="recovery-title"
              className="text-lg font-semibold text-slate-900 dark:text-white"
            >
              Save your recovery code
            </h2>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              This is the only way to recover your account if you forget your password. It was
              generated on this device and never sent to us, so we cannot show it again or reset
              it for you.
            </p>
          </div>
        </div>

        <div className="mb-4 flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-800">
          <code
            data-testid="recovery-code"
            className="text-sm font-bold tracking-wider text-slate-900 dark:text-slate-100"
          >
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

        <Button variant="secondary" className="mb-5 w-full" onClick={download}>
          Download as a file
        </Button>

        <label className="mb-5 flex cursor-pointer items-start gap-3 text-sm text-slate-700 dark:text-slate-300">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            className="mt-0.5 h-4 w-4 shrink-0 rounded border-slate-300 text-primary-600 focus:ring-primary-500 dark:border-slate-600"
          />
          <span>
            I have saved this code somewhere safe. I understand it cannot be recovered, and that
            without it a forgotten password means losing access to my secrets permanently.
          </span>
        </label>

        <Button onClick={onClose} className="w-full" disabled={!acknowledged}>
          Continue to my vault
        </Button>
      </Card>
    </div>
  );
}
