import { useCallback, useEffect, useState } from 'react';
import {
  listSecretVersionsSession,
  restoreSecretVersionSession,
  type DecryptedSecretVersion,
} from '../session';
import { Clock, Eye, EyeOff, RotateCcw, X } from './icons';
import { Button, Card, EmptyState, Skeleton } from './ui';

function formatTimestamp(value: string): string {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

/**
 * Version history for one secret.
 *
 * Every version comes back as ciphertext and is decrypted here with the project
 * key — the server stores the history but cannot read any of it. Restoring is
 * likewise a server-side copy of opaque bytes into a new version, so the old
 * value is never re-encrypted or exposed.
 */
export function SecretHistoryModal({
  projectId,
  environmentId,
  secretKey,
  onClose,
  onRestored,
  onError,
}: {
  projectId: string;
  environmentId: string;
  secretKey: string;
  onClose: () => void;
  onRestored: () => void;
  onError: (message: string) => void;
}) {
  const [versions, setVersions] = useState<DecryptedSecretVersion[] | null>(null);
  const [revealed, setRevealed] = useState<Record<number, boolean>>({});
  const [restoring, setRestoring] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      setVersions(await listSecretVersionsSession(projectId, environmentId, secretKey));
    } catch (e) {
      setVersions([]);
      onError(e instanceof Error ? e.message : 'could not load version history');
    }
  }, [projectId, environmentId, secretKey, onError]);

  useEffect(() => {
    void load();
  }, [load]);

  // Escape closes, as it does for any dialog.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  async function restore(version: number) {
    if (restoring !== null) return;
    setRestoring(version);
    try {
      await restoreSecretVersionSession(projectId, environmentId, secretKey, version);
      onRestored();
      onClose();
    } catch (e) {
      onError(e instanceof Error ? e.message : 'could not restore that version');
    } finally {
      setRestoring(null);
    }
  }

  const current = versions?.[0]?.version;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="history-title"
    >
      <Card className="flex max-h-[80vh] w-full max-w-2xl flex-col p-6 shadow-xl">
        <div className="mb-5 flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <Clock className="mt-0.5 text-slate-400" size={20} />
            <div>
              <h2 id="history-title" className="text-lg font-semibold text-slate-900 dark:text-white">
                History for <code className="font-mono">{secretKey}</code>
              </h2>
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                Decrypted in this browser. The server keeps every version as ciphertext it cannot
                read.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close history"
            className="shrink-0 rounded-md p-1 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <X size={20} />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {versions === null ? (
            <div className="space-y-3">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : versions.length === 0 ? (
            <EmptyState
              icon={Clock}
              title="No history"
              description="This secret has not been changed since it was created."
            />
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {versions.map((v) => (
                <li key={v.version} className="flex items-start justify-between gap-4 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-900 dark:text-slate-100">
                        Version {v.version}
                      </span>
                      {v.version === current && (
                        <span className="text-xs font-medium text-primary-600 dark:text-primary-400">
                          current
                        </span>
                      )}
                    </div>
                    <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                      {formatTimestamp(v.createdAt)}
                    </p>
                    <code className="mt-1.5 block truncate font-mono text-xs text-slate-700 dark:text-slate-300">
                      {revealed[v.version] ? v.value : '•'.repeat(Math.min(v.value.length, 32))}
                    </code>
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <button
                      type="button"
                      onClick={() =>
                        setRevealed((prev) => ({ ...prev, [v.version]: !prev[v.version] }))
                      }
                      aria-label={revealed[v.version] ? 'Hide value' : 'Reveal value'}
                      className="rounded-md p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      {revealed[v.version] ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                    {v.version !== current && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={restoring !== null}
                        onClick={() => restore(v.version)}
                      >
                        <RotateCcw size={14} />
                        {restoring === v.version ? 'Restoring…' : 'Restore'}
                      </Button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <p className="mt-4 border-t border-slate-100 pt-4 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
          Restoring copies an old version forward as a new one. Nothing is overwritten, so the
          history stays complete.
        </p>
      </Card>
    </div>
  );
}
