import { useCallback, useEffect, useState } from 'react';
import type { AuditLogEntry } from '../api';
import { listAuditLogsSession, verifyAuditLogSession } from '../session';
import { ScrollText, ShieldAlert, ShieldCheck } from './icons';
import { Badge, Button, Card, CardHeader, EmptyState, Skeleton } from './ui';

type Verification = { valid: boolean; reason: string | null } | 'checking';

function formatTimestamp(value: string): string {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

function actionVariant(action: string): 'default' | 'success' | 'warning' | 'danger' {
  if (action === 'delete') return 'danger';
  if (action === 'write') return 'warning';
  return 'default';
}

export function AuditLogTab({
  projectId,
  onError,
}: {
  projectId: string;
  onError: (message: string) => void;
}) {
  const [entries, setEntries] = useState<AuditLogEntry[] | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [verified, setVerified] = useState<Record<string, Verification>>({});

  const refresh = useCallback(async () => {
    if (!projectId) {
      setEntries([]);
      return;
    }
    setEntries(null);
    setForbidden(false);
    try {
      setEntries(await listAuditLogsSession(projectId));
    } catch (e) {
      const message = e instanceof Error ? e.message : 'could not load the audit log';
      // The API restricts this to project admins. That is a legitimate answer,
      // not a failure, so it gets an explanation rather than an error toast.
      if (/forbidden/i.test(message)) {
        setForbidden(true);
        setEntries([]);
      } else {
        setEntries([]);
        onError(message);
      }
    }
  }, [projectId, onError]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function verify(entry: AuditLogEntry) {
    setVerified((prev) => ({ ...prev, [entry.id]: 'checking' }));
    try {
      const result = await verifyAuditLogSession(projectId, entry.id);
      setVerified((prev) => ({ ...prev, [entry.id]: result }));
    } catch (e) {
      setVerified((prev) => {
        const next = { ...prev };
        delete next[entry.id];
        return next;
      });
      onError(e instanceof Error ? e.message : 'could not verify that entry');
    }
  }

  if (!projectId) {
    return (
      <div className="mx-auto max-w-4xl">
        <EmptyState
          icon={ScrollText}
          title="Select a project"
          description="Choose a project to see who read or changed its secrets."
        />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
          Audit log
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Every read, write, and delete, recorded server-side. Entries record which secret
          <em> key</em> was touched and by whom — never the value, which the server cannot read.
        </p>
      </div>

      <Card>
        <CardHeader
          title="Recent activity"
          description={
            entries === null
              ? 'Loading…'
              : `${entries.length} most recent ${entries.length === 1 ? 'entry' : 'entries'}.`
          }
          action={<ScrollText className="text-slate-400" size={20} />}
        />
        <div className="p-5">
          {entries === null ? (
            <div className="space-y-3">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : forbidden ? (
            <EmptyState
              icon={ShieldAlert}
              title="Admins only"
              description="The audit log is restricted to project administrators. Ask an admin of this project if you need access."
            />
          ) : entries.length === 0 ? (
            <EmptyState
              icon={ScrollText}
              title="No activity yet"
              description="Reads and writes on this project's secrets will appear here."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  <tr className="border-b border-slate-100 dark:border-slate-800">
                    <th scope="col" className="py-2 pr-4 font-semibold">When</th>
                    <th scope="col" className="py-2 pr-4 font-semibold">Action</th>
                    <th scope="col" className="py-2 pr-4 font-semibold">Key</th>
                    <th scope="col" className="py-2 pr-4 font-semibold">Source</th>
                    <th scope="col" className="py-2 font-semibold">Signature</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {entries.map((entry) => {
                    const state = verified[entry.id];
                    return (
                      <tr key={entry.id}>
                        <td className="whitespace-nowrap py-3 pr-4 text-slate-600 dark:text-slate-300">
                          {formatTimestamp(entry.created_at)}
                        </td>
                        <td className="py-3 pr-4">
                          <Badge variant={actionVariant(entry.action)}>{entry.action}</Badge>
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-slate-900 dark:text-slate-100">
                          {entry.key}
                        </td>
                        <td className="py-3 pr-4 text-slate-500 dark:text-slate-400">
                          {entry.ip_address ?? '—'}
                        </td>
                        <td className="py-3">
                          {!entry.signature_algorithm ? (
                            <span
                              className="text-xs text-slate-400"
                              title="This server was not configured with a signing key when the entry was written."
                            >
                              unsigned
                            </span>
                          ) : state === 'checking' ? (
                            <span className="text-xs text-slate-500">checking…</span>
                          ) : state ? (
                            <span
                              className={`inline-flex items-center gap-1 text-xs font-medium ${
                                state.valid
                                  ? 'text-green-700 dark:text-green-400'
                                  : 'text-red-600 dark:text-red-400'
                              }`}
                              title={state.reason ?? undefined}
                            >
                              {state.valid ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
                              {state.valid ? 'verified' : 'invalid'}
                            </span>
                          ) : (
                            <Button variant="ghost" size="sm" onClick={() => verify(entry)}>
                              Verify
                            </Button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>

      {entries !== null && entries.length > 0 && (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Signed entries carry an ML-DSA-65 signature over the event. Verifying re-checks that
          signature on the server, so an operator who edited the log afterwards cannot make an
          entry verify.
        </p>
      )}
    </div>
  );
}
