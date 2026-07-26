import { useCallback, useEffect, useState } from 'react';
import type { CreatedPat, PatMetadata } from '../api';
import { createPatSession, listPatsSession, revokePatSession } from '../session';
import { AlertTriangle, Check, Copy, KeyRound, Plus, Trash2 } from './icons';
import { Badge, Button, Card, CardHeader, EmptyState, Input, Label, Select, Skeleton } from './ui';

/** Expiry choices. "Never" is offered but not the default. */
const EXPIRY_OPTIONS: { label: string; days?: number }[] = [
  { label: '30 days', days: 30 },
  { label: '90 days', days: 90 },
  { label: '1 year', days: 365 },
  { label: 'Never expires', days: undefined },
];

function formatDate(value: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function status(pat: PatMetadata): { label: string; variant: 'default' | 'success' | 'warning' | 'danger' } {
  if (pat.revoked_at) return { label: 'Revoked', variant: 'danger' };
  if (pat.expires_at && new Date(pat.expires_at) < new Date()) {
    return { label: 'Expired', variant: 'warning' };
  }
  return { label: 'Active', variant: 'success' };
}

/**
 * The token, shown exactly once.
 *
 * The server stores only a SHA-256 hash, so this value is unrecoverable the
 * moment the panel is dismissed. The copy affordance is deliberately prominent.
 */
function NewTokenPanel({ pat, onDismiss }: { pat: CreatedPat; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);

  return (
    <div className="rounded-xl border border-amber-300 bg-amber-50 p-5 dark:border-amber-800 dark:bg-amber-900/20">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" size={20} />
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-amber-900 dark:text-amber-200">
            Copy your token now
          </h3>
          <p className="mt-1 text-sm text-amber-800 dark:text-amber-300">
            This is the only time it will be shown. Nivrit stores only a hash and cannot show it
            to you again.
          </p>

          <div className="mt-3 flex items-center gap-2 rounded-lg border border-amber-300 bg-white p-3 dark:border-amber-800 dark:bg-slate-900">
            <code className="min-w-0 flex-1 break-all font-mono text-xs text-slate-900 dark:text-slate-100">
              {pat.token}
            </code>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(pat.token);
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              }}
              className="shrink-0 rounded-md p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:hover:bg-slate-800 dark:hover:text-slate-100"
              aria-label="Copy token"
            >
              {copied ? <Check size={16} /> : <Copy size={16} />}
            </button>
          </div>

          <p className="mt-3 text-xs text-amber-800 dark:text-amber-300">Use it with the CLI:</p>
          <pre className="mt-1 overflow-x-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-100">
            <code>{`niv login --email you@example.com --token ${pat.token.slice(0, 12)}…`}</code>
          </pre>

          <Button variant="secondary" size="sm" className="mt-4" onClick={onDismiss}>
            I have copied it
          </Button>
        </div>
      </div>
    </div>
  );
}

export function AccessTokensTab({ onError }: { onError: (message: string) => void }) {
  const [tokens, setTokens] = useState<PatMetadata[] | null>(null);
  const [name, setName] = useState('');
  const [expiryIndex, setExpiryIndex] = useState(1); // default 90 days
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedPat | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setTokens(await listPatsSession());
    } catch (e) {
      setTokens([]);
      onError(e instanceof Error ? e.message : 'could not load access tokens');
    }
  }, [onError]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (creating) return;
    if (!name.trim()) {
      onError('Give the token a name so you can recognise it later.');
      return;
    }
    setCreating(true);
    try {
      const pat = await createPatSession(name.trim(), EXPIRY_OPTIONS[expiryIndex]?.days);
      setCreated(pat);
      setName('');
      await refresh();
    } catch (e) {
      onError(e instanceof Error ? e.message : 'could not create the token');
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(pat: PatMetadata) {
    if (revoking) return;
    const confirmed = window.confirm(
      `Revoke "${pat.name}"? Anything using this token stops working immediately.`
    );
    if (!confirmed) return;
    setRevoking(pat.id);
    try {
      await revokePatSession(pat.id);
      await refresh();
    } catch (e) {
      onError(e instanceof Error ? e.message : 'could not revoke the token');
    } finally {
      setRevoking(null);
    }
  }

  const active = (tokens ?? []).filter((t) => !t.revoked_at);

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
          Access tokens
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Tokens authenticate the CLI, the SDKs, and the VS Code extension. They authorise API
          access only — decrypting a secret still requires your master password on that device.
        </p>
      </div>

      {created && <NewTokenPanel pat={created} onDismiss={() => setCreated(null)} />}

      <Card>
        <CardHeader
          title="Create a token"
          description="Give it a name you will recognise, and an expiry if it is for a specific job."
          action={<KeyRound className="text-slate-400" size={20} />}
        />
        <form onSubmit={handleCreate} className="space-y-4 p-5">
          <div className="grid gap-4 sm:grid-cols-[1fr_auto]">
            <div>
              <Label htmlFor="pat-name">Name</Label>
              <Input
                id="pat-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="CI deploy pipeline"
                maxLength={100}
                required
              />
            </div>
            <div>
              <Label htmlFor="pat-expiry">Expires</Label>
              <Select
                id="pat-expiry"
                value={expiryIndex}
                onChange={(e) => setExpiryIndex(Number(e.target.value))}
              >
                {EXPIRY_OPTIONS.map((o, i) => (
                  <option key={o.label} value={i}>
                    {o.label}
                  </option>
                ))}
              </Select>
            </div>
          </div>
          <Button type="submit" disabled={creating}>
            <Plus size={16} />
            {creating ? 'Creating…' : 'Create token'}
          </Button>
        </form>
      </Card>

      <Card>
        <CardHeader
          title="Your tokens"
          description={
            tokens === null
              ? 'Loading…'
              : `${active.length} active of ${tokens.length} total.`
          }
        />
        <div className="p-5">
          {tokens === null ? (
            <div className="space-y-3">
              <Skeleton className="h-14 w-full" />
              <Skeleton className="h-14 w-full" />
            </div>
          ) : tokens.length === 0 ? (
            <EmptyState
              icon={KeyRound}
              title="No access tokens yet"
              description="Create one to use the CLI, an SDK, or the VS Code extension with this account."
            />
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {tokens.map((pat) => {
                const s = status(pat);
                return (
                  <li key={pat.id} className="flex items-center justify-between gap-4 py-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-sm font-medium text-slate-900 dark:text-slate-100">
                          {pat.name}
                        </span>
                        <Badge variant={s.variant}>{s.label}</Badge>
                      </div>
                      <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                        Created {formatDate(pat.created_at)} · Last used{' '}
                        {pat.last_used_at ? formatDate(pat.last_used_at) : 'never'} · Expires{' '}
                        {pat.expires_at ? formatDate(pat.expires_at) : 'never'}
                      </p>
                    </div>
                    {!pat.revoked_at && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleRevoke(pat)}
                        disabled={revoking === pat.id}
                        aria-label={`Revoke ${pat.name}`}
                      >
                        <Trash2 size={16} />
                        {revoking === pat.id ? 'Revoking…' : 'Revoke'}
                      </Button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </Card>
    </div>
  );
}
