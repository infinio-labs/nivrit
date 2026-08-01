import { useCallback, useEffect, useState } from 'react';
import type { Environment, EnvironmentOverride, EnvironmentRole } from '../api';
import {
  listEnvironmentOverridesSession,
  removeEnvironmentOverrideSession,
  setEnvironmentOverrideSession,
} from '../session';
import { Mail, Shield, Trash2 } from './icons';
import { Badge, Button, Card, CardHeader, EmptyState, Input, Label, Select, Skeleton } from './ui';

const roleOptions: { value: EnvironmentRole; label: string; description: string }[] = [
  { value: 'admin', label: 'Admin', description: 'Full access to this environment.' },
  { value: 'member', label: 'Member', description: 'Can read and write secrets here.' },
  { value: 'viewer', label: 'Viewer', description: 'Read-only access to this environment.' },
  { value: 'none', label: 'None', description: 'No access to this environment at all.' },
];

function roleBadgeVariant(role: string): 'default' | 'success' | 'warning' | 'danger' {
  if (role === 'none') return 'danger';
  if (role === 'admin') return 'success';
  return 'default';
}

/**
 * Grant, list, and remove per-environment role overrides (ADR 0009/0010).
 * An override substitutes a project member's role for one environment only;
 * absence of an override means their project-level role applies unchanged.
 * Self-contained like AuditLogTab -- it fetches and manages its own state
 * rather than threading everything through App.tsx.
 */
export function EnvironmentRolesCard({
  projectId,
  environments,
  selectedEnvironmentId,
  onError,
}: {
  projectId: string;
  environments: Environment[];
  selectedEnvironmentId: string;
  onError: (message: string) => void;
}) {
  const [overrides, setOverrides] = useState<EnvironmentOverride[] | null>(null);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<EnvironmentRole>('member');
  const [submitting, setSubmitting] = useState(false);

  const refresh = useCallback(async () => {
    if (!projectId || !selectedEnvironmentId) {
      setOverrides([]);
      return;
    }
    setOverrides(null);
    try {
      setOverrides(await listEnvironmentOverridesSession(projectId, selectedEnvironmentId));
    } catch (e) {
      setOverrides([]);
      onError(e instanceof Error ? e.message : 'could not load environment overrides');
    }
  }, [projectId, selectedEnvironmentId, onError]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function handleSet(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await setEnvironmentOverrideSession(projectId, selectedEnvironmentId, email, role);
      setEmail('');
      await refresh();
    } catch (e) {
      onError(e instanceof Error ? e.message : 'could not set the override');
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRemove(userId: string) {
    try {
      await removeEnvironmentOverrideSession(projectId, selectedEnvironmentId, userId);
      await refresh();
    } catch (e) {
      onError(e instanceof Error ? e.message : 'could not remove the override');
    }
  }

  if (!projectId) return null;

  const envName =
    environments.find((e) => e.id === selectedEnvironmentId)?.name ??
    environments.find((e) => e.id === selectedEnvironmentId)?.slug;

  return (
    <Card>
      <CardHeader
        title="Environment access"
        description={
          envName
            ? `Override a member's role for "${envName}" only -- their role everywhere else is unaffected.`
            : 'Select an environment from the top navigation to manage overrides.'
        }
        action={<Shield className="text-slate-400" size={20} />}
      />
      <div className="space-y-5 p-5">
        {!selectedEnvironmentId ? (
          <EmptyState
            icon={Shield}
            title="No environment selected"
            description="Pick an environment to grant or review role overrides."
          />
        ) : (
          <>
            <form onSubmit={handleSet} className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-[2fr_1fr_auto] sm:items-end">
                <div>
                  <Label htmlFor="env-role-email">Member email</Label>
                  <div className="relative">
                    <Mail
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                      size={16}
                    />
                    <Input
                      id="env-role-email"
                      data-testid="env-role-email-input"
                      type="email"
                      placeholder="teammate@example.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="pl-9"
                      required
                    />
                  </div>
                </div>
                <div>
                  <Label htmlFor="env-role-select">Role</Label>
                  <Select
                    id="env-role-select"
                    data-testid="env-role-select"
                    value={role}
                    onChange={(e) => setRole(e.target.value as EnvironmentRole)}
                  >
                    {roleOptions.map((r) => (
                      <option key={r.value} value={r.value}>
                        {r.label}
                      </option>
                    ))}
                  </Select>
                </div>
                <Button type="submit" data-testid="env-role-set-btn" disabled={submitting}>
                  {submitting ? 'Setting…' : 'Set override'}
                </Button>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {roleOptions.find((r) => r.value === role)?.description} The target must already
                be a project member.
              </p>
            </form>

            <div className="border-t border-slate-100 pt-4 dark:border-slate-800">
              {overrides === null ? (
                <div className="space-y-2">
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                </div>
              ) : overrides.length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  No overrides on this environment -- every member uses their project-level role.
                </p>
              ) : (
                <ul className="space-y-2">
                  {overrides.map((o) => (
                    <li
                      key={o.user_id}
                      className="flex items-center justify-between rounded-lg border border-slate-200 px-3 py-2 dark:border-slate-800"
                    >
                      <span className="font-mono text-xs text-slate-600 dark:text-slate-300">
                        {o.user_id}
                      </span>
                      <div className="flex items-center gap-3">
                        <Badge variant={roleBadgeVariant(o.role)}>{o.role}</Badge>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          data-testid={`env-role-remove-${o.user_id}`}
                          onClick={() => handleRemove(o.user_id)}
                        >
                          <Trash2 size={14} />
                        </Button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </>
        )}
      </div>
    </Card>
  );
}
