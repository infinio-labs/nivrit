import type { Environment } from '../api';
import { EnvironmentRolesCard } from './EnvironmentRolesCard';
import { KeyRound, Mail, ShieldCheck, UserPlus, Users } from './icons';
import { Button, Card, CardHeader, EmptyState, Input, Label, Select } from './ui';

interface MembersTabProps {
  selectedProjectId: string;
  inviteEmail: string;
  setInviteEmail: (v: string) => void;
  inviteRole: 'admin' | 'member' | 'viewer';
  setInviteRole: (v: 'admin' | 'member' | 'viewer') => void;
  onInvite: (e: React.FormEvent) => void;
  onRotateKey: () => void;
  rotatingKey: boolean;
  environments: Environment[];
  selectedEnvironmentId: string;
  onError: (message: string) => void;
}

const roles = [
  {
    value: 'member',
    label: 'Member',
    description: 'Can view and manage secrets in assigned projects.',
  },
  {
    value: 'admin',
    label: 'Admin',
    description: 'Can manage project members, environments, and secrets.',
  },
  {
    value: 'viewer',
    label: 'Viewer',
    description: 'Read-only access to secrets.',
  },
];

export function MembersTab(props: MembersTabProps) {
  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Members</h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Invite teammates and share the project key securely with them.
        </p>
      </div>

      {!props.selectedProjectId ? (
        <EmptyState
          icon={Users}
          title="No project selected"
          description="Select a project from the top navigation to invite members."
        />
      ) : (
        <Card>
          <CardHeader
            title="Invite member"
            description="They will receive access to the currently selected project."
            action={<UserPlus className="text-slate-400" size={20} />}
          />
          <form onSubmit={props.onInvite} className="space-y-5 p-5">
            <div>
              <Label htmlFor="invite-email">Email address</Label>
              <div className="relative">
                <Mail
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                  size={16}
                />
                <Input
                  id="invite-email"
                  data-testid="invite-email-input"
                  type="email"
                  placeholder="teammate@example.com"
                  value={props.inviteEmail}
                  onChange={(e) => props.setInviteEmail(e.target.value)}
                  className="pl-9"
                  required
                />
              </div>
            </div>

            <div>
              <Label htmlFor="invite-role">Role</Label>
              <Select
                id="invite-role"
                data-testid="invite-role-select"
                value={props.inviteRole}
                onChange={(e) => props.setInviteRole(e.target.value as typeof props.inviteRole)}
              >
                {roles.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </Select>
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                {roles.find((r) => r.value === props.inviteRole)?.description}
              </p>
            </div>

            <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-900/50">
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 text-primary-600" size={18} />
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  The project key is encrypted to the invitee&apos;s public key before being sent
                  to the server. Nivrit never sees the plaintext key.
                </p>
              </div>
            </div>

            <Button type="submit" data-testid="invite-btn">
              <UserPlus size={16} />
              Send invite
            </Button>
          </form>
        </Card>
      )}

      {props.selectedProjectId && (
        <Card>
          <CardHeader
            title="Rotate project key"
            description="Mint a new key version, granted only to current members."
            action={<KeyRound className="text-slate-400" size={20} />}
          />
          <div className="space-y-4 p-5">
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Use this after removing someone&apos;s access, or on a schedule. Existing
              secrets are untouched and stay readable under whichever version encrypted
              them — only members present at the moment of rotation receive the new one.
            </p>
            <Button
              type="button"
              variant="secondary"
              data-testid="rotate-key-btn"
              disabled={props.rotatingKey}
              onClick={props.onRotateKey}
            >
              <KeyRound size={16} />
              {props.rotatingKey ? 'Rotating…' : 'Rotate key now'}
            </Button>
          </div>
        </Card>
      )}

      {props.selectedProjectId && (
        <EnvironmentRolesCard
          projectId={props.selectedProjectId}
          environments={props.environments}
          selectedEnvironmentId={props.selectedEnvironmentId}
          onError={props.onError}
        />
      )}
    </div>
  );
}
