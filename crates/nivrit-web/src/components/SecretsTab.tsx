import { useState } from 'react';
import {
  AlertTriangle,
  Copy,
  Eye,
  EyeOff,
  FileUp,
  FolderOpen,
  Clock,
  Pencil,
  Plus,
  Trash2,
  X,
} from './icons';
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  Input,
  Label,
  Select,
} from './ui';
import type { SecretEntry } from '../session';

interface Org {
  id: string;
  name: string;
  slug: string;
}

interface Project {
  id: string;
  org_id: string;
  name: string;
  slug: string;
}

interface Environment {
  id: string;
  project_id: string;
  name: string;
  slug: string;
}

interface SecretsTabProps {
  orgs: Org[];
  selectedOrgId: string;
  setSelectedOrgId: (id: string) => void;
  projects: Project[];
  selectedProjectId: string;
  setSelectedProjectId: (id: string) => void;
  environments: Environment[];
  selectedEnvironmentId: string;
  setSelectedEnvironmentId: (id: string) => void;
  secrets: SecretEntry[];
  listing: boolean;
  secretKey: string;
  setSecretKey: (v: string) => void;
  secretValue: string;
  setSecretValue: (v: string) => void;
  editingSecretKey: string;
  onSetSecret: (e: React.FormEvent) => void;
  onDeleteSecret: (key: string) => void;
  onStartEdit: (secret: SecretEntry) => void;
  onViewHistory: (key: string) => void;
  onCancelEdit: () => void;
  onOpenImport: () => void;
  newOrgName: string;
  setNewOrgName: (v: string) => void;
  newOrgSlug: string;
  setNewOrgSlug: (v: string) => void;
  onCreateOrg: (e: React.FormEvent) => void;
  newProjectName: string;
  setNewProjectName: (v: string) => void;
  newProjectSlug: string;
  setNewProjectSlug: (v: string) => void;
  onCreateProject: (e: React.FormEvent) => void;
  newEnvName: string;
  setNewEnvName: (v: string) => void;
  newEnvSlug: string;
  setNewEnvSlug: (v: string) => void;
  onCreateEnvironment: (e: React.FormEvent) => void;
  hasProjectKey: boolean;
  folders: { id: string; name: string; path: string }[];
  selectedFolderId: string;
  setSelectedFolderId: (id: string) => void;
  newFolderName: string;
  setNewFolderName: (v: string) => void;
  onCreateFolder: (e: React.FormEvent) => void;
  onDeleteFolder: (folderId: string) => void;
  imports: { id: string; source_environment_id: string }[];
  importSourceEnvId: string;
  setImportSourceEnvId: (v: string) => void;
  onCreateImport: (e: React.FormEvent) => void;
  onDeleteImport: (importId: string) => void;
}

export function SecretsTab(props: SecretsTabProps) {
  const selectedEnv = props.environments.find((e) => e.id === props.selectedEnvironmentId);
  const isEditing = props.editingSecretKey !== '';

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
          Secrets
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Manage encrypted environment variables for the selected project and environment.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <CreateCard title="Create organization" description="Start a new team workspace.">
          <form onSubmit={props.onCreateOrg} className="space-y-3">
            <Input
              data-testid="org-name-input"
              placeholder="Organization name"
              value={props.newOrgName}
              onChange={(e) => props.setNewOrgName(e.target.value)}
              required
            />
            <Input
              data-testid="org-slug-input"
              placeholder="org-slug"
              value={props.newOrgSlug}
              onChange={(e) => props.setNewOrgSlug(e.target.value)}
              required
            />
            <Button type="submit" data-testid="create-org-btn" className="w-full">
              Create organization
            </Button>
          </form>
        </CreateCard>

        {props.selectedOrgId && (
          <CreateCard title="Create project" description="A project holds environments and secrets.">
            <form onSubmit={props.onCreateProject} className="space-y-3">
              <Input
                data-testid="project-name-input"
                placeholder="Project name"
                value={props.newProjectName}
                onChange={(e) => props.setNewProjectName(e.target.value)}
                required
              />
              <Input
                data-testid="project-slug-input"
                placeholder="project-slug"
                value={props.newProjectSlug}
                onChange={(e) => props.setNewProjectSlug(e.target.value)}
                required
              />
              <Button type="submit" data-testid="create-project-btn" className="w-full">
                Create project
              </Button>
            </form>
          </CreateCard>
        )}

        {props.selectedProjectId && (
          <CreateCard title="Create environment" description="For example: production, staging, dev.">
            <form onSubmit={props.onCreateEnvironment} className="space-y-3">
              <Input
                data-testid="env-name-input"
                placeholder="Environment name"
                value={props.newEnvName}
                onChange={(e) => props.setNewEnvName(e.target.value)}
                required
              />
              <Input
                data-testid="env-slug-input"
                placeholder="env-slug"
                value={props.newEnvSlug}
                onChange={(e) => props.setNewEnvSlug(e.target.value)}
                required
              />
              <Button type="submit" data-testid="create-env-btn" className="w-full">
                Create environment
              </Button>
            </form>
          </CreateCard>
        )}
      </div>

      {props.selectedProjectId && !props.hasProjectKey && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-900/50 dark:bg-amber-900/20">
          <AlertTriangle className="mt-0.5 text-amber-600 dark:text-amber-400" size={20} />
          <div>
            <p className="text-sm font-medium text-amber-800 dark:text-amber-200">
              Project key not available
            </p>
            <p className="text-sm text-amber-700 dark:text-amber-300/80">
              You may need to be invited to this project before you can view or edit secrets.
            </p>
          </div>
        </div>
      )}

      {props.selectedProjectId && props.selectedEnvironmentId && props.hasProjectKey && (
        <div className="grid gap-4 md:grid-cols-2">
          <CreateCard
            title="Folders"
            description="Group secrets within an environment. Pick one from the Folder selector above."
          >
            <form onSubmit={props.onCreateFolder} className="flex gap-2">
              <Input
                data-testid="folder-name-input"
                placeholder="database"
                value={props.newFolderName}
                onChange={(e) => props.setNewFolderName(e.target.value)}
              />
              <Button type="submit" data-testid="create-folder-btn">
                Add
              </Button>
            </form>
            {props.folders.length > 0 && (
              <ul className="mt-3 space-y-1">
                {props.folders.map((f) => (
                  <li key={f.id} className="flex items-center justify-between gap-2 text-sm">
                    <span className="truncate text-slate-700 dark:text-slate-300">{f.name}</span>
                    <button
                      type="button"
                      onClick={() => props.onDeleteFolder(f.id)}
                      aria-label={`Delete folder ${f.name}`}
                      className="rounded p-1 text-slate-400 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/20"
                    >
                      <Trash2 size={14} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </CreateCard>

          <CreateCard
            title="Inherit from another environment"
            description="Secrets from the source appear here unless a local value of the same name overrides them."
          >
            <form onSubmit={props.onCreateImport} className="flex gap-2">
              <Select
                data-testid="import-source-select"
                value={props.importSourceEnvId}
                onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
                  props.setImportSourceEnvId(e.target.value)
                }
                aria-label="Source environment"
              >
                <option value="">Select environment</option>
                {props.environments
                  .filter((e) => e.id !== props.selectedEnvironmentId)
                  .map((e) => (
                    <option key={e.id} value={e.id}>
                      {e.name || e.slug}
                    </option>
                  ))}
              </Select>
              <Button type="submit" data-testid="create-import-btn">
                Add
              </Button>
            </form>
            {props.imports.length > 0 && (
              <ul className="mt-3 space-y-1">
                {props.imports.map((imp) => {
                  const source = props.environments.find(
                    (e) => e.id === imp.source_environment_id
                  );
                  return (
                    <li key={imp.id} className="flex items-center justify-between gap-2 text-sm">
                      <span className="truncate text-slate-700 dark:text-slate-300">
                        {source?.name || source?.slug || imp.source_environment_id}
                      </span>
                      <button
                        type="button"
                        onClick={() => props.onDeleteImport(imp.id)}
                        aria-label="Remove import"
                        className="rounded p-1 text-slate-400 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/20"
                      >
                        <Trash2 size={14} />
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </CreateCard>
        </div>
      )}

      {props.selectedProjectId && props.selectedEnvironmentId && props.hasProjectKey && (
        <Card>
          <CardHeader
            title={
              <span className="flex items-center gap-2">
                Environment secrets
                {selectedEnv && <Badge>{selectedEnv.name}</Badge>}
              </span>
            }
            description="Add, reveal, copy, edit, or remove secrets. Values are decrypted locally in your browser."
          />

          <div className="border-t border-slate-100 p-5 dark:border-slate-800">
            <form onSubmit={props.onSetSecret} className="mb-6 flex flex-wrap items-start gap-3">
              <div className="min-w-[180px] flex-1">
                <Label htmlFor="secret-key" className="sr-only">
                  Secret key
                </Label>
                <Input
                  id="secret-key"
                  data-testid="secret-key-input"
                  placeholder="Secret key"
                  value={props.secretKey}
                  onChange={(e) => props.setSecretKey(e.target.value)}
                  disabled={isEditing}
                  required
                />
                {isEditing && (
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    Key is locked while editing. Cancel to change it.
                  </p>
                )}
              </div>
              <div className="min-w-[180px] flex-1">
                <Label htmlFor="secret-value" className="sr-only">
                  Secret value
                </Label>
                <Input
                  id="secret-value"
                  data-testid="secret-value-input"
                  placeholder="Secret value"
                  value={props.secretValue}
                  onChange={(e) => props.setSecretValue(e.target.value)}
                  required
                />
              </div>
              <div className="flex items-center gap-2">
                <Button type="submit" data-testid="set-secret-btn">
                  {isEditing ? (
                    <>
                      <Pencil size={16} />
                      Update secret
                    </>
                  ) : (
                    <>
                      <Plus size={16} />
                      Add secret
                    </>
                  )}
                </Button>
                {isEditing && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={props.onCancelEdit}
                    title="Cancel edit"
                    aria-label="Cancel edit"
                  >
                    <X size={16} />
                  </Button>
                )}
                {!isEditing && (
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={props.onOpenImport}
                    title="Import from .env"
                    aria-label="Import from .env"
                  >
                    <FileUp size={16} />
                    <span className="hidden sm:inline">Import .env</span>
                  </Button>
                )}
              </div>
            </form>

            {props.listing ? (
              <div className="flex items-center gap-2 text-sm text-slate-500">
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-primary-600" />
                Loading secrets…
              </div>
            ) : props.secrets.length === 0 ? (
              <EmptyState
                icon={FolderOpen}
                title="No secrets yet"
                description="Add your first secret above or import an existing .env file."
                action={
                  <Button variant="secondary" onClick={props.onOpenImport}>
                    <FileUp size={16} />
                    Import from .env
                  </Button>
                }
              />
            ) : (
              <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-900/50">
                    <tr>
                      <th className="px-4 py-3 font-semibold text-slate-500 dark:text-slate-400">
                        Key
                      </th>
                      <th className="px-4 py-3 font-semibold text-slate-500 dark:text-slate-400">
                        Value
                      </th>
                      <th className="px-4 py-3 font-semibold text-slate-500 dark:text-slate-400">
                        Version
                      </th>
                      <th className="px-4 py-3 text-right"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {props.secrets.map((s) => (
                      <SecretRow
                        key={s.id}
                        secret={s}
                        onDelete={props.onDeleteSecret}
                        onEdit={props.onStartEdit}
                        onViewHistory={props.onViewHistory}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

function CreateCard({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="p-5">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
      <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{description}</p>
      <div className="mt-4">{children}</div>
    </Card>
  );
}

function SecretRow({
  secret,
  onDelete,
  onEdit,
  onViewHistory,
}: {
  secret: SecretEntry;
  onDelete: (k: string) => void;
  onEdit: (s: SecretEntry) => void;
  onViewHistory: (key: string) => void;
}) {
  const [revealed, setRevealed] = useState(false);

  return (
    <tr className="bg-white hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800/50">
      <td className="px-4 py-3 font-medium text-slate-900 dark:text-slate-100">
        <div className="flex items-center gap-2">
          <span>{secret.key}</span>
          {secret.inheritedFrom && (
            <Badge variant="default">
              <span title={`Inherited from ${secret.inheritedFrom}. Saving a value with this name here will override it.`}>
                from {secret.inheritedFrom}
              </span>
            </Badge>
          )}
        </div>
      </td>
      <td className="px-4 py-3 font-mono text-slate-600 dark:text-slate-300">
        {revealed ? secret.value : '•'.repeat(Math.min(secret.value.length, 12))}
      </td>
      <td className="px-4 py-3 text-slate-500">
        <Badge variant="default">v{secret.version}</Badge>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center justify-end gap-1">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={() => onEdit(secret)}
            title="Edit"
            aria-label="Edit"
          >
            <Pencil size={16} />
          </Button>
          {!secret.inheritedFrom && (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={() => onViewHistory(secret.key)}
              title="History"
              aria-label="Version history"
            >
              <Clock size={16} />
            </Button>
          )}
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={() => setRevealed(!revealed)}
            title={revealed ? 'Hide' : 'Show'}
            aria-label={revealed ? 'Hide' : 'Show'}
          >
            {revealed ? <EyeOff size={16} /> : <Eye size={16} />}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={() => navigator.clipboard.writeText(secret.value)}
            title="Copy"
            aria-label="Copy"
          >
            <Copy size={16} />
          </Button>
          {!secret.inheritedFrom && (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={() => onDelete(secret.key)}
              title="Delete"
              aria-label="Delete"
              className="text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20"
            >
              <Trash2 size={16} />
            </Button>
          )}
        </div>
      </td>
    </tr>
  );
}
