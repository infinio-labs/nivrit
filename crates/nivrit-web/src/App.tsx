import { useCallback, useEffect, useState } from 'react';
import { Loader2 } from './components/icons';
import { initCrypto } from './crypto';
import { SessionExpiredError, oauthAuthorizeUrl } from './api';
import { navigate, parseRoute, replaceRoute, type DashboardTab } from './router';
import {
  clearSession,
  createEnvironmentSession,
  createOrgSession,
  createProjectSession,
  deleteEncryptedSecret,
  disableTotpSession,
  forgotPasswordSession,
  getMyOrgsSession,
  getProjectEnvironments,
  listFoldersSession,
  createFolderSession,
  deleteFolderSession,
  listImportsSession,
  createImportSession,
  deleteImportSession,
  getSession,
  inviteProjectMember,
  listEncryptedSecrets,
  listOrgProjectsSession,
  loginSession,
  loginTotpSession,
  processOAuthCallback,
  registerSession,
  resetPasswordSession,
  setEncryptedSecret,
  setupTotpSession,
  verifyTotpSession,
  type SecretEntry,
  type Session,
} from './session';
import { ToastContainer, type ToastMessage } from './components/Toast';
import { AuthViews } from './components/AuthViews';
import { RecoveryCodeModal } from './components/RecoveryCodeModal';
import { ImportEnvModal } from './components/ImportEnvModal';
import { Dashboard } from './components/Dashboard';
import { SecretsTab } from './components/SecretsTab';
import { MembersTab } from './components/MembersTab';
import { SettingsTab } from './components/SettingsTab';
import { AccessTokensTab } from './components/AccessTokensTab';
import { AuditLogTab } from './components/AuditLogTab';
import { SecretHistoryModal } from './components/SecretHistoryModal';

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

type View = 'auth' | 'mfa' | 'oauth' | 'forgot' | 'reset' | 'dashboard';
type Tab = 'secrets' | 'members' | 'audit' | 'tokens' | 'settings';

function App() {
  const [loading, setLoading] = useState(true);
  // One in-flight guard for the auth forms. Every one of them runs Argon2id in
  // WASM, which is measured in seconds, so without this a second click starts a
  // second derivation and can register twice or trip the login rate limiter.
  const [busy, setBusy] = useState<string>('');
  // The URL is the source of truth for which view is showing, so every screen
  // is linkable and the back button works. `setView` is kept as a thin wrapper
  // so the many call sites below read unchanged.
  const [route, setRoute] = useState(() => parseRoute(new URL(window.location.href)));
  const [session, setSession] = useState<Session | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  // MFA is deliberately not a route: it is a transient step holding a
  // short-lived token, which has no business in the address bar or in history.
  const [mfaPending, setMfaPending] = useState(false);

  const view: View = mfaPending
    ? 'mfa'
    : route.name === 'dashboard'
      ? 'dashboard'
      : route.name;
  const activeTab: Tab = route.name === 'dashboard' ? route.tab : 'secrets';

  const setView = useCallback((next: View) => {
    setMfaPending(next === 'mfa');
    switch (next) {
      case 'dashboard':
        navigate({ name: 'dashboard', tab: 'secrets' });
        break;
      case 'forgot':
        navigate({ name: 'forgot' });
        break;
      case 'mfa':
        // Stay where we are; the MFA form replaces the auth screen in place.
        break;
      default:
        navigate({ name: 'auth' });
    }
  }, []);

  const setActiveTab = useCallback((tab: Tab) => {
    navigate({ name: 'dashboard', tab: tab as DashboardTab });
  }, []);

  // Back and forward move between views like any other site.
  useEffect(() => {
    const onPopState = () => setRoute(parseRoute(new URL(window.location.href)));
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  // Auth form state
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');

  // MFA
  const [tempToken, setTempToken] = useState('');
  const [mfaPassword, setMfaPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');

  // OAuth / reset
  const [oauthProvider, setOauthProvider] = useState('');
  const [oauthCode, setOauthCode] = useState('');
  const [oauthState, setOauthState] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [recoveryCodeInput, setRecoveryCodeInput] = useState('');

  // Dashboard state

  const [orgs, setOrgs] = useState<Org[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState('');
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [selectedEnvironmentId, setSelectedEnvironmentId] = useState('');
  const [folders, setFolders] = useState<{ id: string; name: string; path: string }[]>([]);
  // Empty string means the environment root, matching ContextSelect's placeholder.
  const [selectedFolderId, setSelectedFolderId] = useState('');
  const [imports, setImports] = useState<{ id: string; source_environment_id: string }[]>([]);
  const [newFolderName, setNewFolderName] = useState('');
  const [importSourceEnvId, setImportSourceEnvId] = useState('');
  const [secrets, setSecrets] = useState<SecretEntry[]>([]);
  const [listing, setListing] = useState(false);
  // Labels inherited secrets with the environment they came from.
  const environmentNames = new Map(environments.map((e) => [e.id, e.name || e.slug]));
  const [secretKey, setSecretKey] = useState('');
  const [secretValue, setSecretValue] = useState('');
  const [editingSecretKey, setEditingSecretKey] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'member' | 'viewer'>('member');

  // Create form state
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgSlug, setNewOrgSlug] = useState('');
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectSlug, setNewProjectSlug] = useState('');
  const [newEnvName, setNewEnvName] = useState('');
  const [newEnvSlug, setNewEnvSlug] = useState('');

  // Secret version history
  const [historyKey, setHistoryKey] = useState('');

  // Import .env modal
  const [importOpen, setImportOpen] = useState(false);
  const [importContent, setImportContent] = useState('');
  const [importing, setImporting] = useState(false);

  // Settings / TOTP
  const [totpSecret, setTotpSecret] = useState('');
  const [totpUri, setTotpUri] = useState('');
  const [totpVerifyCode, setTotpVerifyCode] = useState('');
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [disableTotpPassword, setDisableTotpPassword] = useState('');
  const [disableTotpCode, setDisableTotpCode] = useState('');

  useEffect(() => {
    initCrypto()
      .then(() => {
        setLoading(false);
        consumeRouteParameters();
      })
      .catch((e) => {
        showToast(`failed to initialize crypto: ${e}`, 'error');
        setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    getMyOrgsSession()
      .then((items) => {
        if (cancelled) return;
        setOrgs(items);
      })
      .catch(() => setOrgs([]));
    return () => {
      cancelled = true;
    };
  }, [session]);

  useEffect(() => {
    if (!selectedOrgId) {
      setProjects([]);
      setSelectedProjectId('');
      return;
    }
    let cancelled = false;
    listOrgProjectsSession(selectedOrgId)
      .then((items) => {
        if (cancelled) return;
        setProjects(items);
      })
      .catch(() => setProjects([]));
    return () => {
      cancelled = true;
    };
  }, [selectedOrgId]);

  useEffect(() => {
    if (!selectedProjectId) {
      setEnvironments([]);
      setSelectedEnvironmentId('');
      setSecrets([]);
      return;
    }
    let cancelled = false;
    getProjectEnvironments(selectedProjectId)
      .then((items) => {
        if (cancelled) return;
        setEnvironments(items);
        if (items.length > 0 && !selectedEnvironmentId) {
          setSelectedEnvironmentId(items[0].id);
        }
      })
      .catch(() => setEnvironments([]));
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId]);

  useEffect(() => {
    setSelectedFolderId('');
    if (!selectedProjectId || !selectedEnvironmentId) {
      setFolders([]);
      return;
    }
    let cancelled = false;
    listFoldersSession(selectedProjectId, selectedEnvironmentId)
      .then((items) => {
        if (!cancelled) setFolders(items);
      })
      .catch(() => setFolders([]));
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId, selectedEnvironmentId]);

  useEffect(() => {
    if (!selectedProjectId || !selectedEnvironmentId) {
      setImports([]);
      return;
    }
    let cancelled = false;
    listImportsSession(selectedProjectId, selectedEnvironmentId, selectedFolderId || null)
      .then((items) => {
        if (!cancelled) setImports(items);
      })
      .catch(() => setImports([]));
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId, selectedEnvironmentId, selectedFolderId]);

  useEffect(() => {
    if (!selectedProjectId || !selectedEnvironmentId) {
      setSecrets([]);
      return;
    }
    let cancelled = false;
    setListing(true);
    listEncryptedSecrets(
      selectedProjectId,
      selectedEnvironmentId,
      selectedFolderId || null,
      environmentNames
    )
      .then((items) => {
        if (cancelled) return;
        setSecrets(items);
      })
      .catch(() => setSecrets([]))
      .finally(() => setListing(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedProjectId, selectedEnvironmentId, selectedFolderId, imports]);

  /**
   * Lift one-time values out of the URL and then scrub them from it.
   *
   * An OAuth code and a reset token are single-use credentials. Leaving them in
   * the address bar puts them in browser history and in the `Referer` of any
   * outbound request, and lets the user navigate back onto a spent one.
   * `replaceRoute` rewrites the entry without adding to the history stack, so
   * back goes where it did before.
   */
  function consumeRouteParameters() {
    const current = parseRoute(new URL(window.location.href));
    if (current.name === 'oauth') {
      setOauthProvider(current.provider);
      setOauthCode(current.code);
      setOauthState(current.state);
      replaceRoute(current);
      setRoute(current);
    } else if (current.name === 'reset') {
      setResetToken(current.token);
      replaceRoute(current);
      setRoute(current);
    }
  }

  function showToast(message: string, type: 'success' | 'error') {
    const id = Math.random().toString(36).slice(2);
    setToasts((prev) => [...prev, { id, message, type }]);
  }

  function dismissToast(id: string) {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  /**
   * Let the browser paint before running blocking work.
   *
   * Argon2id runs synchronously inside the WASM module on the main thread, so
   * setting a "working" flag and calling straight into it would freeze the page
   * before React ever renders the flag. Yielding one frame first means the user
   * sees the pending state instead of a dead UI.
   */
  async function withBusy<T>(label: string, work: () => Promise<T>): Promise<T | undefined> {
    if (busy) return undefined;
    setBusy(label);
    await new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 0)));
    try {
      return await work();
    } catch (e) {
      if (e instanceof SessionExpiredError) {
        handleSessionExpired();
        return undefined;
      }
      showToast(e instanceof Error ? e.message : String(e), 'error');
      return undefined;
    } finally {
      setBusy('');
    }
  }

  /** The server rejected our token: drop keys and return to sign-in. */
  function handleSessionExpired() {
    clearSession();
    setSession(null);
    resetDashboard();
    setView('auth');
    showToast('Your session has expired. Please sign in again.', 'error');
  }

  async function handleAuth(e: React.FormEvent) {
    e.preventDefault();
    await withBusy(isRegister ? 'Creating your vault…' : 'Signing in…', async () => {
      if (isRegister) {
        const { recoveryCode: rc } = await registerSession(email, password, name || undefined);
        setRecoveryCode(rc);
      } else {
        const result = await loginSession(email, password);
        if (result.status === 'MfaRequired') {
          setTempToken(result.temp_token);
          setMfaPassword(password);
          setView('mfa');
          return;
        }
      }
      setPassword('');
      setSession(getSession());
      setView('dashboard');
    });
  }

  async function handleMfa(e: React.FormEvent) {
    e.preventDefault();
    await withBusy('Verifying…', async () => {
      await loginTotpSession(tempToken, totpCode, mfaPassword);
      setMfaPassword('');
      setTotpCode('');
      setSession(getSession());
      setView('dashboard');
    });
  }

  async function handleOAuth(provider: 'google' | 'github') {
    try {
      const { url } = await oauthAuthorizeUrl(provider);
      window.location.href = url;
    } catch {
      showToast('OAuth authorization failed', 'error');
    }
  }

  async function handleOAuthComplete(e: React.FormEvent) {
    e.preventDefault();
    await withBusy('Setting up your vault…', async () => {
      const { recoveryCode: rc } = await processOAuthCallback(
        oauthProvider,
        oauthCode,
        oauthState,
        password
      );
      if (rc) setRecoveryCode(rc);
      setPassword('');
      setSession(getSession());
      setView('dashboard');
    });
  }

  async function handleForgot(e: React.FormEvent) {
    e.preventDefault();
    await withBusy('Sending…', async () => {
      await forgotPasswordSession(email);
      showToast('If this email exists, a reset link has been sent.', 'success');
      setView('auth');
    });
  }

  async function handleReset(e: React.FormEvent) {
    e.preventDefault();
    await withBusy('Recovering your keys…', async () => {
      const { recoveryCode: rc } = await resetPasswordSession(
        resetToken,
        recoveryCodeInput,
        password
      );
      setPassword('');
      setRecoveryCodeInput('');
      setSession(getSession());
      setView('dashboard');
      // The reset just minted a new recovery code and retired the one just
      // used, so it has to be shown now - this is the only time it exists.
      setRecoveryCode(rc);
      showToast('Password reset. You are signed in.', 'success');
    });
  }

  function handleLogout() {
    clearSession();
    setSession(null);
    resetDashboard();
    setView('auth');
  }

  function resetDashboard() {
    setSelectedOrgId('');
    setSelectedProjectId('');
    setSelectedEnvironmentId('');
    setOrgs([]);
    setProjects([]);
    setEnvironments([]);
    setSecrets([]);
    setActiveTab('secrets');
  }

  async function refreshSecrets() {
    if (!selectedProjectId || !selectedEnvironmentId) return;
    setListing(true);
    try {
      // Must carry the selected folder, or saving inside a folder reloads the
      // root and the secret that was just written appears to have vanished.
      const items = await listEncryptedSecrets(
        selectedProjectId,
        selectedEnvironmentId,
        selectedFolderId || null,
        environmentNames
      );
      setSecrets(items);
    } catch (e) {
      console.warn('failed to refresh secrets', e);
    } finally {
      setListing(false);
    }
  }

  async function reloadFolders() {
    setFolders(await listFoldersSession(selectedProjectId, selectedEnvironmentId));
  }

  async function reloadImports() {
    setImports(
      await listImportsSession(selectedProjectId, selectedEnvironmentId, selectedFolderId || null)
    );
  }

  async function handleCreateFolder(e: React.FormEvent) {
    e.preventDefault();
    if (!newFolderName.trim()) return;
    await withBusy('Creating folder…', async () => {
      await createFolderSession(selectedProjectId, selectedEnvironmentId, newFolderName);
      setNewFolderName('');
      await reloadFolders();
      showToast('folder created', 'success');
    });
  }

  async function handleDeleteFolder(folderId: string) {
    const folder = folders.find((f) => f.id === folderId);
    if (!window.confirm(`Delete folder "${folder?.name ?? folderId}"?`)) return;
    await withBusy('Deleting folder…', async () => {
      await deleteFolderSession(selectedProjectId, folderId);
      if (selectedFolderId === folderId) setSelectedFolderId('');
      await reloadFolders();
      showToast('folder deleted', 'success');
    });
  }

  async function handleCreateImport(e: React.FormEvent) {
    e.preventDefault();
    if (!importSourceEnvId) return;
    await withBusy('Linking environment…', async () => {
      await createImportSession(
        selectedProjectId,
        selectedEnvironmentId,
        importSourceEnvId,
        selectedFolderId || null
      );
      setImportSourceEnvId('');
      await reloadImports();
      showToast('environment linked', 'success');
    });
  }

  async function handleDeleteImport(importId: string) {
    await withBusy('Removing link…', async () => {
      await deleteImportSession(selectedProjectId, importId);
      await reloadImports();
      showToast('link removed', 'success');
    });
  }

  async function handleSetSecret(e: React.FormEvent) {
    e.preventDefault();
    await withBusy('Encrypting…', async () => {
      await setEncryptedSecret(
        selectedProjectId,
        selectedEnvironmentId,
        secretKey,
        secretValue,
        selectedFolderId || null
      );
      setSecretKey('');
      setSecretValue('');
      setEditingSecretKey('');
      await refreshSecrets();
      showToast('secret saved', 'success');
    });
  }

  function handleStartEdit(secret: SecretEntry) {
    setSecretKey(secret.key);
    setSecretValue(secret.value);
    setEditingSecretKey(secret.key);
  }

  function handleCancelEdit() {
    setSecretKey('');
    setSecretValue('');
    setEditingSecretKey('');
  }

  async function handleImportEnv(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedProjectId || !selectedEnvironmentId) return;

    const lines = importContent.split(/\r?\n/);
    const entries: { key: string; value: string }[] = [];

    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;

      // Support optional "export " prefix
      const withoutExport = line.startsWith('export ') ? line.slice(7) : line;
      const idx = withoutExport.indexOf('=');
      if (idx <= 0) continue;

      let key = withoutExport.slice(0, idx).trim();
      let value = withoutExport.slice(idx + 1).trim();

      // Strip matching surrounding quotes
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      if (!key) continue;
      entries.push({ key, value });
    }

    if (entries.length === 0) {
      showToast('no valid KEY=VALUE entries found', 'error');
      return;
    }

    setImporting(true);
    let imported = 0;
    let failed = 0;

    try {
      for (const { key, value } of entries) {
        try {
          await setEncryptedSecret(
            selectedProjectId,
            selectedEnvironmentId,
            key,
            value,
            selectedFolderId || null
          );
          imported++;
        } catch {
          failed++;
        }
      }
      await refreshSecrets();
      if (failed === 0) {
        showToast(`imported ${imported} secret${imported === 1 ? '' : 's'}`, 'success');
      } else {
        showToast(
          `imported ${imported}, failed ${failed}`,
          imported > 0 ? 'success' : 'error'
        );
      }
      setImportOpen(false);
      setImportContent('');
    } finally {
      setImporting(false);
    }
  }

  async function handleDeleteSecret(key: string) {
    if (!confirm(`Delete secret "${key}"?`)) return;
    try {
      await deleteEncryptedSecret(
        selectedProjectId,
        selectedEnvironmentId,
        key,
        selectedFolderId || null
      );
      await refreshSecrets();
      showToast('secret deleted', 'success');
    } catch {
      showToast('failed to delete secret', 'error');
    }
  }

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    try {
      await inviteProjectMember(selectedProjectId, inviteEmail, inviteRole);
      setInviteEmail('');
      showToast(`invited ${inviteEmail}`, 'success');
    } catch {
      showToast('invite failed', 'error');
    }
  }

  async function handleCreateOrg(e: React.FormEvent) {
    e.preventDefault();
    try {
      const org = await createOrgSession(newOrgName, newOrgSlug);
      setOrgs((prev) => [...prev, org]);
      setSelectedOrgId(org.id);
      setNewOrgName('');
      setNewOrgSlug('');
      showToast(`created organization ${org.name}`, 'success');
    } catch {
      showToast('failed to create organization', 'error');
    }
  }

  async function handleCreateProject(e: React.FormEvent) {
    e.preventDefault();
    try {
      const project = await createProjectSession(selectedOrgId, newProjectName, newProjectSlug);
      setProjects((prev) => [...prev, project]);
      setSelectedProjectId(project.id);
      setNewProjectName('');
      setNewProjectSlug('');
      showToast(`created project ${project.name}`, 'success');
    } catch {
      showToast('failed to create project', 'error');
    }
  }

  async function handleCreateEnvironment(e: React.FormEvent) {
    e.preventDefault();
    try {
      const env = await createEnvironmentSession(selectedProjectId, newEnvName, newEnvSlug);
      setEnvironments((prev) => [...prev, env]);
      setSelectedEnvironmentId(env.id);
      setNewEnvName('');
      setNewEnvSlug('');
      showToast(`created environment ${env.name}`, 'success');
    } catch {
      showToast('failed to create environment', 'error');
    }
  }

  async function handleSetupTotp() {
    const s = getSession();
    if (!s) return;
    try {
      const res = await setupTotpSession(s.token);
      setTotpSecret(res.secret);
      setTotpUri(res.uri);
    } catch {
      showToast('failed to setup 2FA', 'error');
    }
  }

  async function handleVerifyTotp(e: React.FormEvent) {
    e.preventDefault();
    const s = getSession();
    if (!s) return;
    try {
      await verifyTotpSession(s.token, totpVerifyCode);
      setTotpEnabled(true);
      setTotpSecret('');
      setTotpUri('');
      setTotpVerifyCode('');
      showToast('2FA enabled', 'success');
    } catch {
      showToast('invalid TOTP code', 'error');
    }
  }

  async function handleDisableTotp(e: React.FormEvent) {
    e.preventDefault();
    const s = getSession();
    if (!s) return;
    try {
      await disableTotpSession(s.token, s.email, disableTotpPassword, disableTotpCode);
      setTotpEnabled(false);
      setDisableTotpPassword('');
      setDisableTotpCode('');
      showToast('2FA disabled', 'success');
    } catch {
      showToast('failed to disable 2FA', 'error');
    }
  }

  const hasProjectKey = session ? session.projects.has(selectedProjectId) : false;

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Loader2 className="animate-spin text-primary-600" size={32} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      {view !== 'dashboard' && (
        <AuthViews
          view={view}
          isRegister={isRegister}
          setIsRegister={setIsRegister}
          email={email}
          setEmail={setEmail}
          password={password}
          setPassword={setPassword}
          name={name}
          setName={setName}
          busy={busy}
          totpCode={totpCode}
          setTotpCode={setTotpCode}
          recoveryCodeInput={recoveryCodeInput}
          setRecoveryCodeInput={setRecoveryCodeInput}
          handleAuth={handleAuth}
          handleMfa={handleMfa}
          handleOAuth={handleOAuth}
          handleOAuthComplete={handleOAuthComplete}
          handleForgot={handleForgot}
          handleReset={handleReset}
          setView={setView}
        />
      )}

      {view === 'dashboard' && session && (
        <Dashboard
          session={session}
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          orgs={orgs}
          selectedOrgId={selectedOrgId}
          setSelectedOrgId={setSelectedOrgId}
          projects={projects}
          selectedProjectId={selectedProjectId}
          setSelectedProjectId={setSelectedProjectId}
          environments={environments}
          selectedEnvironmentId={selectedEnvironmentId}
          setSelectedEnvironmentId={setSelectedEnvironmentId}
          folders={folders}
          selectedFolderId={selectedFolderId}
          setSelectedFolderId={setSelectedFolderId}
          onLogout={handleLogout}
        >
          {activeTab === 'secrets' && (
            <SecretsTab
              orgs={orgs}
              selectedOrgId={selectedOrgId}
              setSelectedOrgId={setSelectedOrgId}
              projects={projects}
              selectedProjectId={selectedProjectId}
              setSelectedProjectId={setSelectedProjectId}
              environments={environments}
              selectedEnvironmentId={selectedEnvironmentId}
              setSelectedEnvironmentId={setSelectedEnvironmentId}
              secrets={secrets}
              listing={listing}
              secretKey={secretKey}
              setSecretKey={setSecretKey}
              secretValue={secretValue}
              setSecretValue={setSecretValue}
              editingSecretKey={editingSecretKey}
              onSetSecret={handleSetSecret}
              onDeleteSecret={handleDeleteSecret}
              onStartEdit={handleStartEdit}
              onViewHistory={setHistoryKey}
              onCancelEdit={handleCancelEdit}
              onOpenImport={() => setImportOpen(true)}
              newOrgName={newOrgName}
              setNewOrgName={setNewOrgName}
              newOrgSlug={newOrgSlug}
              setNewOrgSlug={setNewOrgSlug}
              onCreateOrg={handleCreateOrg}
              newProjectName={newProjectName}
              setNewProjectName={setNewProjectName}
              newProjectSlug={newProjectSlug}
              setNewProjectSlug={setNewProjectSlug}
              onCreateProject={handleCreateProject}
              newEnvName={newEnvName}
              setNewEnvName={setNewEnvName}
              newEnvSlug={newEnvSlug}
              setNewEnvSlug={setNewEnvSlug}
              onCreateEnvironment={handleCreateEnvironment}
              hasProjectKey={hasProjectKey}
              folders={folders}
              selectedFolderId={selectedFolderId}
              setSelectedFolderId={setSelectedFolderId}
              newFolderName={newFolderName}
              setNewFolderName={setNewFolderName}
              onCreateFolder={handleCreateFolder}
              onDeleteFolder={handleDeleteFolder}
              imports={imports}
              importSourceEnvId={importSourceEnvId}
              setImportSourceEnvId={setImportSourceEnvId}
              onCreateImport={handleCreateImport}
              onDeleteImport={handleDeleteImport}
            />
          )}
          {activeTab === 'members' && (
            <MembersTab
              selectedProjectId={selectedProjectId}
              inviteEmail={inviteEmail}
              setInviteEmail={setInviteEmail}
              inviteRole={inviteRole}
              setInviteRole={setInviteRole}
              onInvite={handleInvite}
            />
          )}
          {activeTab === 'audit' && (
            <AuditLogTab
              projectId={selectedProjectId}
              onError={(m) => showToast(m, 'error')}
            />
          )}
          {activeTab === 'tokens' && (
            <AccessTokensTab onError={(m) => showToast(m, 'error')} />
          )}
          {activeTab === 'settings' && (
            <SettingsTab
              totpEnabled={totpEnabled}
              totpSecret={totpSecret}
              totpUri={totpUri}
              totpVerifyCode={totpVerifyCode}
              setTotpVerifyCode={setTotpVerifyCode}
              onSetupTotp={handleSetupTotp}
              onVerifyTotp={handleVerifyTotp}
              disableTotpPassword={disableTotpPassword}
              setDisableTotpPassword={setDisableTotpPassword}
              disableTotpCode={disableTotpCode}
              setDisableTotpCode={setDisableTotpCode}
              onDisableTotp={handleDisableTotp}
            />
          )}
        </Dashboard>
      )}

      {importOpen && (
        <ImportEnvModal
          content={importContent}
          onChange={setImportContent}
          onSubmit={handleImportEnv}
          onClose={() => {
            setImportOpen(false);
            setImportContent('');
          }}
          importing={importing}
        />
      )}

      {historyKey && (
        <SecretHistoryModal
          projectId={selectedProjectId}
          environmentId={selectedEnvironmentId}
          secretKey={historyKey}
          onClose={() => setHistoryKey('')}
          onRestored={() => {
            void refreshSecrets();
            showToast('version restored', 'success');
          }}
          onError={(m) => showToast(m, 'error')}
        />
      )}

      {recoveryCode && <RecoveryCodeModal code={recoveryCode} onClose={() => setRecoveryCode('')} />}

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}

export default App;
