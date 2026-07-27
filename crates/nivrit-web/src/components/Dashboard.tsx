import { useState, type ReactNode } from 'react';
import {
  KeyRound,
  ScrollText,
  LayoutDashboard,
  LogOut,
  Menu,
  Settings,
  Shield,
  Users,
  X,
} from './icons';
import { Logo } from './Logo';
import { Button, Separator } from './ui';
import { ContextSelect } from './ContextSelect';
import type { Session } from '../session';

type Tab = 'secrets' | 'members' | 'audit' | 'tokens' | 'settings';

interface DashboardProps {
  session: Session;
  activeTab: Tab;
  setActiveTab: (t: Tab) => void;
  orgs: { id: string; name: string; slug: string }[];
  selectedOrgId: string;
  setSelectedOrgId: (id: string) => void;
  projects: { id: string; org_id: string; name: string; slug: string }[];
  selectedProjectId: string;
  setSelectedProjectId: (id: string) => void;
  environments: { id: string; project_id: string; name: string; slug: string }[];
  selectedEnvironmentId: string;
  setSelectedEnvironmentId: (id: string) => void;
  onLogout: () => void;
  children: ReactNode;
}

const navItems: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: 'secrets', label: 'Secrets', icon: LayoutDashboard },
  { id: 'members', label: 'Members', icon: Users },
  { id: 'audit', label: 'Audit log', icon: ScrollText },
  { id: 'tokens', label: 'Access tokens', icon: KeyRound },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export function Dashboard(props: DashboardProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  const SidebarContent = (
    <>
      <div className="flex items-center justify-between px-5 py-4">
        <Logo />
        <button
          type="button"
          className="rounded-md p-1 text-slate-500 hover:bg-slate-100 md:hidden dark:text-slate-400 dark:hover:bg-slate-800"
          onClick={() => setMobileOpen(false)}
          aria-label="Close navigation"
        >
          <X size={20} />
        </button>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4">
        {navItems.map((item) => {
          const active = props.activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => {
                props.setActiveTab(item.id);
                setMobileOpen(false);
              }}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                active
                  ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300'
                  : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
              }`}
            >
              <item.icon size={18} />
              {item.label}
            </button>
          );
        })}
      </nav>

      <Separator />

      <div className="p-4">
        <div className="mb-3 flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-600 dark:bg-slate-800 dark:text-slate-300">
            {props.session.email.charAt(0).toUpperCase()}
          </div>
          <span className="truncate text-xs font-medium text-slate-500 dark:text-slate-400">
            {props.session.email}
          </span>
        </div>
        <Button
          variant="ghost"
          className="w-full justify-start"
          onClick={props.onLogout}
        >
          <LogOut size={16} />
          Sign out
        </Button>
      </div>
    </>
  );

  return (
    <div className="flex min-h-screen bg-slate-50 dark:bg-slate-950">
      {/* Desktop sidebar */}
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 md:flex">
        {SidebarContent}
      </aside>

      {/* Mobile sidebar overlay */}
      {mobileOpen && (
        <>
          <div
            className="fixed inset-0 z-20 bg-black/40 backdrop-blur-sm md:hidden"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="fixed inset-y-0 left-0 z-30 flex w-64 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 md:hidden">
            {SidebarContent}
          </aside>
        </>
      )}

      <div className="flex flex-1 flex-col md:pl-64">
        {/* Topbar */}
        <header className="sticky top-0 z-10 border-b border-slate-200 bg-white/90 backdrop-blur dark:border-slate-800 dark:bg-slate-900/90">
          <div className="flex flex-wrap items-center gap-4 px-4 py-3 md:px-6">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              className="rounded-md p-2 text-slate-500 hover:bg-slate-100 md:hidden dark:text-slate-400 dark:hover:bg-slate-800"
              aria-label="Open navigation"
            >
              <Menu size={20} />
            </button>

            <div className="hidden items-center gap-2 md:flex">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary-600 text-white">
                <Shield size={16} />
              </div>
              <span className="font-bold text-slate-900 dark:text-white">Nivrit</span>
            </div>

            <div className="flex flex-1 flex-wrap items-center gap-3">
              <ContextSelect
                label="Organization"
                value={props.selectedOrgId}
                onChange={props.setSelectedOrgId}
                options={props.orgs.map((o) => ({ value: o.id, label: o.name || o.slug }))}
                placeholder="Select organization"
                testId="org-select"
              />
              <ContextSelect
                label="Project"
                value={props.selectedProjectId}
                onChange={props.setSelectedProjectId}
                options={props.projects.map((p) => ({ value: p.id, label: p.name || p.slug }))}
                placeholder="Select project"
                disabled={!props.selectedOrgId}
                testId="project-select"
              />
              <ContextSelect
                label="Environment"
                value={props.selectedEnvironmentId}
                onChange={props.setSelectedEnvironmentId}
                options={props.environments.map((e) => ({ value: e.id, label: e.name || e.slug }))}
                placeholder="Select environment"
                disabled={!props.selectedProjectId}
                testId="env-select"
              />
            </div>

            <div className="hidden items-center gap-3 md:flex">
              <span className="text-sm text-slate-500 dark:text-slate-400">
                {props.session.email}
              </span>
              <Button variant="ghost" size="sm" onClick={props.onLogout} aria-label="Sign out">
                <LogOut size={16} />
              </Button>
            </div>
          </div>
        </header>

        {/* Main */}
        <main className="flex-1 p-4 md:p-6">{props.children}</main>
      </div>
    </div>
  );
}
