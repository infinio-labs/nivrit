import { type ReactNode } from 'react';
import { Logo } from './Logo';

export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950">
      <div className="grid min-h-screen lg:grid-cols-2">
        {/* Brand panel */}
        <div className="relative hidden flex-col justify-between overflow-hidden bg-primary-600 p-12 text-white lg:flex">
          <div className="absolute inset-0 bg-gradient-to-br from-primary-600 via-primary-700 to-indigo-800" />
          <div className="relative z-10">
            <Logo className="text-white" />
          </div>

          <div className="relative z-10 max-w-md">
            <h2 className="text-3xl font-bold leading-tight">
              Secrets management built for security-first teams.
            </h2>
            <p className="mt-4 text-primary-100">
              End-to-end encrypted, post-quantum ready, and designed to keep your keys in your
              hands — never ours.
            </p>

            <div className="mt-10 space-y-4 text-sm font-medium text-primary-100">
              <div className="flex items-center gap-3">
                <div className="h-1.5 w-1.5 rounded-full bg-white/80" />
                Client-side encryption with zero knowledge architecture
              </div>
              <div className="flex items-center gap-3">
                <div className="h-1.5 w-1.5 rounded-full bg-white/80" />
                Hybrid X25519 + ML-KEM-768 key encapsulation
              </div>
              <div className="flex items-center gap-3">
                <div className="h-1.5 w-1.5 rounded-full bg-white/80" />
                Environments, projects, and fine-grained access
              </div>
            </div>
          </div>

          <p className="relative z-10 text-xs text-primary-200">
            © {new Date().getFullYear()} Nivrit. Open source. Self-hostable.
          </p>
        </div>

        {/* Form panel */}
        <div className="flex flex-col">
          <div className="flex items-center justify-between p-6 lg:hidden">
            <Logo />
          </div>
          <main className="flex flex-1 items-center justify-center p-4 sm:p-6 lg:p-12">
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
