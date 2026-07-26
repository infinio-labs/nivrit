import { type ReactNode } from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg' | 'icon';
  children: ReactNode;
}

export function Button({
  variant = 'primary',
  size = 'md',
  children,
  className = '',
  ...props
}: ButtonProps) {
  const base =
    'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none';

  const sizes = {
    sm: 'px-3 py-1.5 text-xs',
    md: 'px-4 py-2.5 text-sm',
    lg: 'px-5 py-3 text-sm',
    icon: 'h-9 w-9',
  };

  const styles = {
    primary:
      'bg-primary-600 text-white shadow-sm hover:bg-primary-700 hover:shadow active:bg-primary-800',
    secondary:
      'bg-white text-slate-700 border border-slate-300 shadow-sm hover:bg-slate-50 hover:border-slate-400 dark:bg-slate-900 dark:text-slate-200 dark:border-slate-700 dark:hover:bg-slate-800',
    outline:
      'bg-transparent text-slate-700 border border-slate-300 hover:bg-slate-50 dark:text-slate-300 dark:border-slate-700 dark:hover:bg-slate-800',
    danger:
      'bg-red-600 text-white shadow-sm hover:bg-red-700 active:bg-red-800',
    ghost:
      'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800',
  };

  return (
    <button className={`${base} ${sizes[size]} ${styles[variant]} ${className}`} {...props}>
      {children}
    </button>
  );
}

const inputBase =
  'block w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-primary-500 focus:ring-4 focus:ring-primary-500/10 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100';

export function Input({ className = '', ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input className={`${inputBase} ${className}`} {...props} />;
}

export function Textarea({
  className = '',
  ...props
}: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={`${inputBase} ${className}`} {...props} />;
}

export function Select({ className = '', ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={`${inputBase} ${className}`} {...props} />;
}

export function Label({
  children,
  htmlFor,
  className = '',
}: {
  children: ReactNode;
  htmlFor?: string;
  className?: string;
}) {
  return (
    <label
      htmlFor={htmlFor}
      className={`mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 ${className}`}
    >
      {children}
    </label>
  );
}

export function Card({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900 ${className}`}
    >
      {children}
    </div>
  );
}

export function CardTitle({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <h2
      className={`text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 ${className}`}
    >
      {children}
    </h2>
  );
}

export function CardHeader({
  title,
  description,
  action,
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 px-6 py-5 border-b border-slate-100 dark:border-slate-800">
      <div>
        <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
        {description && (
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{description}</p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

export function Badge({
  children,
  variant = 'default',
}: {
  children: ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger';
}) {
  const styles = {
    default:
      'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
    success:
      'bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-400',
    warning:
      'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-400',
    danger:
      'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400',
  };

  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${styles[variant]}`}
    >
      {children}
    </span>
  );
}

export function Separator({ className = '' }: { className?: string }) {
  return (
    <div
      className={`h-px w-full bg-slate-200 dark:bg-slate-800 ${className}`}
      role="separator"
    />
  );
}

export function Skeleton({ className = '' }: { className?: string }) {
  return (
    <div
      className={`animate-pulse rounded-md bg-slate-200 dark:bg-slate-800 ${className}`}
    />
  );
}

export function EmptyState({
  title,
  description,
  icon: Icon,
  action,
}: {
  title: string;
  description: string;
  icon?: React.ElementType;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-300 bg-slate-50/50 px-6 py-12 text-center dark:border-slate-700 dark:bg-slate-900/50">
      {Icon && <Icon className="mb-4 text-slate-400" size={40} strokeWidth={1.5} />}
      <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
      <p className="mt-1 max-w-xs text-sm text-slate-500 dark:text-slate-400">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}
