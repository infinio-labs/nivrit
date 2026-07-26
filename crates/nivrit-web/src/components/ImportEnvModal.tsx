import { FileUp, X } from 'lucide-react';
import { Button, Card, Textarea } from './ui';

export function ImportEnvModal({
  content,
  onChange,
  onSubmit,
  onClose,
  importing,
}: {
  content: string;
  onChange: (v: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  onClose: () => void;
  importing: boolean;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <Card className="w-full max-w-lg shadow-xl">
        <div className="flex items-start justify-between border-b border-slate-100 p-5 dark:border-slate-800">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-primary-50 p-2 text-primary-600 dark:bg-primary-900/20">
              <FileUp size={20} />
            </div>
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-white">
                Import from .env
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Paste a .env file. Comments and blank lines are ignored.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        <form onSubmit={onSubmit} className="space-y-4 p-5">
          <Textarea
            data-testid="import-env-textarea"
            rows={10}
            placeholder={`DATABASE_URL=postgres://...\nAPI_KEY=sk_live_...\n# comments are ignored`}
            value={content}
            onChange={(e) => onChange(e.target.value)}
            required
            className="font-mono text-xs"
          />

          <div className="flex items-center justify-end gap-3">
            <Button type="button" variant="ghost" onClick={onClose} disabled={importing}>
              Cancel
            </Button>
            <Button type="submit" data-testid="import-env-btn" disabled={importing}>
              {importing ? (
                <>
                  <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                  Importing…
                </>
              ) : (
                <>
                  <FileUp size={16} />
                  Import secrets
                </>
              )}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
